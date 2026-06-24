package com.fizz.pluginguard;

import org.bukkit.Bukkit;
import org.bukkit.ChatColor;
import org.bukkit.command.Command;
import org.bukkit.command.CommandExecutor;
import org.bukkit.command.CommandSender;
import org.bukkit.configuration.ConfigurationSection;
import org.bukkit.configuration.file.FileConfiguration;
import org.bukkit.configuration.file.YamlConfiguration;
import org.bukkit.entity.Player;
import org.bukkit.plugin.java.JavaPlugin;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.StandardCopyOption;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

/**
 * PluginGuard — integrity guard for the WHOLE server tree: the top-level server jar plus every jar under the
 * configured roots (default {@code plugins} + {@code libraries}). Two layers: <b>integrity</b> (SHA-256 vs the
 * trusted, path-mirrored {@code vault/}) and <b>signature</b> (malware fingerprints). It reports where/what,
 * quarantines infected jars and restores the clean copy.
 *
 * <p>The bullet-proof enforcement runs in the {@link GuardAgent} ({@code -javaagent}, before anything loads).
 * As a plugin, jars are already locked at runtime, so the file swap is staged and applied via a JVM shutdown
 * hook — so the <i>next</i> start is clean. Guards a CLEAN baseline; not a substitute for cleaning a host.</p>
 */
public final class PluginGuard extends JavaPlugin implements CommandExecutor {

    private record Pending(File infected, String rel, File clean, File quarantineDir) {
    }

    private Vault vault;
    private JarScanner scanner;
    private File serverRoot;
    private File home; // <serverRoot>/guardio — shared home (vault, quarantine, config) for launcher + agent + plugin
    private FileConfiguration config;
    private List<String> roots;
    private List<String> whitelist;
    private boolean autoQuarantine;
    private boolean autoRestore;
    private boolean autoMap;
    private boolean autoDownload;
    private boolean alertOps;
    private boolean shutdownOnInfection;
    private Healer healer;
    private Map<String, String> sources;
    private String gameVersion;

    private final List<Pending> pending = new ArrayList<>();
    private List<ScanResult> lastResults = new ArrayList<>();
    private boolean infectionAtBoot = false;

    @Override
    public void onLoad() {
        this.serverRoot = resolveServerRoot(); // robust: Paper's plugin remapper can leave getDataFolder()'s parents null
        this.home = new File(serverRoot, "guardio"); // shared home with the launcher + agent (not plugins/<name>)
        this.home.mkdirs();

        File cfgFile = new File(home, "config.yml");
        copyResourceIfMissing("config.yml", cfgFile);
        FileConfiguration c = YamlConfiguration.loadConfiguration(cfgFile);
        this.config = c;

        this.vault = new Vault(home);
        this.scanner = new JarScanner(c.getStringList("entry-signatures"), c.getStringList("content-signatures"));
        this.roots = c.getStringList("scan-roots").isEmpty() ? Roots.DEFAULTS : c.getStringList("scan-roots");
        this.whitelist = Whitelist.load(home);
        this.autoQuarantine = c.getBoolean("auto-quarantine", true);
        this.autoRestore = c.getBoolean("auto-restore", true);
        this.autoMap = c.getBoolean("auto-map", true);
        this.autoDownload = c.getBoolean("auto-download", false);
        this.alertOps = c.getBoolean("alert-ops", true);
        this.shutdownOnInfection = c.getBoolean("shutdown-on-infection", false);
        copyResourceIfMissing("sources.yml", new File(home, "sources.yml"));
        this.healer = new Healer(scanner);
        this.sources = loadSources();
        String gv = c.getString("download-game-version", "");
        this.gameVersion = (gv == null || gv.isBlank()) ? Bukkit.getBukkitVersion().split("-")[0] : gv.trim();

        Runtime.getRuntime().addShutdownHook(new Thread(this::applyPending, "Guardio-remediate"));

        if (c.getBoolean("scan-on-load", true)) {
            getLogger().info("Scanning the server (plugins + libraries + server jar) for tampering/infection...");
            lastResults = runScan(true);
        }
    }

    @Override
    public void onEnable() {
        if (getCommand("guard") != null) {
            getCommand("guard").setExecutor(this);
        }
        int infected = count(ScanResult.Verdict.INFECTED);
        getLogger().info("Active. Vault baseline: " + vault.size() + " jar(s). Last scan: "
                + lastResults.size() + " jar(s), " + infected + " infected.");
        if (!pending.isEmpty()) {
            getLogger().warning(pending.size() + " infected jar(s) will be quarantined + restored on shutdown — "
                    + "RESTART the server to apply. (Tip: enable the -javaagent for pre-load protection.)");
        }
        if (infected > 0 && alertOps) {
            alertOps("&c[PluginGuard] " + infected + " infected jar(s) detected — see console / /guard status.");
        }
        if (autoDownload) {
            Bukkit.getScheduler().runTaskAsynchronously(this, () -> heal(null));
        }
        int mins = config.getInt("periodic-scan-minutes", 0);
        if (mins > 0) {
            long ticks = mins * 60L * 20L;
            Bukkit.getScheduler().runTaskTimerAsynchronously(this, () -> {
                lastResults = runScan(true);
                int n = count(ScanResult.Verdict.INFECTED);
                if (n > 0 && alertOps) {
                    Bukkit.getScheduler().runTask(this, () ->
                            alertOps("&c[PluginGuard] periodic scan: " + n + " infected jar(s)!"));
                }
            }, ticks, ticks);
        }
        if (infectionAtBoot && shutdownOnInfection) {
            getLogger().severe("shutdown-on-infection is ON and infection was found — stopping the server.");
            Bukkit.shutdown();
        }
    }

    // ---- Scanning -------------------------------------------------------

    /** Server root, resolved robustly. Paper's plugin remapper can load us in a pass where getDataFolder()'s
     *  parent chain is null, so prefer the server's working directory and fall back safely (never null). */
    private File resolveServerRoot() {
        try {
            File wc = getServer().getWorldContainer();
            if (wc != null) {
                return wc.getCanonicalFile();
            }
        } catch (Throwable ignored) {
            // server not ready / unavailable — fall through
        }
        File df = getDataFolder();
        if (df != null && df.getParentFile() != null && df.getParentFile().getParentFile() != null) {
            return df.getParentFile().getParentFile();
        }
        return new File(".").getAbsoluteFile();
    }

    /** Copies a bundled resource (config.yml / sources.yml) into Guardio's home if it isn't there yet. */
    private void copyResourceIfMissing(String name, File dest) {
        if (dest.exists()) {
            return;
        }
        try (InputStream in = getResource(name)) {
            if (in != null) {
                File p = dest.getParentFile();
                if (p != null) {
                    p.mkdirs();
                }
                Files.copy(in, dest.toPath());
            }
        } catch (IOException ignored) {
            // non-fatal — defaults apply
        }
    }

    private List<ScanResult> runScan(boolean remediate) {
        List<ScanResult> results = new ArrayList<>();
        for (File jar : Roots.listJars(serverRoot, roots, home)) {
            String rel = Vault.rel(serverRoot, jar);
            String sha = Hashing.sha256(jar);
            List<String> reasons = scanner.scan(jar);
            boolean sigHit = !reasons.isEmpty() && !Whitelist.allows(jar.getName(), whitelist);
            boolean inVault = vault.has(rel);
            boolean hashMatch = inVault && sha != null && sha.equals(vault.hash(rel));
            ScanResult r = new ScanResult(jar, sha, sigHit, inVault, hashMatch, reasons);
            results.add(r);

            if (r.verdict() == ScanResult.Verdict.INFECTED) {
                infectionAtBoot = true;
                String what = sigHit ? String.join("; ", reasons) : "integrity: hash differs from trusted vault copy";
                getLogger().severe("INFECTED: " + rel + "  ->  " + what);
                if (remediate && autoQuarantine) {
                    stageRemediation(jar, rel);
                }
            } else if (r.verdict() == ScanResult.Verdict.UNVERIFIED && autoMap && remediate) {
                if (vault.trust(jar, rel)) {
                    getLogger().info("mapped new jar into vault baseline: " + rel);
                }
            }
        }
        writeReport(results);
        return results;
    }

    /** Queues a quarantine (+ restore if the vault has a clean copy) to run when jars unlock at shutdown. */
    private void stageRemediation(File jar, String rel) {
        File clean = (autoRestore && vault.has(rel)) ? vault.file(rel) : null;
        pending.add(new Pending(jar, rel, clean, new File(home, "quarantine")));
        if (clean == null) {
            getLogger().warning("  no clean copy in vault for " + rel + " — it will be quarantined; reinstall a clean one.");
        }
    }

    /** Runs in the JVM shutdown hook (Bukkit gone, jars unlocked). Writes a result log to disk. */
    private void applyPending() {
        if (pending.isEmpty()) {
            return;
        }
        List<String> log = new ArrayList<>();
        for (Pending p : pending) {
            try {
                if (p.infected().exists()) {
                    File q = new File(p.quarantineDir(), p.rel() + "." + System.currentTimeMillis() + ".infected");
                    File qp = q.getParentFile();
                    if (qp != null) {
                        qp.mkdirs();
                    }
                    Files.move(p.infected().toPath(), q.toPath(), StandardCopyOption.REPLACE_EXISTING);
                    log.add("quarantined " + p.rel());
                }
                if (p.clean() != null && p.clean().exists()) {
                    Files.copy(p.clean().toPath(), p.infected().toPath(), StandardCopyOption.REPLACE_EXISTING);
                    log.add("restored   " + p.rel() + " from vault");
                }
            } catch (IOException ex) {
                log.add("FAILED     " + p.rel() + " : " + ex.getMessage());
            }
        }
        try {
            Files.write(new File(home, "last-remediation.txt").toPath(), log);
        } catch (IOException ignored) {
            // best effort — console may already be down at shutdown
        }
    }

    // ---- Auto-heal (download clean replacements for quarantined plugins) --

    private void heal(CommandSender sender) {
        File quarantine = new File(home, "quarantine");
        List<File> infectedFiles = new ArrayList<>();
        collectInfected(quarantine, infectedFiles);
        Set<String> seen = new HashSet<>();
        List<String> report = new ArrayList<>();
        int healed = 0;
        int manual = 0;
        for (File qf : infectedFiles) {
            String rel = relFromQuarantine(quarantine, qf);
            if (rel == null || !seen.add(rel)) {
                continue;
            }
            File dest = new File(serverRoot, rel);
            if (dest.exists() || vault.has(rel)) {
                continue; // already healed / restored elsewhere
            }
            String[] info = readPluginInfo(qf);
            if (info == null) {
                report.add("skip (no plugin.yml / library): " + rel);
                continue;
            }
            String name = info[0];
            String override = sources.getOrDefault(name, sources.get(new File(rel).getName()));
            Healer.Result res = healer.fetchClean(name, info[1], gameVersion, override);
            if (res.ok()) {
                try {
                    File p = dest.getParentFile();
                    if (p != null) {
                        p.mkdirs();
                    }
                    Files.copy(res.file.toPath(), dest.toPath(), StandardCopyOption.REPLACE_EXISTING);
                    vault.trust(dest, rel);
                    res.file.delete();
                    healed++;
                    report.add("HEALED " + rel + "  <-  " + res.source);
                    getLogger().info("auto-healed " + rel + " from " + res.source);
                } catch (IOException ex) {
                    manual++;
                    report.add("FAILED install " + rel + " : " + ex.getMessage());
                }
            } else {
                manual++;
                report.add("MANUAL " + rel + " (" + name + ") : " + res.error);
                getLogger().warning("could not auto-heal " + name + " — " + res.error + " (reinstall manually).");
            }
        }
        if (!report.isEmpty()) {
            try {
                Files.write(new File(home, "heal-report.txt").toPath(), report);
            } catch (IOException ignored) {
                // non-fatal
            }
        }
        final int h = healed;
        final int m = manual;
        Bukkit.getScheduler().runTask(this, () -> {
            getLogger().info("auto-heal done: " + h + " healed, " + m + " need manual reinstall.");
            String msg = "&a[PluginGuard] auto-heal: &f" + h + "&a healed, &e" + m + "&a need manual reinstall."
                    + (h > 0 ? " &7Restart to load the clean copies." : "");
            if (sender != null) {
                reply(sender, msg);
            } else if (alertOps && (h > 0 || m > 0)) {
                alertOps(msg);
            }
        });
    }

    private void collectInfected(File dir, List<File> out) {
        File[] fs = dir.listFiles();
        if (fs == null) {
            return;
        }
        for (File f : fs) {
            if (f.isDirectory()) {
                collectInfected(f, out);
            } else if (f.getName().endsWith(".infected")) {
                out.add(f);
            }
        }
    }

    /** {@code quarantine/plugins/X.jar.1699.infected} -> {@code plugins/X.jar}. */
    private String relFromQuarantine(File quarantine, File f) {
        return Vault.rel(quarantine, f).replaceAll("\\.\\d+\\.infected$", "");
    }

    /** Reads name + version from a jar's plugin.yml, or null if it has none (not a Bukkit plugin). */
    private String[] readPluginInfo(File jar) {
        try (ZipFile zip = new ZipFile(jar)) {
            ZipEntry e = zip.getEntry("plugin.yml");
            if (e == null) {
                e = zip.getEntry("paper-plugin.yml");
            }
            if (e == null) {
                return null;
            }
            YamlConfiguration y = YamlConfiguration.loadConfiguration(
                    new InputStreamReader(zip.getInputStream(e), StandardCharsets.UTF_8));
            String name = y.getString("name");
            return name == null ? null : new String[]{name, y.getString("version", "")};
        } catch (Exception ex) {
            return null;
        }
    }

    private Map<String, String> loadSources() {
        Map<String, String> m = new HashMap<>();
        File f = new File(home, "sources.yml");
        if (f.isFile()) {
            ConfigurationSection ov = YamlConfiguration.loadConfiguration(f).getConfigurationSection("overrides");
            if (ov != null) {
                for (String k : ov.getKeys(false)) {
                    m.put(k, ov.getString(k));
                }
            }
        }
        return m;
    }

    // ---- Command --------------------------------------------------------

    @Override
    public boolean onCommand(CommandSender sender, Command command, String label, String[] args) {
        String sub = args.length > 0 ? args[0].toLowerCase(Locale.ROOT) : "status";
        switch (sub) {
            case "scan" -> {
                lastResults = runScan(true);
                reply(sender, "&aScan complete: &f" + lastResults.size() + "&a jar(s), &c"
                        + count(ScanResult.Verdict.INFECTED) + "&a infected, &e"
                        + count(ScanResult.Verdict.UNVERIFIED) + "&a unverified.");
                for (ScanResult r : lastResults) {
                    if (r.verdict() == ScanResult.Verdict.INFECTED) {
                        reply(sender, "  &cINFECTED &f" + Vault.rel(serverRoot, r.jar()) + " &7- "
                                + (r.signatureHit() ? String.join("; ", r.reasons()) : "hash mismatch vs vault"));
                    }
                }
                if (!pending.isEmpty()) {
                    reply(sender, "&e" + pending.size() + " fix(es) staged — restart to apply.");
                }
            }
            case "status" -> reply(sender, "&7Vault baseline: &f" + vault.size() + "&7 jar(s). Last scan: &f"
                    + lastResults.size() + "&7 jar(s), &c" + count(ScanResult.Verdict.INFECTED)
                    + "&7 infected, &e" + count(ScanResult.Verdict.UNVERIFIED) + "&7 unverified, &e"
                    + pending.size() + "&7 fix(es) staged for restart.");
            case "trust" -> {
                if (args.length < 2) {
                    reply(sender, "&cUsage: /guard trust <all|jarName>  &7(only trust VERIFIED-clean jars!)");
                    return true;
                }
                trust(sender, args[1]);
            }
            case "restore" -> {
                if (args.length < 2) {
                    reply(sender, "&cUsage: /guard restore <jarName>");
                    return true;
                }
                File jar = resolveJar(args[1]);
                if (jar == null || !vault.has(Vault.rel(serverRoot, jar))) {
                    reply(sender, "&cNo clean vault copy matching '" + args[1] + "'.");
                    return true;
                }
                stageRemediation(jar, Vault.rel(serverRoot, jar));
                reply(sender, "&aStaged restore of &f" + args[1] + "&a from vault — restart to apply.");
            }
            case "allow" -> {
                if (args.length < 2) {
                    reply(sender, "&cUsage: /guard allow <jarName>  &7(clear a false positive — whitelist + map it)");
                    return true;
                }
                try {
                    Whitelist.add(home, args[1]);
                    whitelist = Whitelist.load(home);
                    File jar = resolveJar(args[1]);
                    if (jar != null) {
                        vault.trust(jar, Vault.rel(serverRoot, jar));
                    }
                    reply(sender, "&aWhitelisted &f" + args[1] + "&a — signature ignored and mapped as trusted.");
                } catch (Exception ex) {
                    reply(sender, "&cFailed to whitelist: " + ex.getMessage());
                }
            }
            case "heal" -> {
                reply(sender, "&aAuto-heal started — downloading clean copies for quarantined plugins. "
                        + "Watch console / heal-report.txt; restart when done.");
                Bukkit.getScheduler().runTaskAsynchronously(this, () -> heal(sender));
            }
            default -> reply(sender, "&7/guard &f<scan | status | trust [all|<jar>] | restore <jar> | allow <jar> | heal>");
        }
        return true;
    }

    private void trust(CommandSender sender, String which) {
        if (which.equalsIgnoreCase("all")) {
            int n = 0;
            for (File jar : Roots.listJars(serverRoot, roots, home)) {
                if (vault.trust(jar, Vault.rel(serverRoot, jar))) {
                    n++;
                }
            }
            reply(sender, "&aTrusted &f" + n + "&a jar(s) (whole server) into the vault baseline.");
            reply(sender, "&e⚠ Only do this on a VERIFIED-clean install — it makes these the trusted versions.");
        } else {
            File jar = resolveJar(which);
            if (jar == null) {
                reply(sender, "&cNo such jar: " + which);
                return;
            }
            reply(sender, vault.trust(jar, Vault.rel(serverRoot, jar))
                    ? "&aTrusted &f" + which + "&a into the vault." : "&cFailed to trust " + which);
        }
    }

    // ---- Helpers --------------------------------------------------------

    /** Finds a scanned jar by exact name or by relative path (case-insensitive). */
    private File resolveJar(String arg) {
        for (File jar : Roots.listJars(serverRoot, roots, home)) {
            if (jar.getName().equalsIgnoreCase(arg) || Vault.rel(serverRoot, jar).equalsIgnoreCase(arg)) {
                return jar;
            }
        }
        return null;
    }

    private int count(ScanResult.Verdict v) {
        int n = 0;
        for (ScanResult r : lastResults) {
            if (r.verdict() == v) {
                n++;
            }
        }
        return n;
    }

    private void alertOps(String legacy) {
        for (Player p : Bukkit.getOnlinePlayers()) {
            if (p.isOp()) {
                p.sendMessage(ChatColor.translateAlternateColorCodes('&', legacy));
            }
        }
    }

    private void reply(CommandSender sender, String legacy) {
        sender.sendMessage(ChatColor.translateAlternateColorCodes('&', legacy));
    }

    private void writeReport(List<ScanResult> results) {
        List<String> lines = new ArrayList<>();
        lines.add("PluginGuard scan report");
        lines.add("vault baseline jars: " + vault.size());
        lines.add("");
        for (ScanResult r : results) {
            lines.add(r.verdict() + "  " + Vault.rel(serverRoot, r.jar())
                    + (r.verdict() == ScanResult.Verdict.INFECTED
                        ? "  :: " + (r.signatureHit() ? String.join("; ", r.reasons()) : "hash mismatch vs vault")
                        : ""));
        }
        try {
            Files.write(new File(home, "guard-report.txt").toPath(), lines);
        } catch (IOException ignored) {
            // non-fatal
        }
    }
}
