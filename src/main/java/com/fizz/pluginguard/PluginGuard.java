package com.fizz.pluginguard;

import org.bukkit.Bukkit;
import org.bukkit.ChatColor;
import org.bukkit.command.Command;
import org.bukkit.command.CommandExecutor;
import org.bukkit.command.CommandSender;
import org.bukkit.command.TabCompleter;
import org.bukkit.configuration.ConfigurationSection;
import org.bukkit.configuration.file.FileConfiguration;
import org.bukkit.configuration.file.YamlConfiguration;
import org.bukkit.entity.Player;
import org.bukkit.plugin.Plugin;
import org.bukkit.plugin.java.JavaPlugin;
import org.bukkit.util.StringUtil;

import java.io.File;
import java.io.FileInputStream;
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
import java.util.Properties;
import java.util.Set;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

/**
 * Guardio (plugin layer) — integrity guard for the whole server tree: the server jar plus every jar under the
 * configured roots. Layers: integrity (SHA-256 vs the trusted, path-mirrored vault), signature (malware
 * fingerprints), a known-malware hash feed, and report-only heuristics. The launcher/agent guard before load;
 * as a plugin, jars are locked at runtime so swaps are staged for a JVM shutdown hook.
 */
public final class PluginGuard extends JavaPlugin implements CommandExecutor, TabCompleter {

    private static final List<String> SUBS =
            List.of("scan", "status", "trust", "restore", "allow", "heal", "reload", "version");

    private record Pending(File infected, String rel, File clean, File quarantineDir) {
    }

    private Vault vault;
    private JarScanner scanner;
    private File serverRoot;
    private File home;
    private FileConfiguration config;
    private Messages msg;
    private List<String> roots;
    private List<String> whitelist;
    private boolean autoQuarantine;
    private boolean autoRestore;
    private boolean autoMap;
    private boolean autoDownload;
    private boolean alertOps;
    private boolean shutdownOnInfection;
    private boolean heuristicsOn;
    private Healer healer;
    private Map<String, String> sources;
    private String gameVersion;
    private ThreatFeed threatFeed;
    private String serverName;

    // Discord
    private boolean discordEnabled;
    private String webhook;
    private String discordRole;
    private boolean discordEmbeds;

    private String updateStatus = "(checking)";

    private final List<Pending> pending = new ArrayList<>();
    private List<ScanResult> lastResults = new ArrayList<>();
    private boolean infectionAtBoot = false;

    @Override
    public void onLoad() {
        this.serverRoot = resolveServerRoot();
        this.home = new File(serverRoot, "guardio");
        this.home.mkdirs();

        FileConfiguration c = loadConfigWithMigration();
        this.config = c;

        File msgFile = new File(home, "messages.yml");
        copyResourceIfMissing("messages.yml", msgFile);
        this.msg = new Messages(YamlConfiguration.loadConfiguration(msgFile), Messages.bundledDefaults(this::getResource));

        this.vault = new Vault(home);
        this.scanner = new JarScanner(c.getStringList("signatures.entry"), c.getStringList("signatures.content"));
        this.roots = c.getStringList("scanning.roots").isEmpty() ? Roots.DEFAULTS : c.getStringList("scanning.roots");
        this.whitelist = Whitelist.load(home);
        this.autoQuarantine = c.getBoolean("response.auto-quarantine", true);
        this.autoRestore = c.getBoolean("response.auto-restore", true);
        this.autoMap = c.getBoolean("response.auto-map", true);
        this.autoDownload = c.getBoolean("heal.auto-download", true);
        this.alertOps = c.getBoolean("general.alert-ops", true);
        this.shutdownOnInfection = c.getBoolean("response.shutdown-on-infection", false);
        this.heuristicsOn = c.getBoolean("scanning.heuristics", true);
        copyResourceIfMissing("sources.yml", new File(home, "sources.yml"));
        this.healer = new Healer(scanner);
        this.sources = loadSources();
        String gv = c.getString("heal.game-version", "");
        this.gameVersion = (gv == null || gv.isBlank()) ? Bukkit.getBukkitVersion().split("-")[0] : gv.trim();
        String sn = c.getString("general.server-name", "");
        this.serverName = (sn == null || sn.isBlank()) ? serverRoot.getName() : sn;
        this.threatFeed = ThreatFeed.loadOrFetch(new File(home, "threat-feed.txt"), c.getString("threat-feed.url", ""));

        this.discordEnabled = c.getBoolean("discord.enabled", false);
        String wh = c.getString("discord.webhook", "");
        this.webhook = (wh == null || wh.isBlank()) ? launcherWebhook() : wh.trim(); // fall back to guardio.properties
        this.discordRole = c.getString("discord.mention-role-id", "");
        this.discordEmbeds = c.getBoolean("discord.embeds", true);

        Runtime.getRuntime().addShutdownHook(new Thread(this::applyPending, "Guardio-remediate"));

        if (c.getBoolean("general.scan-on-load", true)) {
            getLogger().info("Scanning the server (plugins + libraries + server jar) for tampering/infection...");
            lastResults = runScan(true);
        }
    }

    @Override
    public void onEnable() {
        if (getCommand("guardio") != null) {
            getCommand("guardio").setExecutor(this);
            getCommand("guardio").setTabCompleter(this);
        }
        for (String line : msg.list("banner", "version", version(), "vault", vault.size(),
                "launcher", launcherActive(), "agent", agentActive())) {
            Bukkit.getConsoleSender().sendMessage(line);
        }
        int infected = count(ScanResult.Verdict.INFECTED);
        getLogger().info("Active. Vault baseline: " + vault.size() + " jar(s). Last scan: "
                + lastResults.size() + " jar(s), " + infected + " infected.");
        if (!pending.isEmpty()) {
            getLogger().warning(pending.size() + " infected jar(s) staged for shutdown — RESTART to apply.");
            if (alertOps) {
                alertOps(msg.get("pending", "count", pending.size()));
            }
        }
        if (autoDownload) {
            Bukkit.getScheduler().runTaskAsynchronously(this, () -> heal(null));
        }
        int mins = config.getInt("general.periodic-scan-minutes", 0);
        if (mins > 0) {
            long ticks = mins * 60L * 20L;
            Bukkit.getScheduler().runTaskTimerAsynchronously(this, () -> lastResults = runScan(true), ticks, ticks);
        }
        if (config.getBoolean("general.update-check", true)) {
            Bukkit.getScheduler().runTaskAsynchronously(this, this::checkUpdate);
        }
        if (infectionAtBoot && shutdownOnInfection) {
            getLogger().severe("shutdown-on-infection is ON and infection was found — stopping the server.");
            Bukkit.shutdown();
        }
    }

    // ---- Config -------------------------------------------------------------

    private FileConfiguration loadConfigWithMigration() {
        File cfgFile = new File(home, "config.yml");
        copyResourceIfMissing("config.yml", cfgFile);
        FileConfiguration c = YamlConfiguration.loadConfiguration(cfgFile);
        if (c.getInt("config-version", 1) < 2) { // upgrade an old (flat/Bulgarian) config
            try {
                Files.move(cfgFile.toPath(), new File(home, "config.yml.old").toPath(), StandardCopyOption.REPLACE_EXISTING);
            } catch (IOException ignored) {
                // best effort
            }
            copyResourceIfMissing("config.yml", cfgFile);
            c = YamlConfiguration.loadConfiguration(cfgFile);
            getLogger().info("Upgraded config.yml to the new format (your old one is saved as config.yml.old).");
        }
        return c;
    }

    private File resolveServerRoot() {
        try {
            File wc = getServer().getWorldContainer();
            if (wc != null) {
                return wc.getCanonicalFile();
            }
        } catch (Throwable ignored) {
            // fall through
        }
        File df = getDataFolder();
        if (df != null && df.getParentFile() != null && df.getParentFile().getParentFile() != null) {
            return df.getParentFile().getParentFile();
        }
        return new File(".").getAbsoluteFile();
    }

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
            // non-fatal
        }
    }

    /** The launcher's webhook (guardio.properties) — so the plugin inherits it when discord.webhook is blank. */
    private String launcherWebhook() {
        File f = new File(home, "guardio.properties");
        if (f.isFile()) {
            try (InputStream in = new FileInputStream(f)) {
                Properties p = new Properties();
                p.load(in);
                return p.getProperty("discord-webhook", "").trim();
            } catch (IOException ignored) {
                // none
            }
        }
        return "";
    }

    // ---- Scanning -----------------------------------------------------------

    private List<ScanResult> runScan(boolean remediate) {
        List<ScanResult> results = new ArrayList<>();
        List<String> events = new ArrayList<>();
        for (File jar : Roots.listJars(serverRoot, roots, home)) {
            String rel = Vault.rel(serverRoot, jar);
            String sha = Hashing.sha256(jar);
            List<String> sigReasons = scanner.scan(jar);
            boolean feedHit = threatFeed != null && threatFeed.contains(sha);
            List<String> reasons = new ArrayList<>(sigReasons);
            if (feedHit) {
                reasons.add("known-malware hash (threat feed)");
            }
            boolean sigHit = feedHit || (!sigReasons.isEmpty() && !Whitelist.allows(jar.getName(), whitelist));
            boolean inVault = vault.has(rel);
            boolean hashMatch = inVault && sha != null && sha.equals(vault.hash(rel));
            ScanResult r = new ScanResult(jar, sha, sigHit, inVault, hashMatch, reasons);
            results.add(r);

            if (r.verdict() == ScanResult.Verdict.INFECTED) {
                infectionAtBoot = true;
                String what = sigHit ? String.join("; ", reasons) : "integrity: hash differs from trusted vault copy";
                getLogger().severe("INFECTED: " + rel + "  ->  " + what);
                if (discordAlert("quarantine")) {
                    events.add(msg.plain("discord.infected", "rel", rel, "reason", what));
                }
                if (remediate && autoQuarantine) {
                    stageRemediation(jar, rel);
                }
            } else if (r.verdict() == ScanResult.Verdict.UNVERIFIED && autoMap && remediate) {
                if (vault.trust(jar, rel)) {
                    getLogger().info("mapped new jar into vault baseline: " + rel);
                }
                if (heuristicsOn && rel.startsWith("plugins")) {
                    List<String> sus = Heuristics.analyze(jar);
                    if (!sus.isEmpty()) {
                        getLogger().warning("SUSPICIOUS (report-only, NOT quarantined): " + rel + "  ->  " + String.join("; ", sus));
                        if (discordAlert("suspicious")) {
                            events.add(msg.plain("discord.suspicious", "rel", rel, "reason", String.join("; ", sus)));
                        }
                    }
                }
            }
        }
        writeReport(results);
        notify("scan", events);
        return results;
    }

    private void stageRemediation(File jar, String rel) {
        File clean = (autoRestore && vault.has(rel)) ? vault.file(rel) : null;
        pending.add(new Pending(jar, rel, clean, new File(home, "quarantine")));
        if (clean == null) {
            getLogger().warning("  no clean copy in vault for " + rel + " — it will be quarantined; reinstall a clean one.");
        }
    }

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
            // best effort
        }
    }

    // ---- Auto-heal ----------------------------------------------------------

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
                continue;
            }
            String[] info = readPluginInfo(qf);
            String pluginName = info != null ? info[0] : null;

            File trusted = TrustedBackups.find(home, pluginName, new File(rel).getName(), scanner);
            if (trusted != null) {
                try {
                    install(trusted, dest, rel);
                    healed++;
                    report.add("HEALED " + rel + "  <-  trusted/" + trusted.getName());
                    getLogger().info("healed " + rel + " from trusted backup " + trusted.getName());
                    continue;
                } catch (IOException ex) {
                    // fall through to download
                }
            }
            if (info == null) {
                report.add("skip (no plugin.yml / library; add a copy to guardio/trusted/): " + rel);
                continue;
            }
            String override = sources.getOrDefault(info[0], sources.get(new File(rel).getName()));
            Healer.Result res = healer.fetchClean(info[0], info[1], gameVersion, override);
            if (res.ok()) {
                try {
                    install(res.file, dest, rel);
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
                report.add("MANUAL " + rel + " (" + info[0] + ") : " + res.error);
                getLogger().warning("could not auto-heal " + info[0] + " — " + res.error + " (reinstall manually).");
            }
        }
        if (!report.isEmpty()) {
            try {
                Files.write(new File(home, "heal-report.txt").toPath(), report);
            } catch (IOException ignored) {
                // non-fatal
            }
            if (discordAlert("heal")) {
                discordSend("auto-heal", report);
            }
        }
        final int h = healed;
        final int m = manual;
        Bukkit.getScheduler().runTask(this, () -> {
            getLogger().info("auto-heal done: " + h + " healed, " + m + " need manual reinstall.");
            String line = msg.get("heal.done", "healed", h, "manual", m, "restart", h > 0 ? msg.get("heal.restart-hint") : "");
            if (sender != null) {
                send(sender, line);
            } else if (alertOps && (h > 0 || m > 0)) {
                alertOps(line);
            }
        });
    }

    private void install(File from, File dest, String rel) throws IOException {
        File p = dest.getParentFile();
        if (p != null) {
            p.mkdirs();
        }
        Files.copy(from.toPath(), dest.toPath(), StandardCopyOption.REPLACE_EXISTING);
        vault.trust(dest, rel);
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

    private String relFromQuarantine(File quarantine, File f) {
        return Vault.rel(quarantine, f).replaceAll("\\.\\d+\\.infected$", "");
    }

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

    // ---- Discord ------------------------------------------------------------

    private boolean discordAlert(String type) {
        return discordEnabled && webhook != null && !webhook.isBlank()
                && config.getBoolean("discord.alerts." + type, true);
    }

    private void notify(String context, List<String> events) {
        if (!discordEnabled || webhook == null || webhook.isBlank() || events == null || events.isEmpty()) {
            return;
        }
        if (isEnabled()) {
            Bukkit.getScheduler().runTaskAsynchronously(this, () -> discordSend(context, events));
        } else {
            discordSend(context, events);
        }
    }

    private void discordSend(String context, List<String> lines) {
        String body = msg.plain("discord.header", "server", serverName, "context", context) + "\n" + String.join("\n", lines);
        String role = (discordRole != null && !discordRole.isBlank()) ? "<@&" + discordRole + "> " : "";
        Notifier.send(webhook, role, body, discordEmbeds);
    }

    // ---- Update check -------------------------------------------------------

    private void checkUpdate() {
        String latest = UpdateChecker.latest(config.getString("general.update-url", "https://api.github.com/repos/fizzexual/Guardio/releases/latest"));
        if (latest == null) {
            updateStatus = msg.get("update.unknown");
        } else if (!latest.equalsIgnoreCase(version())) {
            updateStatus = msg.get("update.available", "latest", latest);
            getLogger().info("A newer Guardio is available: " + latest + " (you have " + version() + ").");
        } else {
            updateStatus = msg.get("update.current");
        }
    }

    // ---- Commands -----------------------------------------------------------

    @Override
    public boolean onCommand(CommandSender sender, Command command, String label, String[] args) {
        String sub = args.length > 0 ? args[0].toLowerCase(Locale.ROOT) : "status";
        switch (sub) {
            case "scan" -> {
                lastResults = runScan(true);
                send(sender, msg.get("scan.complete", "total", lastResults.size(),
                        "infected", count(ScanResult.Verdict.INFECTED), "unverified", count(ScanResult.Verdict.UNVERIFIED)));
                for (ScanResult r : lastResults) {
                    if (r.verdict() == ScanResult.Verdict.INFECTED) {
                        sendRaw(sender, msg.get("scan.infected-line", "rel", Vault.rel(serverRoot, r.jar()),
                                "reason", r.signatureHit() ? String.join("; ", r.reasons()) : "hash mismatch vs vault"));
                    }
                }
                if (!pending.isEmpty()) {
                    send(sender, msg.get("scan.staged", "count", pending.size()));
                }
            }
            case "status" -> send(sender, msg.get("status", "vault", vault.size(), "total", lastResults.size(),
                    "infected", count(ScanResult.Verdict.INFECTED), "unverified", count(ScanResult.Verdict.UNVERIFIED),
                    "staged", pending.size()));
            case "version" -> {
                for (String line : msg.list("version", "version", version(), "vault", vault.size(),
                        "launcher", launcherActive(), "agent", agentActive(), "update", updateStatus)) {
                    sendRaw(sender, line);
                }
            }
            case "trust" -> {
                if (args.length < 2) {
                    send(sender, msg.get("trust.usage"));
                    return true;
                }
                trust(sender, args[1]);
            }
            case "restore" -> {
                if (args.length < 2) {
                    send(sender, msg.get("restore.usage"));
                    return true;
                }
                File jar = resolveJar(args[1]);
                if (jar == null || !vault.has(Vault.rel(serverRoot, jar))) {
                    send(sender, msg.get("restore.none", "jar", args[1]));
                    return true;
                }
                stageRemediation(jar, Vault.rel(serverRoot, jar));
                send(sender, msg.get("restore.staged", "jar", args[1]));
            }
            case "allow" -> {
                if (args.length < 2) {
                    send(sender, msg.get("allow.usage"));
                    return true;
                }
                try {
                    Whitelist.add(home, args[1]);
                    whitelist = Whitelist.load(home);
                    File jar = resolveJar(args[1]);
                    if (jar != null) {
                        vault.trust(jar, Vault.rel(serverRoot, jar));
                    }
                    send(sender, msg.get("allow.done", "jar", args[1]));
                } catch (Exception ex) {
                    send(sender, msg.get("allow.fail", "error", ex.getMessage()));
                }
            }
            case "heal" -> {
                send(sender, msg.get("heal.started"));
                Bukkit.getScheduler().runTaskAsynchronously(this, () -> heal(sender));
            }
            case "reload" -> {
                if (args.length < 2) {
                    send(sender, msg.get("reload.usage"));
                    return true;
                }
                Reloader.Result res = Reloader.reload(this, args[1]);
                for (String line : res.lines()) {
                    sendRaw(sender, msg.get(res.ok() ? "reload.line" : "reload.line-warn", "line", line));
                }
                send(sender, res.ok() ? msg.get("reload.ok", "plugin", args[1]) : msg.get("reload.fail", "plugin", args[1]));
                notify("reload", List.of((res.ok() ? "🔄 reloaded `" : "⚠️ reload FAILED for `") + args[1]
                        + "` by " + sender.getName()));
            }
            default -> send(sender, msg.get("command.unknown"));
        }
        return true;
    }

    @Override
    public List<String> onTabComplete(CommandSender sender, Command command, String alias, String[] args) {
        if (!sender.hasPermission("guardio.admin")) {
            return List.of();
        }
        if (args.length == 1) {
            return StringUtil.copyPartialMatches(args[0], SUBS, new ArrayList<>());
        }
        if (args.length == 2) {
            List<String> opts = switch (args[0].toLowerCase(Locale.ROOT)) {
                case "trust" -> {
                    List<String> l = jarNames();
                    l.add(0, "all");
                    yield l;
                }
                case "restore", "allow" -> jarNames();
                case "reload" -> pluginNames();
                default -> List.of();
            };
            return StringUtil.copyPartialMatches(args[1], opts, new ArrayList<>());
        }
        return List.of();
    }

    private List<String> jarNames() {
        List<String> out = new ArrayList<>();
        for (File jar : Roots.listJars(serverRoot, roots, home)) {
            out.add(jar.getName());
        }
        return out;
    }

    private List<String> pluginNames() {
        List<String> out = new ArrayList<>();
        for (Plugin p : Bukkit.getPluginManager().getPlugins()) {
            out.add(p.getName());
        }
        return out;
    }

    private void trust(CommandSender sender, String which) {
        if (which.equalsIgnoreCase("all")) {
            int n = 0;
            for (File jar : Roots.listJars(serverRoot, roots, home)) {
                if (vault.trust(jar, Vault.rel(serverRoot, jar))) {
                    n++;
                }
            }
            send(sender, msg.get("trust.all", "count", n));
            send(sender, msg.get("trust.warn"));
        } else {
            File jar = resolveJar(which);
            if (jar == null) {
                send(sender, msg.get("trust.none", "jar", which));
                return;
            }
            send(sender, vault.trust(jar, Vault.rel(serverRoot, jar))
                    ? msg.get("trust.one", "jar", which) : msg.get("trust.fail", "jar", which));
        }
    }

    // ---- Helpers ------------------------------------------------------------

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

    private String version() {
        return getDescription().getVersion();
    }

    private String launcherActive() {
        return System.getProperty("guardio.launcher") != null ? "&ayes" : "&cno";
    }

    private String agentActive() {
        return System.getProperty("guardio.agent") != null ? "&ayes" : "&cno";
    }

    private void alertOps(String colored) {
        String line = msg.prefix() + colored;
        for (Player p : Bukkit.getOnlinePlayers()) {
            if (p.isOp()) {
                p.sendMessage(line);
            }
        }
    }

    private void send(CommandSender sender, String colored) {
        sender.sendMessage(msg.prefix() + colored);
    }

    private void sendRaw(CommandSender sender, String colored) {
        sender.sendMessage(colored);
    }

    private void writeReport(List<ScanResult> results) {
        List<String> lines = new ArrayList<>();
        lines.add("Guardio scan report");
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
