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
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Properties;
import java.util.Set;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.function.Consumer;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

/**
 * Guardio (plugin layer) — runtime integrity guard + control plane. Scans run on a single dedicated executor
 * (off the main thread, never overlapping) with an incremental SHA-256 cache; detection spans integrity,
 * signature, threat-feed, heuristic, cracked-plugin, and honeypot layers. A real-time {@link FileWatcher}
 * triggers re-scans, and an HTML report is written each scan. Locked-jar swaps are staged for a shutdown hook.
 */
public final class PluginGuard extends JavaPlugin implements CommandExecutor, TabCompleter {

    private static final List<String> SUBS =
            List.of("scan", "status", "version", "doctor", "report", "trust", "restore", "allow", "heal", "reload");

    private record Pending(File infected, String rel, File clean, File quarantineDir) {
    }

    private Vault vault;
    private JarScanner scanner;
    private File serverRoot;
    private File home;
    private FileConfiguration config;
    private Messages msg;
    private List<String> roots;
    private volatile List<String> whitelist; // reassigned on the main thread (allow cmd), read on the scan thread
    private boolean autoQuarantine;
    private boolean autoRestore;
    private boolean autoMap;
    private boolean autoDownload;
    private boolean alertOps;
    private boolean shutdownOnInfection;
    private boolean heuristicsOn;
    private boolean detectCracked;
    private boolean honeypotOn;
    private boolean allowlistOnly;
    private boolean realTimeWatch;
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

    private List<String> devPlugins = List.of();

    private String updateStatus = "(checking)";

    private final List<Pending> pending = Collections.synchronizedList(new ArrayList<>());
    private volatile List<ScanResult> lastResults = new ArrayList<>();
    private boolean infectionAtBoot = false;

    private ExecutorService scanExecutor;
    private final Map<String, String> shaCache = new HashMap<>(); // path|mtime|size -> sha (executor-thread only)
    private Map<String, String> prevSnapshot = new HashMap<>();    // rel -> sha, from the previous scan
    private FileWatcher watcher;
    private DownloadServer downloadServer;
    private Thread remediateHook;

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
        this.detectCracked = c.getBoolean("scanning.detect-cracked", true);
        this.honeypotOn = c.getBoolean("scanning.honeypot", true);
        this.allowlistOnly = c.getBoolean("response.allowlist-only", false);
        this.realTimeWatch = c.getBoolean("scanning.real-time-watch", true);
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
        this.webhook = (wh == null || wh.isBlank()) ? readProp("discord-webhook") : wh.trim();
        this.discordRole = c.getString("discord.mention-role-id", "");
        this.discordEmbeds = c.getBoolean("discord.embeds", true);
        // Plugins the operator builds + rebuilds themselves; a change to one is re-baselined, not flagged.
        // Single source = guardio.properties (the pure-JDK launcher/agent can't parse this YAML config).
        this.devPlugins = DevPlugins.parse(readProp("dev-plugins"));
        // Self-integrity is enforced by the launcher + pre-load agent on the REAL jar (the plugin's own jar is
        // remapped by Paper, so a plugin-layer self-hash would false-positive). The launcher re-syncs the
        // plugins/ copy from the verified root each boot, so this layer doesn't need its own check.

        this.scanExecutor = Executors.newSingleThreadExecutor(r -> {
            Thread t = new Thread(r, "Guardio-scan");
            t.setDaemon(true);
            return t;
        });
        this.prevSnapshot = loadSnapshot();
        if (honeypotOn) {
            Honeypot.deploy(serverRoot, home);
        }

        this.remediateHook = new Thread(this::applyPending, "Guardio-remediate");
        Runtime.getRuntime().addShutdownHook(remediateHook);

        if (c.getBoolean("general.scan-on-load", true)) {
            getLogger().info("Scanning the server (plugins + libraries + server jar) for tampering/infection...");
            lastResults = runScan(true); // synchronous at load — scheduler/executor consumers not yet active
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
            Bukkit.getScheduler().runTaskTimerAsynchronously(this, () -> submitScan(null), ticks, ticks);
        }
        if (realTimeWatch) {
            watcher = new FileWatcher(watchDirs(), () -> submitScan(null));
            watcher.start();
            getLogger().info("Real-time watcher active on: " + roots);
        }
        if (config.getBoolean("download-server.enabled", false)) {
            try {
                downloadServer = new DownloadServer(config.getInt("download-server.port", 20010),
                        config.getString("download-server.token", ""),
                        config.getBoolean("download-server.localhost-only", true),
                        config.getBoolean("download-server.allow-quarantine", false), home);
                downloadServer.start();
                if (downloadServer.isDisabled()) {
                    getLogger().warning("download-server enabled but no token set — endpoint NOT started.");
                } else {
                    getLogger().info("download endpoint listening on port " + config.getInt("download-server.port", 20010)
                            + (config.getBoolean("download-server.localhost-only", true) ? " (localhost only)" : " (ALL interfaces)"));
                }
            } catch (Exception ex) {
                getLogger().warning("could not start download endpoint: " + ex.getMessage());
            }
        }
        if (config.getBoolean("general.update-check", true)) {
            Bukkit.getScheduler().runTaskAsynchronously(this, this::checkUpdate);
        }
        if (infectionAtBoot && shutdownOnInfection) {
            getLogger().severe("shutdown-on-infection is ON and infection was found — stopping the server.");
            Bukkit.shutdown();
        }
    }

    @Override
    public void onDisable() {
        if (watcher != null) {
            watcher.stop();
        }
        if (downloadServer != null) {
            downloadServer.stop();
        }
        if (scanExecutor != null) {
            scanExecutor.shutdownNow();
        }
        if (healer != null) {
            healer.close(); // shut down its HttpClient SelectorManager thread (no leak across /reload)
        }
        if (remediateHook != null) {
            try {
                Runtime.getRuntime().removeShutdownHook(remediateHook); // let this dead instance be GC'd
            } catch (IllegalStateException ignored) {
                // already shutting down
            }
        }
    }

    // ---- Config -------------------------------------------------------------

    private FileConfiguration loadConfigWithMigration() {
        File cfgFile = new File(home, "config.yml");
        copyResourceIfMissing("config.yml", cfgFile);
        FileConfiguration c = YamlConfiguration.loadConfiguration(cfgFile);
        if (c.getInt("config-version", 1) < 2) {
            File old = new File(home, "config.yml.old");
            File fresh = new File(home, "config.yml.new");
            try {
                // Stage the new config to a temp file and VERIFY it before touching the live one — so a failure
                // can never leave the server with no config (which would silently reset every setting).
                try (InputStream in = getResource("config.yml")) {
                    if (in == null) {
                        getLogger().warning("no bundled config to upgrade to — keeping your current config.yml.");
                        return c;
                    }
                    Files.copy(in, fresh.toPath(), StandardCopyOption.REPLACE_EXISTING);
                }
                if (!fresh.isFile() || fresh.length() == 0) {
                    getLogger().warning("config upgrade aborted (couldn't stage the new config) — keeping current.");
                    fresh.delete();
                    return c;
                }
                Files.move(cfgFile.toPath(), old.toPath(), StandardCopyOption.REPLACE_EXISTING);  // back up old
                Files.move(fresh.toPath(), cfgFile.toPath(), StandardCopyOption.REPLACE_EXISTING); // promote new
                c = YamlConfiguration.loadConfiguration(cfgFile);
                getLogger().info("Upgraded config.yml to the new format (your old one is saved as config.yml.old).");
            } catch (IOException ex) {
                getLogger().severe("config upgrade failed (" + ex.getMessage() + ") — keeping your existing config.");
                if (!cfgFile.isFile() && old.isFile()) { // restore the backup if we lost the live file
                    try {
                        Files.move(old.toPath(), cfgFile.toPath(), StandardCopyOption.REPLACE_EXISTING);
                    } catch (IOException ignored) {
                        // nothing more we can do
                    }
                }
                c = YamlConfiguration.loadConfiguration(cfgFile);
            }
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

    private String readProp(String key) {
        File f = new File(home, "guardio.properties");
        if (f.isFile()) {
            try (InputStream in = new FileInputStream(f)) {
                Properties p = new Properties();
                p.load(in);
                return p.getProperty(key, "").trim();
            } catch (IOException ignored) {
                // none
            }
        }
        return "";
    }

    private List<File> watchDirs() {
        List<File> dirs = new ArrayList<>();
        for (String r : roots) {
            File d = new File(serverRoot, r);
            if (d.isDirectory()) {
                dirs.add(d);
            }
        }
        return dirs;
    }

    // ---- Scanning -----------------------------------------------------------

    /** Submits a scan to the single-thread executor (never overlapping); optional main-thread callback. */
    private void submitScan(Consumer<List<ScanResult>> done) {
        if (scanExecutor == null || scanExecutor.isShutdown()) {
            return;
        }
        scanExecutor.submit(() -> {
            List<ScanResult> r = runScan(true);
            lastResults = r;
            if (done != null && isEnabled()) {
                Bukkit.getScheduler().runTask(this, () -> done.accept(r));
            }
        });
    }

    /** SHA-256 with an incremental cache keyed by path+mtime+size, so unchanged jars aren't re-hashed. */
    private String cachedSha(File f) {
        String key = f.getPath() + "|" + f.lastModified() + "|" + f.length();
        String cached = shaCache.get(key);
        if (cached != null) {
            return cached;
        }
        String sha = Hashing.sha256(f);
        if (sha != null) {
            shaCache.put(key, sha);
        }
        return sha;
    }

    private List<ScanResult> runScan(boolean remediate) {
        List<ScanResult> results = new ArrayList<>();
        List<String> events = new ArrayList<>();
        Map<String, String> snapshot = new LinkedHashMap<>();
        for (File jar : Roots.listJars(serverRoot, roots, home)) {
            String rel = Vault.rel(serverRoot, jar);
            List<String> sigReasons = scanner.scan(jar);
            if (JarScanner.unreadableOnly(sigReasons)) {
                // transient lock / IO error — could NOT read it; do not treat as malware. Skip this scan.
                getLogger().warning("could not read " + rel + " (" + sigReasons.get(0) + ") — skipped this scan");
                String prevSha = prevSnapshot.get(rel);
                if (prevSha != null) {
                    snapshot.put(rel, prevSha); // keep the prior entry so the change report isn't skewed
                }
                continue;
            }
            boolean inVault = vault.has(rel);
            // Vaulted jars are always hashed FRESH (the incremental cache could otherwise return a stale hash
            // for a same-size/same-mtime swap); only not-yet-mapped jars use the cache.
            String sha = inVault ? Hashing.sha256(jar) : cachedSha(jar);
            if (sha != null) {
                snapshot.put(rel, sha);
            }
            boolean feedHit = threatFeed != null && threatFeed.contains(sha);
            boolean isPlugin = rel.startsWith("plugins");
            boolean allowlistBlock = allowlistOnly && isPlugin && !inVault && !feedHit && sigReasons.isEmpty()
                    && !Whitelist.allows(jar.getName(), whitelist);

            List<String> reasons = new ArrayList<>(sigReasons);
            if (feedHit) {
                reasons.add("known-malware hash (threat feed)");
            }
            if (allowlistBlock) {
                reasons.add("not on allowlist (allowlist-only mode)");
            }
            // Treat an allowlist block as a signature hit so it counts + reports as INFECTED (it is quarantined).
            boolean sigHit = feedHit || allowlistBlock
                    || (!sigReasons.isEmpty() && !Whitelist.allows(jar.getName(), whitelist));
            boolean hashMatch = inVault && sha != null && sha.equals(vault.hash(rel));

            // Developer plugin the operator rebuilds themselves: a changed-but-signature-clean dev-plugin is
            // re-baselined (vault updated to the new build) rather than flagged as infection. The malware layers
            // (sigHit covers signature + threat-feed + allowlist) still gate this, so an actually-infected dev
            // build is NOT silently trusted.
            if (inVault && !hashMatch && !sigHit && DevPlugins.matches(jar.getName(), devPlugins)) {
                if (remediate && vault.trust(jar, rel)) {
                    getLogger().info("dev-plugin updated -> re-baselined: " + rel);
                    if (discordAlert("restore")) {
                        events.add("🔧 dev-plugin re-baselined: " + rel);
                    }
                }
                hashMatch = true; // treat as trusted against the refreshed baseline (don't flag your own rebuild)
            }

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
                if (isPlugin) {
                    reportOnly(rel, jar, events);
                }
            }
        }
        Honeypot.check(serverRoot, home).forEach(trip -> {
            getLogger().severe("HONEYPOT: " + trip);
            if (discordAlert("suspicious")) {
                events.add("🪤 " + trip);
            }
        });
        changeReport(snapshot, events);
        saveSnapshot(snapshot);
        prevSnapshot = snapshot;
        writeReports(results);
        notify("scan", events);
        return results;
    }

    /** Report-only layers (heuristics + cracked-plugin), never auto-quarantine. */
    private void reportOnly(String rel, File jar, List<String> events) {
        List<String> flags = new ArrayList<>();
        if (heuristicsOn) {
            flags.addAll(Heuristics.analyze(jar));
        }
        if (detectCracked) {
            flags.addAll(CrackedPluginDetector.analyze(jar));
        }
        if (!flags.isEmpty()) {
            getLogger().warning("SUSPICIOUS (report-only, NOT quarantined): " + rel + "  ->  " + String.join("; ", flags));
            if (discordAlert("suspicious")) {
                events.add(msg.plain("discord.suspicious", "rel", rel, "reason", String.join("; ", flags)));
            }
        }
    }

    private void changeReport(Map<String, String> current, List<String> events) {
        if (prevSnapshot.isEmpty()) {
            return; // first run — nothing to diff against
        }
        List<String> added = new ArrayList<>();
        List<String> removed = new ArrayList<>();
        List<String> changed = new ArrayList<>();
        for (Map.Entry<String, String> e : current.entrySet()) {
            String old = prevSnapshot.get(e.getKey());
            if (old == null) {
                added.add(e.getKey());
            } else if (!old.equals(e.getValue())) {
                changed.add(e.getKey());
            }
        }
        for (String k : prevSnapshot.keySet()) {
            if (!current.containsKey(k)) {
                removed.add(k);
            }
        }
        if (added.isEmpty() && removed.isEmpty() && changed.isEmpty()) {
            return;
        }
        getLogger().info("changes since last scan: +" + added.size() + " new, ~" + changed.size()
                + " changed, -" + removed.size() + " removed.");
        for (String a : added) {
            getLogger().info("  + " + a);
        }
        for (String ch : changed) {
            getLogger().info("  ~ " + ch);
        }
        for (String rm : removed) {
            getLogger().info("  - " + rm);
        }
        if (discordEnabled) {
            events.add(msg.plain("discord.changes", "added", added.size(), "changed", changed.size(), "removed", removed.size()));
        }
    }

    private Map<String, String> loadSnapshot() {
        Map<String, String> m = new HashMap<>();
        File f = new File(home, "snapshot.txt");
        if (f.isFile()) {
            try {
                for (String line : Files.readAllLines(f.toPath())) {
                    int tab = line.indexOf('\t');
                    if (tab > 0) {
                        m.put(line.substring(0, tab), line.substring(tab + 1).trim());
                    }
                }
            } catch (IOException ignored) {
                // none
            }
        }
        return m;
    }

    private void saveSnapshot(Map<String, String> snapshot) {
        List<String> lines = new ArrayList<>(snapshot.size());
        for (Map.Entry<String, String> e : snapshot.entrySet()) {
            lines.add(e.getKey() + "\t" + e.getValue());
        }
        try {
            Files.write(new File(home, "snapshot.txt").toPath(), lines);
        } catch (IOException ignored) {
            // non-fatal
        }
    }

    private void stageRemediation(File jar, String rel) {
        synchronized (pending) {
            for (Pending p : pending) {
                if (p.rel().equals(rel)) {
                    return; // already staged — don't double-remediate the same jar
                }
            }
            // Don't restore from the vault if the vault copy IS the known-malware (a feed hash on a previously
            // trusted jar) — that would re-install the payload. Quarantine only; let heal fetch a clean copy.
            boolean vaultIsMalware = vault.has(rel) && threatFeed != null && threatFeed.contains(vault.hash(rel));
            File clean = (autoRestore && vault.has(rel) && !vaultIsMalware) ? vault.file(rel) : null;
            pending.add(new Pending(jar, rel, clean, new File(home, "quarantine")));
            if (clean == null) {
                getLogger().warning("  no clean vault copy to restore for " + rel + " — it will be quarantined; reinstall a clean one.");
            }
        }
    }

    private void applyPending() {
        // Stop any in-flight scan first: the scan thread is a daemon that keeps running during JVM shutdown,
        // and it reads the same jars we're about to move/overwrite here.
        if (scanExecutor != null) {
            scanExecutor.shutdownNow();
            try {
                scanExecutor.awaitTermination(5, TimeUnit.SECONDS);
            } catch (InterruptedException ignored) {
                Thread.currentThread().interrupt();
            }
        }
        List<Pending> copy;
        synchronized (pending) {
            if (pending.isEmpty()) {
                return;
            }
            copy = new ArrayList<>(pending);
        }
        List<String> log = new ArrayList<>();
        for (Pending p : copy) {
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

    // ---- Reporting ----------------------------------------------------------

    private void writeReports(List<ScanResult> results) {
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
        try {
            String stamp = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss z").format(new Date());
            ReportExporter.write(new File(home, "report.html"),
                    ReportExporter.html(serverName, stamp, vault.size(), serverRoot, results));
        } catch (IOException ignored) {
            // non-fatal
        }
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
        String latest = UpdateChecker.latest(config.getString("general.update-url",
                "https://api.github.com/repos/fizzexual/Guardio/releases/latest"));
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
                send(sender, msg.get("scan.started"));
                submitScan(r -> {
                    send(sender, msg.get("scan.complete", "total", r.size(),
                            "infected", count(r, ScanResult.Verdict.INFECTED), "unverified", count(r, ScanResult.Verdict.UNVERIFIED)));
                    for (ScanResult x : r) {
                        if (x.verdict() == ScanResult.Verdict.INFECTED) {
                            sendRaw(sender, msg.get("scan.infected-line", "rel", Vault.rel(serverRoot, x.jar()),
                                    "reason", x.signatureHit() ? String.join("; ", x.reasons()) : "hash mismatch vs vault"));
                        }
                    }
                    if (!pending.isEmpty()) {
                        send(sender, msg.get("scan.staged", "count", pending.size()));
                    }
                });
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
            case "doctor" -> doctor(sender);
            case "report" -> {
                writeReports(lastResults);
                send(sender, msg.get("report.written", "path", "guardio/report.html"));
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
                String rrel = Vault.rel(serverRoot, jar);
                stageRemediation(jar, rrel);
                send(sender, msg.get("restore.staged", "jar", args[1]));
                if (discordAlert("restore")) {
                    notify("restore", List.of(msg.plain("discord.restore", "rel", rrel)));
                }
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

    private void doctor(CommandSender s) {
        send(s, msg.get("doctor.header"));
        line(s, System.getProperty("guardio.launcher") != null, "Launcher active (server-jar healing on)");
        line(s, System.getProperty("guardio.agent") != null, "Pre-load agent active");
        line(s, vault.size() > 0, "Vault baseline set (" + vault.size() + " jars)");
        line(s, config.getInt("config-version", 1) >= 2, "Config up to date (v" + config.getInt("config-version", 1) + ")");
        line(s, home.canWrite(), "guardio/ is writable");
        line(s, threatFeed != null, "Threat feed loaded (" + (threatFeed != null ? threatFeed.size() : 0) + " hashes)");
        line(s, !discordEnabled || (webhook != null && !webhook.isBlank()), "Discord webhook set (or disabled)");
        line(s, count(ScanResult.Verdict.INFECTED) == 0, "No infected jars in last scan");
        line(s, pending.isEmpty(), "No fixes pending restart");
    }

    private void line(CommandSender s, boolean ok, String label) {
        sendRaw(s, msg.get(ok ? "doctor.pass" : "doctor.fail", "label", label));
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
        return count(lastResults, v);
    }

    private int count(List<ScanResult> results, ScanResult.Verdict v) {
        int n = 0;
        for (ScanResult r : results) {
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
        String l = msg.prefix() + colored;
        for (Player p : Bukkit.getOnlinePlayers()) {
            if (p.isOp()) {
                p.sendMessage(l);
            }
        }
    }

    private void send(CommandSender sender, String colored) {
        sender.sendMessage(msg.prefix() + colored);
    }

    private void sendRaw(CommandSender sender, String colored) {
        sender.sendMessage(colored);
    }
}
