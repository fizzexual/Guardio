package com.fizz.pluginguard;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.lang.management.ManagementFactory;
import java.net.URI;
import java.net.URL;
import java.net.URLClassLoader;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Locale;
import java.util.Properties;
import java.util.jar.JarFile;

/**
 * Guardio launcher - the "more than a plugin" mode. Run it INSTEAD of the server jar:
 * <pre>java -jar Guardio.jar</pre>
 * It runs before any server/plugin code, so it can clean and HEAL the whole tree - including the server jar
 * itself (which the in-server agent can only detect, because the JVM holds it open; the launcher is the
 * running process, so the server jar is free to replace). Then it launches the real server as a supervised
 * subprocess with the agent + plugin active inside for a second layer.
 *
 * <p>Self-protection: it hashes its own jar each run and warns if it changed (tamper). Because it executes
 * before the server (and thus before any in-plugin malware), the infector never runs during a guarded boot,
 * so it can't tamper with Guardio mid-run. Settings live in {@code guardio.properties} (auto-created).</p>
 *
 * <p>Pure JDK (no Bukkit/Gson) so it runs standalone. Plugin auto-download from Modrinth stays in the in-server
 * plugin layer; the launcher heals the server jar via a direct official URL and restores everything else from
 * the vault.</p>
 */
public final class GuardioLauncher {

    private static final List<String> ENTRY_SIGS = List.of("javassist/orgs/", "javassist/ws/");
    private static final List<String> CONTENT_SIGS = List.of("pluginstatstrack");
    private static final String RED = (char) 27 + "[1;31m";
    private static final String GRN = (char) 27 + "[1;32m";
    private static final String RESET = (char) 27 + "[0m";

    private GuardioLauncher() {
    }

    static final String SERVERJAR_DIR = "guardio/serverjar"; // server jar lives here, relative to the root

    public static void main(String[] args) throws Exception {
        boolean scanOnly = Arrays.asList(args).contains("--scan-only");
        File selfJar = ownJar();
        // Server root = the folder that holds guardio-v1.0.0.jar, so double-clicking the jar works no matter
        // what working directory the OS hands us. Falls back to the current directory.
        File serverRoot = (selfJar != null && selfJar.getParentFile() != null)
                ? selfJar.getParentFile().getCanonicalFile()
                : new File(".").getCanonicalFile();

        // Double-clicked on Windows (javaw -> no console)? Reopen in a real console window so the server is
        // visible and you can type commands; then this windowless process exits.
        if (!scanOnly && isWindows() && launchedByJavaw() && reopenInConsole(selfJar, serverRoot)) {
            return;
        }

        File guardFolder = new File(serverRoot, "guardio"); // Guardio's home: vault, quarantine, config, serverjar/
        File serverJarDir = new File(serverRoot, SERVERJAR_DIR);
        serverJarDir.mkdirs();

        // Tidy layout: move a server jar sitting in the root (old layout / fresh upload) into guardio/serverjar/.
        migrateServerJar(serverRoot, serverJarDir, selfJar);

        Props cfg = Props.loadOrCreate(new File(guardFolder, "guardio.properties"), serverRoot,
                selfJar == null ? "" : selfJar.getName());

        // Resolve the REAL server jar (path relative to root, e.g. guardio/serverjar/purpur-1.21.11.jar).
        if (cfg.get("server-jar", "").isBlank()) {
            String detected = Props.detectServerJar(serverRoot, selfJar == null ? "" : selfJar.getName());
            if (detected != null) {
                cfg.set("server-jar", detected);
                banner("auto-detected server jar: " + detected);
            }
        }

        banner("Guardio launcher - guarding the whole server BEFORE it loads...");
        selfCheck(guardFolder);
        ensurePluginCopy(serverRoot, selfJar); // keep a synced copy in plugins/ so the in-server plugin loads
        scanAndHeal(serverRoot, guardFolder, cfg);

        if (scanOnly) {
            banner("--scan-only: not launching the server.");
            return;
        }
        System.exit(launchLoop(serverRoot, guardFolder, cfg, args));
    }

    /** Moves a server-looking jar from the root into guardio/serverjar/ if that folder has none yet. */
    private static void migrateServerJar(File serverRoot, File serverJarDir, File selfJar) {
        File[] already = serverJarDir.listFiles((d, n) -> n.toLowerCase(Locale.ROOT).endsWith(".jar"));
        if (already != null && already.length > 0) {
            return; // server jar already in place
        }
        String self = selfJar == null ? "" : selfJar.getName().toLowerCase(Locale.ROOT);
        File[] rootJars = serverRoot.listFiles((d, n) -> n.toLowerCase(Locale.ROOT).endsWith(".jar"));
        if (rootJars == null) {
            return;
        }
        for (File j : rootJars) {
            String n = j.getName().toLowerCase(Locale.ROOT);
            if (n.equals(self) || n.contains("guardio") || n.contains("pluginguard")) {
                continue;
            }
            if (n.contains("purpur") || n.contains("paper") || n.contains("spigot")
                    || n.contains("folia") || n.contains("fabric") || n.contains("server")) {
                try {
                    Files.move(j.toPath(), new File(serverJarDir, j.getName()).toPath());
                    banner("moved server jar " + j.getName() + " into " + SERVERJAR_DIR + "/");
                } catch (Exception ex) {
                    logRed("could not move " + j.getName() + " into " + SERVERJAR_DIR + "/: " + ex.getMessage());
                }
                return;
            }
        }
    }

    /** Keeps a copy of Guardio in plugins/ (synced by hash) so the in-server plugin layer + /guard commands load. */
    private static void ensurePluginCopy(File serverRoot, File selfJar) {
        if (selfJar == null) {
            return;
        }
        try {
            File pluginsDir = new File(serverRoot, "plugins");
            pluginsDir.mkdirs();
            File dest = new File(pluginsDir, selfJar.getName());
            String selfHash = Hashing.sha256(selfJar);
            String destHash = dest.isFile() ? Hashing.sha256(dest) : null;
            if (selfHash != null && !selfHash.equals(destHash)) {
                Files.copy(selfJar.toPath(), dest.toPath(), StandardCopyOption.REPLACE_EXISTING);
                banner("installed/updated the in-server plugin copy: plugins/" + selfJar.getName());
            }
        } catch (Exception ex) {
            logRed("could not place the plugin copy in plugins/: " + ex.getMessage());
        }
    }

    // ---- self-protection -----------------------------------------------

    private static void selfCheck(File guardFolder) {
        try {
            File self = ownJar();
            if (self == null) {
                return;
            }
            String h = Hashing.sha256(self);
            File f = new File(guardFolder, "guardio.self");
            if (f.isFile() && h != null) {
                String prev = Files.readString(f.toPath()).trim();
                if (!h.equals(prev)) {
                    logRed("WARNING: Guardio's own jar changed since last run (possible tamper). "
                            + "If you didn't update it, re-download Guardio from a trusted source.");
                }
            }
            if (h != null) {
                Files.writeString(f.toPath(), h);
            }
        } catch (Exception ignored) {
            // self-check is best-effort
        }
    }

    private static File ownJar() {
        try {
            return new File(GuardioLauncher.class.getProtectionDomain().getCodeSource().getLocation().toURI());
        } catch (Exception ex) {
            return null;
        }
    }

    // ---- scan + heal ----------------------------------------------------

    private static void scanAndHeal(File serverRoot, File guardFolder, Props cfg) {
        Vault vault = new Vault(guardFolder);
        JarScanner scanner = new JarScanner(ENTRY_SIGS, CONTENT_SIGS);
        File quarantine = new File(guardFolder, "quarantine");
        List<String> roots = Arrays.asList(cfg.get("scan-roots", "plugins,libraries").trim().split("\\s*,\\s*"));
        String serverJarName = cfg.get("server-jar", "");
        String serverJarUrl = cfg.get("server-jar-url", "");
        ThreatFeed feed = ThreatFeed.loadOrFetch(new File(guardFolder, "threat-feed.txt"), cfg.get("threat-feed-url", ""));
        boolean heuristics = Boolean.parseBoolean(cfg.get("heuristics", "true"));
        String webhook = cfg.get("discord-webhook", "");
        String serverName = serverName(cfg, serverRoot);

        int healed = 0;
        int blocked = 0;
        int restored = 0;
        int mapped = 0;
        List<String> events = new ArrayList<>(); // collected for one Discord summary

        // 1) The server jar - heal it (download a clean copy) if missing / infected (signature or threat-feed) / tampered.
        File serverJar = serverJarName.isBlank() ? null : new File(serverRoot, serverJarName);
        if (serverJar != null) {
            String sha = Hashing.sha256(serverJar);
            boolean missing = !serverJar.isFile();
            boolean infected = !missing && (!scanner.scan(serverJar).isEmpty() || feed.contains(sha));
            boolean tampered = !missing && vault.has(serverJarName)
                    && (sha == null || !sha.equals(vault.hash(serverJarName)));
            if (missing || infected || tampered) {
                logRed("server jar " + serverJarName + (missing ? " is MISSING"
                        : infected ? " is INFECTED" : " was MODIFIED (differs from the trusted copy)")
                        + " - downloading a clean copy from " + serverJarUrl);
                if (downloadVerify(serverJarUrl, serverJar, scanner, quarantine, serverJarName)) {
                    vault.trust(serverJar, serverJarName);
                    healed++;
                    events.add("✅ healed server jar `" + serverJarName + "` from the official source");
                    logGrn("healed server jar from " + serverJarUrl);
                } else {
                    logRed("FAILED to heal the server jar - set a correct 'server-jar-url' in guardio.properties. "
                            + "Refusing to launch a missing/infected server jar.");
                    Notifier.send(webhook, "🛑 **Guardio / " + serverName + "**: server jar `"
                            + serverJarName + "` is bad and could not be healed - refusing to start.");
                    System.exit(2);
                }
            } else if (!vault.has(serverJarName)) {
                vault.trust(serverJar, serverJarName); // first-time baseline of the server jar
                mapped++;
            }
        }

        // 2) plugins + libraries - quarantine infected, restore changed-from-vault / from trusted backup, map new clean.
        for (File jar : Roots.listJars(serverRoot, roots, guardFolder)) {
            if (serverJar != null && jar.getAbsoluteFile().equals(serverJar.getAbsoluteFile())) {
                continue;
            }
            String rel = Vault.rel(serverRoot, jar);
            String sha = Hashing.sha256(jar);
            if (vault.has(rel)) {
                if (sha != null && sha.equals(vault.hash(rel))) {
                    continue;
                }
                if (quarantineFile(jar, rel, quarantine) && copy(vault.file(rel), jar)) {
                    restored++;
                    events.add("♻️ restored `" + rel + "` (differed from the trusted copy)");
                    logRed("restored " + rel + " (differed from mapped copy)");
                }
            } else {
                List<String> sigReasons = scanner.scan(jar);
                boolean infected = !sigReasons.isEmpty() || feed.contains(sha);
                if (infected) {
                    String why = !sigReasons.isEmpty() ? String.join("; ", sigReasons) : "known-malware hash (threat feed)";
                    File trusted = TrustedBackups.find(guardFolder, null, jar.getName(), scanner);
                    if (trusted != null && quarantineFile(jar, rel, quarantine) && copy(trusted, jar)) {
                        vault.trust(jar, rel);
                        restored++;
                        events.add("♻️ restored infected `" + rel + "` from a trusted/ backup");
                        logGrn("restored infected " + rel + " from a trusted backup");
                    } else if (quarantineFile(jar, rel, quarantine)) {
                        blocked++;
                        events.add("🛑 quarantined infected `" + rel + "` :: " + why);
                        logRed("quarantined infected " + rel + " :: " + why
                                + " (the in-server plugin will try to auto-download a clean copy)");
                    }
                } else if (vault.trust(jar, rel)) {
                    mapped++;
                    if (heuristics && rel.startsWith("plugins")) { // report-only, and only for plugins (not vetted libraries)
                        List<String> sus = Heuristics.analyze(jar);
                        if (!sus.isEmpty()) {
                            events.add("⚠️ suspicious (report-only) `" + rel + "` :: " + String.join("; ", sus));
                            logRed("SUSPICIOUS (report-only, NOT quarantined) " + rel + " :: " + String.join("; ", sus));
                        }
                    }
                }
            }
        }
        banner("scan/heal done: server-jar-healed=" + healed + ", blocked=" + blocked + ", restored=" + restored
                + ", mapped=" + mapped + ", vault=" + vault.size() + ", threat-feed=" + feed.size());
        if (!events.isEmpty()) {
            Notifier.send(webhook, "**Guardio / " + serverName + "** (pre-boot scan):\n" + String.join("\n", events));
        }
    }

    private static String serverName(Props cfg, File serverRoot) {
        String n = cfg.get("server-name", "");
        if (n != null && !n.isBlank()) {
            return n;
        }
        String f = serverRoot.getName();
        return (f == null || f.isBlank()) ? "server" : f;
    }

    /** Downloads {@code url} to {@code dest}, verifying it's clean (re-scan) and quarantining the old file. */
    private static boolean downloadVerify(String url, File dest, JarScanner scanner, File quarantine, String rel) {
        if (url == null || url.isBlank()) {
            return false;
        }
        File tmp = null;
        try {
            tmp = File.createTempFile("guardio-dl-", ".jar");
            HttpClient http = HttpClient.newBuilder()
                    .followRedirects(HttpClient.Redirect.NORMAL).connectTimeout(Duration.ofSeconds(20)).build();
            HttpRequest req = HttpRequest.newBuilder(URI.create(url))
                    .header("User-Agent", "Guardio/1.0").timeout(Duration.ofSeconds(180)).GET().build();
            HttpResponse<Path> resp = http.send(req, HttpResponse.BodyHandlers.ofFile(tmp.toPath()));
            if (resp.statusCode() / 100 != 2 || tmp.length() == 0) {
                return false;
            }
            if (!scanner.scan(tmp).isEmpty()) {
                logRed("the downloaded copy ALSO matched a malware signature - rejected.");
                return false;
            }
            if (dest.isFile()) {
                quarantineFile(dest, rel, quarantine);
            }
            File p = dest.getParentFile();
            if (p != null) {
                p.mkdirs();
            }
            Files.copy(tmp.toPath(), dest.toPath(), StandardCopyOption.REPLACE_EXISTING);
            return true;
        } catch (Exception ex) {
            logRed("download error: " + ex.getMessage());
            return false;
        } finally {
            if (tmp != null) {
                tmp.delete();
            }
        }
    }

    // ---- launch + supervise --------------------------------------------

    private static int launchLoop(File serverRoot, File guardFolder, Props cfg, String[] mainArgs) throws Exception {
        String serverJarName = cfg.get("server-jar", "");
        if (serverJarName.isBlank()) {
            logRed("no server jar found (set 'server-jar' in guardio.properties) - nothing to launch.");
            return 2;
        }
        File realJar = new File(serverRoot, serverJarName);
        String mode = cfg.get("launch-mode", "auto").trim().toLowerCase(Locale.ROOT);
        boolean restartOnCrash = Boolean.parseBoolean(cfg.get("restart-on-crash", "false"));
        String restartFlag = cfg.get("restart-flag", "");
        List<String> serverArgs = forwardServerArgs(mainArgs, cfg);
        String mainClass = readMainClass(realJar);

        // How to run the server. Real server bootstraps (paperclip/craftbukkit/bundler/fabric) assume they ARE
        // the main jar on the system classpath, so they can't be hosted in-process via a child classloader -
        // they must run as their own process. Detect those and use a subprocess even in auto mode.
        boolean subprocess;
        if (mode.equals("subprocess")) {
            subprocess = true;
        } else if (needsSubprocess(mainClass)) {
            if (mode.equals("in-process")) {
                logRed("launch-mode=in-process, but '" + mainClass + "' is a server bootstrap that must run as "
                        + "its own process - using a subprocess so the server actually starts.");
            } else {
                banner("'" + mainClass + "' is a server bootstrap - running it as a subprocess (host flags forwarded).");
            }
            subprocess = true;
        } else {
            subprocess = false; // exotic / blocking main — safe to try in-process
        }

        while (true) {
            int code;
            if (!subprocess) {
                boolean ran = launchInProcess(realJar, mainClass, serverArgs);
                if (!ran) {
                    if (mode.equals("in-process")) {
                        logRed("in-process launch failed and fallback is disabled (launch-mode=in-process).");
                        return 3;
                    }
                    logRed("in-process launch failed - falling back to a subprocess.");
                    subprocess = true;
                    continue; // retry this round as a subprocess
                }
                code = 0; // server ran in-process and returned
            } else {
                code = launchSubprocess(serverRoot, cfg, realJar, serverArgs);
            }

            boolean restart = checkRestartFlag(serverRoot, restartFlag);
            if (!restart && restartOnCrash && code != 0) {
                restart = true;
                banner("server exited with code " + code + " - re-scanning, then relaunching...");
            }
            if (!restart) {
                return code;
            }
            scanAndHeal(serverRoot, guardFolder, cfg); // re-guard before every relaunch
        }
    }

    private static String readMainClass(File jar) {
        try (JarFile jf = new JarFile(jar)) {
            return jf.getManifest() == null ? null : jf.getManifest().getMainAttributes().getValue("Main-Class");
        } catch (Exception ex) {
            return null;
        }
    }

    /** True for server bootstraps that must run as their own process (can't be hosted in-process). */
    private static boolean needsSubprocess(String mc) {
        if (mc == null) {
            return true; // unknown — be safe, use a subprocess
        }
        String low = mc.toLowerCase(Locale.ROOT);
        return mc.equals("io.papermc.paperclip.Main")       // Paper / Purpur / Folia (paperclip)
                || mc.startsWith("org.bukkit.craftbukkit.")  // Spigot / CraftBukkit bootstrap + Main
                || mc.equals("net.minecraft.bundler.Main")   // vanilla bundler
                || low.contains("fabric")                    // Fabric launchers
                || low.contains("bootstrap")                 // generic bootstrap launchers
                || low.contains("launchwrapper");            // legacy / Forge launchwrapper
    }

    /** Loads the real server jar in THIS JVM and runs its Main-Class. Returns false if it failed to launch. */
    private static boolean launchInProcess(File realJar, String mainClass, List<String> serverArgs) {
        if (mainClass == null) {
            logRed("the server jar has no Main-Class - can't launch in-process.");
            return false;
        }
        try {
            banner("launching server in-process (" + mainClass + ", same JVM, no extra RAM)...");
            URLClassLoader cl = new URLClassLoader(new URL[]{realJar.toURI().toURL()}, ClassLoader.getSystemClassLoader());
            Thread.currentThread().setContextClassLoader(cl);
            Class<?> m = Class.forName(mainClass, true, cl);
            m.getMethod("main", String[].class).invoke(null, (Object) serverArgs.toArray(new String[0]));
            return true; // server ran (and its main returned) — a normal stop
        } catch (Throwable t) {
            Throwable cause = (t.getCause() != null) ? t.getCause() : t;
            logRed("in-process launch failed: " + cause.getClass().getSimpleName()
                    + (cause.getMessage() != null ? " - " + cause.getMessage() : ""));
            return false;
        }
    }

    /** Re-runs the server as a child JVM, forwarding the host's JVM flags + the agent, with console + stop passthrough. */
    private static int launchSubprocess(File serverRoot, Props cfg, File realJar, List<String> serverArgs) throws Exception {
        String javaBin = System.getProperty("java.home") + File.separator + "bin" + File.separator + "java"
                + (isWindows() ? ".exe" : "");
        List<String> hostJvm = ManagementFactory.getRuntimeMXBean().getInputArguments();
        boolean hostHasHeap = hostJvm.stream().anyMatch(a -> a.startsWith("-Xmx"));
        List<String> jvm = new ArrayList<>();
        for (String a : hostJvm) {
            if (!a.startsWith("-javaagent") && !a.startsWith("-agentlib") && !a.startsWith("-agentpath")) {
                jvm.add(a); // forward the host's flags (heap, GC, etc.), minus agents
            }
        }
        if (!hostHasHeap) {
            jvm.addAll(split(cfg.get("java-args", "-Xmx2G"))); // host gave no heap → use config
        }
        File self = ownJar();
        List<String> cmd = new ArrayList<>();
        cmd.add(javaBin);
        cmd.addAll(jvm);
        if (Boolean.parseBoolean(cfg.get("use-agent", "true")) && self != null) {
            cmd.add("-javaagent:" + self.getPath());
        }
        cmd.add("-jar");
        cmd.add(cfg.get("server-jar", realJar.getName())); // path relative to root (e.g. guardio/serverjar/x.jar)
        cmd.addAll(serverArgs);
        banner("launching server (subprocess): " + String.join(" ", cmd));
        Process proc = new ProcessBuilder(cmd).directory(serverRoot).inheritIO().start();
        Thread hook = new Thread(() -> {
            if (proc.isAlive()) {
                proc.destroyForcibly(); // panel/Ctrl-C stops Guardio → make sure the child dies too (no orphans)
            }
        });
        Runtime.getRuntime().addShutdownHook(hook);
        int code = proc.waitFor();
        try {
            Runtime.getRuntime().removeShutdownHook(hook);
        } catch (IllegalStateException ignored) {
            // already shutting down
        }
        banner("server exited (code " + code + ").");
        return code;
    }

    /** Server args = the host's program args (minus our flags), or the config fallback. */
    private static List<String> forwardServerArgs(String[] mainArgs, Props cfg) {
        List<String> a = new ArrayList<>();
        for (String s : mainArgs) {
            if (!s.equals("--scan-only")) {
                a.add(s);
            }
        }
        return a.isEmpty() ? split(cfg.get("server-args", "nogui")) : a;
    }

    private static boolean checkRestartFlag(File serverRoot, String restartFlag) {
        if (restartFlag != null && !restartFlag.isBlank()) {
            File flag = new File(serverRoot, restartFlag);
            if (flag.exists()) {
                flag.delete();
                banner("restart flag '" + restartFlag + "' found - re-scanning, then relaunching...");
                return true;
            }
        }
        return false;
    }

    // ---- helpers --------------------------------------------------------

    private static boolean quarantineFile(File jar, String rel, File quarantineDir) {
        try {
            File dest = new File(quarantineDir, rel + "." + System.currentTimeMillis() + ".infected");
            File p = dest.getParentFile();
            if (p != null) {
                p.mkdirs();
            }
            Files.move(jar.toPath(), dest.toPath(), StandardCopyOption.REPLACE_EXISTING);
            return true;
        } catch (IOException ex) {
            return false;
        }
    }

    private static boolean copy(File from, File to) {
        try {
            File p = to.getParentFile();
            if (p != null) {
                p.mkdirs();
            }
            Files.copy(from.toPath(), to.toPath(), StandardCopyOption.REPLACE_EXISTING);
            return true;
        } catch (IOException ex) {
            return false;
        }
    }

    private static List<String> split(String s) {
        List<String> out = new ArrayList<>();
        for (String t : s.trim().split("\\s+")) {
            if (!t.isBlank()) {
                out.add(t);
            }
        }
        return out;
    }

    private static boolean isWindows() {
        return System.getProperty("os.name", "").toLowerCase(Locale.ROOT).contains("win");
    }

    /** True when this JVM was started by javaw.exe (i.e. the jar was double-clicked) — no console. */
    private static boolean launchedByJavaw() {
        try {
            return ProcessHandle.current().info().command()
                    .map(c -> c.toLowerCase(Locale.ROOT).endsWith("javaw.exe")).orElse(false);
        } catch (Throwable t) {
            return false;
        }
    }

    /** Reopens Guardio in a visible console window (via a small launch .bat) so a double-click gives an
     *  interactive server. Returns false if it couldn't, so the caller can fall back to a (blind) run. */
    private static boolean reopenInConsole(File self, File serverRoot) {
        if (self == null) {
            return false;
        }
        try {
            File bat = new File(serverRoot, "guardio-run.bat");
            if (!bat.isFile()) {
                String javaExe = System.getProperty("java.home") + "\\bin\\java.exe";
                String c = "@echo off\r\n"
                        + "cd /d \"%~dp0\"\r\n"
                        + "\"" + javaExe + "\" -jar \"" + self.getName() + "\"\r\n"
                        + "echo.\r\n"
                        + "echo Server stopped. Press any key to close.\r\n"
                        + "pause >nul\r\n";
                Files.writeString(bat.toPath(), c);
            }
            // open a new console window running the .bat (it cd's to its own folder, then runs Guardio)
            new ProcessBuilder("cmd", "/c", "start", "Guardio Server", bat.getPath()).start();
            return true;
        } catch (Exception ex) {
            return false;
        }
    }

    private static void banner(String msg) {
        System.out.println(GRN + "[Guardio] " + msg + RESET);
    }

    private static void logGrn(String msg) {
        System.out.println(GRN + "[Guardio] " + msg + RESET);
    }

    private static void logRed(String msg) {
        System.out.println(RED + "[Guardio] " + msg + RESET);
    }

    /** Launcher settings ({@code guardio.properties}); auto-created with sensible defaults on first run. */
    static final class Props {
        private final Properties p = new Properties();

        static Props loadOrCreate(File f, File serverRoot, String selfName) throws IOException {
            Props pr = new Props();
            if (f.isFile()) {
                try (InputStream in = new FileInputStream(f)) {
                    pr.p.load(in);
                }
            } else {
                pr.writeDefaults(f, serverRoot, selfName);
            }
            return pr;
        }

        String get(String k, String d) {
            return p.getProperty(k, d);
        }

        void set(String k, String v) {
            p.setProperty(k, v);
        }

        private void writeDefaults(File f, File serverRoot, String selfName) throws IOException {
            String jar = detectServerJar(serverRoot, selfName); // e.g. guardio/serverjar/purpur-1.21.11.jar
            String ver = (jar == null) ? "" : jar.replaceAll("(?i).*?(\\d+\\.\\d+(?:\\.\\d+)?).*", "$1");
            String url = "";
            if (jar != null && jar.toLowerCase(Locale.ROOT).contains("purpur") && !ver.equals(jar)) {
                url = "https://api.purpurmc.org/v2/purpur/" + ver + "/latest/download";
            }
            File p2 = f.getParentFile();
            if (p2 != null) {
                p2.mkdirs(); // ensure /guardio exists before writing guardio.properties into it
            }
            p.setProperty("server-jar", jar == null ? "" : jar);
            p.setProperty("server-jar-url", url);
            p.setProperty("launch-mode", "auto");
            p.setProperty("java-args", "-Xmx2G -Xms2G");
            p.setProperty("server-args", "nogui");
            p.setProperty("use-agent", "true");
            p.setProperty("restart-on-crash", "false");
            p.setProperty("restart-flag", "hyhandler.restart");
            p.setProperty("scan-roots", "plugins,libraries");
            p.setProperty("discord-webhook", "");
            p.setProperty("server-name", "");
            p.setProperty("threat-feed-url", "");
            p.setProperty("heuristics", "true");
            try (OutputStream out = new FileOutputStream(f)) {
                p.store(out, "Guardio launcher config. launch-mode: auto|in-process|subprocess. server-jar-url MUST "
                        + "point to the OFFICIAL clean server jar (Purpur/Paper API). java-args/server-args are used "
                        + "only if the host passed none (the host's own JVM flags are forwarded automatically). "
                        + "discord-webhook: alerts on quarantine/heal. threat-feed-url: known-malware SHA-256 list. "
                        + "heuristics: report-only backdoor-pattern flagging.");
            }
        }

        /** Server jar inside guardio/serverjar/ (preferred) or the root, as a path relative to the root. */
        static String detectServerJar(File serverRoot, String selfName) {
            File serverJarDir = new File(serverRoot, SERVERJAR_DIR);
            File[] inDir = serverJarDir.listFiles((d, n) -> n.toLowerCase(Locale.ROOT).endsWith(".jar"));
            if (inDir != null && inDir.length > 0) {
                return SERVERJAR_DIR + "/" + inDir[0].getName(); // whatever sits in guardio/serverjar/ is the server jar
            }
            String self = selfName == null ? "" : selfName.toLowerCase(Locale.ROOT);
            File[] jars = serverRoot.listFiles((d, n) -> n.toLowerCase(Locale.ROOT).endsWith(".jar"));
            if (jars == null) {
                return null;
            }
            for (File j : jars) {
                String n = j.getName().toLowerCase(Locale.ROOT);
                if (n.equals(self) || n.contains("guardio") || n.contains("pluginguard")) {
                    continue;
                }
                if (n.contains("purpur") || n.contains("paper") || n.contains("spigot")
                        || n.contains("folia") || n.contains("server") || n.contains("fabric")) {
                    return j.getName();
                }
            }
            return null;
        }
    }
}
