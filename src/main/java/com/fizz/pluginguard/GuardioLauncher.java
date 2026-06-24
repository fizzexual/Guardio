package com.fizz.pluginguard;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.URI;
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

    public static void main(String[] args) throws Exception {
        boolean scanOnly = Arrays.asList(args).contains("--scan-only");
        File serverRoot = new File(".").getCanonicalFile();
        File guardFolder = new File(serverRoot, "plugins/PluginGuard");
        guardFolder.mkdirs();
        Props cfg = Props.loadOrCreate(new File(serverRoot, "guardio.properties"));

        banner("Guardio launcher - guarding the whole server BEFORE it loads...");
        selfCheck(guardFolder);
        scanAndHeal(serverRoot, guardFolder, cfg);

        if (scanOnly) {
            banner("--scan-only: not launching the server.");
            return;
        }
        System.exit(launchLoop(serverRoot, guardFolder, cfg));
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

        int healed = 0;
        int blocked = 0;
        int restored = 0;
        int mapped = 0;

        // 1) The server jar - heal it (download a clean copy) if infected or missing.
        File serverJar = serverJarName.isBlank() ? null : new File(serverRoot, serverJarName);
        if (serverJar != null) {
            String sha = Hashing.sha256(serverJar);
            boolean missing = !serverJar.isFile();
            boolean infected = !missing && !scanner.scan(serverJar).isEmpty();
            boolean tampered = !missing && vault.has(serverJarName)
                    && (sha == null || !sha.equals(vault.hash(serverJarName)));
            if (missing || infected || tampered) {
                logRed("server jar " + serverJarName + (missing ? " is MISSING"
                        : infected ? " is INFECTED" : " was MODIFIED (differs from the trusted copy)")
                        + " - downloading a clean copy from " + serverJarUrl);
                if (downloadVerify(serverJarUrl, serverJar, scanner, quarantine, serverJarName)) {
                    vault.trust(serverJar, serverJarName);
                    healed++;
                    logGrn("healed server jar from " + serverJarUrl);
                } else {
                    logRed("FAILED to heal the server jar - set a correct 'server-jar-url' in guardio.properties. "
                            + "Refusing to launch a missing/infected server jar.");
                    System.exit(2);
                }
            } else if (!vault.has(serverJarName)) {
                vault.trust(serverJar, serverJarName); // first-time baseline of the server jar
                mapped++;
            }
        }

        // 2) plugins + libraries - quarantine infected, restore changed-from-vault, map new clean.
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
                    logRed("restored " + rel + " (differed from mapped copy)");
                }
            } else if (!scanner.scan(jar).isEmpty()) {
                if (quarantineFile(jar, rel, quarantine)) {
                    blocked++;
                    logRed("quarantined infected " + rel + " (the in-server plugin will try to auto-download a clean copy)");
                }
            } else if (vault.trust(jar, rel)) {
                mapped++;
            }
        }
        banner("scan/heal done: server-jar-healed=" + healed + ", blocked=" + blocked
                + ", restored=" + restored + ", mapped=" + mapped + ", vault=" + vault.size());
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

    private static int launchLoop(File serverRoot, File guardFolder, Props cfg) throws Exception {
        String serverJar = cfg.get("server-jar", "");
        if (serverJar.isBlank()) {
            logRed("no 'server-jar' set in guardio.properties - nothing to launch.");
            return 2;
        }
        List<String> javaArgs = split(cfg.get("java-args", "-Xmx2G"));
        List<String> serverArgs = split(cfg.get("server-args", "nogui"));
        boolean useAgent = Boolean.parseBoolean(cfg.get("use-agent", "true"));
        boolean restartOnCrash = Boolean.parseBoolean(cfg.get("restart-on-crash", "false"));
        String restartFlag = cfg.get("restart-flag", "");
        File self = ownJar();
        String javaBin = System.getProperty("java.home") + File.separator + "bin" + File.separator + "java"
                + (isWindows() ? ".exe" : "");

        int code;
        while (true) {
            List<String> cmd = new ArrayList<>();
            cmd.add(javaBin);
            cmd.addAll(javaArgs);
            if (useAgent && self != null) {
                cmd.add("-javaagent:" + self.getPath());
            }
            cmd.add("-jar");
            cmd.add(serverJar);
            cmd.addAll(serverArgs);
            banner("launching server (Guardio supervising): " + serverJar);
            Process proc = new ProcessBuilder(cmd).directory(serverRoot).inheritIO().start();
            code = proc.waitFor();
            banner("server exited (code " + code + ").");

            boolean restart = false;
            if (restartFlag != null && !restartFlag.isBlank()) {
                File flag = new File(serverRoot, restartFlag);
                if (flag.exists()) {
                    flag.delete();
                    restart = true;
                    banner("restart flag '" + restartFlag + "' found - re-scanning, then relaunching...");
                }
            }
            if (!restart && restartOnCrash && code != 0) {
                restart = true;
                banner("server crashed (code " + code + ") - re-scanning, then relaunching...");
            }
            if (!restart) {
                break;
            }
            scanAndHeal(serverRoot, guardFolder, cfg); // re-guard before every relaunch
        }
        return code;
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

        static Props loadOrCreate(File f) throws IOException {
            Props pr = new Props();
            if (f.isFile()) {
                try (InputStream in = new FileInputStream(f)) {
                    pr.p.load(in);
                }
            } else {
                pr.writeDefaults(f);
            }
            return pr;
        }

        String get(String k, String d) {
            return p.getProperty(k, d);
        }

        private void writeDefaults(File f) throws IOException {
            File root = f.getCanonicalFile().getParentFile();
            String jar = detectServerJar(root);
            String ver = (jar == null) ? "" : jar.replaceAll("(?i).*?(\\d+\\.\\d+(?:\\.\\d+)?).*", "$1");
            String url = "";
            if (jar != null && jar.toLowerCase(Locale.ROOT).contains("purpur") && !ver.equals(jar)) {
                url = "https://api.purpur.org/v2/purpur/" + ver + "/latest/download";
            }
            p.setProperty("server-jar", jar == null ? "" : jar);
            p.setProperty("server-jar-url", url);
            p.setProperty("java-args", "-Xmx2G -Xms2G");
            p.setProperty("server-args", "nogui");
            p.setProperty("use-agent", "true");
            p.setProperty("restart-on-crash", "false");
            p.setProperty("restart-flag", "hyhandler.restart");
            p.setProperty("scan-roots", "plugins,libraries");
            try (OutputStream out = new FileOutputStream(f)) {
                p.store(out, "Guardio launcher config. server-jar-url MUST point to the OFFICIAL clean server jar "
                        + "(Purpur/Paper API). For Paper, set the full build download URL.");
            }
        }

        private static String detectServerJar(File root) {
            File[] jars = root.listFiles((d, n) -> n.toLowerCase(Locale.ROOT).endsWith(".jar"));
            if (jars == null) {
                return null;
            }
            for (File j : jars) {
                String n = j.getName().toLowerCase(Locale.ROOT);
                if (n.contains("guardio") || n.contains("pluginguard")) {
                    continue;
                }
                if (n.contains("purpur") || n.contains("paper") || n.contains("spigot") || n.contains("folia")) {
                    return j.getName();
                }
            }
            return null;
        }
    }
}
