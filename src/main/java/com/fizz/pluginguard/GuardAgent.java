package com.fizz.pluginguard;

import java.io.File;
import java.io.IOException;
import java.lang.instrument.Instrumentation;
import java.nio.file.Files;
import java.nio.file.StandardCopyOption;
import java.util.ArrayList;
import java.util.List;

/**
 * Pre-load Java agent - runs in {@code premain()} BEFORE the server loads, so the whole server tree (plugins,
 * libraries, the server jar) is on disk and, except the running server jar, unlocked. Enable in the start
 * command, before {@code -jar}:
 * <pre>java -javaagent:plugins/PluginGuard-1.0.0.jar -jar server.jar nogui</pre>
 *
 * <p>Guards the top-level server jar(s) + every jar under the configured roots (default {@code plugins} +
 * {@code libraries}; add more in {@code plugins/PluginGuard/scan-roots.txt}, one per line). Map-then-load:
 * new clean jars are mapped into the vault; mapped jars that changed are quarantined and the safe copy is
 * restored. If an infected jar can't be removed because it's locked (the running server jar), the agent
 * REFUSES TO START (exit) rather than let it run.</p>
 *
 * <p>Only MALWARE-SPECIFIC signatures are used (see {@link #ENTRY_SIGS}/{@link #CONTENT_SIGS}); a
 * {@code whitelist.txt} clears false positives. Pure JDK (Bukkit isn't loaded yet).</p>
 */
public final class GuardAgent {

    // Malware-specific only (absent from real libraries), to avoid false positives on legit plugins.
    private static final List<String> ENTRY_SIGS = List.of("javassist/orgs/", "javassist/ws/");
    private static final List<String> CONTENT_SIGS = List.of("pluginstatstrack");

    private static final String RED = (char) 27 + "[1;31m";
    private static final String RESET = (char) 27 + "[0m";

    private GuardAgent() {
    }

    public static void premain(String args, Instrumentation inst) {
        run(args);
    }

    public static void agentmain(String args, Instrumentation inst) {
        run(args);
    }

    private static void run(String args) {
        try {
            File serverRoot = ((args != null && !args.isBlank()) ? new File(args.trim()) : new File("."))
                    .getAbsoluteFile();
            File guardFolder = new File(serverRoot, "guardio");
            File quarantine = new File(guardFolder, "quarantine");
            Vault vault = new Vault(guardFolder);
            JarScanner scanner = new JarScanner(ENTRY_SIGS, CONTENT_SIGS);
            List<String> whitelist = Whitelist.load(guardFolder);
            List<String> roots = readRoots(guardFolder);
            ThreatFeed feed = ThreatFeed.loadOrFetch(new File(guardFolder, "threat-feed.txt"), null); // launcher-cached
            List<File> jars = Roots.listJars(serverRoot, roots, guardFolder);

            List<String> report = new ArrayList<>();
            int mapped = 0;
            int restored = 0;
            int blocked = 0;
            int unchanged = 0;
            String lockedInfected = null;

            for (File jar : jars) {
                String rel = Vault.rel(serverRoot, jar);
                String sha = Hashing.sha256(jar);
                if (feed.contains(sha)) {
                    // known-malware hash is authoritative — quarantine even if previously mapped/trusted
                    if (quarantine(jar, rel, quarantine)) {
                        blocked++;
                        report.add("BLOCKED " + rel + " :: known-malware hash (threat feed)");
                        logRed("BLOCKED " + rel + " -> known-malware hash (threat feed)");
                    } else {
                        lockedInfected = rel;
                        report.add("LOCKED-INFECTED " + rel + " :: known-malware hash (threat feed)");
                        logRed("CANNOT remove infected (locked) jar: " + rel + " -> known-malware hash (threat feed)");
                    }
                    continue;
                }
                if (vault.has(rel)) {
                    if (sha != null && sha.equals(vault.hash(rel))) {
                        unchanged++;
                        continue; // matches the mapped safe copy
                    }
                    if (quarantine(jar, rel, quarantine) && restore(vault, rel, jar)) {
                        restored++;
                        report.add("RESTORED " + rel);
                        logRed("RESTORED " + rel + " - differed from mapped copy (threat blocked)");
                    } else {
                        lockedInfected = rel;
                        report.add("LOCKED-CHANGED " + rel);
                    }
                } else {
                    List<String> reasons = scanner.scan(jar);
                    boolean sig = !reasons.isEmpty() && !Whitelist.allows(jar.getName(), whitelist);
                    boolean feedHit = feed.contains(sha);
                    if (sig || feedHit) {
                        String why = sig ? String.join("; ", reasons) : "known-malware hash (threat feed)";
                        if (quarantine(jar, rel, quarantine)) {
                            blocked++;
                            report.add("BLOCKED " + rel + " :: " + why);
                            logRed("BLOCKED infected jar " + rel + " -> " + why);
                        } else {
                            lockedInfected = rel; // can't remove it (running server jar) -> abort below
                            report.add("LOCKED-INFECTED " + rel + " :: " + why);
                            logRed("CANNOT remove infected (locked) jar: " + rel + " -> " + why);
                        }
                    } else if (vault.trust(jar, rel)) {
                        mapped++;
                        report.add("MAPPED " + rel + (reasons.isEmpty() ? "" : " (whitelisted)"));
                    }
                }
            }

            log("pre-load done: scanned " + jars.size() + " jar(s) - mapped " + mapped + ", restored " + restored
                    + ", blocked " + blocked + ", unchanged " + unchanged + ". Vault baseline: " + vault.size() + ".");
            writeReport(guardFolder, report);

            if (lockedInfected != null) {
                logRed("FATAL: infected jar that cannot be removed (it's locked / the running server jar): " + lockedInfected);
                logRed("Refusing to start. Replace it with a clean copy (re-download the server jar), then restart.");
                System.exit(1);
            }
        } catch (Throwable t) {
            logRed("error during pre-load scan: " + t);
        }
    }

    private static List<String> readRoots(File guardFolder) {
        File f = new File(guardFolder, "scan-roots.txt");
        if (f.isFile()) {
            List<String> out = new ArrayList<>();
            try {
                for (String line : Files.readAllLines(f.toPath())) {
                    String s = line.trim();
                    if (!s.isEmpty() && !s.startsWith("#")) {
                        out.add(s);
                    }
                }
            } catch (IOException ignored) {
                // fall through to defaults
            }
            if (!out.isEmpty()) {
                return out;
            }
        }
        return Roots.DEFAULTS;
    }

    private static boolean quarantine(File jar, String rel, File quarantineDir) {
        try {
            File dest = new File(quarantineDir, rel + "." + System.currentTimeMillis() + ".infected");
            File parent = dest.getParentFile();
            if (parent != null) {
                parent.mkdirs();
            }
            Files.move(jar.toPath(), dest.toPath(), StandardCopyOption.REPLACE_EXISTING);
            return true;
        } catch (IOException ex) {
            return false; // locked (e.g. the running server jar)
        }
    }

    private static boolean restore(Vault vault, String rel, File jar) {
        if (!vault.has(rel)) {
            return true; // nothing to restore (already quarantined); not a failure
        }
        try {
            Files.copy(vault.file(rel).toPath(), jar.toPath(), StandardCopyOption.REPLACE_EXISTING);
            return true;
        } catch (IOException ex) {
            return false;
        }
    }

    private static void writeReport(File guardFolder, List<String> report) {
        if (report.isEmpty()) {
            return;
        }
        guardFolder.mkdirs();
        try {
            Files.write(new File(guardFolder, "agent-report.txt").toPath(), report);
        } catch (IOException ignored) {
            // best effort
        }
    }

    private static void log(String msg) {
        System.out.println("[Guardio-Agent] " + msg);
    }

    private static void logRed(String msg) {
        System.out.println(RED + "[Guardio-Agent] " + msg + RESET);
    }
}
