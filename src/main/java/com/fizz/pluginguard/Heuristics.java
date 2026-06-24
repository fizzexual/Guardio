package com.fizz.pluginguard;

import java.io.File;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

/**
 * Report-only behavioral analysis. Scans class bytes for backdoor-like patterns and returns human-readable
 * suspicions - it NEVER causes a quarantine on its own (too prone to false positives, since legit plugins use
 * reflection/exec). A jar is reported only when it shows two+ distinct red flags, or the strong combination of
 * runtime class definition + remote code loading (the shape of the infector that hit this server).
 */
final class Heuristics {

    private static final long MAX_CLASS_BYTES = 3L * 1024 * 1024;

    private Heuristics() {
    }

    static List<String> analyze(File jar) {
        boolean defineClass = false;
        boolean remoteFetch = false;
        boolean exec = false;
        try (ZipFile zip = new ZipFile(jar)) {
            Enumeration<? extends ZipEntry> en = zip.entries();
            while (en.hasMoreElements()) {
                ZipEntry e = en.nextElement();
                if (e.isDirectory() || !e.getName().endsWith(".class") || e.getSize() > MAX_CLASS_BYTES) {
                    continue;
                }
                String body = read(zip, e);
                if (body == null) {
                    continue;
                }
                if (body.contains("defineClass")
                        && (body.contains("java/lang/invoke/MethodHandles") || body.contains("MethodHandles$Lookup"))) {
                    defineClass = true;
                }
                if (body.contains("java/net/URLClassLoader")
                        || (body.contains("java/net/URL") && (body.contains("openStream") || body.contains("openConnection")))) {
                    remoteFetch = true;
                }
                if ((body.contains("java/lang/Runtime") && body.contains("exec")) || body.contains("java/lang/ProcessBuilder")) {
                    exec = true;
                }
                if (defineClass && remoteFetch && exec) {
                    break; // already maximally suspicious
                }
            }
        } catch (Exception ex) {
            return new ArrayList<>();
        }

        List<String> hits = new ArrayList<>();
        if (defineClass) {
            hits.add("runtime class definition (MethodHandles.defineClass) - classic stager");
        }
        if (remoteFetch) {
            hits.add("remote class/code loading (URLClassLoader / URL.openStream)");
        }
        if (exec) {
            hits.add("OS command execution (Runtime.exec / ProcessBuilder)");
        }
        boolean strongCombo = defineClass && remoteFetch;
        return (hits.size() >= 2 || strongCombo) ? hits : new ArrayList<>();
    }

    private static String read(ZipFile zip, ZipEntry e) {
        try (InputStream in = zip.getInputStream(e)) {
            return new String(in.readAllBytes(), StandardCharsets.ISO_8859_1);
        } catch (Exception ex) {
            return null;
        }
    }
}
