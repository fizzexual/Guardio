package com.fizz.pluginguard;

import java.io.File;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

/**
 * Decides which jars across the whole server are guarded: the top-level server jar(s) plus every {@code .jar}
 * under the configured roots (default {@code plugins} + {@code libraries}), scanned recursively. The guard's
 * own folder ({@code plugins/PluginGuard/}, i.e. the vault + quarantine) and the PluginGuard jar are excluded
 * so the guard never scans or restores itself.
 */
final class Roots {

    static final List<String> DEFAULTS = List.of("plugins", "libraries");

    private Roots() {
    }

    static List<File> listJars(File serverRoot, List<String> roots, File guardFolder) {
        List<File> out = new ArrayList<>();
        String guardPath = canon(guardFolder);
        File[] top = serverRoot.listFiles((d, n) -> n.toLowerCase(Locale.ROOT).endsWith(".jar"));
        if (top != null) {
            for (File f : top) {
                addIfOk(out, f, guardPath); // top-level server jar(s), e.g. purpur-1.21.11.jar
            }
        }
        for (String r : roots) {
            walk(new File(serverRoot, r), out, guardPath);
        }
        return out;
    }

    private static void walk(File d, List<File> out, String guardPath) {
        if (d == null || !d.isDirectory()) {
            return;
        }
        if (canon(d).startsWith(guardPath)) {
            return; // never descend into our own vault/quarantine
        }
        File[] fs = d.listFiles();
        if (fs == null) {
            return;
        }
        for (File f : fs) {
            if (f.isDirectory()) {
                walk(f, out, guardPath);
            } else if (f.getName().toLowerCase(Locale.ROOT).endsWith(".jar")) {
                addIfOk(out, f, guardPath);
            }
        }
    }

    private static void addIfOk(List<File> out, File f, String guardPath) {
        if (canon(f).startsWith(guardPath)) {
            return;
        }
        if (f.getName().toLowerCase(Locale.ROOT).contains("pluginguard")) {
            return;
        }
        out.add(f);
    }

    private static String canon(File f) {
        try {
            return f.getCanonicalPath();
        } catch (Exception ex) {
            return f.getAbsolutePath();
        }
    }
}
