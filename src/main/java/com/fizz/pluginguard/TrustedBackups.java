package com.fizz.pluginguard;

import java.io.InputStream;
import java.io.File;
import java.nio.charset.StandardCharsets;
import java.util.Locale;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

/**
 * {@code guardio/trusted/} — a folder where the admin drops their own KNOWN-CLEAN jars (e.g. paid/premium
 * plugins that can't be auto-downloaded from a free source). When an infected jar has no vault copy and no
 * free download, Guardio restores from here — but only after confirming the trusted copy itself scans clean.
 * Pure JDK so the launcher can use it pre-boot too.
 */
final class TrustedBackups {

    static final String DIR = "trusted";

    private TrustedBackups() {
    }

    /** A clean trusted jar matching the plugin name or filename, or null. Returns it only if it scans clean. */
    static File find(File guardHome, String pluginName, String fileName, JarScanner scanner) {
        File dir = new File(guardHome, DIR);
        File[] jars = dir.listFiles((d, n) -> n.toLowerCase(Locale.ROOT).endsWith(".jar"));
        if (jars == null) {
            return null;
        }
        for (File j : jars) {
            boolean match = fileName != null && j.getName().equalsIgnoreCase(fileName);
            if (!match && pluginName != null) {
                String n = readName(j);
                match = n != null && n.equalsIgnoreCase(pluginName);
            }
            if (match && scanner.scan(j).isEmpty()) {
                return j; // only hand back a trusted copy that is itself clean
            }
        }
        return null;
    }

    /** Reads {@code name:} from plugin.yml without Bukkit YAML (so the launcher can use it). */
    private static String readName(File jar) {
        try (ZipFile zip = new ZipFile(jar)) {
            ZipEntry e = zip.getEntry("plugin.yml");
            if (e == null) {
                e = zip.getEntry("paper-plugin.yml");
            }
            if (e == null) {
                return null;
            }
            try (InputStream in = zip.getInputStream(e)) {
                String body = new String(in.readAllBytes(), StandardCharsets.UTF_8);
                for (String line : body.split("\n")) {
                    String s = line.trim();
                    if (s.startsWith("name:")) {
                        return s.substring(5).trim().replaceAll("^['\"]|['\"]$", "");
                    }
                }
            }
        } catch (Exception ignored) {
            // not a Bukkit plugin / unreadable
        }
        return null;
    }
}
