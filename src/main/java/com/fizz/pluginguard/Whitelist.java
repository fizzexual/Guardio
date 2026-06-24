package com.fizz.pluginguard;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

/**
 * A plain-text allow-list at {@code plugins/PluginGuard/whitelist.txt} — one jar name (or name fragment)
 * per line, {@code #} comments allowed. A jar whose name matches is never signature-flagged (it's still
 * integrity-checked once mapped). Plain text so the pre-server agent can read it without a YAML parser.
 */
final class Whitelist {

    private Whitelist() {
    }

    static List<String> load(File guardFolder) {
        List<String> out = new ArrayList<>();
        File f = new File(guardFolder, "whitelist.txt");
        if (f.isFile()) {
            try {
                for (String line : Files.readAllLines(f.toPath())) {
                    String s = line.trim().toLowerCase(Locale.ROOT);
                    if (!s.isEmpty() && !s.startsWith("#")) {
                        out.add(s);
                    }
                }
            } catch (IOException ignored) {
                // missing/unreadable whitelist just means "nothing whitelisted"
            }
        }
        return out;
    }

    static boolean allows(String jarName, List<String> whitelist) {
        String n = jarName.toLowerCase(Locale.ROOT);
        for (String w : whitelist) {
            if (n.contains(w)) {
                return true;
            }
        }
        return false;
    }

    /** Appends a name/fragment to the whitelist file (creating it if needed). */
    static void add(File guardFolder, String entry) throws IOException {
        guardFolder.mkdirs();
        File f = new File(guardFolder, "whitelist.txt");
        String line = entry.trim() + System.lineSeparator();
        Files.write(f.toPath(), line.getBytes(),
                java.nio.file.StandardOpenOption.CREATE, java.nio.file.StandardOpenOption.APPEND);
    }
}
