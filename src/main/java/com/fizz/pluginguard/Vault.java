package com.fizz.pluginguard;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.StandardCopyOption;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * The trusted baseline: a {@code vault/} folder that MIRRORS the guarded tree — entries are keyed by their
 * path relative to the server root (e.g. {@code plugins/X.jar}, {@code libraries/a/b/c.jar},
 * {@code purpur-1.21.11.jar}). Stores known-clean copies (the source of truth for restoring) and their
 * SHA-256 hashes. Populated explicitly (auto-map of new clean jars, or {@code /guard trust}) — never
 * auto-trusts a signature-flagged jar.
 */
final class Vault {

    private final File dir;
    // Concurrent: written by the scan executor, the async heal task, and main-thread commands; read on all three.
    private final Map<String, String> hashes = new ConcurrentHashMap<>(); // relative path -> sha256

    Vault(File guardFolder) {
        this.dir = new File(guardFolder, "vault");
        this.dir.mkdirs();
        reindex();
    }

    void reindex() {
        hashes.clear();
        walk(dir);
    }

    private void walk(File d) {
        File[] fs = d.listFiles();
        if (fs == null) {
            return;
        }
        for (File f : fs) {
            if (f.isDirectory()) {
                walk(f);
            } else if (f.getName().toLowerCase(Locale.ROOT).endsWith(".jar")) {
                String h = Hashing.sha256(f);
                if (h != null) {
                    hashes.put(rel(dir, f), h);
                }
            }
        }
    }

    /** Path of {@code f} relative to {@code base}, normalised to forward slashes. */
    static String rel(File base, File f) {
        return base.toPath().toAbsolutePath().normalize()
                .relativize(f.toPath().toAbsolutePath().normalize())
                .toString().replace('\\', '/');
    }

    boolean has(String rel) {
        return hashes.containsKey(rel);
    }

    String hash(String rel) {
        return hashes.get(rel);
    }

    File file(String rel) {
        return new File(dir, rel);
    }

    int size() {
        return hashes.size();
    }

    /** Copies a (presumed-clean) jar into the vault under {@code rel} and records its hash. */
    boolean trust(File jar, String rel) {
        try {
            File dest = new File(dir, rel);
            File parent = dest.getParentFile();
            if (parent != null) {
                parent.mkdirs();
            }
            Files.copy(jar.toPath(), dest.toPath(), StandardCopyOption.REPLACE_EXISTING);
            String h = Hashing.sha256(jar);
            if (h != null) {
                hashes.put(rel, h);
            }
            return true;
        } catch (IOException ex) {
            return false;
        }
    }
}
