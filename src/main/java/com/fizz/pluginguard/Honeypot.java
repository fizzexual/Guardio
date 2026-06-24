package com.fizz.pluginguard;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Canary / honeypot files. Guardio drops innocuous-looking bait files inside the server tree; if anything
 * modifies or deletes them between checks, that's a strong signal something is actively walking the disk and
 * tampering. {@link #deploy} (re)creates the canaries and records their SHA-256 baseline; {@link #check}
 * compares the live files against that baseline and reports any that were tripped.
 */
final class Honeypot {

    /** Baseline file under guardHome: one {@code relpath<TAB>sha256} line per canary. */
    private static final String BASELINE = "honeypot.dat";

    /** Server-relative bait paths. The guardHome canary is handled separately (see {@link #deploy}). */
    private static final String[] SERVER_CANARIES = {
            "plugins/.cache/session.lock",
            "libraries/.index",
    };

    /** File name of the bait dropped inside guardHome itself. */
    private static final String HOME_CANARY = ".canary";

    private Honeypot() {
    }

    /**
     * (Re)creates every canary file with deterministic content and overwrites the SHA-256 baseline.
     * Best effort: any per-file failure is swallowed so a single unwritable path can't abort deployment,
     * and this method never throws out.
     *
     * @param serverRoot the server's top-level directory (bait is dropped relative to it)
     * @param guardHome  the guard's private folder (holds the baseline plus one bait file)
     */
    static void deploy(File serverRoot, File guardHome) {
        if (serverRoot == null || guardHome == null) {
            return;
        }
        Map<String, String> baseline = new LinkedHashMap<>();
        for (String rel : SERVER_CANARIES) {
            File f = new File(serverRoot, rel);
            writeCanary(f, contentFor(rel));
            String sha = sha256(f);
            if (sha != null) {
                baseline.put(toRel(rel), sha);
            }
        }
        File home = new File(guardHome, HOME_CANARY);
        writeCanary(home, contentFor(HOME_CANARY));
        String homeSha = sha256(home);
        if (homeSha != null) {
            baseline.put(HOME_CANARY, homeSha);
        }
        writeBaseline(guardHome, baseline);
    }

    /**
     * Compares each recorded canary against its baseline hash. A missing file yields
     * {@code "canary DELETED: <relpath>"}; a present file whose SHA differs yields
     * {@code "canary MODIFIED: <relpath>"}. Does not re-deploy.
     *
     * @param serverRoot the server's top-level directory
     * @param guardHome  the guard's private folder (holds the baseline + home canary)
     * @return tripped canaries (empty if all intact, or if no baseline exists)
     */
    static List<String> check(File serverRoot, File guardHome) {
        List<String> tripped = new ArrayList<>();
        if (serverRoot == null || guardHome == null) {
            return tripped;
        }
        Map<String, String> baseline = readBaseline(guardHome);
        if (baseline.isEmpty()) {
            return tripped; // nothing deployed yet (or baseline unreadable) — report nothing
        }
        for (Map.Entry<String, String> e : baseline.entrySet()) {
            String rel = e.getKey();
            String expected = e.getValue();
            File f = HOME_CANARY.equals(rel) ? new File(guardHome, HOME_CANARY) : new File(serverRoot, rel);
            if (!f.isFile()) {
                tripped.add("canary DELETED: " + rel);
                continue;
            }
            String actual = sha256(f);
            if (actual == null) {
                continue; // couldn't read it right now (transient lock) — inconclusive, not a tamper alert
            }
            if (!actual.equals(expected)) {
                tripped.add("canary MODIFIED: " + rel);
            }
        }
        return tripped;
    }

    /** Writes deterministic bait content to {@code f}, creating parent dirs. Best effort; swallows failures. */
    private static void writeCanary(File f, byte[] content) {
        if (f == null) {
            return;
        }
        try {
            File parent = f.getParentFile();
            if (parent != null) {
                parent.mkdirs();
            }
            Files.write(f.toPath(), content);
        } catch (Exception ignored) {
            // best effort: an unwritable canary simply won't appear in the baseline
        }
    }

    /** Overwrites the baseline file with {@code relpath<TAB>sha256} lines. Best effort; swallows failures. */
    private static void writeBaseline(File guardHome, Map<String, String> baseline) {
        try {
            guardHome.mkdirs();
            StringBuilder sb = new StringBuilder();
            for (Map.Entry<String, String> e : baseline.entrySet()) {
                sb.append(e.getKey()).append('\t').append(e.getValue()).append('\n');
            }
            Files.write(new File(guardHome, BASELINE).toPath(), sb.toString().getBytes(StandardCharsets.UTF_8));
        } catch (Exception ignored) {
            // best effort
        }
    }

    /** Reads the baseline into an ordered map. Returns an empty map if absent or unreadable. */
    private static Map<String, String> readBaseline(File guardHome) {
        Map<String, String> out = new LinkedHashMap<>();
        File f = new File(guardHome, BASELINE);
        if (!f.isFile()) {
            return out;
        }
        try {
            Path p = f.toPath();
            for (String line : Files.readAllLines(p, StandardCharsets.UTF_8)) {
                int tab = line.indexOf('\t');
                if (tab <= 0 || tab >= line.length() - 1) {
                    continue; // skip blank or malformed lines
                }
                out.put(line.substring(0, tab), line.substring(tab + 1).trim());
            }
        } catch (IOException ignored) {
            return new LinkedHashMap<>();
        }
        return out;
    }

    /**
     * Deterministic filler for a canary: a plausible comment header plus fixed pseudo-random-looking bytes.
     * Content must be stable (no {@code Math.random}/{@code Date}) so the baseline hash stays reproducible.
     */
    private static byte[] contentFor(String key) {
        StringBuilder sb = new StringBuilder();
        sb.append("# auto-generated cache index - do not edit\n");
        sb.append("# session=").append(fixedToken(key)).append('\n');
        sb.append("v=1\n");
        // fixed body derived deterministically from the key; looks like opaque binary-ish filler
        byte[] body = new byte[64];
        int seed = key.hashCode();
        for (int i = 0; i < body.length; i++) {
            seed = seed * 1103515245 + 12345; // classic LCG, deterministic per key
            body[i] = (byte) ((seed >>> 16) & 0xFF);
        }
        sb.append(hex(body)).append('\n');
        return sb.toString().getBytes(StandardCharsets.UTF_8);
    }

    /** A short stable hex token derived from {@code key} (deterministic), used in the comment header. */
    private static String fixedToken(String key) {
        long h = 1125899906842597L; // prime
        for (int i = 0; i < key.length(); i++) {
            h = 31 * h + key.charAt(i);
        }
        return Long.toHexString(h);
    }

    /** Normalizes a relative path to use forward slashes in the baseline file. */
    private static String toRel(String rel) {
        return rel.replace(File.separatorChar, '/').replace('\\', '/');
    }

    /** Lowercase hex encoding of a byte array. */
    private static String hex(byte[] bytes) {
        StringBuilder sb = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) {
            sb.append(Character.forDigit((b >> 4) & 0xF, 16)).append(Character.forDigit(b & 0xF, 16));
        }
        return sb.toString();
    }

    /** SHA-256 of a file as lowercase hex, or {@code null} if it can't be read. */
    private static String sha256(File f) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            md.update(Files.readAllBytes(f.toPath()));
            return hex(md.digest());
        } catch (Exception ex) {
            return null;
        }
    }
}
