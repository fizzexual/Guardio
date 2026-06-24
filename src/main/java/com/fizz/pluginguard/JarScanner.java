package com.fizz.pluginguard;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

/**
 * Signature scanner. Reads a jar (read-only — works even while the jar is loaded/locked) and flags it if
 * any zip-entry name contains an "entry signature" (injected/hidden package) or any {@code .class} body
 * contains a "content signature" (e.g. the C2 domain). Pure detection — never modifies the jar.
 */
final class JarScanner {

    private static final int MAX_REASONS = 10;
    private static final long MAX_CLASS_BYTES = 3_000_000L;
    static final String UNREADABLE_PREFIX = "unreadable jar";

    /** True if the only "reason" is that the jar couldn't be read (transient lock/IO) — NOT a malware match. */
    static boolean unreadableOnly(List<String> reasons) {
        return reasons.size() == 1 && reasons.get(0).startsWith(UNREADABLE_PREFIX);
    }

    private final List<String> entrySignatures;
    private final List<String> contentSignatures;

    JarScanner(List<String> entrySignatures, List<String> contentSignatures) {
        this.entrySignatures = entrySignatures;
        this.contentSignatures = contentSignatures;
    }

    /** Returns the list of matched-signature reasons (empty = no signature hit). */
    List<String> scan(File jar) {
        List<String> reasons = new ArrayList<>();
        try (ZipFile zip = new ZipFile(jar)) {
            Enumeration<? extends ZipEntry> entries = zip.entries();
            while (entries.hasMoreElements() && reasons.size() < MAX_REASONS) {
                ZipEntry e = entries.nextElement();
                String name = e.getName();
                for (String sig : entrySignatures) {
                    if (!sig.isEmpty() && name.contains(sig)) {
                        reasons.add("injected path: " + name);
                        break;
                    }
                }
                if (!contentSignatures.isEmpty() && name.endsWith(".class")
                        && e.getSize() >= 0 && e.getSize() < MAX_CLASS_BYTES) {
                    String body = read(zip, e);
                    if (body != null) {
                        for (String sig : contentSignatures) {
                            if (!sig.isEmpty() && body.contains(sig)) {
                                reasons.add("malware string '" + sig + "' in " + name);
                            }
                        }
                    }
                }
            }
        } catch (IOException ex) {
            reasons.add(UNREADABLE_PREFIX + " (" + ex.getMessage() + ")");
        }
        return reasons;
    }

    private static String read(ZipFile zip, ZipEntry e) {
        try (InputStream in = zip.getInputStream(e)) {
            // ISO-8859-1 maps bytes 1:1, so ASCII signature substrings match reliably in bytecode.
            return new String(in.readAllBytes(), StandardCharsets.ISO_8859_1);
        } catch (IOException ex) {
            return null;
        }
    }
}
