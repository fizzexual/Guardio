package com.fizz.pluginguard;

import java.io.File;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

/**
 * Report-only detector for CRACKED / NULLED premium plugins - one of the top malware-infection vectors, since
 * leaked builds are a common carrier for the injector that hit this server. It scans entry bytes for a curated,
 * deliberately SPECIFIC set of markers (leak-site domains, "cracked by" credits) that only appear in pirated
 * builds, plus an author/description literally claiming "nulled"/"cracked". It returns human-readable reasons and
 * NEVER acts on them - the caller decides what to do (it must not delete or quarantine anything itself).
 *
 * <p>False-positive-conscious by design: only the explicit markers below trip it. Generic strings (e.g. "crack",
 * "leak" on their own) are intentionally NOT used, so a legitimately-licensed plugin is not flagged. Any error
 * opening or reading the jar yields an empty list - "can't tell" is treated as "not flagged".
 */
final class CrackedPluginDetector {

    private static final int MAX_REASONS = 8;
    private static final int MAX_CLASSES = 4000;
    private static final long MAX_ENTRY_BYTES = 2L * 1024 * 1024;

    /**
     * Markers that only show up in leaked/cracked builds. Stored lower-case; the search is case-insensitive.
     * Kept narrow on purpose - each is a leak-site domain or an explicit piracy credit, not a generic word.
     */
    private static final String[] MARKERS = {
            "nulled.to",
            "nulledbb",
            "nulled by",
            "blackspigot",
            "spigotunlocked",
            "leaked by",
            "leakedbukkit",
            "leaked.cx",
            "cracked by",
            "crack by",
            "mcleaks",
    };

    /** Text-ish (non-{@code .class}) entry suffixes whose whole body is worth scanning for markers. */
    private static final String[] TEXT_SUFFIXES = {".yml", ".yaml", ".properties", ".txt"};

    /** Manifest/plugin.yml fields that literally claiming these words is itself a strong signal. */
    private static final String[] METADATA_WORDS = {"nulled", "cracked"};

    private CrackedPluginDetector() {
    }

    /** Returns distinct cracked/nulled-marker reasons, capped at {@value #MAX_REASONS} (empty = clean). */
    static List<String> analyze(File jar) {
        List<String> reasons = new ArrayList<>();
        Set<String> seenMarkers = new LinkedHashSet<>();
        int classesRead = 0;
        try (ZipFile zip = new ZipFile(jar)) {
            Enumeration<? extends ZipEntry> entries = zip.entries();
            while (entries.hasMoreElements() && reasons.size() < MAX_REASONS) {
                ZipEntry e = entries.nextElement();
                if (e.isDirectory() || e.getSize() > MAX_ENTRY_BYTES) {
                    continue;
                }
                String name = e.getName();
                boolean isClass = name.endsWith(".class");
                boolean isText = isTextEntry(name);
                if (!isClass && !isText) {
                    continue;
                }
                if (isClass) {
                    if (classesRead >= MAX_CLASSES) {
                        continue;
                    }
                    classesRead++;
                }

                String body = read(zip, e);
                if (body == null) {
                    continue;
                }
                String lower = body.toLowerCase(Locale.ROOT);

                for (String marker : MARKERS) {
                    if (lower.contains(marker) && seenMarkers.add(marker)) {
                        reasons.add("cracked/nulled marker: '" + marker + "' in " + name);
                        if (reasons.size() >= MAX_REASONS) {
                            break;
                        }
                    }
                }

                // A manifest / plugin.yml that literally credits "nulled"/"cracked" is its own signal.
                if (isMetadataEntry(name)) {
                    for (String word : METADATA_WORDS) {
                        String tag = "metadata:" + word;
                        if (lower.contains(word) && seenMarkers.add(tag)) {
                            reasons.add("plugin metadata claims '" + word + "' in " + name);
                            if (reasons.size() >= MAX_REASONS) {
                                break;
                            }
                        }
                    }
                }
            }
        } catch (Exception ex) {
            return new ArrayList<>();
        }
        return reasons;
    }

    private static boolean isTextEntry(String name) {
        String lower = name.toLowerCase(Locale.ROOT);
        for (String suffix : TEXT_SUFFIXES) {
            if (lower.endsWith(suffix)) {
                return true;
            }
        }
        return false;
    }

    private static boolean isMetadataEntry(String name) {
        String lower = name.toLowerCase(Locale.ROOT);
        return lower.endsWith("plugin.yml")
                || lower.endsWith("paper-plugin.yml")
                || lower.endsWith("meta-inf/manifest.mf");
    }

    private static String read(ZipFile zip, ZipEntry e) {
        try (InputStream in = zip.getInputStream(e)) {
            // ISO-8859-1 maps bytes 1:1, so ASCII marker substrings match reliably in bytecode and text alike.
            return new String(in.readAllBytes(), StandardCharsets.ISO_8859_1);
        } catch (Exception ex) {
            return null;
        }
    }
}
