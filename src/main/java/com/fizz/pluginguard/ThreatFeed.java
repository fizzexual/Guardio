package com.fizz.pluginguard;

import java.io.File;
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.file.Files;
import java.time.Duration;
import java.util.HashSet;
import java.util.Locale;
import java.util.Set;

/**
 * Known-malware SHA-256 hash feed. Fetches a plaintext list (one hash per line, optional "{@code <hash> name}",
 * {@code #} comments) from a URL, caches it to disk, and matches jars by hash — so a known payload is caught
 * even when renamed. Pure JDK (no Gson) so every layer can use it. Best-effort: a fetch failure falls back to
 * the cached copy, and an empty feed simply matches nothing.
 */
final class ThreatFeed {

    private final Set<String> hashes = new HashSet<>();

    private ThreatFeed() {
    }

    /** Refreshes the cache from {@code url} (best-effort) then loads hashes from the cache file. */
    static ThreatFeed loadOrFetch(File cache, String url) {
        ThreatFeed f = new ThreatFeed();
        if (url != null && !url.isBlank()) {
            try {
                HttpClient http = HttpClient.newBuilder()
                        .followRedirects(HttpClient.Redirect.NORMAL).connectTimeout(Duration.ofSeconds(15)).build();
                HttpRequest req = HttpRequest.newBuilder(URI.create(url))
                        .header("User-Agent", "Guardio/1.0").timeout(Duration.ofSeconds(30)).GET().build();
                HttpResponse<String> resp = http.send(req, HttpResponse.BodyHandlers.ofString());
                if (resp.statusCode() / 100 == 2 && resp.body() != null && !resp.body().isBlank()) {
                    File p = cache.getParentFile();
                    if (p != null) {
                        p.mkdirs();
                    }
                    Files.writeString(cache.toPath(), resp.body());
                }
            } catch (Exception ignored) {
                // offline / bad URL — fall back to the cached copy
            }
        }
        if (cache.isFile()) {
            try {
                for (String line : Files.readAllLines(cache.toPath())) {
                    f.add(line);
                }
            } catch (IOException ignored) {
                // unreadable cache — feed stays empty
            }
        }
        return f;
    }

    private void add(String line) {
        String s = line.trim();
        if (s.isEmpty() || s.startsWith("#")) {
            return;
        }
        int sp = s.indexOf(' ');
        if (sp < 0) {
            sp = s.indexOf('\t');
        }
        String h = (sp > 0 ? s.substring(0, sp) : s).trim().toLowerCase(Locale.ROOT);
        if (h.matches("[0-9a-f]{64}")) {
            hashes.add(h);
        }
    }

    boolean contains(String sha256) {
        return sha256 != null && hashes.contains(sha256.toLowerCase(Locale.ROOT));
    }

    int size() {
        return hashes.size();
    }
}
