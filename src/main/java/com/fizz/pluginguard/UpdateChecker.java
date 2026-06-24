package com.fizz.pluginguard;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Tiny update check: reads the latest release tag from a URL and returns it (or null on any failure). Pure JDK
 * (no Gson) — it just regexes {@code "tag_name":"..."} out of the GitHub releases JSON, or treats a plain-text
 * body as the version. Never downloads anything. When the repo is private / unreachable it simply returns null.
 */
final class UpdateChecker {

    private static final Pattern TAG = Pattern.compile("\"tag_name\"\\s*:\\s*\"([^\"]+)\"");

    private UpdateChecker() {
    }

    /** Latest version string (leading 'v' stripped), or null if it can't be determined. */
    static String latest(String url) {
        if (url == null || url.isBlank()) {
            return null;
        }
        try {
            HttpClient http = HttpClient.newBuilder()
                    .followRedirects(HttpClient.Redirect.NORMAL).connectTimeout(Duration.ofSeconds(10)).build();
            HttpRequest req = HttpRequest.newBuilder(URI.create(url))
                    .header("User-Agent", "Guardio/1.0").header("Accept", "application/vnd.github+json")
                    .timeout(Duration.ofSeconds(15)).GET().build();
            HttpResponse<String> resp = http.send(req, HttpResponse.BodyHandlers.ofString());
            if (resp.statusCode() / 100 != 2 || resp.body() == null) {
                return null;
            }
            String body = resp.body().trim();
            Matcher m = TAG.matcher(body);
            String tag = m.find() ? m.group(1) : (body.length() <= 32 && !body.contains("{") ? body : null);
            if (tag == null) {
                return null;
            }
            return tag.startsWith("v") || tag.startsWith("V") ? tag.substring(1) : tag;
        } catch (Exception ex) {
            return null;
        }
    }
}
