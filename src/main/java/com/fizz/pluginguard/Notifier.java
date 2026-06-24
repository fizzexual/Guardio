package com.fizz.pluginguard;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;

/**
 * Posts a one-line alert to a Discord webhook. Pure JDK (no Gson) so the launcher, agent, and plugin can all
 * use it. Synchronous with a short timeout; callers on the main server thread should invoke it off-thread.
 */
final class Notifier {

    private Notifier() {
    }

    static void send(String webhook, String content) {
        if (webhook == null || webhook.isBlank() || content == null || content.isBlank()) {
            return;
        }
        try {
            String msg = content.length() > 1900 ? content.substring(0, 1900) + "…" : content;
            String json = "{\"content\":\"" + escape(msg) + "\"}";
            HttpClient http = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(10)).build();
            HttpRequest req = HttpRequest.newBuilder(URI.create(webhook))
                    .header("Content-Type", "application/json")
                    .header("User-Agent", "Guardio/1.0")
                    .timeout(Duration.ofSeconds(15))
                    .POST(HttpRequest.BodyPublishers.ofString(json, StandardCharsets.UTF_8))
                    .build();
            http.send(req, HttpResponse.BodyHandlers.discarding());
        } catch (Exception ignored) {
            // alerting is best-effort — never let it break a scan or a boot
        }
    }

    private static String escape(String s) {
        StringBuilder b = new StringBuilder(s.length() + 16);
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '"' -> b.append("\\\"");
                case '\\' -> b.append("\\\\");
                case '\n' -> b.append("\\n");
                case '\r' -> { /* drop */ }
                case '\t' -> b.append("\\t");
                default -> {
                    if (c < 0x20) {
                        b.append(String.format("\\u%04x", (int) c));
                    } else {
                        b.append(c);
                    }
                }
            }
        }
        return b.toString();
    }
}
