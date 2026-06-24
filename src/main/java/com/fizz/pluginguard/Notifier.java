package com.fizz.pluginguard;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;

/**
 * Posts alerts to a Discord webhook. Pure JDK (no Gson) so the launcher, agent, and plugin can all use it.
 * Synchronous with a short timeout; callers on the main server thread should invoke it off-thread.
 */
final class Notifier {

    private Notifier() {
    }

    /** Plain content line (used by the launcher/agent). */
    static void send(String webhook, String content) {
        if (content == null || content.isBlank()) {
            return;
        }
        String c = content.length() > 1900 ? content.substring(0, 1900) + "…" : content;
        post(webhook, "{\"content\":\"" + escape(c) + "\"}");
    }

    /** Plugin send: optional role mention + plain-or-embed formatting. */
    static void send(String webhook, String roleMention, String text, boolean embed) {
        if (text == null || text.isBlank()) {
            return;
        }
        String mention = roleMention == null ? "" : roleMention;
        String json;
        if (embed) {
            String desc = text.length() > 3900 ? text.substring(0, 3900) + "…" : text;
            json = "{\"content\":\"" + escape(mention) + "\",\"embeds\":[{\"title\":\"Guardio\",\"description\":\""
                    + escape(desc) + "\",\"color\":15158332}]}";
        } else {
            String c = mention + text;
            if (c.length() > 1900) {
                c = c.substring(0, 1900) + "…";
            }
            json = "{\"content\":\"" + escape(c) + "\"}";
        }
        post(webhook, json);
    }

    private static void post(String webhook, String json) {
        if (webhook == null || webhook.isBlank()) {
            return;
        }
        try {
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
