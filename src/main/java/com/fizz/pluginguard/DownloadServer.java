package com.fizz.pluginguard;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;

import java.io.File;
import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

/**
 * Tiny, token-authenticated, read-only HTTP server for pulling files off a headless
 * server without FTP/panel access. Built purely on the JDK's {@code com.sun.net.httpserver}.
 *
 * <p><b>Security model</b> (all enforced unconditionally):
 * <ul>
 *   <li><b>Disabled by default.</b> A null/blank token leaves the server unbound; nothing is
 *       served and no port is opened ({@link #isDisabled()} returns {@code true}).</li>
 *   <li><b>Bind scope.</b> Binds loopback ({@code 127.0.0.1}) when {@code bindLocalhostOnly},
 *       otherwise all interfaces ({@code 0.0.0.0}). Callers should default to loopback only.</li>
 *   <li><b>Authentication.</b> Every request must present the exact token via the
 *       {@code X-Guardio-Token} header or {@code ?token=} query param. Comparison is
 *       constant-time ({@link MessageDigest#isEqual}). Missing/wrong token yields 401 and no body.</li>
 *   <li><b>Path containment.</b> Only files whose real (canonical, symlink-resolved) path lies
 *       inside an allowed base are served. Allowed bases are {@code guardHome/vault},
 *       {@code guardHome} (for {@code *.txt} reports and {@code *.html}), and
 *       {@code guardHome/quarantine} only when {@code allowQuarantine} is true. Everything else
 *       (traversal via {@code ..}, absolute paths, symlink escapes, disallowed extensions in the
 *       home base) is rejected with 403; missing files yield 404. No file outside the bases is
 *       ever reachable.</li>
 * </ul>
 *
 * <p>This is a download-only surface: it exposes {@code GET /} (an HTML index) and
 * {@code GET /dl} (a streamed attachment). It never writes, deletes, executes, or lists outside
 * the allowed bases, so it cannot be turned into a vector for handing out malware.
 */
final class DownloadServer {

    private static final String TOKEN_HEADER = "X-Guardio-Token";
    private static final String OCTET_STREAM = "application/octet-stream";

    private final int port;
    private final String token;
    private final boolean bindLocalhostOnly;
    private final boolean allowQuarantine;
    private final File guardHome;
    private final boolean disabled;

    private HttpServer server;
    private ExecutorService executor;

    DownloadServer(int port, String token, boolean bindLocalhostOnly, boolean allowQuarantine, File guardHome) {
        this.port = port;
        this.token = token;
        this.bindLocalhostOnly = bindLocalhostOnly;
        this.allowQuarantine = allowQuarantine;
        this.guardHome = guardHome;
        this.disabled = (token == null || token.isBlank());
    }

    /** @return true when no usable token was supplied; in that state {@link #start()} is a no-op. */
    boolean isDisabled() {
        return disabled;
    }

    /**
     * Binds and starts the server. Idempotent: a second call while running does nothing.
     * When {@link #isDisabled()}, returns immediately without binding (caller handles messaging).
     */
    void start() throws IOException {
        if (disabled) {
            return;
        }
        if (server != null) {
            return;
        }
        String host = bindLocalhostOnly ? "127.0.0.1" : "0.0.0.0";
        HttpServer s = HttpServer.create(new InetSocketAddress(host, port), 0);
        this.executor = Executors.newFixedThreadPool(2);
        s.setExecutor(executor);
        s.createContext("/", wrap(this::handleIndex));
        s.createContext("/dl", wrap(this::handleDownload));
        s.start();
        this.server = s;
    }

    /** Stops the server and shuts down its executor. Idempotent and safe if never started. */
    void stop() {
        if (server != null) {
            server.stop(0);
            server = null;
        }
        if (executor != null) {
            executor.shutdownNow();
            try {
                executor.awaitTermination(2, TimeUnit.SECONDS);
            } catch (InterruptedException ignored) {
                Thread.currentThread().interrupt();
            }
            executor = null;
        }
    }

    // --- handler wrapping ----------------------------------------------------

    /** Wraps a handler so any throwable becomes a 500 instead of killing the server thread. */
    private HttpHandler wrap(HttpHandler delegate) {
        return exchange -> {
            try {
                delegate.handle(exchange);
            } catch (Throwable t) {
                try {
                    sendText(exchange, 500, "Internal Server Error");
                } catch (IOException ignored) {
                    // nothing further we can do
                } finally {
                    exchange.close();
                }
            }
        };
    }

    // --- routes --------------------------------------------------------------

    /** {@code GET /} -> HTML index of downloadable files; requires a valid token. */
    private void handleIndex(HttpExchange exchange) throws IOException {
        if (!authorize(exchange)) {
            return;
        }
        if (!"GET".equalsIgnoreCase(exchange.getRequestMethod())) {
            sendText(exchange, 405, "Method Not Allowed");
            return;
        }

        StringBuilder html = new StringBuilder(2048);
        html.append("<!DOCTYPE html><html><head><meta charset=\"utf-8\">")
            .append("<title>PluginGuard Downloads</title></head><body>")
            .append("<h1>PluginGuard Downloads</h1>");

        for (Map.Entry<String, Path> base : allowedBases().entrySet()) {
            html.append("<h2>").append(htmlEscape(base.getKey())).append("</h2><ul>");
            List<String> rels = listRelativeFiles(base.getValue());
            if (rels.isEmpty()) {
                html.append("<li><em>(none)</em></li>");
            } else {
                for (String rel : rels) {
                    String href = "/dl?path=" + urlEncode(rel) + "&token=" + urlEncode(token);
                    html.append("<li><a href=\"").append(htmlEscape(href)).append("\">")
                        .append(htmlEscape(rel)).append("</a></li>");
                }
            }
            html.append("</ul>");
        }

        html.append("</body></html>");
        sendHtml(exchange, 200, html.toString());
    }

    /** {@code GET /dl?path=...} -> streams the file as an attachment; 403 outside bases, 404 if absent. */
    private void handleDownload(HttpExchange exchange) throws IOException {
        if (!authorize(exchange)) {
            return;
        }
        if (!"GET".equalsIgnoreCase(exchange.getRequestMethod())) {
            sendText(exchange, 405, "Method Not Allowed");
            return;
        }

        Map<String, String> query = parseQuery(exchange);
        String rel = query.get("path");
        if (rel == null || rel.isBlank()) {
            sendText(exchange, 400, "Missing path");
            return;
        }

        Path resolved = resolveAllowed(rel);
        if (resolved == null) {
            sendText(exchange, 403, "Forbidden");
            return;
        }
        if (!Files.isRegularFile(resolved)) {
            sendText(exchange, 404, "Not Found");
            return;
        }

        byte[] data = Files.readAllBytes(resolved);
        String fileName = resolved.getFileName().toString();
        exchange.getResponseHeaders().set("Content-Type", OCTET_STREAM);
        exchange.getResponseHeaders().set("Content-Disposition",
                "attachment; filename=\"" + sanitizeHeaderValue(fileName) + "\"");
        exchange.sendResponseHeaders(200, data.length);
        try (OutputStream os = exchange.getResponseBody()) {
            os.write(data);
        }
    }

    // --- security: auth + path containment -----------------------------------

    /**
     * Constant-time token check against {@code X-Guardio-Token} header or {@code ?token=}.
     * On failure sends 401 (no body) and returns false.
     */
    private boolean authorize(HttpExchange exchange) throws IOException {
        String presented = exchange.getRequestHeaders().getFirst(TOKEN_HEADER);
        if (presented == null) {
            presented = parseQuery(exchange).get("token");
        }
        if (presented != null && tokensMatch(presented, token)) {
            return true;
        }
        sendText(exchange, 401, "Unauthorized");
        return false;
    }

    /** Constant-time comparison of two tokens by their UTF-8 bytes. */
    private static boolean tokensMatch(String presented, String expected) {
        byte[] a = presented.getBytes(StandardCharsets.UTF_8);
        byte[] b = expected.getBytes(StandardCharsets.UTF_8);
        return MessageDigest.isEqual(a, b);
    }

    /**
     * Resolves a client-supplied relative path against every allowed base and returns the real
     * (canonical, symlink-resolved) path only if it is genuinely contained within that base and,
     * for the home base, has an allowed report extension. Returns {@code null} for anything that
     * escapes (traversal, absolute paths, symlink escapes) or is otherwise not permitted.
     */
    private Path resolveAllowed(String rel) {
        for (Map.Entry<String, Path> entry : allowedBases().entrySet()) {
            Path base = entry.getValue();
            Path baseReal = realPathOrNull(base);
            if (baseReal == null) {
                continue;
            }
            Path candidate = realPathOrNull(base.resolve(rel));
            if (candidate == null) {
                continue;
            }
            if (!candidate.startsWith(baseReal)) {
                continue; // traversal / symlink escape -> not contained
            }
            if (isHomeBase(base) && !isAllowedReport(candidate)) {
                continue; // the bare home base only exposes *.txt and *.html
            }
            return candidate;
        }
        return null;
    }

    /** Ordered map of display-label -> base directory for every currently allowed base. */
    private Map<String, Path> allowedBases() {
        Map<String, Path> bases = new LinkedHashMap<>();
        Path home = guardHome.toPath();
        bases.put("vault", home.resolve("vault"));
        bases.put("reports", home);
        if (allowQuarantine) {
            bases.put("quarantine", home.resolve("quarantine"));
        }
        return bases;
    }

    private boolean isHomeBase(Path base) {
        return base.equals(guardHome.toPath());
    }

    private static boolean isAllowedReport(Path file) {
        String name = file.getFileName().toString().toLowerCase(Locale.ROOT);
        return name.endsWith(".txt") || name.endsWith(".html");
    }

    /**
     * Lists files directly relevant to a base for the index. For the home base only top-level
     * {@code *.txt}/{@code *.html} reports are listed (so the index never advertises subdirs like
     * vault/quarantine twice); other bases are walked recursively. Paths are returned relative to
     * the base, using {@code /} separators. Anything that escapes the base is skipped.
     */
    private List<String> listRelativeFiles(Path base) {
        List<String> out = new ArrayList<>();
        Path baseReal = realPathOrNull(base);
        if (baseReal == null || !Files.isDirectory(baseReal)) {
            return out;
        }
        boolean homeBase = isHomeBase(base);
        try {
            int depth = homeBase ? 1 : Integer.MAX_VALUE;
            try (var stream = Files.walk(baseReal, depth)) {
                stream.filter(Files::isRegularFile)
                      .filter(p -> !homeBase || isAllowedReport(p))
                      .forEach(p -> {
                          Path relPath = baseReal.relativize(p);
                          out.add(relPath.toString().replace(File.separatorChar, '/'));
                      });
            }
        } catch (IOException ignored) {
            // best-effort listing; an unreadable base simply shows nothing
        }
        out.sort(String::compareTo);
        return out;
    }

    /** Resolves the real path (following symlinks); returns null if it does not exist or errors. */
    private static Path realPathOrNull(Path p) {
        try {
            return p.toRealPath();
        } catch (IOException e) {
            return null;
        }
    }

    // --- small HTTP helpers --------------------------------------------------

    /** Parses the request URI query string into a decoded key/value map (last value wins). */
    private static Map<String, String> parseQuery(HttpExchange exchange) {
        Map<String, String> result = new LinkedHashMap<>();
        String raw = exchange.getRequestURI().getRawQuery();
        if (raw == null || raw.isEmpty()) {
            return result;
        }
        for (String pair : raw.split("&")) {
            if (pair.isEmpty()) {
                continue;
            }
            int eq = pair.indexOf('=');
            String key = eq >= 0 ? pair.substring(0, eq) : pair;
            String val = eq >= 0 ? pair.substring(eq + 1) : "";
            result.put(urlDecode(key), urlDecode(val));
        }
        return result;
    }

    private void sendText(HttpExchange exchange, int status, String body) throws IOException {
        send(exchange, status, "text/plain; charset=utf-8", body.getBytes(StandardCharsets.UTF_8));
    }

    private void sendHtml(HttpExchange exchange, int status, String body) throws IOException {
        send(exchange, status, "text/html; charset=utf-8", body.getBytes(StandardCharsets.UTF_8));
    }

    /** Sets content type + length, writes the body, and closes the exchange. */
    private void send(HttpExchange exchange, int status, String contentType, byte[] body) throws IOException {
        exchange.getResponseHeaders().set("Content-Type", contentType);
        exchange.sendResponseHeaders(status, body.length);
        try (OutputStream os = exchange.getResponseBody()) {
            os.write(body);
        }
    }

    // --- escaping ------------------------------------------------------------

    private static String htmlEscape(String s) {
        StringBuilder sb = new StringBuilder(s.length() + 16);
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '&' -> sb.append("&amp;");
                case '<' -> sb.append("&lt;");
                case '>' -> sb.append("&gt;");
                case '"' -> sb.append("&quot;");
                case '\'' -> sb.append("&#39;");
                default -> sb.append(c);
            }
        }
        return sb.toString();
    }

    /** Strips characters that could break out of the Content-Disposition filename. */
    private static String sanitizeHeaderValue(String s) {
        return s.replaceAll("[\\r\\n\"]", "_");
    }

    private static String urlEncode(String s) {
        return java.net.URLEncoder.encode(s, StandardCharsets.UTF_8);
    }

    private static String urlDecode(String s) {
        return URLDecoder.decode(s, StandardCharsets.UTF_8);
    }
}
