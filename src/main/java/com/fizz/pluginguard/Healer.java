package com.fizz.pluginguard;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import java.io.BufferedInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.time.Duration;
import java.util.Locale;

/**
 * Auto-healer: fetches a CLEAN replacement jar for an infected plugin from a free source (Modrinth's public
 * API, or a manual override — {@code modrinth:<slug>} / {@code url:<jar>} / {@code github:<owner/repo>}),
 * then verifies it two ways before trusting it: the source's published SHA-512 (when available) AND a re-scan
 * with PluginGuard's own {@link JarScanner}. A download that fails either check is rejected.
 *
 * <p>Only works for FREE, publicly downloadable plugins. Premium (no public API) and custom/private plugins
 * return a failure so the caller can flag them for manual reinstall. Runs at runtime (has network + Gson) —
 * never in the pre-load agent.</p>
 */
final class Healer {

    static final class Result {
        final File file;
        final String source;
        final String error;

        private Result(File file, String source, String error) {
            this.file = file;
            this.source = source;
            this.error = error;
        }

        static Result ok(File f, String s) {
            return new Result(f, s, null);
        }

        static Result fail(String e) {
            return new Result(null, null, e);
        }

        boolean ok() {
            return file != null;
        }
    }

    private static final String UA = "PluginGuard/1.0 (Minecraft server anti-malware healer)";
    private static final String API = "https://api.modrinth.com/v2";

    private final HttpClient http = HttpClient.newBuilder()
            .connectTimeout(Duration.ofSeconds(12))
            .followRedirects(HttpClient.Redirect.NORMAL)
            .build();
    private final JarScanner scanner;

    Healer(JarScanner scanner) {
        this.scanner = scanner;
    }

    /** Shuts down the long-lived HttpClient's SelectorManager thread + connection pool (Java 21 AutoCloseable). */
    void close() {
        try {
            http.close();
        } catch (Throwable ignored) {
            // best effort
        }
    }

    /** Downloads + verifies a clean copy; {@code override} (may be null) wins over a Modrinth name search. */
    Result fetchClean(String name, String version, String gameVersion, String override) {
        try {
            Candidate c = (override != null && !override.isBlank())
                    ? fromOverride(override, gameVersion)
                    : fromModrinth(name, gameVersion);
            if (c == null) {
                return Result.fail("no free source matched '" + name + "'");
            }
            File tmp = File.createTempFile("pg-heal-", ".jar");
            if (!download(c.url, tmp)) {
                tmp.delete();
                return Result.fail("download failed (" + c.url + ")");
            }
            if (c.sha512 != null) {
                String h = sha(tmp, "SHA-512");
                if (h == null || !h.equalsIgnoreCase(c.sha512)) {
                    tmp.delete();
                    return Result.fail("hash mismatch from " + c.source);
                }
            }
            java.util.List<String> sig = scanner.scan(tmp);
            if (!sig.isEmpty()) {
                tmp.delete();
                return Result.fail("downloaded copy ALSO flagged (" + sig.get(0) + ") — rejected");
            }
            return Result.ok(tmp, c.source);
        } catch (Exception ex) {
            return Result.fail("error: " + ex.getMessage());
        }
    }

    private static final class Candidate {
        String url;
        String sha512;
        String source;
    }

    private Candidate fromOverride(String ov, String gv) throws Exception {
        if (ov.startsWith("modrinth:")) {
            return modrinthProject(ov.substring("modrinth:".length()).trim(), gv);
        }
        if (ov.startsWith("url:")) {
            Candidate c = new Candidate();
            c.url = ov.substring("url:".length()).trim();
            c.source = "url override";
            return c;
        }
        if (ov.startsWith("github:")) {
            return github(ov.substring("github:".length()).trim());
        }
        return null;
    }

    private Candidate fromModrinth(String name, String gv) throws Exception {
        String facets = URLEncoder.encode("[[\"project_type:plugin\"]]", StandardCharsets.UTF_8);
        String url = API + "/search?limit=5&query=" + URLEncoder.encode(name, StandardCharsets.UTF_8) + "&facets=" + facets;
        JsonArray hits = getJson(url).getAsJsonObject().getAsJsonArray("hits");
        if (hits == null || hits.isEmpty()) {
            return null;
        }
        String slug = null;
        for (JsonElement h : hits) {
            JsonObject o = h.getAsJsonObject();
            if (name.equalsIgnoreCase(str(o, "slug")) || name.equalsIgnoreCase(str(o, "title"))) {
                slug = str(o, "slug");
                break;
            }
        }
        if (slug == null) {
            slug = str(hits.get(0).getAsJsonObject(), "slug"); // best-effort top hit
        }
        return slug == null ? null : modrinthProject(slug, gv);
    }

    private Candidate modrinthProject(String slug, String gv) throws Exception {
        JsonArray versions = getJson(API + "/project/" + slug + "/version").getAsJsonArray();
        JsonObject best = null;
        for (JsonElement ve : versions) {
            JsonObject v = ve.getAsJsonObject();
            if (!loaderOk(v)) {
                continue;
            }
            if (gameOk(v, gv)) {
                best = v;
                break; // newest loader+game match
            }
            if (best == null) {
                best = v; // fallback: newest loader-compatible
            }
        }
        if (best == null) {
            return null;
        }
        JsonArray files = best.getAsJsonArray("files");
        JsonObject file = null;
        for (JsonElement fe : files) {
            JsonObject f = fe.getAsJsonObject();
            if (f.has("primary") && f.get("primary").getAsBoolean()) {
                file = f;
                break;
            }
        }
        if (file == null && files.size() > 0) {
            file = files.get(0).getAsJsonObject();
        }
        if (file == null) {
            return null;
        }
        Candidate c = new Candidate();
        c.url = str(file, "url");
        c.source = "modrinth:" + slug + " " + str(best, "version_number");
        JsonObject hashes = file.has("hashes") ? file.getAsJsonObject("hashes") : null;
        if (hashes != null && hashes.has("sha512")) {
            c.sha512 = hashes.get("sha512").getAsString();
        }
        return c.url == null ? null : c;
    }

    private boolean loaderOk(JsonObject v) {
        JsonArray l = v.getAsJsonArray("loaders");
        if (l == null) {
            return false;
        }
        for (JsonElement e : l) {
            String s = e.getAsString().toLowerCase(Locale.ROOT);
            if (s.equals("paper") || s.equals("spigot") || s.equals("bukkit") || s.equals("purpur") || s.equals("folia")) {
                return true;
            }
        }
        return false;
    }

    private boolean gameOk(JsonObject v, String gv) {
        if (gv == null || gv.isBlank()) {
            return true;
        }
        JsonArray g = v.getAsJsonArray("game_versions");
        if (g == null) {
            return false;
        }
        String major = gv.replaceAll("^(\\d+\\.\\d+).*", "$1");
        for (JsonElement e : g) {
            String s = e.getAsString();
            if (s.equals(gv) || s.equals(major)) {
                return true;
            }
        }
        return false;
    }

    private Candidate github(String repo) throws Exception {
        JsonObject rel = getJson("https://api.github.com/repos/" + repo + "/releases/latest").getAsJsonObject();
        JsonArray assets = rel.getAsJsonArray("assets");
        if (assets != null) {
            for (JsonElement ae : assets) {
                JsonObject a = ae.getAsJsonObject();
                String n = str(a, "name");
                if (n != null && n.toLowerCase(Locale.ROOT).endsWith(".jar")) {
                    Candidate c = new Candidate();
                    c.url = str(a, "browser_download_url");
                    c.source = "github:" + repo;
                    return c;
                }
            }
        }
        return null;
    }

    private JsonElement getJson(String url) throws Exception {
        HttpRequest req = HttpRequest.newBuilder(URI.create(url))
                .header("User-Agent", UA).header("Accept", "application/json")
                .timeout(Duration.ofSeconds(20)).GET().build();
        HttpResponse<String> resp = http.send(req, HttpResponse.BodyHandlers.ofString());
        if (resp.statusCode() / 100 != 2) {
            throw new IOException("HTTP " + resp.statusCode() + " for " + url);
        }
        return JsonParser.parseString(resp.body());
    }

    private boolean download(String url, File dest) {
        try {
            HttpRequest req = HttpRequest.newBuilder(URI.create(url))
                    .header("User-Agent", UA).timeout(Duration.ofSeconds(90)).GET().build();
            HttpResponse<Path> resp = http.send(req, HttpResponse.BodyHandlers.ofFile(dest.toPath()));
            return resp.statusCode() / 100 == 2 && dest.length() > 0;
        } catch (Exception ex) {
            return false;
        }
    }

    private static String str(JsonObject o, String k) {
        return o.has(k) && !o.get(k).isJsonNull() ? o.get(k).getAsString() : null;
    }

    private static String sha(File f, String algo) {
        try (InputStream in = new BufferedInputStream(new FileInputStream(f))) {
            MessageDigest md = MessageDigest.getInstance(algo);
            byte[] buf = new byte[8192];
            int n;
            while ((n = in.read(buf)) > 0) {
                md.update(buf, 0, n);
            }
            StringBuilder sb = new StringBuilder();
            for (byte b : md.digest()) {
                sb.append(Character.forDigit((b >> 4) & 0xF, 16)).append(Character.forDigit(b & 0xF, 16));
            }
            return sb.toString();
        } catch (Exception ex) {
            return null;
        }
    }
}
