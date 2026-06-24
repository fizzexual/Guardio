package com.fizz.pluginguard;

import org.bukkit.ChatColor;
import org.bukkit.configuration.file.FileConfiguration;
import org.bukkit.configuration.file.YamlConfiguration;

import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

/**
 * Loads {@code messages.yml} (recolorable + translatable). Every key falls back to the bundled default if the
 * user removed it. {@code get}/{@code list} apply {@code {placeholder}} substitution and translate '&' colours.
 */
final class Messages {

    private final FileConfiguration user;
    private final FileConfiguration defaults;

    Messages(FileConfiguration user, FileConfiguration defaults) {
        this.user = user;
        this.defaults = defaults;
    }

    /** Bundled defaults from the jar, so missing keys still resolve. */
    static FileConfiguration bundledDefaults(java.util.function.Function<String, InputStream> resource) {
        try (InputStream in = resource.apply("messages.yml")) {
            if (in != null) {
                return YamlConfiguration.loadConfiguration(new InputStreamReader(in, StandardCharsets.UTF_8));
            }
        } catch (Exception ignored) {
            // fall through
        }
        return new YamlConfiguration();
    }

    String prefix() {
        return color(raw("prefix", ""));
    }

    /** Colored, placeholder-filled single line (no prefix). kv = key1, val1, key2, val2, ... */
    String get(String key, Object... kv) {
        return color(fill(raw(key, "&c[missing: " + key + "]"), kv));
    }

    /** Filled but NOT color-translated — for Discord (markdown, no '&' codes). */
    String plain(String key, Object... kv) {
        return fill(raw(key, "[missing: " + key + "]"), kv);
    }

    List<String> list(String key, Object... kv) {
        List<String> lines = user.getStringList(key);
        if (lines.isEmpty()) {
            lines = defaults.getStringList(key);
        }
        List<String> out = new ArrayList<>(lines.size());
        for (String s : lines) {
            out.add(color(fill(s, kv)));
        }
        return out;
    }

    private String raw(String key, String fallback) {
        String v = user.getString(key);
        if (v == null) {
            v = defaults.getString(key);
        }
        return v != null ? v : fallback;
    }

    private static String fill(String s, Object... kv) {
        for (int i = 0; i + 1 < kv.length; i += 2) {
            s = s.replace("{" + kv[i] + "}", String.valueOf(kv[i + 1]));
        }
        return s;
    }

    private static String color(String s) {
        return ChatColor.translateAlternateColorCodes('&', s);
    }
}
