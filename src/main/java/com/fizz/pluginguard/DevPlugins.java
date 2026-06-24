package com.fizz.pluginguard;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

/**
 * Developer-mode plugin list. Jars the operator compiles and rebuilds themselves (set in
 * {@code guardio.properties} as {@code dev-plugins=Hyblock,HyData,BossForge}). When such a jar's hash changes,
 * Guardio updates its trusted baseline (re-maps) instead of treating the change as tampering — so a developer
 * can iterate on their own plugins while Guardio stays fully armed against everything else.
 *
 * <p><b>Safety:</b> this only suppresses the L1 integrity verdict (hash-changed-from-baseline). The malware
 * layers (signature, threat-feed) still run; a dev-plugin that actually trips one is still quarantined, because
 * that means the build itself got infected. Only list jars you build yourself: a name on this list means Guardio
 * trusts ANY change to a jar matching it, including a malicious swap that carries no known signature.</p>
 */
final class DevPlugins {

    private DevPlugins() {
    }

    /** Parses a comma-separated list of case-insensitive jar-name fragments. */
    static List<String> parse(String csv) {
        List<String> out = new ArrayList<>();
        if (csv != null) {
            for (String part : csv.split(",")) {
                String t = part.trim().toLowerCase(Locale.ROOT);
                if (!t.isEmpty()) {
                    out.add(t);
                }
            }
        }
        return out;
    }

    /** True if {@code jarName} contains any configured fragment. */
    static boolean matches(String jarName, List<String> fragments) {
        if (jarName == null || fragments == null || fragments.isEmpty()) {
            return false;
        }
        String n = jarName.toLowerCase(Locale.ROOT);
        for (String f : fragments) {
            if (n.contains(f)) {
                return true;
            }
        }
        return false;
    }
}
