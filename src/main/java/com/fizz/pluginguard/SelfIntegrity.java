package com.fizz.pluginguard;

import java.io.File;
import java.nio.file.Files;

/**
 * Self-tamper detection. Records this jar's SHA-256 on the first (clean) run in {@code guardio/guardio.self}
 * and verifies it on every run from all three layers (launcher, agent, plugin). If the {@code pluginstatstrack}
 * -style infector injects classes into Guardio's own jar, the bytes change and this trips.
 *
 * <p><b>Honest scope:</b> this stops the AUTOMATED malware this plugin fights (it injects into jars
 * indiscriminately and won't re-baseline Guardio's record). It does NOT stop a targeted human who controls the
 * box and can simply patch the check out — no self-check can. Mode {@code self-protect}: {@code off|warn|refuse}.
 * On a legitimate update the jar hash changes too; in {@code refuse} mode delete {@code guardio.self} to accept
 * the new build (in {@code warn} mode it re-baselines automatically with a one-time notice).</p>
 */
final class SelfIntegrity {

    enum Status { OK, FIRST_RUN, TAMPERED, UNKNOWN }

    private SelfIntegrity() {
    }

    /** The jar these classes were loaded from (the launcher's root jar, or the in-server plugin copy). */
    static File ownJar() {
        try {
            return new File(SelfIntegrity.class.getProtectionDomain().getCodeSource().getLocation().toURI());
        } catch (Exception ex) {
            return null;
        }
    }

    /** Verifies this jar against the recorded baseline. {@code record}=true establishes it on first run. */
    static Status check(File guardHome, boolean record) {
        File self = ownJar();
        if (self == null || !self.isFile()) {
            return Status.UNKNOWN;
        }
        String h = Hashing.sha256(self);
        if (h == null) {
            return Status.UNKNOWN;
        }
        File base = new File(guardHome, "guardio.self");
        try {
            if (!base.isFile()) {
                if (record) {
                    guardHome.mkdirs();
                    Files.writeString(base.toPath(), h);
                }
                return Status.FIRST_RUN;
            }
            return h.equals(Files.readString(base.toPath()).trim()) ? Status.OK : Status.TAMPERED;
        } catch (Exception ex) {
            return Status.UNKNOWN;
        }
    }

    /** Re-records the baseline to the current jar (used in warn/off mode after an accepted change). */
    static void rebaseline(File guardHome) {
        File self = ownJar();
        if (self == null) {
            return;
        }
        String h = Hashing.sha256(self);
        if (h == null) {
            return;
        }
        try {
            guardHome.mkdirs();
            Files.writeString(new File(guardHome, "guardio.self").toPath(), h);
        } catch (Exception ignored) {
            // best effort
        }
    }
}
