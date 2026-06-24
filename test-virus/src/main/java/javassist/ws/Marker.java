package javassist.ws;

/**
 * HARMLESS marker class. It exists ONLY so PluginGuard's scanner has something to detect:
 * <ul>
 *   <li>its package/path {@code javassist/ws/} matches an entry-signature, and</li>
 *   <li>the fake string below matches a content-signature.</li>
 * </ul>
 * There is deliberately NO real behaviour here — no {@code java.net}, no {@code Runtime}, no reflection,
 * no file access, no payload. It mimics the real malware's <i>fingerprint</i> only, never its actions.
 */
public final class Marker {

    /** A fake, C2-looking string used purely as detection bait. It is never used to connect anywhere. */
    public static final String FAKE_MARKER =
            "pluginstatstrack.xyz [FAKE - PluginGuard test bait, not a real address]";

    private Marker() {
    }
}
