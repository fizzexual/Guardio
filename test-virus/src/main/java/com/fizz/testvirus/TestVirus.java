package com.fizz.testvirus;

import org.bukkit.plugin.java.JavaPlugin;

/**
 * A HARMLESS test plugin for verifying PluginGuard. It performs NO malicious action whatsoever — no network
 * calls, no file writes, no reflection, no class loading. Its only purpose is to carry a fake malware
 * signature (see {@link javassist.ws.Marker}) so PluginGuard detects and quarantines it during a test.
 *
 * <p>Expected behaviour:</p>
 * <ul>
 *   <li>With the agent enabled — this jar is quarantined <b>before</b> it loads, so {@code onEnable} below
 *       never even runs.</li>
 *   <li>As a plugin only — it loads and logs these warnings, and PluginGuard quarantines it on shutdown.</li>
 * </ul>
 */
public final class TestVirus extends JavaPlugin {

    @Override
    public void onEnable() {
        getLogger().warning("HARMLESS PluginGuard test plugin — it performs NO malicious action.");
        getLogger().warning("It only carries a FAKE signature so PluginGuard should detect & quarantine it.");
        getLogger().warning("Unused bait string: " + javassist.ws.Marker.FAKE_MARKER);
    }
}
