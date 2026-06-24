package com.fizz.gtest;

import org.bukkit.Bukkit;
import org.bukkit.ChatColor;
import org.bukkit.command.Command;
import org.bukkit.command.CommandExecutor;
import org.bukkit.command.CommandSender;
import org.bukkit.event.EventHandler;
import org.bukkit.event.Listener;
import org.bukkit.event.player.PlayerJoinEvent;
import org.bukkit.plugin.java.JavaPlugin;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.StandardOpenOption;
import java.security.MessageDigest;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

/**
 * GuardioTester — a 100% HARMLESS test harness for Guardio. It performs no malicious action: it never opens a
 * network connection, never executes a command, never loads code. On request it writes small INERT jars (just
 * ZIP files containing marker strings / flagged package names) into {@code plugins/} so you can watch Guardio
 * detect each layer, and it registers a listener + a ticking task so you can verify {@code /guardio reload}
 * doesn't double-register.
 *
 * <p>The malware markers ("pluginstatstrack", the backdoor-API token list) are stored Base64-encoded and only
 * decoded when writing a decoy, so this plugin's own classes stay clean and Guardio won't flag the tester.</p>
 */
public final class GuardioTester extends JavaPlugin implements CommandExecutor, Listener {

    // Base64 so these strings are NOT literally present in this plugin's bytecode (else Guardio would flag us).
    private static final String B64_C2 = "cGx1Z2luc3RhdHN0cmFjaw=="; // "pluginstatstrack"
    private static final String B64_BAIT =
            "R3VhcmRpbyBoZXVyaXN0aWMgdGVzdCBiYWl0IChoYXJtbGVzcykuIHJlZnM6IGphdmEvbGFuZy9pbnZva2UvTWV0aG9kSGFuZ"
          + "GxlcyBkZWZpbmVDbGFzcyBqYXZhL25ldC9VUkxDbGFzc0xvYWRlciBqYXZhL25ldC9VUkwgb3BlblN0cmVhbSBqYXZhL2xhbm"
          + "cvUnVudGltZSBleGVjIGphdmEvbGFuZy9Qcm9jZXNzQnVpbGRlcg==";

    @Override
    public void onEnable() {
        if (getCommand("gtest") != null) {
            getCommand("gtest").setExecutor(this);
        }
        getServer().getPluginManager().registerEvents(this, this);
        getLogger().info("HARMLESS Guardio test harness active (instance=" + System.identityHashCode(this)
                + "). It does NOTHING malicious. Use /gtest help.");
        // Ticking task tagged with this instance id — for verifying /guardio reload (old task must stop; a
        // reloaded instance gets a new id; you should only ever see ONE id ticking).
        Bukkit.getScheduler().runTaskTimer(this,
                () -> getLogger().info("GT-TICK instance=" + System.identityHashCode(this)), 100L, 100L); // every 5s
    }

    @Override
    public void onDisable() {
        getLogger().info("GuardioTester disabled (instance=" + System.identityHashCode(this) + ").");
    }

    @EventHandler
    public void onJoin(PlayerJoinEvent e) {
        getLogger().info("GT listener fired for " + e.getPlayer().getName() + " (instance="
                + System.identityHashCode(this) + ")");
    }

    @Override
    public boolean onCommand(CommandSender s, Command cmd, String label, String[] args) {
        String sub = args.length > 0 ? args[0].toLowerCase(Locale.ROOT) : "help";
        try {
            switch (sub) {
                case "signature" -> makeSignature(s);
                case "heuristic" -> makeHeuristic(s);
                case "feedtest" -> makeFeedTest(s);
                case "tamper" -> tamper(s);
                case "hash" -> hash(s, args);
                case "id" -> reply(s, "&bGuardioTester instance id: &f" + System.identityHashCode(this)
                        + " &7— run &f/guardio reload GuardioTester&7, then /gtest id again: the id should change "
                        + "and only ONE 'GT-TICK' id should keep logging (no double).");
                case "clean" -> clean(s);
                default -> help(s);
            }
        } catch (Exception ex) {
            reply(s, "&cError: " + ex.getMessage());
        }
        return true;
    }

    private void help(CommandSender s) {
        reply(s, "&b== GuardioTester &7(harmless — generates decoys to test Guardio) &b==");
        reply(s, "&f/gtest signature &7- jar that trips signature detection (entry + content) -> quarantined");
        reply(s, "&f/gtest heuristic &7- jar that trips the report-only heuristic scan (NOT quarantined)");
        reply(s, "&f/gtest feedtest &7- clean jar + adds its hash to the threat feed -> quarantined by hash (after restart)");
        reply(s, "&f/gtest tamper &7- integrity test: trust it, then re-run to modify it -> restored from vault");
        reply(s, "&f/gtest hash <jar> &7- print a jar's SHA-256");
        reply(s, "&f/gtest id &7- show instance id (verify /guardio reload doesn't double-register)");
        reply(s, "&f/gtest clean &7- delete the gtest-*.jar decoys this plugin made");
        reply(s, "&7After signature/heuristic/feedtest: run &f/guardio scan&7 (or restart) to watch Guardio react.");
    }

    private void makeSignature(CommandSender s) throws Exception {
        Map<String, byte[]> e = new LinkedHashMap<>();
        e.put("javassist/ws/Marker.class", bytes("FAKE - Guardio test bait, not real malware"));
        e.put("javassist/orgs/java_websocket/Stub.class", bytes("FAKE - Guardio test bait"));
        e.put("payload.class", bytes("FAKE harmless Guardio test. content marker: " + dec(B64_C2)
                + " [NOT a real address]"));
        File f = writeJar("gtest-signature-malware.jar", e);
        reply(s, "&aWrote &f" + f.getName() + "&a (entry-sig javassist/ws + javassist/orgs, content-sig marker).");
        reply(s, "&7Run &f/guardio scan&7 — it should report INFECTED and quarantine it on restart.");
    }

    private void makeHeuristic(CommandSender s) throws Exception {
        Map<String, byte[]> e = new LinkedHashMap<>();
        e.put("bait.class", bytes(dec(B64_BAIT))); // contains defineClass + URLClassLoader + Runtime/exec tokens
        File f = writeJar("gtest-suspicious.jar", e);
        reply(s, "&aWrote &f" + f.getName() + "&a (backdoor-API tokens, but inert).");
        reply(s, "&7Run &f/guardio scan&7 — it should log SUSPICIOUS (report-only) and LEAVE it in place.");
    }

    private void makeFeedTest(CommandSender s) throws Exception {
        Map<String, byte[]> e = new LinkedHashMap<>();
        e.put("clean.txt", bytes("harmless clean jar for Guardio threat-feed testing"));
        File f = writeJar("gtest-feedbait.jar", e);
        String sha = sha256(f);
        File feed = new File(guardHome(), "threat-feed.txt");
        feed.getParentFile().mkdirs();
        Files.writeString(feed.toPath(), sha + " gtest-feedbait (Guardio test)\n",
                StandardOpenOption.CREATE, StandardOpenOption.APPEND);
        reply(s, "&aWrote &f" + f.getName() + "&a (clean) and added its hash to &fguardio/threat-feed.txt&a.");
        reply(s, "&7SHA-256: &f" + sha);
        reply(s, "&7RESTART the server — Guardio reloads the feed at boot and quarantines it by hash (even though it's clean).");
    }

    private void tamper(CommandSender s) throws Exception {
        File f = new File(pluginsDir(), "gtest-tamper.jar");
        if (!f.isFile()) {
            Map<String, byte[]> e = new LinkedHashMap<>();
            e.put("clean.txt", bytes("clean integrity-test jar"));
            writeJar("gtest-tamper.jar", e);
            reply(s, "&aWrote &fgtest-tamper.jar&a (clean).");
            reply(s, "&71) &f/guardio trust gtest-tamper.jar&7  2) &f/gtest tamper&7 again to modify it  3) &f/guardio scan&7");
        } else {
            Files.writeString(f.toPath(), "\nGUARDIO-TAMPER-TEST", StandardOpenOption.APPEND);
            reply(s, "&eModified &fgtest-tamper.jar&e (its hash now differs from the trusted copy).");
            reply(s, "&7Run &f/guardio scan&7 — it should detect the integrity mismatch and restore the vault copy.");
        }
    }

    private void hash(CommandSender s, String[] args) throws Exception {
        if (args.length < 2) {
            reply(s, "&cUsage: /gtest hash <jarName>");
            return;
        }
        File f = new File(pluginsDir(), args[1]);
        if (!f.isFile()) {
            reply(s, "&cNo such jar in plugins/: " + args[1]);
            return;
        }
        reply(s, "&7SHA-256 of &f" + args[1] + "&7: &f" + sha256(f));
    }

    private void clean(CommandSender s) {
        File[] fs = pluginsDir().listFiles((d, n) -> n.startsWith("gtest-") && n.endsWith(".jar"));
        int n = 0;
        if (fs != null) {
            for (File f : fs) {
                if (f.delete()) {
                    n++;
                }
            }
        }
        reply(s, "&aDeleted &f" + n + "&a gtest decoy jar(s). (Quarantined copies in guardio/quarantine/ stay.)");
    }

    // ---- helpers --------------------------------------------------------

    private File pluginsDir() {
        return getDataFolder().getParentFile(); // <root>/plugins
    }

    private File guardHome() {
        return new File(pluginsDir().getParentFile(), "guardio"); // <root>/guardio
    }

    private File writeJar(String name, Map<String, byte[]> entries) throws IOException {
        File dest = new File(pluginsDir(), name);
        try (ZipOutputStream z = new ZipOutputStream(new FileOutputStream(dest))) {
            for (Map.Entry<String, byte[]> e : entries.entrySet()) {
                z.putNextEntry(new ZipEntry(e.getKey()));
                z.write(e.getValue());
                z.closeEntry();
            }
        }
        return dest;
    }

    private static byte[] bytes(String s) {
        return s.getBytes(StandardCharsets.UTF_8);
    }

    private static String dec(String b64) {
        return new String(Base64.getDecoder().decode(b64), StandardCharsets.UTF_8);
    }

    private static String sha256(File f) throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        byte[] hash = md.digest(Files.readAllBytes(f.toPath()));
        StringBuilder sb = new StringBuilder(hash.length * 2);
        for (byte b : hash) {
            sb.append(Character.forDigit((b >> 4) & 0xF, 16)).append(Character.forDigit(b & 0xF, 16));
        }
        return sb.toString();
    }

    private void reply(CommandSender s, String legacy) {
        s.sendMessage(ChatColor.translateAlternateColorCodes('&', legacy));
    }
}
