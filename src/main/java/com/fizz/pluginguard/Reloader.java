package com.fizz.pluginguard;

import org.bukkit.Bukkit;
import org.bukkit.command.Command;
import org.bukkit.command.CommandMap;
import org.bukkit.command.PluginCommand;
import org.bukkit.event.HandlerList;
import org.bukkit.plugin.Plugin;
import org.bukkit.plugin.PluginManager;

import java.io.File;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.net.URLClassLoader;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.logging.Level;
import java.util.zip.ZipFile;

/**
 * Clean, quiet plugin reload. Unlike a naive disable/enable, it FORCE-tears-down everything Bukkit can track —
 * event listeners, scheduler tasks, commands, service providers, plugin-messaging channels — regardless of
 * whether the plugin's own {@code onDisable} did so. That kills the classic "it registers twice after a
 * reload" bug (which is almost always a leaked listener or task). It reloads ONLY the named plugin and warns
 * about dependents, and refuses Paper-style ({@code paper-plugin.yml}) plugins, whose new bootstrap can't be
 * safely reloaded at runtime.
 *
 * <p>Honest limit: registrations a plugin makes into ANOTHER plugin's private internals (with no unregister
 * and no cleanup in onDisable) can't be undone generically — those need that plugin's own reload. But the
 * forced Bukkit teardown covers the large majority of real double-registration cases.</p>
 */
final class Reloader {

    record Result(boolean ok, List<String> lines) {
    }

    private Reloader() {
    }

    static Result reload(Plugin self, String name) {
        List<String> out = new ArrayList<>();
        PluginManager pm = Bukkit.getPluginManager();
        Plugin target = pm.getPlugin(name);
        if (target == null) {
            return new Result(false, List.of("No loaded plugin named '" + name + "' (use the exact plugin name)."));
        }
        if (target == self) {
            return new Result(false, List.of("Refusing to reload Guardio itself."));
        }
        File file;
        try {
            file = getFile(target);
        } catch (Exception ex) {
            return new Result(false, List.of("Could not locate " + name + "'s jar: " + ex.getMessage()));
        }
        if (file == null || !file.isFile()) {
            return new Result(false, List.of("Could not find " + name + "'s jar on disk."));
        }
        if (isPaperPlugin(file)) {
            return new Result(false, List.of(name + " is a Paper-style plugin (paper-plugin.yml) — Paper's new "
                    + "plugin system can't be safely reloaded at runtime. Restart the server to reload it."));
        }

        List<String> dependents = dependentsOf(name);
        if (!dependents.isEmpty()) {
            out.add("note: depended on by " + String.join(", ", dependents) + " — they may need a reload/restart too.");
        }

        Level prev = target.getLogger().getLevel();
        try {
            target.getLogger().setLevel(Level.WARNING); // quiet the plugin's own INFO chatter during the cycle
            forcedTeardown(target, out);
            pm.disablePlugin(target);
            unload(target, out);

            Plugin loaded = loadPlugin(pm, file);
            if (loaded == null) {
                return new Result(false, append(out, "loadPlugin returned null — reload failed; restart the server."));
            }
            pm.enablePlugin(loaded);
            loaded.getLogger().setLevel(prev);
            out.add("reloaded " + loaded.getName() + " v" + loaded.getDescription().getVersion() + " cleanly.");
            return new Result(true, out);
        } catch (Throwable t) {
            return new Result(false, append(out, "reload error: " + t.getClass().getSimpleName()
                    + (t.getMessage() != null ? " - " + t.getMessage() : "") + " — restart the server to be safe."));
        }
    }

    private static void forcedTeardown(Plugin p, List<String> out) {
        try {
            HandlerList.unregisterAll(p);
        } catch (Throwable ignored) {
            // listeners
        }
        try {
            Bukkit.getScheduler().cancelTasks(p);
        } catch (Throwable ignored) {
            // tasks
        }
        try {
            Bukkit.getServicesManager().unregisterAll(p);
        } catch (Throwable ignored) {
            // service providers (economy/permissions/etc.)
        }
        try {
            Bukkit.getMessenger().unregisterIncomingPluginChannel(p);
            Bukkit.getMessenger().unregisterOutgoingPluginChannel(p);
        } catch (Throwable ignored) {
            // plugin messaging channels
        }
        try {
            removeCommands(p);
        } catch (Throwable ignored) {
            // commands
        }
        out.add("forced teardown: listeners, tasks, services, channels, commands cleared.");
    }

    private static void removeCommands(Plugin plugin) throws Exception {
        CommandMap map = Bukkit.getServer().getCommandMap();
        Field kf = findField(map.getClass(), "knownCommands");
        if (kf == null) {
            return;
        }
        kf.setAccessible(true);
        @SuppressWarnings("unchecked")
        Map<String, Command> known = (Map<String, Command>) kf.get(map);
        Iterator<Map.Entry<String, Command>> it = known.entrySet().iterator();
        while (it.hasNext()) {
            Command cmd = it.next().getValue();
            if (cmd instanceof PluginCommand pc && pc.getPlugin() == plugin) {
                cmd.unregister(map);
                it.remove();
            }
        }
    }

    /** On Paper, load via PaperPluginInstanceManager.loadPlugin(Path) — the Bukkit-interface loadPlugin(File)
     *  routes through provider storage and fails at runtime ("didn't load any plugin providers"). */
    private static Plugin loadPlugin(PluginManager pm, File file) throws Exception {
        Object im = instanceManager(pm);
        if (im != null) {
            Method m = findMethod(im.getClass(), "loadPlugin", Path.class);
            if (m != null) {
                m.setAccessible(true);
                return (Plugin) m.invoke(im, file.toPath());
            }
        }
        return pm.loadPlugin(file); // SimplePluginManager (older / non-Paper)
    }

    /** The real PaperPluginInstanceManager (holds the live plugin lists + the working runtime loadPlugin(Path)).
     *  Bukkit.getPluginManager() is a compat SimplePluginManager whose loadPlugin(File) fails at runtime; the
     *  real one is CraftServer.paperPluginManager.instanceManager. */
    private static Object instanceManager(PluginManager pm) {
        Object im = tryField(pm, "instanceManager"); // if pm is already PaperPluginManagerImpl
        if (im != null) {
            return im;
        }
        Object paperMgr = tryField(Bukkit.getServer(), "paperPluginManager"); // CraftServer public field
        if (paperMgr != null) {
            return tryField(paperMgr, "instanceManager");
        }
        return null;
    }

    private static Object tryField(Object obj, String name) {
        try {
            Field f = findField(obj.getClass(), name);
            if (f != null) {
                f.setAccessible(true);
                return f.get(obj);
            }
        } catch (Throwable ignored) {
            // absent on this server type
        }
        return null;
    }

    /** Removes the plugin from the manager's lists (Paper instanceManager or SimplePluginManager) + closes its CL. */
    private static void unload(Plugin plugin, List<String> out) throws Exception {
        PluginManager pm = Bukkit.getPluginManager();
        Object holder = instanceManager(pm);
        if (holder == null) {
            holder = pm;
        }
        removeFrom(holder, "plugins", plugin);
        removeFrom(holder, "lookupNames", plugin);

        ClassLoader cl = plugin.getClass().getClassLoader();
        if (cl instanceof URLClassLoader u) {
            nullField(cl, "plugin");      // break PluginClassLoader -> plugin back-refs to help GC
            nullField(cl, "pluginInit");
            u.close();                    // release the jar lock + free classes
        }
        out.add("unloaded " + plugin.getName() + " (removed from manager, classloader closed).");
    }

    /** Removes {@code plugin} from a List field, or from a Map field by value. */
    private static void removeFrom(Object holder, String field, Plugin plugin) {
        try {
            Field f = findField(holder.getClass(), field);
            if (f == null) {
                return;
            }
            f.setAccessible(true);
            Object v = f.get(holder);
            if (v instanceof List<?> list) {
                list.removeIf(o -> o == plugin);
            } else if (v instanceof Map<?, ?> map) {
                map.values().removeIf(o -> o == plugin);
            }
        } catch (Throwable ignored) {
            // best effort
        }
    }

    private static void nullField(Object obj, String field) {
        try {
            Field f = findField(obj.getClass(), field);
            if (f != null) {
                f.setAccessible(true);
                f.set(obj, null);
            }
        } catch (Throwable ignored) {
            // best effort
        }
    }

    private static File getFile(Plugin p) throws Exception {
        Method m = null;
        Class<?> c = p.getClass();
        while (c != null && m == null) {
            try {
                m = c.getDeclaredMethod("getFile");
            } catch (NoSuchMethodException e) {
                c = c.getSuperclass();
            }
        }
        if (m == null) {
            return null;
        }
        m.setAccessible(true);
        return (File) m.invoke(p);
    }

    private static boolean isPaperPlugin(File jar) {
        try (ZipFile z = new ZipFile(jar)) {
            return z.getEntry("paper-plugin.yml") != null && z.getEntry("plugin.yml") == null;
        } catch (Exception ex) {
            return false;
        }
    }

    private static List<String> dependentsOf(String name) {
        List<String> deps = new ArrayList<>();
        for (Plugin p : Bukkit.getPluginManager().getPlugins()) {
            if (p.getDescription().getDepend().contains(name) || p.getDescription().getSoftDepend().contains(name)) {
                deps.add(p.getName());
            }
        }
        return deps;
    }

    private static Field findField(Class<?> c, String name) {
        while (c != null) {
            try {
                return c.getDeclaredField(name);
            } catch (NoSuchFieldException e) {
                c = c.getSuperclass();
            }
        }
        return null;
    }

    private static Method findMethod(Class<?> c, String name, Class<?>... params) {
        while (c != null) {
            try {
                return c.getDeclaredMethod(name, params);
            } catch (NoSuchMethodException e) {
                c = c.getSuperclass();
            }
        }
        return null;
    }

    private static List<String> append(List<String> out, String line) {
        out.add(line);
        return out;
    }
}
