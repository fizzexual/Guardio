package com.fizz.pluginguard;

import java.io.File;
import java.io.IOException;
import java.nio.file.FileVisitResult;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.SimpleFileVisitor;
import java.nio.file.StandardWatchEventKinds;
import java.nio.file.WatchEvent;
import java.nio.file.WatchKey;
import java.nio.file.WatchService;
import java.nio.file.attribute.BasicFileAttributes;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.TimeUnit;

/**
 * Real-time filesystem watcher. Given a list of directories, it watches each one and all of its
 * subdirectories recursively (the JDK {@link WatchService} is intentionally NOT recursive, so this
 * class walks the tree and registers every directory itself, and registers any new subdirectory the
 * moment it is created). It fires the supplied callback when a {@code .jar} is created or modified so
 * PluginGuard can re-scan; deletes are ignored since a missing jar needs no heal.
 *
 * <p>Bursts are debounced: the first relevant event arms a ~2s window during which further events are
 * swallowed, then {@code onChange} runs ONCE at the end of that window. The callback runs on the single
 * daemon watcher thread, so the supplied {@link Runnable} is responsible for marshalling back onto the
 * main/Bukkit thread if it needs to.</p>
 *
 * <p>Pure JDK — no Bukkit, no external dependencies. {@link #start()} and {@link #stop()} are both
 * idempotent, and {@code stop()} is safe to call even if {@code start()} never ran.</p>
 */
final class FileWatcher {

    /** How long to keep coalescing events after the first one before firing the callback once. */
    private static final long DEBOUNCE_MS = 2000L;

    /** How long the loop blocks waiting for events before re-checking the running flag. */
    private static final long POLL_MS = 500L;

    private final List<File> dirs;
    private final Runnable onChange;

    // Maps each WatchKey back to the directory it watches, so newly-created dirs can be resolved
    // to absolute paths and registered. Touched only from the watcher thread.
    private final Map<WatchKey, Path> watched = new HashMap<>();

    private volatile boolean running;
    private WatchService service; // created in start(), closed in stop()
    private Thread thread;

    FileWatcher(List<File> dirs, Runnable onChange) {
        this.dirs = dirs;
        this.onChange = onChange;
    }

    /** Starts the single daemon watcher thread. Idempotent: a second call while running is a no-op. */
    synchronized void start() {
        if (running) {
            return;
        }
        if (dirs == null || dirs.isEmpty() || onChange == null) {
            return; // nothing to watch / nobody to notify
        }
        try {
            service = dirs.get(0).toPath().getFileSystem().newWatchService();
        } catch (IOException | RuntimeException ex) {
            service = null;
            return; // can't watch on this filesystem — give up quietly, plugin still works without live watching
        }

        running = true;
        thread = new Thread(this::runLoop, "Guardio-watcher");
        thread.setDaemon(true);
        thread.start();
    }

    /** Closes the WatchService and stops the thread. Idempotent and safe to call if never started. */
    synchronized void stop() {
        running = false;
        WatchService s = service;
        service = null;
        if (s != null) {
            try {
                s.close(); // unblocks the loop's poll() with a ClosedWatchServiceException
            } catch (IOException ignored) {
                // already closed / closing — nothing more to do
            }
        }
        Thread t = thread;
        thread = null;
        if (t != null) {
            t.interrupt(); // wake it if it's mid-poll or sleeping out a debounce window
        }
    }

    private void runLoop() {
        WatchService s = service;
        if (s == null) {
            return;
        }

        // Register the given roots and everything beneath them. A failure on one dir must not kill the watcher.
        for (File dir : dirs) {
            if (dir != null) {
                registerTree(dir.toPath());
            }
        }

        while (running) {
            WatchKey key;
            try {
                key = s.poll(POLL_MS, TimeUnit.MILLISECONDS);
            } catch (InterruptedException ie) {
                Thread.currentThread().interrupt();
                return; // stop() asked us to quit
            } catch (RuntimeException closed) {
                return; // ClosedWatchServiceException from stop() — done
            }
            if (key == null) {
                continue; // poll timed out; loop back and re-check running
            }

            boolean relevant = drainKey(key);

            // Re-queue the directory for future events; if it's gone, drop it.
            if (!key.reset()) {
                watched.remove(key);
            }

            if (relevant) {
                debounceThenFire(s);
            }
        }
    }

    /**
     * Processes all pending events on a key. Returns true if at least one was a {@code .jar} create/modify
     * (so the caller should fire after debouncing). Never throws — a single bad event must not kill the loop.
     */
    private boolean drainKey(WatchKey key) {
        Path dir = watched.get(key);
        boolean relevant = false;
        for (WatchEvent<?> event : key.pollEvents()) {
            try {
                WatchEvent.Kind<?> kind = event.kind();
                if (kind == StandardWatchEventKinds.OVERFLOW) {
                    relevant = true; // events were lost — force a re-scan to be safe
                    continue;
                }
                if (!(event.context() instanceof Path name)) {
                    continue;
                }
                Path child = dir != null ? dir.resolve(name) : name;

                // A freshly-created subdirectory must be registered so nested plugin folders are covered.
                if (kind == StandardWatchEventKinds.ENTRY_CREATE && Files.isDirectory(child)) {
                    registerTree(child);
                }

                // Only creates/modifies of .jar files trigger a heal; deletes are deliberately ignored.
                if ((kind == StandardWatchEventKinds.ENTRY_CREATE || kind == StandardWatchEventKinds.ENTRY_MODIFY)
                        && isJar(name)) {
                    relevant = true;
                }
            } catch (RuntimeException ignored) {
                // malformed event / transient FS error — skip it, keep watching
            }
        }
        return relevant;
    }

    /**
     * After a relevant event, keep draining (and discarding) further events for ~2s, then fire {@code onChange}
     * exactly once. New subdirectories seen during the window are still registered so we don't miss them.
     */
    private void debounceThenFire(WatchService s) {
        long deadline = System.currentTimeMillis() + DEBOUNCE_MS;
        while (running) {
            long remaining = deadline - System.currentTimeMillis();
            if (remaining <= 0) {
                break;
            }
            WatchKey key;
            try {
                key = s.poll(remaining, TimeUnit.MILLISECONDS);
            } catch (InterruptedException ie) {
                Thread.currentThread().interrupt();
                return; // stop() during the window — drop the pending fire
            } catch (RuntimeException closed) {
                return; // service closed
            }
            if (key == null) {
                break; // window elapsed with no further events
            }
            drainKey(key); // keep registering new dirs; the boolean is irrelevant, we're already firing
            if (!key.reset()) {
                watched.remove(key);
            }
        }

        if (running) {
            fire();
        }
    }

    private void fire() {
        try {
            onChange.run();
        } catch (RuntimeException ex) {
            // The callback misbehaved — never let it take down the watcher thread.
        }
    }

    /** Registers {@code root} and every existing subdirectory under it. Per-dir failures are swallowed. */
    private void registerTree(Path root) {
        if (root == null) {
            return;
        }
        try {
            Files.walkFileTree(root, new SimpleFileVisitor<>() {
                @Override
                public FileVisitResult preVisitDirectory(Path dir, BasicFileAttributes attrs) {
                    register(dir);
                    return FileVisitResult.CONTINUE;
                }

                @Override
                public FileVisitResult visitFileFailed(Path file, IOException exc) {
                    return FileVisitResult.CONTINUE; // unreadable entry — skip, keep walking
                }
            });
        } catch (IOException | RuntimeException ex) {
            register(root); // walk failed (e.g. root vanished mid-walk); still try the root itself
        }
    }

    /** Registers a single directory with the WatchService. A failure here must not propagate. */
    private void register(Path dir) {
        WatchService s = service;
        if (s == null || dir == null) {
            return;
        }
        try {
            WatchKey key = dir.register(s,
                    StandardWatchEventKinds.ENTRY_CREATE,
                    StandardWatchEventKinds.ENTRY_MODIFY,
                    StandardWatchEventKinds.ENTRY_DELETE); // observe deletes so reset() stays accurate, but don't fire on them
            watched.put(key, dir);
        } catch (IOException | RuntimeException ignored) {
            // not a dir, gone, or unsupported — skip this one, the rest of the tree is unaffected
        }
    }

    private static boolean isJar(Path name) {
        return name.toString().toLowerCase(Locale.ROOT).endsWith(".jar");
    }
}
