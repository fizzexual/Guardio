# Guardio (PluginGuard)

A whole‑server integrity guard / anti‑tamper plugin for Paper/Purpur (1.21). One jar that detects, quarantines,
and **auto‑heals** infected/tampered server jars — built after a self‑spreading plugin‑jar infector
(`pluginstatstrack` C2, shaded `javassist/orgs` + `javassist/ws`, a `…L10` loader) hit a real server.

> **It guards a clean baseline.** It is **not** a cure for an already‑compromised *host* — OS‑level
> persistence, stolen credentials, or a trojaned OS/server are outside any plugin's reach. Clean the host and
> rotate credentials too.

One jar, three modes: **launcher** (`java -jar`), **agent** (`-javaagent`), and **plugin** (in `plugins/`).

## What it does
- **Launcher** (`java -jar guardio-v1.0.0.jar`) — the strongest mode, and **host‑agnostic**: make Guardio the jar your
  host launches and it runs *before* the server, so it can clean and **heal the whole tree including the server
  jar itself** (download a clean copy from the official Purpur/Paper URL when it's infected, modified, or
  missing), then runs the real server. It **forwards the host's own JVM flags + program args** (heap, GC,
  `nogui`, …) and passes the console/stop through, so it drops into any panel (Pterodactyl, Multicraft, …) or
  start script unchanged. Two ways to run the server (`launch-mode`): **in‑process** (same JVM — zero extra RAM,
  one process; best for memory‑capped panels) with automatic fallback to a **subprocess** (separate JVM —
  rock‑solid for any server software) if the server doesn't cooperate. Because it runs before any plugin, the
  infector never executes during a guarded boot, so it can't tamper with Guardio mid‑run; it self‑hash‑checks
  each start.
- **Pre‑load agent** (`-javaagent`) — runs in `premain`, before any plugin loads, so jars are unlocked. This is
  the only true "before everything" hook (a `plugin.yml` can't guarantee it).
- **Whole‑server scope** — the top‑level server jar + every jar under configurable roots (default `plugins` +
  `libraries`, recursive).
- **Two detection layers** — **integrity** (SHA‑256 vs a trusted, path‑mirrored `vault/`) and **signature**
  (malware‑specific fingerprints only, to avoid false positives on legit plugins).
- **Map‑then‑load** — a new clean jar is *mapped* into the vault as its baseline; a mapped jar that changed is
  quarantined and the safe copy is restored. An infected jar that can't be removed (the running server jar)
  makes the agent **refuse to start**.
- **Auto‑heal** — when an infected plugin has no vault copy, it downloads a **clean** replacement from a free
  source (Modrinth, or a `sources.yml` override), **verified twice** (source SHA‑512 + a re‑scan) before use.
  Premium/private plugins can't be auto‑fetched and are flagged for manual reinstall.

## Layout
Guardio owns a clean, self-contained tree:
```
<server root>/
├── guardio-v1.0.0.jar          ← the launcher you run
├── guardio/                    ← Guardio's home
│   ├── serverjar/<server>.jar  ← the real server jar lives here
│   ├── vault/  quarantine/
│   └── guardio.properties, config.yml, sources.yml, reports
└── plugins/  libraries/  world/  …   ← plugins/ also gets a synced Guardio copy (the in-server layer)
```

## Install

**Recommended — launcher mode** (guards the whole server, incl. the server jar):
1. Put `guardio-v1.0.0.jar` in the server root, and your server jar in the root too (Guardio moves it into
   `guardio/serverjar/`), or place it directly in `guardio/serverjar/`.
2. Run it: `java -Xmx4G -jar guardio-v1.0.0.jar`  (put `-Xmx`/flags on the Guardio command — it forwards them).
3. First run creates `guardio/` (config + vault), moves the server jar into `guardio/serverjar/`, drops a synced
   plugin copy in `plugins/`, scans/heals the whole tree, then launches + supervises the server. Do the first
   run on a **clean** install so the baseline is clean.

**On a hosting panel (Pterodactyl, Multicraft, shared hosts, …):** point the panel at `guardio-v1.0.0.jar`
(rename it to whatever jar the panel runs — often `server.jar` — or set the panel's jar/startup field). Guardio
finds the real server jar in `guardio/serverjar/` (auto-detecting + moving one if needed) and runs it, forwarding
the panel's `-Xmx`/flags + console. `launch-mode=in-process` keeps it to a single process for hard memory caps.

**Or agent‑only mode** (no launcher; guards plugins + libraries, detects the server jar but can't heal it live):
```
java -Xmx4G -javaagent:guardio-v1.0.0.jar -jar guardio/serverjar/<server>.jar nogui
```

After the first clean boot the vault baseline is set (auto‑map handles new clean jars; `/guard trust all` forces it).

## Commands (`guardio.admin` / op)
- `/guard scan` — rescan now + report
- `/guard status` — vault size, last scan, staged fixes
- `/guard trust [all|<jar>]` — (re)map clean jar(s) as the trusted baseline
- `/guard restore <jar>` — restore a jar from the vault
- `/guard allow <jar>` — whitelist a false positive
- `/guard heal` — download clean replacements for quarantined plugins

## Config
`guardio/guardio.properties` (launcher, auto‑created) — `server-jar` (path under `guardio/serverjar/`),
`server-jar-url`, `launch-mode` (`auto`/`in-process`/`subprocess`), `java-args`/`server-args` (fallback only —
the host's own flags are forwarded), `use-agent`, `restart-on-crash`, `restart-flag`, `scan-roots`.
`guardio/config.yml` (plugin) — scan roots, signatures, auto‑map/quarantine/restore/download, whitelist, shutdown‑on‑infection.
`guardio/sources.yml` (plugin) — download overrides (`modrinth:<slug>` / `url:<jar>` / `github:<owner/repo>`).

## Testing
`test-virus/` is a **harmless** test plugin: it carries a fake signature (a benign `javassist.ws.Marker`
class) so PluginGuard flags and quarantines it — it performs no malicious action. Build it and drop it in
`plugins/` to see the guard work.
