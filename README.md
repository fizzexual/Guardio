# Guardio (PluginGuard)

A whole‑server integrity guard / anti‑tamper plugin for Paper/Purpur (1.21). One jar that detects, quarantines,
and **auto‑heals** infected/tampered server jars — built after a self‑spreading plugin‑jar infector
(`pluginstatstrack` C2, shaded `javassist/orgs` + `javassist/ws`, a `…L10` loader) hit a real server.

> **It guards a clean baseline.** It is **not** a cure for an already‑compromised *host* — OS‑level
> persistence, stolen credentials, or a trojaned OS/server are outside any plugin's reach. Clean the host and
> rotate credentials too.

One jar, three modes: **launcher** (`java -jar`), **agent** (`-javaagent`), and **plugin** (in `plugins/`).

## What it does
- **Launcher** (`java -jar Guardio.jar`) — the strongest mode. Runs *before* the server as the parent process,
  so it can clean and **heal the whole tree including the server jar itself** (download a clean copy from the
  official Purpur/Paper URL when it's infected, modified, or missing), then launches + supervises the server as
  a subprocess (with the agent + plugin active inside). Because it runs before any plugin, the infector never
  executes during a guarded boot, so it can't tamper with Guardio mid‑run; it also self‑hash‑checks each start.
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

## Install

**Recommended — launcher mode** (guards the whole server, incl. the server jar):
1. Put `PluginGuard-1.0.0.jar` in `plugins/`.
2. Start the server through it: `java -jar plugins/PluginGuard-1.0.0.jar`
3. First run auto‑creates `guardio.properties` (server jar, the official download URL, heap, restart flag).
   It then scans/heals the tree and launches + supervises the server. Do the first run on a **clean** install
   so the baseline is clean.

**Or agent‑only mode** (guards plugins + libraries, detects the server jar but can't heal it live):
```
java -Xmx4G -javaagent:plugins/PluginGuard-1.0.0.jar -jar paper.jar nogui
```

Either way, after the first clean boot the vault baseline is set (auto‑map handles new clean jars; `/guard
trust all` forces it).

## Commands (`pluginguard.admin` / op)
- `/guard scan` — rescan now + report
- `/guard status` — vault size, last scan, staged fixes
- `/guard trust [all|<jar>]` — (re)map clean jar(s) as the trusted baseline
- `/guard restore <jar>` — restore a jar from the vault
- `/guard allow <jar>` — whitelist a false positive
- `/guard heal` — download clean replacements for quarantined plugins

## Config
`config.yml` — scan roots, signatures, auto‑map/quarantine/restore/download, whitelist, shutdown‑on‑infection.
`sources.yml` — download overrides (`modrinth:<slug>` / `url:<jar>` / `github:<owner/repo>`).

## Testing
`test-virus/` is a **harmless** test plugin: it carries a fake signature (a benign `javassist.ws.Marker`
class) so PluginGuard flags and quarantines it — it performs no malicious action. Build it and drop it in
`plugins/` to see the guard work.
