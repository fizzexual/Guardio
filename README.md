# Guardio (PluginGuard)

A whole‑server integrity guard / anti‑tamper plugin for Paper/Purpur (1.21). One jar that detects, quarantines,
and **auto‑heals** infected/tampered server jars — built after a self‑spreading plugin‑jar infector
(`pluginstatstrack` C2, shaded `javassist/orgs` + `javassist/ws`, a `…L10` loader) hit a real server.

> **It guards a clean baseline.** It is **not** a cure for an already‑compromised *host* — OS‑level
> persistence, stolen credentials, or a trojaned OS/server are outside any plugin's reach. Clean the host and
> rotate credentials too.

## What it does
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
1. Drop `PluginGuard-1.0.0.jar` in `plugins/`.
2. Add the agent to your start command, before `-jar`:
   ```
   java -Xmx4G -javaagent:plugins/PluginGuard-1.0.0.jar -jar paper.jar nogui
   ```
3. Start once on a **clean** install, then `/guard trust all` to lock in the baseline (auto‑map does this for
   new clean jars too).

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
