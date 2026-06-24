# Guardio — marketplace listing

> Paste into BuiltByBit / Polymart / SpigotMC (their editors take Markdown or BBCode — headings, bullets and
> the table below convert cleanly). Everything here is accurate to the current build; don't add claims beyond it.

---

## Tagline (pick one)
- **Guardio — your server's immune system. Blocks malware, heals infected plugins, and reloads cleanly — before they ever load.**
- **The all‑in‑one server guardian: pre‑load malware blocking, auto‑healing, and a clean plugin reload.**

---

## Short description (the "summary" field)
Guardio is a whole‑server integrity guard that detects, quarantines, and **auto‑heals** tampered or
malware‑infected plugin/library/server jars — and reloads plugins cleanly without the double‑registration
bugs of the usual reload tools. One jar, runs before your server even loads.

---

## Full description

### Why Guardio exists
Guardio was built after a real, self‑spreading plugin‑jar infector (the `pluginstatstrack` family — ~154
injected classes per jar, a hidden WebSocket C2, a runtime class stager) tore through a live network via cracked
plugins. Antivirus scans the wrong layer and after the fact; Guardio guards the **right** layer — every jar,
**before** it loads, **every boot** — and then fixes what it finds.

### What it does
- **🛡 Pre‑load protection.** Guardio runs *before* the server and its plugins, as the launcher and a pre‑load
  agent — so an infected jar is caught before a single class of it executes.
- **🔬 Four‑layer detection.** Integrity (SHA‑256 vs a trusted, path‑mirrored vault) · malware signatures ·
  a known‑malware **hash feed** (catches a payload even when renamed) · report‑only **heuristics** that flag
  backdoor behaviour (runtime class definition, remote class loading, `Runtime.exec`).
- **💉 Auto‑heal.** When an infected plugin has no clean baseline, Guardio downloads a **clean replacement**
  from a free source (Modrinth) or your own `trusted/` backups — **verified twice** (publisher SHA‑512 + a full
  re‑scan) before it's installed. It even **heals the server jar itself** from the official Purpur/Paper source.
- **🧹 Cracked/nulled‑plugin detection.** Flags the leaked/cracked builds that are the #1 infection vector.
- **👀 Real‑time watcher.** Re‑scans the instant a jar appears or changes — not just on a timer.
- **🪤 Honeypots.** Canary files that alert the moment something tampers with them.
- **🔁 Clean plugin reload.** `/guardio reload <plugin>` force‑tears‑down the plugin's listeners, tasks,
  commands, services and channels first — so it can't double‑register ("it fires twice now") like naïve
  disable/enable reloaders.
- **🔔 Discord alerts.** Rich embeds with role pings on quarantine / restore / heal / suspicion / changes.
- **🩺 `/guardio doctor`.** One command tells you exactly whether you're protected.
- **🧰 Operator niceties.** Startup change report, HTML security report, a token‑auth download endpoint to pull
  files off a headless host, a safe‑mode boot (load only verified plugins after an incident), tab‑completion,
  an update checker, and a fully translatable `messages.yml`.

### How it works (the short version)
One self‑contained jar exposes **three layers** — a process **launcher** (guards + heals before the JVM even
opens the server jar), a **pre‑load agent** (guards before any plugin classloads), and an in‑server **plugin**
(runtime re‑scans + the `/guardio` control plane). Together they guard your server tree at three checkpoints
on every boot. Zero runtime dependencies beyond the JDK.

---

## Comparison

| | **Guardio** | PlugMan‑style reloaders | Generic AV / jar scanners |
|---|:--:|:--:|:--:|
| Detects infected plugin jars | ✅ | ❌ | ✅ |
| Runs **before** plugins load (pre‑load) | ✅ | ❌ | ❌ |
| **Auto‑heals** (downloads a clean copy) | ✅ | ❌ | ❌ |
| Heals the **server jar** itself | ✅ | ❌ | ❌ |
| Known‑malware **hash feed** | ✅ | ❌ | ⚠ varies |
| Clean reload (no double‑registration) | ✅ | ⚠ partial | ❌ |
| Real‑time file watcher | ✅ | ❌ | ⚠ varies |
| Discord alerts | ✅ | ❌ | ❌ |
| One jar, no dependencies | ✅ | ✅ | ⚠ varies |

---

## Compatibility
- **Paper‑family servers** — Paper, Purpur, Folia and forks, **1.21+**. (Built on the Paper API; uses
  Paper‑only hooks, so pure Spigot/Bukkit isn't supported.)
- **Java 21+.**
- Tested on **Purpur 1.21.11 / JDK 21**.

## Quick start
1. Drop `guardio-v1.0.0.jar` in your server folder; put your server jar there too.
2. Start it — **double‑click the jar**, or `java -Xmx4G -jar guardio-v1.0.0.jar`, or point your panel's startup jar at it.
3. First boot sets up `guardio/`, baselines your (clean) install, and guards every boot after.

## Requirements / honest notes (please read before buying)
- Guardio guards your **server tree**; it is **not** a host‑level antivirus. A compromised OS or stolen
  credentials need cleaning independently.
- **Premium** plugins can't be auto‑downloaded (no free source) — keep a clean copy in `guardio/trusted/` and
  Guardio restores from there.
- On **Paper 1.21+**, a reloaded plugin's *commands* may need one restart to fully re‑bind (its
  listeners/tasks/etc. reload cleanly).

---

## FAQ
**Does it lag my server?** Scans run off the main thread with an incremental hash cache — no TPS impact.
**Will it false‑flag my legit plugins?** Signatures are malware‑specific only; the heuristic + cracked layers
are **report‑only** (they never auto‑remove). A false positive is one `/guardio allow <jar>` away.
**Does it phone home?** No telemetry. It only contacts the sources you configure (Modrinth for healing, your
threat‑feed URL, your Discord webhook).
**What if it can't heal something?** It quarantines it and tells you exactly what + where, and flags it for
manual reinstall.

---

## Pricing (suggestion — your call)
A one‑jar security + utility plugin with auto‑heal, a pre‑load launcher, and a clean reloader sits comfortably
in the **~$10–20 one‑time** range on BuiltByBit/Polymart (compare: premium utility plugins $5–15, security/
anti‑malware offerings $10–25). Consider launching at the lower end with an intro discount to gather reviews,
then raising it. **Add a license check before listing** (else it's leaked day one).

---

## Screenshot / GIF shot list (what to capture)
1. **GIF — the catch:** drop an infected jar into `plugins/`, watcher fires, console shows `🛑 quarantined …`,
   server keeps running. (Use the bundled GuardioTester: `/gtest signature` → `/guardio scan`.)
2. **GIF — auto‑heal:** an infected plugin → Guardio downloads + verifies a clean copy → next boot it's back.
3. **Screenshot — Discord embed** firing on a quarantine (with a role ping).
4. **Screenshot — `/guardio doctor`** all‑green health check.
5. **Screenshot — the HTML security report** (`guardio/report.html`) open in a browser.
6. **GIF — clean reload:** `/guardio reload <plugin>` with no console spam + no double‑fire.
7. **Screenshot — the startup banner** (`GUARDIO v1.0.0 … vault N jars | launcher yes | agent yes`).
