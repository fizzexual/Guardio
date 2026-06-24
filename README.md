# Guardio

**A multi‑context integrity‑enforcement and malware‑remediation engine for Paper‑family Minecraft servers (1.21+).**
Guardio operates as a single self‑contained artifact exposing **three JVM entry points** — a process‑supervising
**launcher** (`Main-Class`), a pre‑load **instrumentation agent** (`Premain-Class`/`Agent-Class`), and an
in‑process **Bukkit plugin** — and applies a **four‑layer detection pipeline** over a **content‑addressable,
path‑mirrored trust store** to detect, quarantine, restore, and autonomously re‑provision tampered or
weaponized JAR artifacts across the entire server tree.

---

## 1. Threat model

Guardio is engineered against self‑propagating JAR‑infector malware of the **`pluginstatstrack`** class — a
polymorphic loader observed injecting **≈154 classes per host artifact**, comprising a shaded
`javassist/orgs/…` namespace (relocated `org.java_websocket` + `slf4j`), a `javassist/ws/…` WebSocket C2 client
(`mc.pluginstatstrack.xyz:5050/ws`), an egress‑profiling probe (`checkip.amazonaws.com`), a runtime class
stager built on `java.lang.invoke.MethodHandles$Lookup#defineClass`, and a manifest‑injected `…L10` bootstrap
that re‑enters the payload on every classload. Propagation vector: trojanized loaders (`ULoader`, JNIC
native‑obfuscated) and cracked premium artifacts. The infector is **path‑agnostic and re‑entrant**, which
defeats single‑point AV scanning and mandates a **whole‑tree, every‑boot, pre‑execution** enforcement model.

---

## 2. Execution topology

```
                       ┌─────────────────────────── guardio-v1.0.0.jar ───────────────────────────┐
  java -jar  ─────────▶│ (1) LAUNCHER  Main-Class            process supervisor, T0 enforcement     │
                       │      • resolves server-root from CodeSource (cwd-independent)              │
                       │      • whole-tree scan/heal BEFORE the server JVM exists                   │
                       │      • server-jar re-provisioning (official upstream, SHA-verified)        │
                       │      • forks the server, forwarding host JVM args (RuntimeMXBean)          │
                       │              │                                                             │
                       │              ▼  spawns child JVM  (-javaagent:self -Dguardio.launcher)     │
                       │ (2) AGENT  premain()                T1 enforcement, pre-classload          │
                       │      • runs before any plugin/library is loaded; jars unlocked             │
                       │      • map-then-load reconciliation against the trust store                │
                       │              │                                                             │
                       │              ▼  Bukkit bootstrap                                            │
                       │ (3) PLUGIN  onLoad/onEnable         T2 enforcement, runtime + control plane │
                       │      • runtime re-scan, scheduler-driven periodic sweeps                   │
                       │      • remediation staging (locked-jar swap via shutdown hook)             │
                       │      • Modrinth/trusted re-provisioning, /guardio control surface          │
                       └────────────────────────────────────────────────────────────────────────────┘
```

A boot is guarded at **three temporal checkpoints** (T0 pre‑JVM, T1 pre‑classload, T2 runtime). The launcher
selects an in‑process `URLClassLoader` re‑entry **or** a forked child JVM by introspecting the server jar's
`Main-Class` against a bootstrap‑signature set (`io.papermc.paperclip.Main`, `org.bukkit.craftbukkit.*`,
`net.minecraft.bundler.Main`, Fabric/launchwrapper) — paperclip‑class bootstraps are isolation‑incompatible
with child‑classloader hosting and are therefore forked, with host `-Xmx`/GC flags forwarded verbatim.

---

## 3. Detection pipeline (four layers)

| # | Layer | Mechanism | Authority | Cost |
|---|-------|-----------|-----------|------|
| L1 | **Integrity** | SHA‑256 of each artifact vs the path‑keyed trust‑store baseline | deterministic | O(bytes), hash‑cached |
| L2 | **Signature (IOC)** | ZIP entry‑name fragments + ISO‑8859‑1 content‑byte scan of `.class` members (≤3 MiB/class, ≤10 reasons) | malware‑specific only | O(entries) |
| L3 | **Threat‑intel feed** | membership test of artifact SHA‑256 against a remote, cached known‑malware hash set | **authoritative — overrides trust** | O(1) |
| L4 | **Heuristic (report‑only)** | constant‑pool token analysis: `MethodHandles.defineClass` ∧ `{URLClassLoader│URL.openStream}` ∧ `{Runtime.exec│ProcessBuilder}`; emits on ≥2 categories or the define‑class∧remote‑fetch dyad | advisory — **never auto‑quarantines** | O(bytes), plugins‑scope only |

L2 signatures are deliberately constrained to strings/paths **absent from legitimate libraries** (verified
against a 118‑artifact Paper dependency set with a 0‑false‑positive result) to eliminate collateral
quarantine. L3 is authoritative: a feed hash match **supersedes a prior trust mapping**, closing the
"trusted‑then‑later‑classified" window. L4 is strictly advisory to preserve a zero‑false‑quarantine guarantee.

---

## 4. Trust store & reconciliation (map‑then‑load)

The trust store is a **path‑mirrored, content‑verified vault** keyed by artifact path relative to server‑root.
Reconciliation is a three‑way state machine evaluated per artifact at every checkpoint:

```
UNMAPPED  ──(L2∧¬whitelist ∨ L3)──▶ QUARANTINE ──▶ re-provision (vault│trusted│Modrinth)
UNMAPPED  ──(clean)──────────────▶ MAP (baseline)        + L4 advisory emit
MAPPED    ──(SHA match)──────────▶ ADMIT (no-op)
MAPPED    ──(SHA divergence)─────▶ QUARANTINE ──▶ restore vault copy
```

At T1 (agent) all targets except the running `-jar` are unlocked and swapped atomically (`Files.move`); at T2
(plugin) live artifacts are file‑locked, so remediation is **staged and committed in a JVM shutdown hook**,
yielding a clean *next* boot. The server jar is re‑provisioned only by the launcher (T0), where it is not yet
the running image.

---

## 5. Autonomous re‑provisioning

Quarantined artifacts with no vault baseline are re‑provisioned through a **two‑source, dual‑verification**
pipeline: (a) operator‑curated `guardio/trusted/` backups (premium artifacts with no free distribution), then
(b) Modrinth API v2 resolution by loader+game‑version, with **SHA‑512 upstream verification AND a full
re‑scan** of the candidate before installation. The server jar is re‑provisioned from the official upstream
(Purpur/Paper distribution API). Provisioning is non‑destructive and idempotent; every installed artifact is
re‑baselined into the vault.

---

## 6. Clean reload subsystem

`/guardio reload <plugin>` performs a **deterministic teardown** of all Bukkit‑tracked registration surfaces —
`HandlerList` listeners, scheduler tasks, `ServicesManager` providers, plugin‑messaging channels, and the
`CommandMap` `knownCommands` projection — **prior to** disable, eliminating the double‑registration class of
defects endemic to naïve disable/enable cycles. Classloader disposal (`URLClassLoader#close` + back‑reference
nulling) releases the artifact handle and admits GC. Re‑entry uses Paper's runtime loader
(`PaperPluginManagerImpl.instanceManager#loadPlugin(Path)`) — the Bukkit‑interface `loadPlugin(File)` routes
through provider storage and fails at runtime. Dependents are dependency‑graph‑resolved and warned;
`paper-plugin.yml` bootstrap plugins (and hybrids that ship one) are refused (incompatible with runtime
re‑entry). **Caveat:** a reloaded plugin's *commands* are re‑registered best‑effort, but on Paper 1.21+ the
legacy command may remain in Brigadier's dispatcher until a full restart — use the namespaced `/plugin:cmd`
form in the interim, or restart to fully re‑bind. Listeners/tasks/services/channels re‑bind cleanly regardless.

---

## 7. Operational characteristics

- **Single artifact**, three manifest entry points; **zero runtime dependencies** beyond the JDK (Gson is
  `provided` by the platform; the launcher/agent paths are pure JDK).
- **Checkpoint coverage:** T0 (pre‑JVM) ∪ T1 (pre‑classload) ∪ T2 (runtime) — an artifact is evaluated up to 3×.
- **Verified reference deployment:** Purpur 1.21.11 / JDK 21, 122–129‑artifact baseline, `Done` in 15–23 s,
  graceful‑stop and clean‑reload validated, **0 exceptions**.
- **Marker‑based posture introspection:** `guardio.launcher` / `guardio.agent` system properties expose live
  protection state to `/guardio version` and (roadmap) `/guardio doctor`.
- **Alerting:** Discord webhook (embed or plain, role‑mention, per‑event gating), inheriting the launcher
  webhook when unset; fully externalized, recolorable/translatable message catalog (`messages.yml`).

---

## 8. Deployment

Place `guardio-v1.0.0.jar` in the server root; the real server jar in root or `guardio/serverjar/`.
- **Double‑click** the jar (a console is spawned), or **`java -Xmx4G -jar guardio-v1.0.0.jar`**, or point any
  panel's startup jar at it. First boot provisions `guardio/` (config + vault), relocates the server jar into
  `guardio/serverjar/`, syncs an in‑server plugin copy, scans/heals, then forks + supervises the server.
- **Agent‑only** (no launcher): `java -javaagent:guardio-v1.0.0.jar -jar guardio/serverjar/<server>.jar nogui`.

**Control surface** (`/guardio`, alias `/guard`, perm `guardio.admin`, tab‑completed):
`scan · status · version · trust [all|<jar>] · restore <jar> · allow <jar> · heal · reload <plugin>`.

**Configuration:** `guardio/config.yml` (sectioned: `general · scanning · response · heal · threat-feed ·
discord · signatures`), `guardio/messages.yml` (i18n), `guardio/guardio.properties` (launcher), `guardio/sources.yml`
(provisioning overrides), `guardio/trusted/` (operator backups).

---

## 9. Boundary conditions (honest limits)

Guardio enforces integrity of the **server tree**; it is **not** a host‑level EDR. OS‑resident persistence,
exfiltrated credentials, or a trojanized OS/JRE are out of scope — a compromised host requires OS remediation
and credential rotation independent of Guardio. Premium artifacts without a free distribution channel cannot be
auto‑provisioned and are flagged for manual reinstatement (or served from `guardio/trusted/`). The heuristic
layer is advisory by design and must not be interpreted as a definitive verdict.

---

## 10. Test harness

`test-harness/` builds **GuardioTester** — a non‑malicious instrumentation plugin that emits inert decoy
artifacts (Base64‑encoded markers, so the harness itself is not flagged) exercising L1–L4, quarantine/restore,
threat‑feed‑by‑hash, and reload idempotency via `/gtest {signature│heuristic│feedtest│tamper│id│clean}`.

## 11. Self‑hardening & build
- **Self‑integrity (anti‑injection).** The launcher and the pre‑load agent record Guardio's own jar SHA‑256 on
  the first clean run (`guardio/guardio.self`) and verify it on every boot — *before* the plugin loads. If the
  infector injects classes into Guardio's own jar, the bytes change and `self-protect=refuse` aborts startup
  (exit 3) with an alert. **Honest scope:** this stops the *automated* malware (it won't re‑baseline Guardio's
  record); a *targeted human* who controls the box can patch the check out — no self‑check can defeat that.
- **Obfuscation.** `mvn package -Prelease` runs ProGuard to rename all internal classes and strip debug info
  (deters decompilation / cracking) while keeping the entry points so it still loads. Plain `mvn package` stays
  readable for development. Obfuscation is *deterrence*, not invincibility.
- **Build:** `mvn package` → readable dev jar; `mvn package -Prelease` → the shippable obfuscated jar.
