PluginGuard — how it works and how to use it
=============================================

PROTECTS A CLEAN BASELINE. Clean the host and install clean plugins FIRST.

Two layers (use both):
  1) AGENT (runs BEFORE any plugin loads — the real "loads first" guarantee).
     Add to your server start command, before -jar:
        java -Xmx4G -javaagent:plugins/PluginGuard-1.0.0.jar -jar paper.jar nogui
     (If your plugins folder isn't ./plugins, pass it: -javaagent:...PluginGuard-1.0.0.jar=/path/to/plugins)
  2) PLUGIN (the /guard commands, reports, alerts, periodic scans). Just drop the same jar in /plugins.

MAP-THEN-LOAD MODEL
  - New plugin  -> signature-scanned; if clean it's MAPPED (copied into plugins/PluginGuard/vault/) as the
                   trusted baseline. If it carries a malware signature it's QUARANTINED and NOT mapped.
  - Mapped plugin -> if the live jar matches its mapped copy it loads as-is; if it differs
                   (tampered/infected/updated) the live jar is quarantined and the safe mapped copy is
                   restored. The agent does this BEFORE load; the plugin (no agent) applies it on shutdown.

LEGIT UPDATES
  Same-filename update -> reverts to the mapped version. Accept the new version with:  /guard trust <jar>
  (Tip: versioned filenames like Plugin-1.3.jar are seen as NEW and auto-mapped, so updates are painless.)

COMMANDS  (permission: pluginguard.admin / op)
  /guard scan                 rescan now + report
  /guard status               vault size, last scan summary, staged fixes
  /guard trust [all|<jar>]    (re)map current jar(s) as the trusted baseline — only on VERIFIED-clean jars
  /guard restore <jar>        restore a jar from the vault

FOLDERS (under plugins/PluginGuard/)
  vault/        the trusted/mapped clean jars (source of truth)
  quarantine/   infected/tampered jars moved here as evidence
  guard-report.txt / agent-report.txt / last-remediation.txt   logs

TESTING with the TestVirus plugin
  Drop TestVirus-1.0.0.jar into /plugins. It is HARMLESS (no network/files/payload) — it only carries a fake
  signature. With the agent enabled it is quarantined before it can load; as a plugin-only setup it loads once
  (logs a warning) and is quarantined on shutdown. Check console, /guard status, and plugins/PluginGuard/quarantine/.
