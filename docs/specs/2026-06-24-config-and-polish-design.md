# Guardio — Config & Polish Pass (design)

Date: 2026-06-24

## Goal
Make Guardio feel like a finished, sellable plugin: a clean English config, command tab‑completion,
fully configurable/translatable messages, and basic release hygiene (version + update awareness, banner).

## In scope
1. **Tab completion** for `/guardio` (alias `/guard`).
2. **`config.yml` rewritten in English**, grouped into sections, with a dedicated `discord:` block.
3. **`guardio.properties`** (launcher) — English section comments (stays flat; `.properties` can't nest).
4. **`messages.yml`** — every player/console/Discord string, recolorable + translatable.
5. **Update checker + `/guardio version`** — compare against the latest GitHub release; log if newer.
6. **Startup banner** — clean, colored, shows version.

## Out of scope (roadmap, separate specs)
bStats; `/guardio gui`; PlaceholderAPI; ops.json/config‑integrity monitoring; web dashboard; licensing.

## Design

### Tab completion
A `TabCompleter` registered on the `guardio` command.
- Arg 1: `scan status trust restore allow heal reload version` (filtered by what's typed).
- Arg 2, contextual:
  - `trust` → `all` + scanned jar names
  - `restore` / `allow` → scanned jar names (relative paths)
  - `reload` → loaded plugin names (`Bukkit.getPluginManager().getPlugins()`)
- Permission‑aware: only suggest if sender has `guardio.admin`.

### config.yml (nested, English)
```yaml
general:      { server-name, scan-on-load, periodic-scan-minutes }
scanning:     { roots[], heuristics }
response:     { auto-quarantine, auto-restore, auto-map, shutdown-on-infection }
heal:         { auto-download, game-version }
threat-feed:  { url }
discord:      { enabled, webhook, mention-role-id, embeds, alerts:{quarantine,restore,heal,suspicious} }
signatures:   { content[], entry[] }   # advanced
```
- Plugin reads nested keys (`getConfig().getString("discord.webhook")`, etc.).
- `discord.enabled` gates all alerts; `discord.alerts.*` toggles per event; `mention-role-id` prepends
  `<@&id>` on infection/quarantine; `embeds` chooses a Discord embed vs a plain content line.
- **Back‑compat:** existing flat/Bulgarian `config.yml` files are replaced — Guardio writes the new default
  if the file is missing or has no `config-version`; add `config-version: 2` to detect + (re)generate.

### guardio.properties
Keep flat keys; add grouped `#` comment headers (Server / Launch / Guarding / Discord / Threat‑feed) in English.

### Discord across the two layers (important)
There are two senders: the **launcher** (pre‑boot alerts, before the JVM has Bukkit/YAML) and the **plugin**
(runtime alerts). The launcher can only read `guardio.properties`, so its webhook stays there as
`discord-webhook=`. The plugin reads the rich `discord:` block in `config.yml`. To avoid the user setting the
URL twice, the plugin will **fall back to the `guardio.properties` webhook** if `discord.webhook` is blank — so
setting it once in `guardio.properties` covers both layers, and `config.yml` can override + add the toggles.

### messages.yml
- Keys for every emitted string (scan results, quarantine/restore/heal lines, command replies, Discord
  templates). Placeholders like `{jar}`, `{reason}`, `{count}`, `{server}`, `{version}`.
- Color: legacy `&` codes (translate on send). A `Messages` class loads the file, applies placeholders, and
  every `reply/log/alert` routes through it. Missing keys fall back to a bundled default.

### Update checker + version
- On enable (async): GET `https://api.github.com/repos/fizzexual/Guardio/releases/latest`, compare `tag_name`
  to the plugin version; if newer, log one line (configurable on/off). Never auto‑downloads.
- `/guardio version` → version, vault size, launcher/agent active, update status.

### Startup banner
A short colored banner in the launcher + the plugin enable (name + version + "guarding N jars").

## Testing
- Tab completion: verify suggestions per arg + permission gating (manual on test‑server).
- Config: fresh boot regenerates the nested English config; nested keys read correctly; Discord per‑event
  toggles honored.
- messages.yml: change a message + a color, confirm it shows; delete a key, confirm fallback.
- Update checker: point at the repo, confirm "up to date" / "newer available" paths; `/guardio version` output.
- Regression: full launcher boot on Purpur 1.21.11 reaches Done; scan/quarantine/heal/reload still work
  (re‑run GuardioTester's `/gtest` matrix).
```
