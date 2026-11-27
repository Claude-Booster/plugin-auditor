<p align="center">
  <img src="assets/banner.svg" width="900" alt="plugin-auditor — see what a plugin runs and loads before you enable it"/>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/python-3.10%2B-7c8cf0?style=flat-square&labelColor=0c1a28" alt="Python 3.10+"/>
  <img src="https://img.shields.io/badge/dependencies-none%20(stdlib)-56c596?style=flat-square&labelColor=0c1a28" alt="No dependencies"/>
  <img src="https://img.shields.io/badge/scan-read--only%20by%20default%2C%20--with--mcp%20opt--in-56c596?style=flat-square&labelColor=0c1a28" alt="Read-only by default"/>
  <img src="https://img.shields.io/badge/mcp-delegates%20to%20mcp--auditor-7c8cf0?style=flat-square&labelColor=0c1a28" alt="Delegates MCP to mcp-auditor"/>
</p>

---

## What it is

A Claude Code **plugin is a filesystem bundle**, not a single MCP server — and when you enable it, many of its parts **execute** (hooks, `bin/` binaries, background monitors, `workflows/*.js`, LSP servers, bundled scripts) or **load into the model's context** (the markdown of its skills, commands, and agents). Reviewing the plugin's *code* misses most of this.

**plugin-auditor** statically inspects a plugin bundle and flags the risky parts in plain English. It is **read-only by default**: it never runs any hook, script, binary, workflow, monitor, or MCP server from the plugin (unless you pass `--with-mcp`, see Safety), never prints sensitive `userConfig`/`env` values (key names only); command and URL evidence is shown with likely secrets (tokens, passwords, Authorization/Bearer, URL credentials, query values) masked on a best-effort basis.

> It sits alongside the sibling tools: **config-guard** gates/quarantines untrusted config; **plugin-auditor** deep-analyzes a plugin bundle; **mcp-auditor** audits the MCP tool metadata within it — plugin-auditor delegates to it.

## What it inspects

<p align="center">
  <img src="assets/surface.svg" width="820" alt="Surfaces inspected: hooks, bin, monitors, workflows and lsp, bundled scripts, skills/commands/agents, manifest, and bundled MCP"/>
</p>

- **Hooks** — commands that auto-run on Claude events (flags `curl|sh`, credential reads).
- **`bin/`** — executables placed on the Bash tool's PATH (Claude can run them as bare commands).
- **Monitors** — persistent background shell processes started at session start.
- **`workflows/*.js` & LSP servers** — code that runs.
- **Bundled scripts** — `curl|sh`, credential reads, base64, network egress.
- **skills / commands / agents markdown** — prompt-injection, hidden/zero-width unicode, credential refs, and over-broad `allowed-tools` grants.
- **Manifest provenance** — missing `version` (floats), Anthropic-name impersonation, sensitive `userConfig` fields, remote `.mcpb`/`.dxt` URLs, `..` path traversal.
- **Bundled MCP servers** — static provenance, and delegation to **mcp-auditor** for live tool-metadata.

## Install

A self-contained Claude Code **skill** — auto-discovered, **no configuration, no build step**:

```bash
git clone https://github.com/Claude-Booster/plugin-auditor.git ~/.claude/skills/plugin-auditor
```

The engine lives at [`scripts/plugin_auditor.py`](scripts/plugin_auditor.py). Then ask Claude *"audit this plugin"* / *"is this plugin safe?"*.

### Requirements

| Tool | Needed for | If missing |
|------|-----------|------------|
| **Python 3.10+** — standard library only, no `pip install` | Everything | The tool can't run |

## Usage

```bash
# audit one plugin bundle (or a directory of plugins — audits each)
python scripts/plugin_auditor.py audit "C:/path/to/plugin"

# also run mcp-auditor on any bundled MCP server
python scripts/plugin_auditor.py audit "C:/path/to/plugin" --with-mcp
```

Exit code is `1` when any HIGH finding exists, else `0`. Without `--with-mcp`, bundled MCP servers get static provenance checks plus a note to run mcp-auditor (nothing is spawned).

## Reading the report

Leads with a one-line verdict + per-severity counts, then findings grouped HIGH→INFO, each naming the plugin → component → "what to check" with an evidence snippet. A footer states it's a **static** scan — it executed nothing (unless `--with-mcp` ran mcp-auditor, in which case the footer says so), and runtime behavior / live MCP tool-metadata aren't covered (unless `--with-mcp` ran).

## Where things live

| Thing | Location |
|-------|----------|
| The engine | `scripts/plugin_auditor.py` (inside this skill) |
| Tests | `scripts/test_plugin_auditor.py` |

## Safety

- **Read-only by default.** It only reads files and pattern-matches — it never executes hooks, scripts, binaries, workflows, monitors, or MCP servers from the plugin — except via the opt-in `--with-mcp` (below).
- **Contained reads** — symlinks and paths resolving outside the plugin (e.g. `..` in manifest entries) are never read; they are reported as findings. Without `--with-mcp` the tool never opens credential files or uses the network; `CRED_PATTERNS` only match text inside the audited plugin. `--with-mcp` shells out with a fixed argv (no shell) and refuses a symlinked script.
- **Secrets masked** — sensitive `userConfig`/`env` surfaces show key names only; command/URL evidence masks likely secrets (best-effort, heuristic — not a guarantee).
- The only thing it may spawn is the sibling **mcp-auditor** script (`~/.claude/skills/mcp-auditor/scripts/mcp_auditor.py`, which then runs as you), and only with `--with-mcp`. `--with-mcp` hands off to mcp-auditor, which STARTS every stdio MCP server declared in the standard MCP project config file found anywhere under the plugin (servers declared inline in the plugin manifest are not live-audited) plus your own configured MCP servers, connects to http MCP URLs, and updates its own baseline (so the plugin's current MCP tool metadata becomes the reference for later change checks) - all as you; use it only after reviewing the static report. Its output is secret-masked best-effort.

## Scanning this skill with SkillSpector
`.skillspector-baseline.yaml` records the by-design findings, each with a stated reason: credential-pattern regexes, detection-only network words, the opt-in `--with-mcp` subprocess, test fixtures, the commit-guard hook scripts and their comment text, and a decorative banner label. When passed with `--baseline`, a static-only scan (`--no-llm`, including the YARA analyzer) reports 0 findings; without `--baseline` SkillSpector does not apply it and reports all of them. The optional LLM/semantic analyzers were not run. It is evidence-bound: changing a flagged file re-activates its findings until they are reviewed again (regenerate with `skillspector baseline`). Scan with:

```
skillspector scan . --no-llm --baseline .skillspector-baseline.yaml
```

## Contributing

To *use* the skill you need nothing below. For changes, run the tests from the skill folder:

```bash
cd scripts && python -m unittest -v
```
