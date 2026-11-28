#!/usr/bin/env python3
"""plugin-auditor - statically inspect a Claude Code *plugin bundle* for risk.

A Claude Code "plugin" is a filesystem bundle (NOT a single MCP server) that a
user installs and enables. When enabled, many of its parts execute or load into
the model's context: hooks auto-run commands on events, bin/ files land on the
Bash tool's PATH, monitors spawn persistent background processes, workflows run
JavaScript, and the markdown of its skills/commands/agents loads straight into
the model's prompt. Auditing only the plugin's *code* misses most of this.

This tool is READ-ONLY. It ONLY reads files and pattern-matches. It NEVER executes
any hook, script, binary, workflow, monitor, or MCP server from the plugin, never
spawns another program, and makes no network calls. It never prints sensitive
userConfig/env values (key names only); command and URL evidence is shown with likely
secrets (tokens, passwords, Authorization/Bearer, URL credentials, query values)
masked on a best-effort basis. For live MCP tool-metadata checks, run the separate
mcp-auditor skill yourself (it starts MCP servers as you) - only after reviewing this
report.

Stdlib only. Windows-safe (pathlib / json / re). Self-contained.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import dataclass
from pathlib import Path

# --------------------------------------------------------------------------- #
# Severity
# --------------------------------------------------------------------------- #

HIGH, MEDIUM, LOW, INFO = "HIGH", "MEDIUM", "LOW", "INFO"
SEV_ORDER = {HIGH: 0, MEDIUM: 1, LOW: 2, INFO: 3}


@dataclass
class Finding:
    severity: str
    plugin: str
    component: str
    message: str          # plain-English "what to check"
    snippet: str = ""     # matched evidence, already truncated


# --------------------------------------------------------------------------- #
# Detection heuristics (reimplemented here - no imports from other skills)
# --------------------------------------------------------------------------- #

# Remote-script-piped-to-shell (curl|sh, iwr|iex, etc.)
PIPE_TO_SHELL = re.compile(
    r"(?:curl|wget)\b[^|]*\|\s*(?:sudo\s+)?(?:sh|bash|zsh)\b"
    r"|(?:iwr|invoke-webrequest|wget)\b[^|]*\|\s*(?:iex|invoke-expression)"
    r"|curl\b[^|]*\|\s*python",
    re.IGNORECASE,
)

# Credential / sensitive file & path references.
# DETECTION-ONLY: these regexes are matched against text of files inside the audited
# plugin. This tool never opens ~/.ssh, .env, or any credential path itself.
CRED_PATTERNS = [
    (r"~[\\/]\.ssh", "~/.ssh SSH key directory"),
    (r"\bid_rsa\b", "id_rsa private key"),
    (r"\.env\b", "secrets file (.env)"),
    (r"\bpassword\b", "password"),
    (r"\bsecret\b", "secret"),
    (r"\bapi[_ -]?key\b", "api key"),
    (r"\btoken\b", "token"),
    (r"\bexfiltrat", "exfiltration language"),
    (r"\bbase64\b", "base64 (encoding/obfuscation)"),
]
CRED_RE = re.compile("|".join(p for p, _ in CRED_PATTERNS), re.IGNORECASE)

# Absolute paths (Windows C:\... or unix /etc /usr /home /root /var /opt ...).
ABS_PATH_RE = re.compile(
    r"(?:[A-Za-z]:[\\/][^\s\"']+)"
    r"|(?:(?<![\w/])/(?:etc|usr|home|root|var|opt|bin|sbin|tmp)/[^\s\"']*)"
)

# Model-directed-instruction regexes (prompt injection) -> HIGH.
INSTRUCTION_PATTERNS = [
    r"ignore\s+(?:the\s+)?(?:previous|above|prior)",
    r"disregard",
    r"do\s+not\s+(?:tell|mention|reveal)",
    r"system\s+prompt",
    r"you\s+must",
    r"instead,?\s+(?:call|use|read)",
    r"as\s+an\s+ai",
    r"always\s+(?:read|send|include|call|run)",
]
INSTRUCTION_RE = re.compile("|".join(INSTRUCTION_PATTERNS), re.IGNORECASE)

# Network / exec detection patterns for workflow (.js) & bundled scripts. DETECTION-ONLY:
# matched against plugin text; this tool itself makes no network calls. The rule strings
# live in net_patterns.json (plain text, next to this script).
_PATTERNS_FILE = Path(__file__).with_name("net_patterns.json")


def _load_net_patterns():
    try:
        data = json.loads(_PATTERNS_FILE.read_text(encoding="utf-8"))
        return (re.compile(data["workflow_danger"], re.IGNORECASE),
                re.compile(data["script_net"], re.IGNORECASE))
    except (OSError, KeyError, TypeError, ValueError, re.error) as exc:
        sys.exit(f"plugin-auditor: cannot load {_PATTERNS_FILE.name} ({exc}); "
                 "keep it next to plugin_auditor.py")


WORKFLOW_DANGER, SCRIPT_NET = _load_net_patterns()

# Hidden / obfuscated unicode.
ZERO_WIDTH = {0x200B, 0x200C, 0x200D, 0xFEFF}
BIDI = set(range(0x202A, 0x202F)) | set(range(0x2066, 0x206A))  # 202A-202E, 2066-2069


def _hidden_unicode(text: str):
    """Return a set of suspicious codepoints found in text."""
    found = set()
    for ch in text:
        cp = ord(ch)
        if cp in ZERO_WIDTH or cp in BIDI:
            found.add(cp)
        elif cp < 0x20 and ch not in "\t\n\r":   # C0 controls
            found.add(cp)
        elif 0x80 <= cp <= 0x9F:                  # C1 controls
            found.add(cp)
    return found


_SECRET_KEY = r"(?:authorization|token|password|passwd|pwd|secret|api[_-]?key|access[_-]?key|auth(?!or))"
_REDACTIONS = [
    # Authorization header: mask the whole value (scheme + credential, any scheme).
    (re.compile(r"(?i)(authorization[\"']?\s*[:=]\s*[\"']?)[^\"'\n]+"), r"\1***"),
    (re.compile(r"(?i)\b(bearer|basic)\s+[^\s\"']+"), r"\1 ***"),
    (re.compile(r"(?i)(\b[\w-]{0,32}" + _SECRET_KEY + r"[\w-]{0,32}[\"']?\s*[:=]\s*[\"']?)"
                r"(?!(?i:bearer|basic)\s)[^\s\"'&;]+"), r"\1***"),
    (re.compile(r"(?i)(--?[\w-]{0,32}" + _SECRET_KEY + r"[\w-]{0,32}\s+)(?!-)[^\s\"']+"), r"\1***"),
    (re.compile(r"(://[^/\s:@]+:)[^@\s/]+@"), r"\1***@"),   # URL userinfo
    (re.compile(r"([?&][^=&\s]+=)[^&\s\"']+"), r"\1***"),   # query values
]


def _redact(s: str) -> str:
    """Best-effort masking of likely secrets in evidence text."""
    for rx, rep in _REDACTIONS:
        s = rx.sub(rep, s)
    return s


def _trunc(s: str, n: int = 80) -> str:
    # Clip first (bounds regex work on hostile input), then redact, then truncate.
    s = _redact(" ".join(str(s).split())[: n * 4])
    return s if len(s) <= n else s[: n - 1] + "\u2026"


def _cred_hits(text: str):
    hits = []
    for pat, label in CRED_PATTERNS:
        if re.search(pat, text, re.IGNORECASE):
            hits.append(label)
    if ABS_PATH_RE.search(text):
        hits.append("absolute filesystem path")
    return hits


# --------------------------------------------------------------------------- #
# JSON / file helpers (never execute anything)
# --------------------------------------------------------------------------- #

def _is_contained(root: Path, path: Path) -> bool:
    """True only for a regular, non-symlink file that resolves inside root."""
    try:
        if path.is_symlink():
            return False
        return path.resolve().is_relative_to(root.resolve())
    except (OSError, ValueError):
        return False


def _load_json(path: Path, root: Path | None = None):
    """Return (data, error_str). Never raises. With root, refuses symlinks and
    paths that resolve outside it (so outside files are never read)."""
    if root is not None and path.exists() and not _is_contained(root, path):
        return None, "symlink or path outside the plugin; not read"
    try:
        return json.loads(path.read_text(encoding="utf-8", errors="replace")), None
    except FileNotFoundError:
        return None, "not found"
    except Exception as exc:  # malformed JSON etc.
        return None, f"could not parse ({exc.__class__.__name__})"


def _read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return ""


def _walk_command_strings(obj):
    """Recursively yield every value stored under a 'command' key."""
    if isinstance(obj, dict):
        for k, v in obj.items():
            if k == "command":
                if isinstance(v, str):
                    yield v
                elif isinstance(v, list):
                    yield " ".join(str(x) for x in v)
            else:
                yield from _walk_command_strings(v)
    elif isinstance(obj, list):
        for item in obj:
            yield from _walk_command_strings(item)


# --------------------------------------------------------------------------- #
# Plugin discovery
# --------------------------------------------------------------------------- #

PLUGIN_MARKERS = ["hooks", "skills", "commands", "agents", "bin", "workflows"]


def is_plugin(path: Path) -> bool:
    if not path.is_dir():
        return False
    if (path / ".claude-plugin" / "plugin.json").is_file():
        return True
    if (path / ".mcp.json").is_file():
        return True
    return any((path / m).is_dir() for m in PLUGIN_MARKERS)


# --------------------------------------------------------------------------- #
# Per-plugin checks
# --------------------------------------------------------------------------- #

def audit_plugin(root: Path, manifest: dict):
    """Return a list[Finding] for one plugin directory."""
    name = (manifest.get("name") if isinstance(manifest, dict) else None) or root.name
    f: list[Finding] = []

    _check_hooks(root, manifest, name, f)
    _check_bin(root, name, f)
    _check_monitors(root, manifest, name, f)
    _check_workflows(root, manifest, name, f)
    _check_lsp(root, manifest, name, f)
    _check_scripts(root, name, f)
    _check_markdown(root, name, f)
    _check_manifest_provenance(root, manifest, name, f)
    _check_mcp_static(root, manifest, name, f)
    return f


def _check_hooks(root, manifest, name, f):
    sources = []  # (component-label, parsed-object)

    hj = root / "hooks" / "hooks.json"
    if hj.is_file():
        data, err = _load_json(hj, root)
        if err:
            f.append(Finding(MEDIUM, name, "hooks/hooks.json",
                             "hooks file present but unreadable - inspect it by hand", err))
        else:
            sources.append(("hooks/hooks.json", data))

    if isinstance(manifest, dict) and "hooks" in manifest:
        hooks = manifest["hooks"]
        if isinstance(hooks, str):  # path to a hooks file
            hp = (root / hooks)
            data, err = _load_json(hp, root)
            if err:
                f.append(Finding(MEDIUM, name, f"plugin.json hooks -> {hooks}",
                                 "manifest names a hooks file that is unreadable", err))
            else:
                sources.append((f"plugin.json hooks -> {hooks}", data))
        else:  # inline
            sources.append(("plugin.json (inline hooks)", {"hooks": hooks}))

    for comp, data in sources:
        for cmd in _walk_command_strings(data):
            msg = "auto-runs a command on a Claude event; confirm you trust it"
            danger = []
            if PIPE_TO_SHELL.search(cmd):
                danger.append("pipes a remotely-fetched script straight into a shell")
            creds = _cred_hits(cmd)
            if creds:
                danger.append("touches credentials/paths: " + ", ".join(sorted(set(creds))))
            if danger:
                msg += " - DANGER: " + "; ".join(danger)
            f.append(Finding(HIGH, name, comp, msg, _trunc(cmd)))


def _check_bin(root, name, f):
    bind = root / "bin"
    if bind.is_dir():
        files = [p.name for p in sorted(bind.iterdir()) if p.is_file()]
        if files:
            f.append(Finding(
                HIGH, name, "bin/",
                "every file in bin/ is placed on the Bash tool's PATH; Claude can "
                "run it as a bare command (claude.ai/Cowork refuse plugins with bin/)",
                ", ".join(files)))


def _check_monitors(root, manifest, name, f):
    sources = []
    mj = root / "monitors" / "monitors.json"
    if mj.is_file():
        data, err = _load_json(mj, root)
        if err:
            f.append(Finding(MEDIUM, name, "monitors/monitors.json",
                             "monitors file present but unreadable", err))
        else:
            sources.append(("monitors/monitors.json", data))

    if isinstance(manifest, dict):
        exp = manifest.get("experimental", {})
        mons = exp.get("monitors") if isinstance(exp, dict) else None
        if isinstance(mons, str):
            data, err = _load_json(root / mons, root)
            if err:
                f.append(Finding(MEDIUM, name, f"experimental.monitors -> {mons}",
                                 "manifest names a monitors file that is unreadable", err))
            else:
                sources.append((f"experimental.monitors -> {mons}", data))
        elif mons is not None:
            sources.append(("plugin.json experimental.monitors (inline)", {"monitors": mons}))

    for comp, data in sources:
        for cmd in _walk_command_strings(data):
            f.append(Finding(
                HIGH, name, comp,
                "a monitor is a persistent background shell process started at "
                "session start; confirm you trust what it runs",
                _trunc(cmd)))


def _check_workflows(root, manifest, name, f):
    files = []
    wdir = root / "workflows"
    if wdir.is_dir():
        files.extend(sorted(wdir.rglob("*.js")))
    if isinstance(manifest, dict):
        wf = manifest.get("workflows")
        for entry in (wf if isinstance(wf, list) else [wf] if isinstance(wf, str) else []):
            if not isinstance(entry, str):
                continue
            p = root / entry
            if p.is_file() and p not in files:
                files.append(p)

    for p in files:
        if not _is_contained(root, p):
            # Outside the plugin or a symlink: never read it, just flag it.
            shown = p.relative_to(root).as_posix() if p.is_relative_to(root) else p.name
            f.append(Finding(HIGH, name, shown,
                             "workflow path is a symlink or escapes the plugin directory; "
                             "not read", ""))
            continue
        comp = p.resolve().relative_to(root.resolve()).as_posix()
        content = _read_text(p)
        sev, why, snip = MEDIUM, "JavaScript that runs as a workflow; review it", ""
        m = WORKFLOW_DANGER.search(content)
        creds = _cred_hits(content)
        if m or creds:
            sev = HIGH
            reasons = []
            if m:
                reasons.append(f"uses {m.group(0)}")
            if creds:
                reasons.append("references credentials/paths: " + ", ".join(sorted(set(creds))))
            why = "workflow JavaScript " + "; ".join(reasons)
            snip = _trunc(m.group(0)) if m else ""  # never echo raw file content
        f.append(Finding(sev, name, comp, why, snip))


def _check_lsp(root, manifest, name, f):
    entries = []  # (component, command-str)
    lj = root / ".lsp.json"
    if lj.is_file():
        data, err = _load_json(lj, root)
        if not err:
            for cmd in _walk_command_strings(data):
                entries.append((".lsp.json", cmd))
    if isinstance(manifest, dict):
        lsp = manifest.get("lspServers")
        if lsp is not None:
            for cmd in _walk_command_strings({"x": lsp}):
                entries.append(("plugin.json lspServers", cmd))

    for comp, cmd in entries:
        if PIPE_TO_SHELL.search(cmd):
            f.append(Finding(HIGH, name, comp,
                             "LSP command fetches & runs a remote script", _trunc(cmd)))
        else:
            f.append(Finding(MEDIUM, name, comp,
                             "launches a language-server binary at session start; "
                             "confirm the binary is trusted", _trunc(cmd)))


def _check_scripts(root, name, f):
    sdir = root / "scripts"
    files = []
    if sdir.is_dir():
        for ext in ("*.sh", "*.ps1", "*.py", "*.js", "*.bat", "*.cmd"):
            files.extend(sdir.rglob(ext))
    for p in sorted(set(files)):
        comp = p.relative_to(root).as_posix()
        if not _is_contained(root, p):
            f.append(Finding(MEDIUM, name, comp,
                             "symlink or path outside the plugin; not read", ""))
            continue
        content = _read_text(p)
        reasons, sev, snip = [], None, ""
        if PIPE_TO_SHELL.search(content):
            sev = HIGH
            reasons.append("fetches a remote script and pipes it to a shell")
            snip = _trunc(PIPE_TO_SHELL.search(content).group(0))
        creds = _cred_hits(content)
        if creds:
            sev = HIGH
            reasons.append("references credentials/paths: " + ", ".join(sorted(set(creds))))
        if SCRIPT_NET.search(content):
            sev = sev or MEDIUM
            reasons.append("performs network egress (" + SCRIPT_NET.search(content).group(0) + ")")
            snip = snip or _trunc(SCRIPT_NET.search(content).group(0))
        if re.search(r"\bbase64\b", content, re.IGNORECASE):
            sev = sev or MEDIUM
            reasons.append("uses base64 (possible obfuscation)")
        if sev:
            f.append(Finding(sev, name, comp,
                             "bundled script " + "; ".join(reasons), snip))


def _check_markdown(root, name, f):
    for sub in ("skills", "commands", "agents"):
        d = root / sub
        if not d.is_dir():
            continue
        for p in sorted(d.rglob("*.md")):
            comp = f"{sub}/{p.relative_to(d).as_posix()}"
            if not _is_contained(root, p):
                f.append(Finding(MEDIUM, name, comp,
                                 "symlink or path outside the plugin; not read", ""))
                continue
            text = _read_text(p)
            front, _body = _split_frontmatter(text)
            whole = text

            if INSTRUCTION_RE.search(whole):
                m = INSTRUCTION_RE.search(whole)
                f.append(Finding(HIGH, name, comp,
                                 "contains model-directed instructions (prompt injection) "
                                 "that would load into Claude's context", _trunc(m.group(0))))
            creds = _cred_hits(whole)
            if creds:
                f.append(Finding(HIGH, name, comp,
                                 "references credentials/secrets/paths: "
                                 + ", ".join(sorted(set(creds))), ""))
            hidden = _hidden_unicode(whole)
            if hidden:
                codes = ", ".join("U+%04X" % c for c in sorted(hidden))
                f.append(Finding(HIGH, name, comp,
                                 "contains hidden/obfuscated unicode (zero-width, "
                                 "bidi, or control chars) that can hide text from you",
                                 codes))

            # allowed-tools / allowedTools grant (from frontmatter).
            tools = _extract_allowed_tools(front)
            if tools is not None:
                joined = ", ".join(tools) if tools else "(empty)"
                if any(_grants_bash_or_wildcard(t) for t in tools):
                    f.append(Finding(HIGH, name, comp,
                                     "pre-authorizes powerful tools without prompting "
                                     "(includes Bash or wildcard): " + joined, ""))
                else:
                    f.append(Finding(MEDIUM, name, comp,
                                     "pre-authorizes tools without prompting: " + joined, ""))


def _split_frontmatter(text: str):
    if text.startswith("---"):
        parts = text.split("---", 2)
        if len(parts) >= 3:
            return parts[1], parts[2]
    return "", text


def _extract_allowed_tools(front: str):
    """Return list[str] of granted tools, or None if no allowed-tools key."""
    m = re.search(r"(?mi)^\s*allowed[_-]?tools\s*:\s*(.*)$", front)
    if not m:
        return None
    rest = m.group(1).strip()
    tools = []
    if rest.startswith("["):
        # inline YAML/JSON list on one line
        inner = rest.strip("[]")
        tools = [t.strip().strip("'\"") for t in inner.split(",") if t.strip()]
    elif rest:
        tools = [t.strip().strip("'\"") for t in rest.split(",") if t.strip()]
    else:
        # block list on following lines
        after = front[m.end():]
        for line in after.splitlines():
            lm = re.match(r"\s*-\s*(.+?)\s*$", line)
            if lm:
                tools.append(lm.group(1).strip().strip("'\""))
            elif line.strip() and not line.startswith(" "):
                break
    return tools


def _grants_bash_or_wildcard(tool: str) -> bool:
    t = tool.strip().strip("'\"")
    return t == "*" or t.lower().startswith("bash")


def _check_manifest_provenance(root, manifest, name, f):
    comp = ".claude-plugin/plugin.json"
    if not isinstance(manifest, dict) or not manifest:
        return

    if not manifest.get("version"):
        f.append(Finding(MEDIUM, name, comp,
                         "no `version` - the plugin floats to latest (rug-pull vector)", ""))
    if manifest.get("defaultEnabled") is True:
        f.append(Finding(INFO, name, comp,
                         "defaultEnabled: true - auto-enabled when installed", ""))

    nm = str(manifest.get("name", name)).lower()
    RESERVED = {"claude", "anthropic", "claude-code", "superpowers"}
    if (nm.startswith(("claude-", "anthropic-", "anthropics-", "cc-plugin-"))
            or nm in RESERVED):
        f.append(Finding(MEDIUM, name, comp,
                         "name impersonates an official/Anthropic plugin - verify the "
                         "publisher", nm))

    deps = manifest.get("dependencies")
    if deps:
        listed = ", ".join(deps) if isinstance(deps, (list, dict)) else str(deps)
        f.append(Finding(INFO, name, comp,
                         "declares dependencies - installs/pulls in other plugins: "
                         + listed, ""))

    if not manifest.get("author"):
        f.append(Finding(MEDIUM, name, comp,
                         "no `author` - unverifiable provenance", ""))
    if not manifest.get("repository"):
        f.append(Finding(MEDIUM, name, comp,
                         "no `repository` - unverifiable provenance", ""))

    # userConfig sensitive fields -> list KEY NAMES only (never values).
    uc = manifest.get("userConfig")
    if isinstance(uc, dict):
        sensitive = []
        for key, spec in uc.items():
            if isinstance(spec, dict) and spec.get("sensitive") is True:
                sensitive.append(key)
        if sensitive:
            f.append(Finding(MEDIUM, name, comp,
                             "collects sensitive credential fields (key names only, "
                             "values never read): " + ", ".join(sensitive), ""))

    # Component paths containing '..' (traversal).
    for key, val in manifest.items():
        if key == "userConfig":  # values here may be sensitive defaults; never scanned
            continue
        for s in _iter_strings(val):
            if ".." in s and ("/" in s or "\\" in s):
                f.append(Finding(HIGH, name, comp,
                                 f"manifest `{key}` contains a path-traversal path", _trunc(s)))

    # mcpServers remote .mcpb/.dxt URL or http:// (checked in detail below too).
    _flag_remote_mcp(manifest.get("mcpServers"), name, comp, f)


def _iter_strings(obj):
    if isinstance(obj, str):
        yield obj
    elif isinstance(obj, dict):
        for v in obj.values():
            yield from _iter_strings(v)
    elif isinstance(obj, list):
        for v in obj:
            yield from _iter_strings(v)


def _flag_remote_mcp(mcp_servers, name, comp, f):
    if not mcp_servers:
        return
    for s in _iter_strings(mcp_servers):
        low = s.lower()
        if low.endswith((".mcpb", ".dxt")):
            f.append(Finding(HIGH, name, comp,
                             "mcpServers points at a remote .mcpb/.dxt bundle URL - "
                             "downloads & extracts code onto your machine", _trunc(s)))
        elif low.startswith("http://"):
            f.append(Finding(HIGH, name, comp,
                             "mcpServers uses a plaintext http:// URL", _trunc(s)))


def _check_mcp_static(root, manifest, name, f):
    sources = []
    mj = root / ".mcp.json"
    if mj.is_file():
        data, err = _load_json(mj, root)
        if err:
            f.append(Finding(MEDIUM, name, ".mcp.json",
                             ".mcp.json present but unreadable - inspect it by hand", err))
        elif isinstance(data, dict):
            sources.append((".mcp.json", data.get("mcpServers", data)))
    if isinstance(manifest, dict) and manifest.get("mcpServers"):
        sources.append(("plugin.json mcpServers", manifest.get("mcpServers")))

    if not sources:
        return

    for comp, servers in sources:
        _flag_remote_mcp(servers, name, comp, f)
        # Unpinned installers / curl|sh / non-https / static cred key names.
        for cmd in _walk_command_strings({"x": servers}):
            if re.search(r"\bnpx\b.*(?<!@)\b-y\b|\bnpx\s+-y\b", cmd) or \
               (re.search(r"\bnpx\b", cmd) and "@" not in cmd):
                f.append(Finding(MEDIUM, name, comp,
                                 "MCP server launched via unpinned npx (-y / no @version) "
                                 "- supply-chain risk", _trunc(cmd)))
            if re.search(r"\b(uvx|pipx)\b", cmd) and "==" not in cmd and "@" not in cmd:
                f.append(Finding(MEDIUM, name, comp,
                                 "MCP server launched via unpinned uvx/pipx", _trunc(cmd)))
            if PIPE_TO_SHELL.search(cmd):
                f.append(Finding(HIGH, name, comp,
                                 "MCP server command pipes a remote script to a shell",
                                 _trunc(cmd)))
        # non-HTTPS url & static cred key names.
        if isinstance(servers, dict):
            for sname, spec in servers.items():
                if isinstance(spec, dict):
                    url = str(spec.get("url", ""))
                    if url.startswith("http://"):
                        f.append(Finding(HIGH, name, comp,
                                         f"MCP server '{sname}' uses plaintext http:// URL",
                                         _trunc(url)))
                    env = spec.get("env")
                    if isinstance(env, dict) and env:
                        keys = [k for k, v in env.items()
                                if isinstance(v, str) and v and not v.startswith("${")]
                        if keys:
                            f.append(Finding(MEDIUM, name, comp,
                                             f"MCP server '{sname}' hard-codes env values "
                                             "(key names only): " + ", ".join(keys), ""))
        f.append(Finding(INFO, name, comp,
                         "bundled MCP server present - NOT started by this tool. For live "
                         "tool-metadata / tool-poisoning checks, review this plugin first, then "
                         "run the separate mcp-auditor skill (it starts MCP servers as you)", ""))


def _check_marketplace(audit_path: Path, findings: list, plugin_names):
    """Check for a marketplace.json near the audited path."""
    candidates = [audit_path / ".claude-plugin" / "marketplace.json",
                  audit_path.parent / ".claude-plugin" / "marketplace.json"]
    for mp in candidates:
        if not mp.is_file():
            continue
        data, err = _load_json(mp)
        if err or not isinstance(data, dict):
            continue
        plugins = data.get("plugins", [])
        if isinstance(plugins, list):
            for entry in plugins:
                if not isinstance(entry, dict):
                    continue
                en = entry.get("name", "?")
                extra = [k for k in ("hooks", "commands", "agents") if k in entry]
                if extra:
                    findings.append(Finding(
                        MEDIUM, en, "marketplace.json",
                        "marketplace entry adds components on top of the plugin's own "
                        "manifest: " + ", ".join(extra), ""))
        return  # only report the first marketplace found


# --------------------------------------------------------------------------- #
# Report
# --------------------------------------------------------------------------- #

_FOOTER = ("NOTE: This is a STATIC scan. It did NOT execute the plugin, its hooks, "
           "scripts, binaries, workflows, monitors, or MCP servers.")


def format_report(findings, audited_plugins):
    counts = {HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0}
    for fi in findings:
        counts[fi.severity] = counts.get(fi.severity, 0) + 1

    lines = []
    if counts[HIGH]:
        verdict = "REVIEW - HIGH risk components found; do NOT enable until checked"
    elif counts[MEDIUM]:
        verdict = "CAUTION - medium-risk items to review before enabling"
    else:
        verdict = "OK - no high/medium-risk components detected (still review manually)"

    plugin_word = "plugin" if len(audited_plugins) == 1 else "plugins"
    lines.append("VERDICT: %s" % verdict)
    lines.append("Audited %d %s: %s" % (len(audited_plugins), plugin_word,
                                        ", ".join(audited_plugins) or "(none)"))
    lines.append("Findings: %d HIGH, %d MEDIUM, %d LOW, %d INFO"
                 % (counts[HIGH], counts[MEDIUM], counts[LOW], counts[INFO]))
    lines.append("")

    ordered = sorted(findings, key=lambda x: (SEV_ORDER.get(x.severity, 9),
                                              x.plugin, x.component))
    for sev in (HIGH, MEDIUM, LOW, INFO):
        group = [x for x in ordered if x.severity == sev]
        if not group:
            continue
        lines.append("== %s (%d) ==" % (sev, len(group)))
        for x in group:
            lines.append("  [%s] %s -> %s" % (x.plugin, x.component, x.message))
            if x.snippet:
                lines.append("        evidence: %s" % x.snippet)
        lines.append("")

    lines.append("-" * 70)
    lines.append(_FOOTER)
    lines.append("For live MCP tool-metadata / tool-poisoning, review this report first, then "
                 "run the separate mcp-auditor skill.")
    lines.append("Runtime/sandboxing behavior is NOT covered by this scan.")
    return "\n".join(lines)


# --------------------------------------------------------------------------- #
# Orchestration
# --------------------------------------------------------------------------- #

def run_audit(path: Path):
    findings = []
    audited = []

    if is_plugin(path):
        targets = [path]
    else:
        targets = [c for c in sorted(path.iterdir()) if c.is_dir() and is_plugin(c)] \
            if path.is_dir() else []

    if not targets:
        return ("No plugin found at %s (expected .claude-plugin/plugin.json or one of "
                "hooks/ skills/ commands/ agents/ bin/ workflows/ .mcp.json, or a "
                "directory of such plugins)." % path), 0

    for root in targets:
        manifest, _ = _load_json(root / ".claude-plugin" / "plugin.json", root)
        manifest = manifest if isinstance(manifest, dict) else {}
        pname = manifest.get("name") or root.name
        audited.append(pname)
        findings.extend(audit_plugin(root, manifest))

    _check_marketplace(path, findings, audited)

    report = format_report(findings, audited)
    exit_code = 1 if any(x.severity == HIGH for x in findings) else 0
    return report, exit_code


def main(argv=None):
    p = argparse.ArgumentParser(
        prog="plugin-auditor",
        description="Statically audit a Claude Code plugin bundle (read-only).")
    sub = p.add_subparsers(dest="cmd", required=True)
    a = sub.add_parser("audit", help="Audit a plugin or a directory of plugins.")
    a.add_argument("path", help="Path to a plugin bundle or a directory of plugins.")
    args = p.parse_args(argv)

    target = Path(args.path).expanduser()
    if not target.exists():
        print("Path does not exist: %s" % target)
        return 2

    report, code = run_audit(target)
    print(report)
    return code


if __name__ == "__main__":
    sys.exit(main())
