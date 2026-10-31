#!/usr/bin/env python3
"""Print the last N turns of the newest Grok session for this workspace.

Why this exists: a context compaction can leave an agent with the summary but
not the working thread. Running this script after compaction restores the recent
user instructions, tool activity and assistant reasoning so work continues in
the same direction instead of restarting.

Usage:
    python scripts/recall.py                 # last 20 turns, this workspace
    python scripts/recall.py --turns 40      # last 40
    python scripts/recall.py --session ID    # a specific session id
    python scripts/recall.py --list          # list recent sessions
    python scripts/recall.py --json          # machine-readable records

A turn is one user message plus the assistant messages and tool calls that
follow it. Long tool arguments are truncated; nothing here is sent anywhere.
"""

from __future__ import annotations

import argparse
import ast
import json
import os
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path


def grok_home() -> Path:
    override = os.environ.get("GROK_HOME")
    if override:
        return Path(override)
    return Path.home() / ".grok"


def escape_project(path: Path) -> str:
    """Grok escapes a project path into a session directory name."""
    text = str(path.resolve())
    return (
        text.replace("%", "%25")
        .replace(":", "%3A")
        .replace("\\", "%5C")
        .replace("/", "%2F")
    )


@dataclass
class Turn:
    index: int
    user: str = ""
    assistant: list[str] = field(default_factory=list)
    tools: list[str] = field(default_factory=list)

    def render(self, max_chars: int = 4000) -> str:
        parts = [f"=== turn {self.index} ==="]
        if self.user:
            parts.append("USER:\n" + truncate(self.user, max_chars))
        if self.assistant:
            parts.append(
                "ASSISTANT:\n" + truncate("\n".join(self.assistant), max_chars)
            )
        if self.tools:
            shown = self.tools[-12:]
            label = (
                "TOOLS"
                if len(self.tools) <= 12
                else f"TOOLS (last 12 of {len(self.tools)})"
            )
            parts.append(label + ": " + ", ".join(shown))
        return "\n\n".join(parts)


def truncate(text: str, limit: int) -> str:
    text = text.strip()
    if len(text) <= limit:
        return text
    return text[: limit - 20] + "\n… [truncated]"


REMINDER = re.compile(
    r"<(system-reminder|memory-context|goal-state|user_info|rules)>.*?</\1>", re.DOTALL
)
WRAPPERS = re.compile(r"</?user_query>")


def clean_user(text: str) -> str:
    """Grok stores user content as a Python literal list of content parts."""
    stripped = text.strip()
    if stripped.startswith("[") and "'type'" in stripped:
        try:
            parts = ast.literal_eval(stripped)
        except (ValueError, SyntaxError):
            parts = None
        if isinstance(parts, list):
            texts = [
                part.get("text", "")
                for part in parts
                if isinstance(part, dict) and part.get("type") == "text"
            ]
            text = "\n".join(texts)
    text = REMINDER.sub("", text)
    text = WRAPPERS.sub("", text)
    return text.strip()


def summarize_tool_call(call: dict) -> str:
    name = call.get("name", "tool")
    raw = call.get("arguments", "")
    try:
        args = json.loads(raw) if isinstance(raw, str) else raw
    except json.JSONDecodeError:
        return f"{name}({truncate(str(raw), 120)})"
    if isinstance(args, dict):
        command = args.get("command") or args.get("description") or ""
        if command:
            return f"{name}({truncate(str(command), 160)})"
    return f"{name}(...)"


def load_turns(history: Path, keep: int) -> list[Turn]:
    turns: list[Turn] = []
    current: Turn | None = None
    with history.open("r", encoding="utf-8", errors="replace") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                continue
            kind = record.get("type")
            if kind == "user":
                current = Turn(
                    index=len(turns) + 1,
                    user=clean_user(str(record.get("content", ""))),
                )
                turns.append(current)
            elif kind == "assistant":
                if current is None:
                    current = Turn(index=1)
                    turns.append(current)
                content = str(record.get("content", "")).strip()
                if content:
                    current.assistant.append(content)
                for call in record.get("tool_calls") or []:
                    current.tools.append(summarize_tool_call(call))
    return turns[-keep:]


def newest_session(root: Path) -> Path | None:
    if not root.is_dir():
        return None
    candidates = [
        child
        for child in root.iterdir()
        if child.is_dir() and (child / "chat_history.jsonl").is_file()
    ]
    if not candidates:
        return None
    return max(
        candidates, key=lambda path: (path / "chat_history.jsonl").stat().st_mtime
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--turns", type=int, default=20, help="how many turns to print")
    parser.add_argument(
        "--session", help="session id under the workspace session directory"
    )
    parser.add_argument(
        "--workspace", default=os.getcwd(), help="workspace path to look up"
    )
    parser.add_argument(
        "--list", action="store_true", help="list recent sessions and exit"
    )
    parser.add_argument("--json", action="store_true", help="emit JSON records")
    args = parser.parse_args()

    home = grok_home()
    workspace = Path(args.workspace).resolve()
    session_root = home / "sessions" / escape_project(workspace)

    # Grok keys sessions by the workspace the CLI was started in. A repository
    # inside that workspace (this repo) therefore looks up its parents until a
    # session directory exists.
    if not args.session and not (session_root / ".").is_dir():
        for parent in workspace.parents:
            candidate = home / "sessions" / escape_project(parent)
            if candidate.is_dir():
                session_root = candidate
                workspace = parent
                break

    if args.list:
        if not session_root.is_dir():
            print(f"no sessions for {workspace} under {session_root}", file=sys.stderr)
            return 1
        sessions = sorted(
            session_root.iterdir(),
            key=lambda path: (
                (path / "chat_history.jsonl").stat().st_mtime
                if (path / "chat_history.jsonl").is_file()
                else 0
            ),
            reverse=True,
        )
        for session in sessions:
            history = session / "chat_history.jsonl"
            if history.is_file():
                print(f"{session.name}\t{history.stat().st_size} bytes")
        return 0

    if args.session:
        session = session_root / args.session
    else:
        session = newest_session(session_root)
    if session is None or not (session / "chat_history.jsonl").is_file():
        print(
            f"no chat history for {workspace} ({session_root}); run from the project root "
            "or pass --workspace",
            file=sys.stderr,
        )
        return 1

    turns = load_turns(session / "chat_history.jsonl", max(1, args.turns))
    turns = [turn for turn in turns if turn.user or turn.assistant or turn.tools]
    if args.json:
        payload = [
            {
                "index": turn.index,
                "user": turn.user,
                "assistant": turn.assistant,
                "tools": turn.tools,
            }
            for turn in turns
        ]
        print(json.dumps(payload, indent=2))
        return 0

    print(f"session: {session}")
    print(f"turns: {len(turns)}")
    print()
    for turn in turns:
        print(turn.render())
        print()
    memory = home / "memory-v2" / "workspaces"
    if memory.is_dir():
        print("memory topics:")
        for topic in sorted(memory.glob("*/topics/*.md")):
            print(f"  {topic}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
