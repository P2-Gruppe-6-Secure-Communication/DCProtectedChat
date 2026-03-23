"""
Group state management for pairwise fan-out group messaging.

Groups are identified by a UUID and stored locally as JSON files.
No server-side group concept exists — the group_id is included in
every envelope so recipients can route incoming messages to the
correct conversation.

Disk layout:
  ~/.p2chat/<device_id>/groups/<group_id>.json
"""

from __future__ import annotations

import json
import time
import uuid
from pathlib import Path

_DATA_ROOT = Path.home() / ".p2chat"


def _groups_dir(device_id: str) -> Path:
    return _DATA_ROOT / device_id / "groups"


def _group_path(device_id: str, group_id: str) -> Path:
    return _groups_dir(device_id) / f"{group_id}.json"


def create_group(device_id: str, name: str, members: list[str]) -> dict:
    """
    Create a new group, persist it, and return the group dict.

    `members` should include the other participants. The local device_id
    is always added automatically. Raises ValueError on invalid input.
    """
    name = name.strip()
    if not name:
        raise ValueError("Group name cannot be empty")

    member_set = {m.strip() for m in members if m.strip()}
    member_set.add(device_id)
    if len(member_set) < 2:
        raise ValueError("A group needs at least one other member")

    group = {
        "group_id": str(uuid.uuid4()),
        "name": name,
        "members": sorted(member_set),
        "created_at_ms": int(time.time() * 1000),
    }
    save_group(device_id, group)
    return group


def save_group(device_id: str, group: dict) -> None:
    """Persist a group dict to disk (create or overwrite)."""
    path = _group_path(device_id, group["group_id"])
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(group, indent=2), encoding="utf-8")


def load_group(device_id: str, group_id: str) -> dict | None:
    """Load a single group by ID. Returns None if not found."""
    path = _group_path(device_id, group_id)
    if not path.exists():
        return None
    return json.loads(path.read_text(encoding="utf-8"))


def list_groups(device_id: str) -> list[dict]:
    """Return all groups for device_id, sorted by created_at_ms ascending."""
    d = _groups_dir(device_id)
    if not d.exists():
        return []
    groups = []
    for p in d.glob("*.json"):
        try:
            groups.append(json.loads(p.read_text(encoding="utf-8")))
        except Exception:
            pass  # corrupt file — skip silently
    return sorted(groups, key=lambda g: g.get("created_at_ms", 0))


def add_member(device_id: str, group_id: str, new_member: str) -> dict:
    """
    Add new_member to an existing group. Returns the updated group dict.
    Raises ValueError if the group does not exist.
    """
    group = load_group(device_id, group_id)
    if group is None:
        raise ValueError(f"Group {group_id!r} not found")
    new_member = new_member.strip()
    if not new_member:
        raise ValueError("Member ID cannot be empty")
    members = set(group["members"])
    members.add(new_member)
    group["members"] = sorted(members)
    save_group(device_id, group)
    return group
