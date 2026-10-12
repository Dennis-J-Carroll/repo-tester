"""Resolve installed npm package identities from package-lock v2/v3 data."""

from __future__ import annotations

import json
from collections import deque
from dataclasses import dataclass


@dataclass(frozen=True)
class LockedPackage:
    name: str
    version: str
    lock_path: str
    chain: tuple[str, ...]

    @property
    def direct(self) -> bool:
        return len(self.chain) == 1


def parse_npm_lock(manifest_text: str, lock_text: str) -> tuple[list[LockedPackage], list[str]]:
    """Return reachable lock entries and limits on their reliability.

    Resolve each dependency using Node's nearest-node_modules lookup. An entry
    present in a lockfile but unreachable from its root is not an installed
    dependency for this scan.
    """
    try:
        manifest = json.loads(manifest_text)
        lock = json.loads(lock_text)
    except (TypeError, ValueError) as exc:
        return [], [f"Invalid npm manifest or lockfile: {exc}"]
    if not isinstance(manifest, dict) or not isinstance(lock, dict):
        return [], ["Invalid npm manifest or lockfile: expected JSON objects"]
    if lock.get("lockfileVersion") not in (2, 3):
        return [], ["Unsupported npm lockfile version; only v2/v3 are resolved"]
    packages = lock.get("packages")
    if not isinstance(packages, dict) or not isinstance(packages.get(""), dict):
        return [], ["npm lockfile has no root packages entry"]

    warnings: list[str] = []
    root = packages[""]
    kinds = ("dependencies", "devDependencies", "optionalDependencies")
    declared: dict[str, str] = {}
    locked_specs: dict[str, str] = {}
    for kind in kinds:
        if isinstance(manifest.get(kind), dict):
            declared.update(manifest[kind])
        if isinstance(root.get(kind), dict):
            locked_specs.update(root[kind])
    if declared != locked_specs:
        warnings.append("package.json and package-lock.json root dependency specs differ; lockfile may be stale")

    def resolve(parent: str, name: str) -> str | None:
        current = parent
        while True:
            candidate = f"{current}/node_modules/{name}" if current else f"node_modules/{name}"
            if candidate in packages:
                return candidate
            if not current:
                return None
            current = current.rpartition("/node_modules/")[0] if "/node_modules/" in current else ""

    queue: deque[tuple[str, str, tuple[str, ...]]] = deque()
    for name in locked_specs:
        if isinstance(name, str):
            queue.append(("", name, (name,)))
    seen: set[str] = set()
    result: list[LockedPackage] = []
    missing: set[str] = set()
    while queue:
        parent, name, chain = queue.popleft()
        path = resolve(parent, name)
        if path is None:
            missing.add(name)
            continue
        if path in seen:
            continue
        seen.add(path)
        entry = packages[path]
        if not isinstance(entry, dict):
            continue
        version = entry.get("version")
        if isinstance(version, str) and version and not entry.get("link"):
            # npm aliases keep their real name in package metadata when present.
            package_name = entry.get("name") or path.rsplit("node_modules/", 1)[-1]
            if isinstance(package_name, str):
                result.append(LockedPackage(package_name, version, path, chain))
        for kind in ("dependencies", "optionalDependencies"):
            children = entry.get(kind, {})
            if isinstance(children, dict):
                for child in children:
                    if isinstance(child, str):
                        queue.append((path, child, (*chain, child)))
    if missing:
        warnings.append(f"{len(missing)} dependency names in lockfile could not be resolved")
    return result, warnings
