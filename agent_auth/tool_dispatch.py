"""A deliberately small server-owned file tool, not an agent sandbox.

The gateway authorizes a logical resource before dispatch. Dispatch independently
resolves that resource below a stable directory descriptor and never follows
symlinks. No tool for shell execution exists in this demonstration.
"""
from __future__ import annotations

import os
import posixpath
import stat
from pathlib import Path


class ToolDispatchError(Exception):
    pass


class FileToolDispatcher:
    def __init__(self, root: Path, *, max_bytes: int = 4096):
        self._root_fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        self.max_bytes = max_bytes
        self.dispatch_count = 0

    def close(self) -> None:
        if self._root_fd is not None:
            os.close(self._root_fd)
            self._root_fd = None

    def execute(self, request: dict[str, str]) -> dict:
        if request.get("tool") != "file" or request.get("action") != "read":
            raise ToolDispatchError("unsupported_tool_or_action")
        resource = request.get("resource")
        if not isinstance(resource, str) or "\x00" in resource:
            raise ToolDispatchError("invalid_resource")
        # Require a canonical spelling shared with the authorization request.
        # Parent components are rejected even if normalization stays in scope.
        parts = resource.split("/")
        if resource != posixpath.normpath(resource) or any(p in {".", ".."} for p in parts):
            raise ToolDispatchError("noncanonical_resource")
        if not resource.startswith("/research/"):
            raise ToolDispatchError("resource_outside_tool_root")
        relative = parts[2:]
        if not relative or any(not part for part in relative):
            raise ToolDispatchError("invalid_resource")
        directory_fd = os.dup(self._root_fd)
        file_fd = None
        try:
            for component in relative[:-1]:
                next_fd = os.open(
                    component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                    dir_fd=directory_fd,
                )
                os.close(directory_fd)
                directory_fd = next_fd
            # NONBLOCK avoids hanging if an attacker substitutes a FIFO.
            file_fd = os.open(
                relative[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
                dir_fd=directory_fd,
            )
            if not stat.S_ISREG(os.fstat(file_fd).st_mode):
                raise ToolDispatchError("resource_not_regular_file")
            chunks = []
            remaining = self.max_bytes + 1
            while remaining:
                chunk = os.read(file_fd, remaining)
                if not chunk:
                    break
                chunks.append(chunk)
                remaining -= len(chunk)
            data = b"".join(chunks)
            if len(data) > self.max_bytes:
                raise ToolDispatchError("file_too_large")
            content = data.decode("utf-8")
            self.dispatch_count += 1
            return {"content": content, "bytes_read": len(data), "resource": resource}
        except (OSError, UnicodeError) as exc:
            raise ToolDispatchError("file_access_denied") from exc
        finally:
            if file_fd is not None:
                os.close(file_fd)
            os.close(directory_fd)
