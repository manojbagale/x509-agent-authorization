import os
from pathlib import Path

import pytest

from agent_auth.tool_dispatch import FileToolDispatcher, ToolDispatchError


def request(resource, tool="file", action="read"):
    return {"tool": tool, "action": action, "resource": resource}


def test_read_resolves_logical_path_and_counts_only_completed_execution(tmp_path):
    (tmp_path / "nested").mkdir()
    (tmp_path / "nested" / "paper.txt").write_text("actual bytes")
    dispatcher = FileToolDispatcher(tmp_path)
    try:
        assert dispatcher.execute(request("/research/nested/paper.txt"))["content"] == "actual bytes"
        assert dispatcher.dispatch_count == 1
        for resource in ("/research/../secret", "/research/nested/../paper.txt", "/research//paper.txt", "/research-old/paper.txt", "research/paper.txt", "/research/paper\x00.txt"):
            with pytest.raises(ToolDispatchError):
                dispatcher.execute(request(resource))
        assert dispatcher.dispatch_count == 1
    finally:
        dispatcher.close()


def test_leaf_and_directory_symlinks_cannot_escape_root(tmp_path):
    root = tmp_path / "root"
    root.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "secret.txt").write_text("secret")
    (root / "leaf.txt").symlink_to(outside / "secret.txt")
    (root / "nested").symlink_to(outside, target_is_directory=True)
    dispatcher = FileToolDispatcher(root)
    try:
        for resource in ("/research/leaf.txt", "/research/nested/secret.txt"):
            with pytest.raises(ToolDispatchError):
                dispatcher.execute(request(resource))
        assert dispatcher.dispatch_count == 0
    finally:
        dispatcher.close()


def test_stable_root_descriptor_survives_path_replacement(tmp_path):
    root = tmp_path / "root"
    root.mkdir()
    (root / "paper.txt").write_text("original")
    dispatcher = FileToolDispatcher(root)
    root.rename(tmp_path / "original-root")
    root.mkdir()
    (root / "paper.txt").write_text("replacement")
    try:
        assert dispatcher.execute(request("/research/paper.txt"))["content"] == "original"
    finally:
        dispatcher.close()


def test_unsupported_tools_large_files_and_special_files_fail_closed(tmp_path):
    (tmp_path / "large.txt").write_bytes(b"12345")
    os.mkfifo(tmp_path / "fifo")
    dispatcher = FileToolDispatcher(tmp_path, max_bytes=4)
    try:
        for req in (request("/research/large.txt"), request("/research/fifo"), request("/research/large.txt", "shell", "execute"), request("/research/large.txt", action="write")):
            with pytest.raises(ToolDispatchError):
                dispatcher.execute(req)
        assert dispatcher.dispatch_count == 0
    finally:
        dispatcher.close()
