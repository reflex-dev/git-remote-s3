"""A push leaves nothing behind however it ends, and says why it failed."""

import os
import signal
import subprocess
import sys
import textwrap
import time
from unittest.mock import patch

import pytest

from git_remote_s3 import git
from git_remote_s3.enums import UriScheme
from git_remote_s3.remote import S3Remote, Terminated, main

SHA = "c105d19ba64965d2c9d3d3246e7269059ef8bb8a"
BRANCH = "refs/heads/main"


def _remote(session_client_mock):
    session_client_mock.return_value.list_objects_v2.return_value = {"Contents": []}
    return S3Remote(UriScheme.S3, None, "test_bucket", "test_prefix")


def _push_dirs(root):
    return [p for p in os.listdir(root) if p.startswith("git_remote_s3_push_")]


@pytest.fixture
def temp_root(tmp_path, monkeypatch):
    monkeypatch.setattr("tempfile.tempdir", str(tmp_path))
    return tmp_path


def _bundle_into(folder, sha, ref):
    path = f"{folder}/{sha}.bundle"
    with open(path, "wb") as f:
        f.write(b"x" * 1024)
    return path


@patch("git_remote_s3.git.rev_parse", return_value=SHA)
@patch("git_remote_s3.git.bundle", side_effect=_bundle_into)
@patch("boto3.Session.client")
def test_a_pushed_bundle_leaves_no_temp_dir(client, bundle, rev_parse, temp_root):
    s3_remote = _remote(client)

    assert s3_remote.cmd_push(f"push {BRANCH}:{BRANCH}") == f"ok {BRANCH}\n"

    assert _push_dirs(temp_root) == []


@patch("git_remote_s3.git.rev_parse", return_value=SHA)
@patch("git_remote_s3.git.bundle", side_effect=_bundle_into)
@patch("boto3.Session.client")
def test_a_terminated_upload_removes_the_bundle_and_releases_the_lock(
    client, bundle, rev_parse, temp_root
):
    s3_remote = _remote(client)
    client.return_value.upload_file.side_effect = Terminated()

    with pytest.raises(Terminated):
        s3_remote.cmd_push(f"push {BRANCH}:{BRANCH}")

    assert _push_dirs(temp_root) == []
    released = [
        c
        for c in client.return_value.delete_object.call_args_list
        if c.kwargs["Key"].endswith("LOCK#.lock")
    ]
    assert len(released) == 1


@patch("git_remote_s3.git.rev_parse", return_value=SHA)
@patch(
    "git_remote_s3.git.bundle",
    side_effect=git.BundleError(
        "fatal: sha1 file '/tmp/x.bundle.lock' write error: No space left on device\n"
    ),
)
@patch("boto3.Session.client")
def test_a_failed_bundle_reports_gits_reason(client, bundle, rev_parse, temp_root):
    s3_remote = _remote(client)

    res = s3_remote.cmd_push(f"push {BRANCH}:{BRANCH}")

    assert res.startswith(f"error {BRANCH} ")
    assert "No space left on device" in res
    # One protocol line: git reads the next line as the next ref's status.
    assert res.count("\n") == 1
    assert client.return_value.upload_file.call_count == 0
    assert _push_dirs(temp_root) == []


def test_bundle_raises_gits_own_stderr(tmp_path):
    repo = tmp_path / "repo"
    subprocess.run(["git", "init", "-q", str(repo)], check=True)
    subprocess.run(
        [
            "git",
            "-C",
            str(repo),
            "-c",
            "user.email=a@b",
            "-c",
            "user.name=a",
            "commit",
            "-q",
            "--allow-empty",
            "-m",
            "m",
        ],
        check=True,
    )
    cwd = os.getcwd()
    os.chdir(repo)
    try:
        with pytest.raises(git.BundleError) as raised:
            git.bundle(folder=str(tmp_path / "missing"), sha=SHA, ref="HEAD")
    finally:
        os.chdir(cwd)

    assert "fatal" in str(raised.value)


@patch("git_remote_s3.remote.S3Remote")
@patch(
    "git_remote_s3.remote.parse_git_url", return_value=(UriScheme.S3, None, "b", "p")
)
def test_main_exits_as_terminated(parse, remote, monkeypatch):
    monkeypatch.setattr(sys, "argv", ["git-remote-s3", "origin", "s3://b/p"])
    remote.side_effect = Terminated()
    previous = signal.getsignal(signal.SIGTERM)
    try:
        with pytest.raises(SystemExit) as exited:
            main()
    finally:
        signal.signal(signal.SIGTERM, previous)

    assert exited.value.code == 128 + signal.SIGTERM


def test_sigterm_runs_finally_blocks(tmp_path):
    """The real signal, not a raised exception: what timeout(1) actually sends."""
    marker = tmp_path / "bundle"
    ready = tmp_path / "ready"
    script = textwrap.dedent(f"""
        import os, signal, time
        from git_remote_s3.remote import _raise_terminated
        signal.signal(signal.SIGTERM, _raise_terminated)
        open({str(marker)!r}, "w").close()
        try:
            open({str(ready)!r}, "w").close()
            time.sleep(30)
        finally:
            os.remove({str(marker)!r})
        """)
    proc = subprocess.Popen([sys.executable, "-c", script])
    deadline = time.monotonic() + 10
    while not ready.exists() and time.monotonic() < deadline:
        time.sleep(0.05)

    proc.send_signal(signal.SIGTERM)
    proc.wait(timeout=10)

    assert not marker.exists()


@patch("git_remote_s3.git.is_ancestor", return_value=True)
@patch("git_remote_s3.git.rev_parse", return_value=SHA)
@patch("git_remote_s3.git.bundle", side_effect=_bundle_into)
@patch("boto3.Session.client")
def test_a_sigterm_after_the_upload_still_deletes_the_old_bundle(
    client, bundle, rev_parse, is_ancestor, temp_root
):
    """The kill that left 9a626ed1's main holding two bundles (2026-10-05)."""
    from git_remote_s3.remote import _raise_terminated

    s3_remote = _remote(client)
    old = {"Key": f"test_prefix/{BRANCH}/{'d' * 40}.bundle"}
    client.return_value.list_objects_v2.return_value = {"Contents": [old]}
    deleted = []

    def delete_object(Bucket, Key):
        if Key == old["Key"]:
            # The signal lands while the old bundle's delete is in flight.
            _raise_terminated(signal.SIGTERM, None)
        deleted.append(Key)

    client.return_value.delete_object.side_effect = delete_object
    previous = signal.getsignal(signal.SIGTERM)
    try:
        with pytest.raises(Terminated):
            s3_remote.cmd_push(f"push {BRANCH}:{BRANCH}")
    finally:
        signal.signal(signal.SIGTERM, previous)

    assert old["Key"] in deleted
    assert any(key.endswith("LOCK#.lock") for key in deleted)
    assert _push_dirs(temp_root) == []
