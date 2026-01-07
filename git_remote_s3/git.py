# SPDX-FileCopyrightText: 2023-present Amazon.com, Inc. or its affiliates
#
# SPDX-License-Identifier: Apache-2.0

import re
import subprocess
import sys


class GitError(Exception):
    pass


def archive(*, folder: str, ref: str) -> str:
    """Archive the content of the folder into a repo.zip file

    Args:
        folder (str): the folder to archive
        ref (str): the ref to archive

    Returns:
        str: the path to the archive file
    """

    file_path = f"{folder}/repo.zip"
    result = subprocess.run(
        ["git", "archive", "--format", "zip", "--output", file_path, ref],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=True,
    )

    if result.returncode == 0:
        return file_path
    else:
        raise GitError(result.stderr.decode("utf8"))


def bundle(*, folder: str, sha: str, ref: str, basis: str = None) -> str:
    """Bundles the content of the folder into a sha.bundle file

    Args:
        folder (str): the folder to bundle
        sha (str): the sha of the bundle. A bundle is stored as sha.bundle
        ref (str): the ref to bundle
        basis (str): optional basis sha - if provided, creates incremental bundle
                     excluding commits reachable from basis

    Returns:
        str: the path to the bundle file
    """
    file_path = f"{folder}/{sha}.bundle"
    cmd = ["git", "bundle", "create", file_path, ref]
    if basis:
        cmd.append(f"^{basis}")
    result = subprocess.run(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=True,
    )

    if result.returncode == 0:
        return file_path
    else:
        raise GitError(result.stderr.decode("utf8"))


def unbundle(*, bundle_path: str, ref: str):
    """Unbundles a bundle file.

    Args:
        bundle_path (str): full path to the bundle file
        ref (str): the ref to checkout after unbundling
    """
    subprocess.run(
        ["git", "bundle", "unbundle", bundle_path, ref],
        stdout=sys.stderr,
        check=True,
    )


def rev_parse(ref: str) -> str:
    """Gets the sha of a ref

    Args:
        ref (str): the ref to get the sha for

    Raises:
        Exception: if the ref is not found

    Returns:
        str: _description_
    """

    result = subprocess.run(["git", "rev-parse", ref], stdout=subprocess.PIPE)
    if result.returncode != 0:
        raise GitError(f"fatal: {ref} not found")
    sha = result.stdout.decode("utf8").strip()
    return sha


def is_ancestor(ancestor: str, descendant: str) -> bool:
    """Checks if the ancestor is an ancestor of the descendant

    Args:
        ancestor (str): the ancestor ref
        descendant (str): the descendant ref

    Returns:
        bool: true if the ancestor is an ancestor of the descendant
    """
    result = subprocess.run(
        ["git", "merge-base", "--is-ancestor", ancestor, descendant],
        stderr=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
    )
    return result.returncode == 0


def get_remote_url(remote: str) -> str:
    result = subprocess.run(
        ["git", "remote", "get-url", remote], stdout=subprocess.PIPE
    )
    if result.returncode != 0:
        raise GitError(f"fatal: {remote} not found")
    url = result.stdout.decode("utf8").strip()
    return url


# validate refname according to
# https://github.com/git/git/blob/406f326d271e0bacecdb00425422c5fa3f314930/refs.c#L170
def validate_ref_name(name: str) -> bool:
    return (
        re.search(
            r"(^\.)|(\.\.)|([:\?\[\\\^\~\s\*\]])|(\.lock$)|(/$)|(@\{)|([\x00-\x1f])",
            name,
        )
        is None
    )


def get_last_commit_message() -> str:
    result = subprocess.run(
        ["git", "log", "-1", "--pretty=%h %s"], stdout=subprocess.PIPE
    )
    if result.returncode != 0:
        raise GitError("fatal: an error as occurred")
    message = result.stdout.decode("utf8").strip()
    return message
