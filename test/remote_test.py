import datetime
import json
import tempfile
import threading
from io import BytesIO, StringIO

import botocore
import botocore.client
from botocore.exceptions import ClientError
from mock import patch

from git_remote_s3 import S3Remote, UriScheme

SHA1 = "c105d19ba64965d2c9d3d3246e7269059ef8bb8a"
SHA2 = "c105d19ba64965d2c9d3d3246e7269059ef8bb8b"
SHA3 = "c105d19ba64965d2c9d3d3246e7269059ef8bb8c"
INVALID_SHA = "z45"
BUNDLE_SUFFIX = ".bundle"
MOCK_BUNDLE_CONTENT = b"MOCK_BUNDLE_CONTENT"
ARCHIVE_SUFFIX = ".zip"
MOCK_ARCHIVE_CONTENT = b"MOCK_ARCHIVE_CONTENT"
BRANCH = "pytest"


def create_list_objects_v2_mock(
    *,
    protected=False,
    no_head=False,
    branch=BRANCH,
    shas,
):
    def s3_list_objects_v2_mock(Prefix, **kwargs):
        content = []
        for s in shas:
            content.append(
                {
                    "Key": f"test_prefix/refs/heads/{branch}/{s}.bundle",
                    "LastModified": datetime.datetime.now(),
                }
            )
        if protected:
            content.append(
                {
                    "Key": f"test_prefix/refs/heads/{branch}/PROTECTED#",
                    "LastModified": datetime.datetime.now(),
                }
            )
        if not no_head:
            content.append(
                {
                    "Key": "test_prefix/HEAD",
                    "LastModified": datetime.datetime.now(),
                }
            )
        return {
            "Contents": [c for c in content if c["Key"].startswith(Prefix)],
            "NextContinuationToken": None,
        }

    return s3_list_objects_v2_mock


def create_get_object_no_manifest_mock(branch=BRANCH):
    """Mock get_object that returns NoSuchKey for manifest (legacy mode)."""

    def get_object_side_effect(Bucket, Key):
        if Key.endswith("manifest.json"):
            raise ClientError({"Error": {"Code": "NoSuchKey"}}, "get_object")
        if Key.endswith("/HEAD"):
            return {"Body": BytesIO(f"refs/heads/{branch}".encode("utf-8"))}
        raise ClientError({"Error": {"Code": "NoSuchKey"}}, "get_object")

    return get_object_side_effect


@patch("sys.stdout", new_callable=StringIO)
@patch("boto3.Session.client")
def test_cmd_list(session_client_mock, stdout_mock):
    s3_remote = S3Remote(UriScheme.S3, None, "test_bucket", "test_prefix")

    session_client_mock.return_value.list_objects_v2.side_effect = (
        create_list_objects_v2_mock(shas=[SHA1])
    )
    session_client_mock.assert_called_once_with("s3")
    assert s3_remote.bucket == "test_bucket"
    assert s3_remote.prefix == "test_prefix"
    assert s3_remote.s3 == session_client_mock.return_value
    session_client_mock.return_value.get_object.return_value = {
        "Body": BytesIO(b"refs/heads/%b" % str.encode(BRANCH))
    }
    s3_remote.cmd_list()
    assert (
        f"@refs/heads/{BRANCH} HEAD\n{SHA1} refs/heads/{BRANCH}\n\n"
        == stdout_mock.getvalue()
    )


@patch("sys.stdout", new_callable=StringIO)
@patch("boto3.Session.client")
def test_list_refs(session_client_mock, stdout_mock):
    s3_remote = S3Remote(UriScheme.S3, None, "test_bucket", "nested/test_prefix")

    session_client_mock.return_value.list_objects_v2.return_value = {
        "Contents": [
            {
                "Key": f"nested/test_prefix/refs/heads/{BRANCH}/{SHA1}.bundle",
                "LastModified": datetime.datetime.now(),
            },
            {
                "Key": f"nested/test_prefix/refs/tags/v1/{SHA1}.bundle",
                "LastModified": datetime.datetime.now(),
            },
        ]
    }

    session_client_mock.assert_called_once_with("s3")
    assert s3_remote.bucket == "test_bucket"
    assert s3_remote.prefix == "nested/test_prefix"
    assert s3_remote.s3 == session_client_mock.return_value
    refs = s3_remote.list_refs(bucket=s3_remote.bucket, prefix=s3_remote.prefix)
    assert len(refs) == 2
    assert f"refs/heads/{BRANCH}/{SHA1}.bundle" in refs
    assert f"refs/tags/v1/{SHA1}.bundle" in refs


@patch("sys.stdout", new_callable=StringIO)
@patch("boto3.Session.client")
def test_cmd_list_nested_prefix(session_client_mock, stdout_mock):
    s3_remote = S3Remote(UriScheme.S3, None, "test_bucket", "nested/test_prefix")

    session_client_mock.return_value.list_objects_v2.return_value = {
        "Contents": [
            {
                "Key": f"nested/test_prefix/refs/heads/{BRANCH}/{SHA1}.bundle",
                "LastModified": datetime.datetime.now(),
            },
            {
                "Key": "nested/test_prefix/HEAD",
                "LastModified": datetime.datetime.now(),
            },
        ]
    }
    session_client_mock.assert_called_once_with("s3")
    assert s3_remote.bucket == "test_bucket"
    assert s3_remote.prefix == "nested/test_prefix"
    assert s3_remote.s3 == session_client_mock.return_value
    session_client_mock.return_value.get_object.return_value = {
        "Body": BytesIO(b"refs/heads/%b" % str.encode(BRANCH))
    }
    s3_remote.cmd_list()
    assert (
        f"@refs/heads/{BRANCH} HEAD\n{SHA1} refs/heads/{BRANCH}\n\n"
        == stdout_mock.getvalue()
    )


@patch("sys.stdout", new_callable=StringIO)
@patch("boto3.Session.client")
def test_cmd_list_no_head(session_client_mock, stdout_mock):
    s3_remote = S3Remote(UriScheme.S3, None, "test_bucket", "test_prefix")

    session_client_mock.return_value.list_objects_v2.side_effect = (
        create_list_objects_v2_mock(shas=[SHA1], no_head=True)
    )

    def error(**kwargs):
        raise botocore.exceptions.ClientError(
            {"Error": {"Code": "NoSuchKey"}}, "get_object"
        )

    session_client_mock.return_value.get_object.side_effect = error
    session_client_mock.assert_called_once_with("s3")
    assert s3_remote.bucket == "test_bucket"
    assert s3_remote.prefix == "test_prefix"
    assert s3_remote.s3 == session_client_mock.return_value
    s3_remote.cmd_list()
    assert f"{SHA1} refs/heads/{BRANCH}\n\n" == stdout_mock.getvalue()


@patch("sys.stdout", new_callable=StringIO)
@patch("boto3.Session.client")
def test_cmd_list_with_head_not_exsting_ref(session_client_mock, stdout_mock):
    s3_remote = S3Remote(UriScheme.S3, None, "test_bucket", "test_prefix")

    session_client_mock.return_value.list_objects_v2.side_effect = (
        create_list_objects_v2_mock(shas=[SHA1])
    )
    session_client_mock.return_value.get_object.return_value = {
        "Body": BytesIO(b"refs/heads/master")
    }
    session_client_mock.assert_called_once_with("s3")
    assert s3_remote.bucket == "test_bucket"
    assert s3_remote.prefix == "test_prefix"
    assert s3_remote.s3 == session_client_mock.return_value
    s3_remote.cmd_list()
    assert f"{SHA1} refs/heads/{BRANCH}\n\n" == stdout_mock.getvalue()


@patch("sys.stdout", new_callable=StringIO)
@patch("boto3.Session.client")
def test_cmd_list_protected_branch(session_client_mock, stdout_mock):
    s3_remote = S3Remote(UriScheme.S3, None, "test_bucket", "test_prefix")

    session_client_mock.return_value.list_objects_v2.side_effect = (
        create_list_objects_v2_mock(protected=True, shas=[SHA1])
    )

    session_client_mock.return_value.get_object.return_value = {
        "Body": BytesIO(b"refs/heads/%b" % str.encode(BRANCH))
    }
    session_client_mock.assert_called_once_with("s3")
    assert s3_remote.bucket == "test_bucket"
    assert s3_remote.prefix == "test_prefix"
    assert s3_remote.s3 == session_client_mock.return_value
    s3_remote.cmd_list()
    assert (
        f"@refs/heads/{BRANCH} HEAD\n{SHA1} refs/heads/{BRANCH}\n\n"
        == stdout_mock.getvalue()
    )


@patch("git_remote_s3.git.is_ancestor")
@patch("git_remote_s3.git.rev_parse")
@patch("git_remote_s3.git.bundle")
@patch("boto3.Session.client")
def test_cmd_push_no_force_unprotected_ancestor(
    session_client_mock, bundle_mock, rev_parse_mock, is_ancestor_mock
):
    s3_remote = S3Remote(UriScheme.S3, None, "test_bucket", "test_prefix")
    rev_parse_mock.return_value = SHA1
    temp_dir = tempfile.mkdtemp("test_temp")
    temp_file = tempfile.NamedTemporaryFile(dir=temp_dir, suffix=BUNDLE_SUFFIX)
    with open(temp_file.name, "wb") as f:
        f.write(MOCK_BUNDLE_CONTENT)
    bundle_mock.return_value = temp_file.name
    session_client_mock.return_value.list_objects_v2.side_effect = (
        create_list_objects_v2_mock(protected=True, shas=[SHA1])
    )
    session_client_mock.return_value.get_object.side_effect = (
        create_get_object_no_manifest_mock()
    )
    is_ancestor_mock.return_value = True
    assert s3_remote.s3 == session_client_mock.return_value
    res = s3_remote.cmd_push(f"push refs/heads/{BRANCH}:refs/heads/{BRANCH}")
    put_calls = [
        c
        for c in session_client_mock.return_value.put_object.call_args_list
        if not c.kwargs["Key"].endswith(".lock")
    ]
    assert len(put_calls) == 2  # bundle + manifest
    del_calls = [
        c
        for c in session_client_mock.return_value.delete_object.call_args_list
        if not c.kwargs["Key"].endswith(".lock")
    ]
    assert len(del_calls) == 1
    assert res == (f"ok refs/heads/{BRANCH}\n")


@patch("git_remote_s3.git.archive")
@patch("git_remote_s3.git.is_ancestor")
@patch("git_remote_s3.git.rev_parse")
@patch("git_remote_s3.git.bundle")
@patch("boto3.Session.client")
def test_cmd_push_no_force_unprotected_ancestor_s3_zip(
    session_client_mock, bundle_mock, rev_parse_mock, is_ancestor_mock, archive_mock
):
    s3_remote = S3Remote(UriScheme.S3_ZIP, None, "test_bucket", "test_prefix")
    rev_parse_mock.return_value = SHA1

    temp_dir = tempfile.mkdtemp("test_temp")
    temp_file = tempfile.NamedTemporaryFile(dir=temp_dir, suffix=BUNDLE_SUFFIX)
    with open(temp_file.name, "wb") as f:
        f.write(MOCK_BUNDLE_CONTENT)
    bundle_mock.return_value = temp_file.name

    temp_file_archive = tempfile.NamedTemporaryFile(dir=temp_dir, suffix=ARCHIVE_SUFFIX)
    with open(temp_file_archive.name, "wb") as f:
        f.write(MOCK_ARCHIVE_CONTENT)
    archive_mock.return_value = temp_file_archive.name

    session_client_mock.return_value.list_objects_v2.side_effect = (
        create_list_objects_v2_mock(protected=True, shas=[SHA1])
    )
    session_client_mock.return_value.get_object.side_effect = (
        create_get_object_no_manifest_mock()
    )

    is_ancestor_mock.return_value = True

    assert s3_remote.s3 == session_client_mock.return_value

    res = s3_remote.cmd_push(f"push refs/heads/{BRANCH}:refs/heads/{BRANCH}")
    put_calls = [
        c
        for c in session_client_mock.return_value.put_object.call_args_list
        if not c.kwargs["Key"].endswith(".lock")
    ]
    assert len(put_calls) == 3  # bundle + manifest + zip
    del_calls = [
        c
        for c in session_client_mock.return_value.delete_object.call_args_list
        if not c.kwargs["Key"].endswith(".lock")
    ]
    assert len(del_calls) == 1
    assert res == (f"ok refs/heads/{BRANCH}\n")


@patch("git_remote_s3.git.is_ancestor")
@patch("git_remote_s3.git.rev_parse")
@patch("git_remote_s3.git.bundle")
@patch("boto3.Session.client")
def test_cmd_push_no_force_unprotected_no_ancestor(
    session_client_mock, bundle_mock, rev_parse_mock, is_ancestor_mock
):
    s3_remote = S3Remote(UriScheme.S3, None, "test_bucket", "test_prefix")
    rev_parse_mock.return_value = SHA1
    temp_dir = tempfile.mkdtemp("test_temp")
    temp_file = tempfile.NamedTemporaryFile(dir=temp_dir, suffix=BUNDLE_SUFFIX)
    with open(temp_file.name, "wb") as f:
        f.write(MOCK_BUNDLE_CONTENT)
    bundle_mock.return_value = temp_file.name
    session_client_mock.return_value.list_objects_v2.side_effect = (
        create_list_objects_v2_mock(shas=[SHA2])
    )
    session_client_mock.return_value.get_object.side_effect = (
        create_get_object_no_manifest_mock()
    )

    is_ancestor_mock.return_value = False
    assert s3_remote.s3 == session_client_mock.return_value
    res = s3_remote.cmd_push(f"push refs/heads/{BRANCH}:refs/heads/{BRANCH}")
    put_calls = [
        c
        for c in session_client_mock.return_value.put_object.call_args_list
        if not c.kwargs.get("Key", "").endswith(".lock")
    ]
    assert len(put_calls) == 0
    del_calls = [
        c
        for c in session_client_mock.return_value.delete_object.call_args_list
        if not c.kwargs["Key"].endswith(".lock")
    ]
    assert len(del_calls) == 0
    assert res.startswith("error")


@patch("git_remote_s3.git.is_ancestor")
@patch("git_remote_s3.git.rev_parse")
@patch("git_remote_s3.git.bundle")
@patch("boto3.Session.client")
def test_cmd_push_force_no_ancestor(
    session_client_mock, bundle_mock, rev_parse_mock, is_ancestor_mock
):
    s3_remote = S3Remote(UriScheme.S3, None, "test_bucket", "test_prefix")
    rev_parse_mock.return_value = SHA1
    temp_dir = tempfile.mkdtemp("test_temp")
    temp_file = tempfile.NamedTemporaryFile(dir=temp_dir, suffix=BUNDLE_SUFFIX)
    with open(temp_file.name, "wb") as f:
        f.write(MOCK_BUNDLE_CONTENT)
    bundle_mock.return_value = temp_file.name
    session_client_mock.return_value.list_objects_v2.side_effect = (
        create_list_objects_v2_mock(shas=[SHA2])
    )
    session_client_mock.return_value.get_object.side_effect = (
        create_get_object_no_manifest_mock()
    )
    is_ancestor_mock.return_value = False
    assert s3_remote.s3 == session_client_mock.return_value
    res = s3_remote.cmd_push(f"push +refs/heads/{BRANCH}:refs/heads/{BRANCH}")
    put_calls = [
        c
        for c in session_client_mock.return_value.put_object.call_args_list
        if not c.kwargs["Key"].endswith(".lock")
    ]
    assert len(put_calls) == 2  # bundle + manifest
    del_calls = [
        c
        for c in session_client_mock.return_value.delete_object.call_args_list
        if not c.kwargs["Key"].endswith(".lock")
    ]
    assert len(del_calls) == 1
    assert res.startswith("ok")


@patch("git_remote_s3.git.archive")
@patch("git_remote_s3.git.is_ancestor")
@patch("git_remote_s3.git.rev_parse")
@patch("git_remote_s3.git.bundle")
@patch("boto3.Session.client")
def test_cmd_push_force_no_ancestor_s3_zip(
    session_client_mock, bundle_mock, rev_parse_mock, is_ancestor_mock, archive_mock
):
    s3_remote = S3Remote(UriScheme.S3_ZIP, None, "test_bucket", "test_prefix")

    rev_parse_mock.return_value = SHA1

    temp_dir = tempfile.mkdtemp("test_temp")
    temp_file = tempfile.NamedTemporaryFile(dir=temp_dir, suffix=BUNDLE_SUFFIX)
    with open(temp_file.name, "wb") as f:
        f.write(MOCK_BUNDLE_CONTENT)
    bundle_mock.return_value = temp_file.name

    temp_file_archive = tempfile.NamedTemporaryFile(dir=temp_dir, suffix=ARCHIVE_SUFFIX)
    with open(temp_file_archive.name, "wb") as f:
        f.write(MOCK_ARCHIVE_CONTENT)
    archive_mock.return_value = temp_file_archive.name

    session_client_mock.return_value.list_objects_v2.side_effect = (
        create_list_objects_v2_mock(shas=[SHA2])
    )
    session_client_mock.return_value.get_object.side_effect = (
        create_get_object_no_manifest_mock()
    )

    is_ancestor_mock.return_value = False

    assert s3_remote.s3 == session_client_mock.return_value

    res = s3_remote.cmd_push(f"push +refs/heads/{BRANCH}:refs/heads/{BRANCH}")
    put_calls = [
        c
        for c in session_client_mock.return_value.put_object.call_args_list
        if not c.kwargs["Key"].endswith(".lock")
    ]
    assert len(put_calls) == 3  # bundle + manifest + zip
    del_calls = [
        c
        for c in session_client_mock.return_value.delete_object.call_args_list
        if not c.kwargs["Key"].endswith(".lock")
    ]
    assert len(del_calls) == 1
    assert res.startswith("ok")


@patch("git_remote_s3.git.is_ancestor")
@patch("git_remote_s3.git.rev_parse")
@patch("git_remote_s3.git.bundle")
@patch("boto3.Session.client")
def test_cmd_push_force_no_ancestor_protected(
    session_client_mock, bundle_mock, rev_parse_mock, is_ancestor_mock
):
    s3_remote = S3Remote(UriScheme.S3, None, "test_bucket", "test_prefix")
    rev_parse_mock.return_value = SHA1
    temp_dir = tempfile.mkdtemp("test_temp")
    temp_file = tempfile.NamedTemporaryFile(dir=temp_dir, suffix=BUNDLE_SUFFIX)
    with open(temp_file.name, "wb") as f:
        f.write(MOCK_BUNDLE_CONTENT)
    bundle_mock.return_value = temp_file.name
    session_client_mock.return_value.list_objects_v2.side_effect = (
        create_list_objects_v2_mock(protected=True, shas=[SHA2])
    )
    session_client_mock.return_value.get_object.side_effect = (
        create_get_object_no_manifest_mock()
    )
    is_ancestor_mock.return_value = False
    assert s3_remote.s3 == session_client_mock.return_value
    res = s3_remote.cmd_push(f"push +refs/heads/{BRANCH}:refs/heads/{BRANCH}")
    put_calls = [
        c
        for c in session_client_mock.return_value.put_object.call_args_list
        if not c.kwargs["Key"].endswith(".lock")
    ]
    assert len(put_calls) == 0
    del_calls = [
        c
        for c in session_client_mock.return_value.delete_object.call_args_list
        if not c.kwargs["Key"].endswith(".lock")
    ]
    assert len(del_calls) == 0
    assert res.startswith("error")


@patch("git_remote_s3.git.is_ancestor")
@patch("git_remote_s3.git.rev_parse")
@patch("git_remote_s3.git.bundle")
@patch("boto3.Session.client")
def test_cmd_push_empty_bucket(
    session_client_mock, bundle_mock, rev_parse_mock, is_ancestor_mock
):
    s3_remote = S3Remote(UriScheme.S3, None, "test_bucket", "test_prefix")
    rev_parse_mock.return_value = SHA1
    temp_dir = tempfile.mkdtemp("test_temp")
    temp_file = tempfile.NamedTemporaryFile(dir=temp_dir, suffix=BUNDLE_SUFFIX)
    with open(temp_file.name, "wb") as f:
        f.write(MOCK_BUNDLE_CONTENT)
    bundle_mock.return_value = temp_file.name

    session_client_mock.return_value.head_object.side_effect = ClientError(
        {"Error": {"Code": "NoSuchKey"}}, "head_object"
    )
    session_client_mock.return_value.get_object.side_effect = (
        create_get_object_no_manifest_mock()
    )

    is_ancestor_mock.return_value = False
    assert s3_remote.s3 == session_client_mock.return_value
    res = s3_remote.cmd_push(f"push refs/heads/{BRANCH}:refs/heads/{BRANCH}")
    put_calls = [
        c
        for c in session_client_mock.return_value.put_object.call_args_list
        if not c.kwargs["Key"].endswith(".lock")
    ]
    assert len(put_calls) == 3  # bundle + manifest + HEAD
    del_calls = [
        c
        for c in session_client_mock.return_value.delete_object.call_args_list
        if not c.kwargs["Key"].endswith(".lock")
    ]
    assert len(del_calls) == 0
    assert res.startswith("ok")


@patch("git_remote_s3.git.archive")
@patch("git_remote_s3.git.is_ancestor")
@patch("git_remote_s3.git.rev_parse")
@patch("git_remote_s3.git.bundle")
@patch("boto3.Session.client")
def test_cmd_push_empty_bucket_s3_zip(
    session_client_mock,
    bundle_mock,
    rev_parse_mock,
    is_ancestor_mock,
    archive_mock,
):
    s3_remote = S3Remote(UriScheme.S3_ZIP, None, "test_bucket", "test_prefix")

    rev_parse_mock.return_value = SHA1

    temp_dir = tempfile.mkdtemp("test_temp")
    temp_file = tempfile.NamedTemporaryFile(dir=temp_dir, suffix=BUNDLE_SUFFIX)
    with open(temp_file.name, "wb") as f:
        f.write(MOCK_BUNDLE_CONTENT)
    bundle_mock.return_value = temp_file.name

    temp_file_archive = tempfile.NamedTemporaryFile(dir=temp_dir, suffix=ARCHIVE_SUFFIX)
    with open(temp_file_archive.name, "wb") as f:
        f.write(MOCK_ARCHIVE_CONTENT)
    archive_mock.return_value = temp_file_archive.name

    session_client_mock.return_value.head_object.side_effect = ClientError(
        {"Error": {"Code": "NoSuchKey"}}, "head_object"
    )
    session_client_mock.return_value.get_object.side_effect = (
        create_get_object_no_manifest_mock()
    )

    is_ancestor_mock.return_value = False

    assert s3_remote.s3 == session_client_mock.return_value

    res = s3_remote.cmd_push(f"push refs/heads/{BRANCH}:refs/heads/{BRANCH}")
    put_calls = [
        c
        for c in session_client_mock.return_value.put_object.call_args_list
        if not c.kwargs["Key"].endswith(".lock")
    ]
    assert len(put_calls) == 4  # bundle + manifest + zip + HEAD
    del_calls = [
        c
        for c in session_client_mock.return_value.delete_object.call_args_list
        if not c.kwargs["Key"].endswith(".lock")
    ]
    assert len(del_calls) == 0
    assert res.startswith("ok")


@patch("git_remote_s3.git.archive")
@patch("git_remote_s3.git.is_ancestor")
@patch("git_remote_s3.git.rev_parse")
@patch("git_remote_s3.git.bundle")
@patch("git_remote_s3.git.get_last_commit_message")
@patch("boto3.Session.client")
def test_cmd_push_s3_zip_put_object_params(
    session_client_mock,
    get_last_commit_message_mock,
    bundle_mock,
    rev_parse_mock,
    is_ancestor_mock,
    archive_mock,
):
    s3_remote = S3Remote(UriScheme.S3_ZIP, None, "test_bucket", "test_prefix")
    rev_parse_mock.return_value = SHA1
    get_last_commit_message_mock.return_value = "test commit message"

    temp_dir = tempfile.mkdtemp("test_temp")
    temp_file = tempfile.NamedTemporaryFile(dir=temp_dir, suffix=BUNDLE_SUFFIX)
    with open(temp_file.name, "wb") as f:
        f.write(MOCK_BUNDLE_CONTENT)
    bundle_mock.return_value = temp_file.name

    temp_file_archive = tempfile.NamedTemporaryFile(dir=temp_dir, suffix=ARCHIVE_SUFFIX)
    with open(temp_file_archive.name, "wb") as f:
        f.write(MOCK_ARCHIVE_CONTENT)
    archive_mock.return_value = temp_file_archive.name

    session_client_mock.return_value.list_objects_v2.side_effect = (
        create_list_objects_v2_mock(shas=[SHA2])
    )
    session_client_mock.return_value.get_object.side_effect = (
        create_get_object_no_manifest_mock()
    )

    is_ancestor_mock.return_value = True

    s3_remote.cmd_push(f"push refs/heads/{BRANCH}:refs/heads/{BRANCH}")

    put_object_calls = [
        c
        for c in session_client_mock.return_value.put_object.call_args_list
        if not c.kwargs["Key"].endswith(".lock")
    ]
    assert len(put_object_calls) == 3  # bundle + manifest + zip

    # Check bundle upload
    bundle_call = put_object_calls[0]
    assert bundle_call.kwargs["Bucket"] == "test_bucket"
    assert bundle_call.kwargs["Key"].endswith(".bundle")

    # Check zip upload (after manifest)
    zip_call = put_object_calls[2]
    assert zip_call.kwargs["Bucket"] == "test_bucket"
    assert zip_call.kwargs["Key"].endswith("repo.zip")
    assert (
        zip_call.kwargs["Metadata"]["codepipeline-artifact-revision-summary"]
        == "test commit message"
    )


@patch("git_remote_s3.git.is_ancestor")
@patch("git_remote_s3.git.rev_parse")
@patch("git_remote_s3.git.bundle")
@patch("boto3.Session.client")
def test_cmd_push_multiple_heads(
    session_client_mock, bundle_mock, rev_parse_mock, is_ancestor_mock
):
    s3_remote = S3Remote(UriScheme.S3, None, "test_bucket", "test_prefix")
    rev_parse_mock.return_value = SHA1
    temp_dir = tempfile.mkdtemp("test_temp")
    temp_file = tempfile.NamedTemporaryFile(dir=temp_dir, suffix=BUNDLE_SUFFIX)
    with open(temp_file.name, "wb") as f:
        f.write(MOCK_BUNDLE_CONTENT)
    bundle_mock.return_value = temp_file.name
    session_client_mock.return_value.list_objects_v2.side_effect = (
        create_list_objects_v2_mock(shas=[SHA1, SHA2])
    )
    session_client_mock.return_value.get_object.side_effect = (
        create_get_object_no_manifest_mock()
    )
    is_ancestor_mock.return_value = False
    assert s3_remote.s3 == session_client_mock.return_value
    res = s3_remote.cmd_push(f"push refs/heads/{BRANCH}:refs/heads/{BRANCH}")
    put_calls = [
        c
        for c in session_client_mock.return_value.put_object.call_args_list
        if not c.kwargs["Key"].endswith(".lock")
    ]
    assert len(put_calls) == 0
    del_calls = [
        c
        for c in session_client_mock.return_value.delete_object.call_args_list
        if not c.kwargs["Key"].endswith(".lock")
    ]
    assert len(del_calls) == 0
    assert res.startswith("error")


@patch("git_remote_s3.git.unbundle")
@patch("boto3.Session.client")
def test_cmd_fetch(session_client_mock, unbundle_mock):
    s3_remote = S3Remote(UriScheme.S3, None, "test_bucket", "test_prefix")

    # No manifest - legacy fetch
    session_client_mock.return_value.get_object.side_effect = (
        create_get_object_no_manifest_mock()
    )

    # Make download_file create actual file
    def download_file_side_effect(Bucket, Key, Filename, Config=None):
        with open(Filename, "wb") as f:
            f.write(MOCK_BUNDLE_CONTENT)

    session_client_mock.return_value.download_file.side_effect = (
        download_file_side_effect
    )

    s3_remote.cmd_fetch(f"fetch {SHA1} refs/heads/{BRANCH}")

    unbundle_mock.assert_called_once()
    assert session_client_mock.return_value.download_file.call_count == 1


@patch("git_remote_s3.git.unbundle")
@patch("boto3.Session.client")
def test_cmd_fetch_same_ref(session_client_mock, unbundle_mock):
    s3_remote = S3Remote(UriScheme.S3, None, "test_bucket", "test_prefix")

    # No manifest - legacy fetch
    session_client_mock.return_value.get_object.side_effect = (
        create_get_object_no_manifest_mock()
    )

    # Make download_file create actual file
    def download_file_side_effect(Bucket, Key, Filename, Config=None):
        with open(Filename, "wb") as f:
            f.write(MOCK_BUNDLE_CONTENT)

    session_client_mock.return_value.download_file.side_effect = (
        download_file_side_effect
    )

    s3_remote.cmd_fetch(f"fetch {SHA1} refs/heads/{BRANCH}")
    s3_remote.cmd_fetch(f"fetch {SHA1} refs/heads/{BRANCH}")
    unbundle_mock.assert_called_once()
    assert session_client_mock.return_value.download_file.call_count == 1


@patch("sys.stdout", new_callable=StringIO)
@patch("boto3.Session.client")
def test_cmd_option(session_client_mock, stdout_mock):
    s3_remote = S3Remote(UriScheme.S3, None, "test_bucket", "test_prefix")
    s3_remote.cmd_option("option verbosity 2")
    assert stdout_mock.getvalue().startswith("ok\n")
    s3_remote.cmd_option("option concurrency 1")
    assert stdout_mock.getvalue().endswith("unsupported\n")


@patch("sys.stdout", new_callable=StringIO)
@patch("boto3.Session.client")
def test_cmd_capabilities(session_client_mock, stdout_mock):
    s3_remote = S3Remote(UriScheme.S3, None, "test_bucket", "test_prefix")
    s3_remote.cmd_capabilities()
    assert "fetch" in stdout_mock.getvalue()
    assert "option" in stdout_mock.getvalue()
    assert "push" in stdout_mock.getvalue()


@patch("boto3.Session.client")
def test_cmd_push_delete(session_client_mock):
    s3_remote = S3Remote(UriScheme.S3, None, "test_bucket", "test_prefix")

    session_client_mock.return_value.list_objects_v2.return_value = {
        "Contents": [
            {
                "Key": f"test_prefix/refs/heads/{BRANCH}/{SHA1}.bundle",
                "LastModified": datetime.datetime.now(),
            }
        ]
    }
    assert s3_remote.s3 == session_client_mock.return_value
    res = s3_remote.cmd_push(f"push :refs/heads/{BRANCH}")
    assert session_client_mock.return_value.delete_object.call_count == 1
    assert res == (f"ok refs/heads/{BRANCH}\n")


@patch("boto3.Session.client")
def test_cmd_push_delete_s3_zip(session_client_mock):
    s3_remote = S3Remote(UriScheme.S3_ZIP, None, "test_bucket", "test_prefix")

    session_client_mock.return_value.list_objects_v2.return_value = {
        "Contents": [
            {
                "Key": f"test_prefix/refs/heads/{BRANCH}/{SHA1}.bundle",
                "LastModified": datetime.datetime.now(),
            },
            {
                "Key": f"test_prefix/refs/heads/{BRANCH}/repo.zip",
                "LastModified": datetime.datetime.now(),
            },
        ]
    }
    assert s3_remote.s3 == session_client_mock.return_value
    res = s3_remote.cmd_push(f"push :refs/heads/{BRANCH}")
    assert session_client_mock.return_value.delete_object.call_count == 2
    assert res == (f"ok refs/heads/{BRANCH}\n")


@patch("boto3.Session.client")
def test_cmd_push_delete_fails_with_multiple_heads(session_client_mock):
    s3_remote = S3Remote(UriScheme.S3, None, "test_bucket", "test_prefix")

    session_client_mock.return_value.list_objects_v2.return_value = {
        "Contents": [
            {
                "Key": f"test_prefix/refs/heads/{BRANCH}/{SHA1}.bundle",
                "LastModified": datetime.datetime.now(),
            },
            {
                "Key": f"test_prefix/refs/heads/{BRANCH}/{SHA2}.bundle",
                "LastModified": datetime.datetime.now(),
            },
        ]
    }
    assert s3_remote.s3 == session_client_mock.return_value
    res = s3_remote.cmd_push(f"push :refs/heads/{BRANCH}")
    assert session_client_mock.return_value.delete_object.call_count == 0
    assert res.startswith("error")


@patch("boto3.Session.client")
def test_cmd_push_delete_fails_with_multiple_heads_s3_zip(session_client_mock):
    s3_remote = S3Remote(UriScheme.S3_ZIP, None, "test_bucket", "test_prefix")

    session_client_mock.return_value.list_objects_v2.return_value = {
        "Contents": [
            {
                "Key": f"test_prefix/refs/heads/{BRANCH}/{SHA1}.bundle",
                "LastModified": datetime.datetime.now(),
            },
            {
                "Key": f"test_prefix/refs/heads/{BRANCH}/{SHA2}.bundle",
                "LastModified": datetime.datetime.now(),
            },
            {
                "Key": f"test_prefix/refs/heads/{BRANCH}/repo.zip",
                "LastModified": datetime.datetime.now(),
            },
        ]
    }
    assert s3_remote.s3 == session_client_mock.return_value
    res = s3_remote.cmd_push(f"push :refs/heads/{BRANCH}")
    assert session_client_mock.return_value.delete_object.call_count == 0
    assert res.startswith("error")


@patch("git_remote_s3.git.bundle")
@patch("git_remote_s3.git.rev_parse")
@patch("boto3.Session.client")
def test_simultaneous_pushes_single_bundle_remains(
    session_client_mock, rev_parse_mock, bundle_mock
):
    s3_remote = S3Remote(UriScheme.S3, None, "test_bucket", "test_prefix")

    storage = {}
    lock_keys = []
    storage_lock = threading.Lock()

    def list_objects_v2_side_effect(Bucket, Prefix, **kwargs):
        with storage_lock:
            if Prefix.endswith("/LOCKS/"):
                contents = [
                    {"Key": k, "LastModified": datetime.datetime.now()}
                    for k in lock_keys
                ]
            else:
                contents = [
                    {"Key": k, "LastModified": datetime.datetime.now()}
                    for k in storage.keys()
                    if k.startswith(Prefix)
                ]
        return {"Contents": contents, "NextContinuationToken": None}

    def put_object_side_effect(Bucket, Key, Body=None, **kwargs):
        with storage_lock:
            # Simulate S3 conditional writes for lock creation using If-None-Match
            if Key.endswith(".lock"):
                if kwargs.get("IfNoneMatch") == "*":
                    if Key in lock_keys:
                        raise botocore.exceptions.ClientError(
                            {
                                "ResponseMetadata": {"HTTPStatusCode": 412},
                                "Error": {"Code": "PreconditionFailed"},
                            },
                            "put_object",
                        )
                    lock_keys.append(Key)
                else:
                    lock_keys.append(Key)
            else:
                data = Body.read() if hasattr(Body, "read") else Body or b""
                storage[Key] = data
        return {}

    def delete_object_side_effect(Bucket, Key):
        with storage_lock:
            storage.pop(Key, None)
            try:
                lock_keys.remove(Key)
            except ValueError:
                pass
        return {}

    def get_object_side_effect(Bucket, Key):
        # No manifest exists - legacy mode
        if Key.endswith("manifest.json"):
            raise ClientError({"Error": {"Code": "NoSuchKey"}}, "get_object")
        if Key.endswith("/HEAD"):
            return {"Body": BytesIO(f"refs/heads/{BRANCH}".encode("utf-8"))}
        raise ClientError({"Error": {"Code": "NoSuchKey"}}, "get_object")

    session_client_mock.return_value.list_objects_v2.side_effect = (
        list_objects_v2_side_effect
    )
    session_client_mock.return_value.put_object.side_effect = put_object_side_effect
    session_client_mock.return_value.delete_object.side_effect = (
        delete_object_side_effect
    )
    session_client_mock.return_value.get_object.side_effect = get_object_side_effect
    # Provide a concrete LastModified for lock head checks (non-stale)
    session_client_mock.return_value.head_object.side_effect = lambda Bucket, Key: {
        "LastModified": datetime.datetime.now()
    }

    def rev_parse_side_effect(local_ref: str):
        return SHA1 if "branch1" in local_ref else SHA2

    rev_parse_mock.side_effect = rev_parse_side_effect

    def bundle_side_effect(folder: str, sha: str, ref: str, basis: str = None):
        temp_file = tempfile.NamedTemporaryFile(
            dir=folder, suffix=BUNDLE_SUFFIX, delete=False
        )
        with open(temp_file.name, "wb") as f:
            f.write(MOCK_BUNDLE_CONTENT)
        return temp_file.name

    bundle_mock.side_effect = bundle_side_effect

    remote_ref = f"refs/heads/{BRANCH}"

    t1 = threading.Thread(
        target=s3_remote.cmd_push, args=(f"push refs/heads/branch1:{remote_ref}",)
    )
    t2 = threading.Thread(
        target=s3_remote.cmd_push, args=(f"push refs/heads/branch2:{remote_ref}",)
    )

    t1.start()
    t2.start()
    t1.join()
    t2.join()

    with storage_lock:
        bundles = [
            k
            for k in storage.keys()
            if k.startswith(f"test_prefix/{remote_ref}/") and k.endswith(".bundle")
        ]

    # Only one push should succeed due to per-ref locking; the other will fail to acquire lock
    assert len(bundles) == 1
    assert bundles[0].endswith(f"/{SHA1}.bundle") or bundles[0].endswith(
        f"/{SHA2}.bundle"
    )


@patch("boto3.Session.client")
def test_acquire_lock_deletes_stale_and_reacquires(session_client_mock):
    s3_remote = S3Remote(UriScheme.S3, None, "test_bucket", "test_prefix")

    # Ensure initial list call in constructor succeeds
    session_client_mock.return_value.list_objects_v2.return_value = {
        "Contents": [],
        "NextContinuationToken": None,
    }

    # Simulate existing lock causing first put to fail with 412, then succeed after delete
    attempts = {"count": 0}

    def put_object_side_effect(Bucket, Key, Body=None, IfNoneMatch=None, **kwargs):
        if Key.endswith(".lock") and IfNoneMatch == "*":
            if attempts["count"] == 0:
                attempts["count"] += 1
                raise botocore.exceptions.ClientError(
                    {
                        "ResponseMetadata": {"HTTPStatusCode": 412},
                        "Error": {"Code": "PreconditionFailed"},
                    },
                    "put_object",
                )
        return {}

    # Stale lock: last_modified far in the past
    def head_object_side_effect(Bucket, Key):
        return {
            "LastModified": datetime.datetime.now() - datetime.timedelta(seconds=120)
        }

    session_client_mock.return_value.put_object.side_effect = put_object_side_effect
    session_client_mock.return_value.head_object.side_effect = head_object_side_effect
    session_client_mock.return_value.delete_object.return_value = {}

    # Make TTL small enough so 120s old is stale
    s3_remote.lock_ttl_seconds = 60

    remote_ref = f"refs/heads/{BRANCH}"
    lock_key = s3_remote.acquire_lock(remote_ref)

    expected_lock_key = f"test_prefix/{remote_ref}/LOCK#.lock"
    assert lock_key == expected_lock_key

    # Verify delete was called exactly once for the stale lock
    delete_calls = [
        c
        for c in session_client_mock.return_value.delete_object.call_args_list
        if c.kwargs["Key"].endswith(".lock")
    ]
    assert len(delete_calls) == 1

    # Verify put was attempted at least twice (initial fail + reacquire)
    put_lock_calls = [
        c
        for c in session_client_mock.return_value.put_object.call_args_list
        if c.kwargs.get("Key", "").endswith(".lock")
    ]
    assert len(put_lock_calls) >= 2


# =============================================================================
# Incremental Bundle Tests
# =============================================================================


def create_manifest(checkpoint_sha, checkpoint_key, chain=None):
    """Helper to create a manifest dict."""
    return {
        "version": 1,
        "checkpoint": {"sha": checkpoint_sha, "key": checkpoint_key},
        "chain": chain or [],
    }


def create_manifest_mock(prefix, branch, manifest_data):
    """Helper to create a mock for get_object that returns manifest JSON."""

    def get_object_side_effect(Bucket, Key):
        if Key == f"{prefix}/refs/heads/{branch}/manifest.json":
            return {"Body": BytesIO(json.dumps(manifest_data).encode("utf-8"))}
        elif Key == f"{prefix}/HEAD":
            return {"Body": BytesIO(f"refs/heads/{branch}".encode("utf-8"))}
        raise ClientError({"Error": {"Code": "NoSuchKey"}}, "get_object")

    return get_object_side_effect


@patch("git_remote_s3.git.is_ancestor")
@patch("git_remote_s3.git.rev_parse")
@patch("git_remote_s3.git.bundle")
@patch("boto3.Session.client")
def test_cmd_push_first_push_creates_manifest(
    session_client_mock, bundle_mock, rev_parse_mock, is_ancestor_mock
):
    """First push to empty bucket creates manifest with checkpoint."""
    s3_remote = S3Remote(UriScheme.S3, None, "test_bucket", "test_prefix")
    rev_parse_mock.return_value = SHA1

    temp_dir = tempfile.mkdtemp("test_temp")
    temp_file = tempfile.NamedTemporaryFile(dir=temp_dir, suffix=BUNDLE_SUFFIX)
    with open(temp_file.name, "wb") as f:
        f.write(MOCK_BUNDLE_CONTENT)
    bundle_mock.return_value = temp_file.name

    # Empty bucket - no manifest, no bundles
    def get_object_error(**kwargs):
        raise ClientError({"Error": {"Code": "NoSuchKey"}}, "get_object")

    session_client_mock.return_value.get_object.side_effect = get_object_error
    session_client_mock.return_value.list_objects_v2.return_value = {
        "Contents": [],
        "NextContinuationToken": None,
    }
    session_client_mock.return_value.head_object.side_effect = ClientError(
        {"Error": {"Code": "NoSuchKey"}}, "head_object"
    )

    res = s3_remote.cmd_push(f"push refs/heads/{BRANCH}:refs/heads/{BRANCH}")

    assert res == f"ok refs/heads/{BRANCH}\n"

    # Should have put_object calls for: bundle, manifest, HEAD
    put_calls = [
        c
        for c in session_client_mock.return_value.put_object.call_args_list
        if not c.kwargs["Key"].endswith(".lock")
    ]

    # Find the manifest put call
    manifest_calls = [c for c in put_calls if c.kwargs["Key"].endswith("manifest.json")]
    assert len(manifest_calls) == 1

    # Verify manifest content
    manifest_body = manifest_calls[0].kwargs["Body"]
    manifest = json.loads(manifest_body.decode("utf-8"))
    assert manifest["version"] == 1
    assert manifest["checkpoint"]["sha"] == SHA1
    assert manifest["chain"] == []


@patch("git_remote_s3.git.is_ancestor")
@patch("git_remote_s3.git.rev_parse")
@patch("git_remote_s3.git.bundle")
@patch("boto3.Session.client")
def test_cmd_push_incremental_with_existing_manifest(
    session_client_mock, bundle_mock, rev_parse_mock, is_ancestor_mock
):
    """Push with existing manifest creates incremental bundle and updates chain."""
    s3_remote = S3Remote(UriScheme.S3, None, "test_bucket", "test_prefix")
    rev_parse_mock.return_value = SHA2  # New commit
    is_ancestor_mock.return_value = True  # SHA1 is ancestor of SHA2

    temp_dir = tempfile.mkdtemp("test_temp")
    temp_file = tempfile.NamedTemporaryFile(dir=temp_dir, suffix=BUNDLE_SUFFIX)
    with open(temp_file.name, "wb") as f:
        f.write(MOCK_BUNDLE_CONTENT)
    bundle_mock.return_value = temp_file.name

    # Existing manifest with SHA1 as checkpoint
    existing_manifest = create_manifest(
        SHA1, f"test_prefix/refs/heads/{BRANCH}/{SHA1}.bundle"
    )

    session_client_mock.return_value.get_object.side_effect = create_manifest_mock(
        "test_prefix", BRANCH, existing_manifest
    )
    session_client_mock.return_value.list_objects_v2.return_value = {
        "Contents": [
            {
                "Key": f"test_prefix/refs/heads/{BRANCH}/manifest.json",
                "LastModified": datetime.datetime.now(),
            },
            {
                "Key": f"test_prefix/refs/heads/{BRANCH}/{SHA1}.bundle",
                "LastModified": datetime.datetime.now(),
            },
        ],
        "NextContinuationToken": None,
    }

    res = s3_remote.cmd_push(f"push refs/heads/{BRANCH}:refs/heads/{BRANCH}")

    assert res == f"ok refs/heads/{BRANCH}\n"

    # Verify bundle was created with basis (incremental)
    bundle_mock.assert_called_once()
    call_kwargs = bundle_mock.call_args.kwargs
    assert call_kwargs["basis"] == SHA1
    assert call_kwargs["sha"] == SHA2

    # Check manifest was updated with chain entry
    put_calls = [
        c
        for c in session_client_mock.return_value.put_object.call_args_list
        if not c.kwargs["Key"].endswith(".lock")
    ]
    manifest_calls = [c for c in put_calls if c.kwargs["Key"].endswith("manifest.json")]
    assert len(manifest_calls) == 1

    manifest_body = manifest_calls[0].kwargs["Body"]
    manifest = json.loads(manifest_body.decode("utf-8"))
    assert manifest["checkpoint"]["sha"] == SHA1  # Checkpoint unchanged
    assert len(manifest["chain"]) == 1
    assert manifest["chain"][0]["from"] == SHA1
    assert manifest["chain"][0]["to"] == SHA2


@patch("git_remote_s3.git.is_ancestor")
@patch("git_remote_s3.git.rev_parse")
@patch("git_remote_s3.git.bundle")
@patch("boto3.Session.client")
def test_cmd_push_creates_checkpoint_when_chain_limit_reached(
    session_client_mock, bundle_mock, rev_parse_mock, is_ancestor_mock
):
    """Push creates new checkpoint when chain reaches checkpoint_interval."""
    s3_remote = S3Remote(UriScheme.S3, None, "test_bucket", "test_prefix")
    # Use default checkpoint_interval (30)

    rev_parse_mock.return_value = SHA3  # New commit
    is_ancestor_mock.return_value = True

    temp_dir = tempfile.mkdtemp("test_temp")
    temp_file = tempfile.NamedTemporaryFile(dir=temp_dir, suffix=BUNDLE_SUFFIX)
    with open(temp_file.name, "wb") as f:
        f.write(MOCK_BUNDLE_CONTENT)
    bundle_mock.return_value = temp_file.name

    # Build chain at limit (30 entries)
    chain = []
    prev_sha = SHA1
    for i in range(s3_remote.checkpoint_interval):
        next_sha = f"{i:040x}"
        chain.append(
            {
                "from": prev_sha,
                "to": next_sha,
                "key": f"test_prefix/refs/heads/{BRANCH}/{next_sha}.bundle",
            }
        )
        prev_sha = next_sha

    existing_manifest = create_manifest(
        SHA1, f"test_prefix/refs/heads/{BRANCH}/{SHA1}.bundle", chain=chain
    )

    session_client_mock.return_value.get_object.side_effect = create_manifest_mock(
        "test_prefix", BRANCH, existing_manifest
    )
    session_client_mock.return_value.list_objects_v2.return_value = {
        "Contents": [
            {
                "Key": f"test_prefix/refs/heads/{BRANCH}/manifest.json",
                "LastModified": datetime.datetime.now(),
            },
        ],
        "NextContinuationToken": None,
    }

    res = s3_remote.cmd_push(f"push refs/heads/{BRANCH}:refs/heads/{BRANCH}")

    assert res == f"ok refs/heads/{BRANCH}\n"

    # Verify bundle was created WITHOUT basis (full bundle for checkpoint)
    bundle_mock.assert_called_once()
    call_kwargs = bundle_mock.call_args.kwargs
    assert call_kwargs.get("basis") is None  # Full bundle, not incremental

    # Check manifest was reset with new checkpoint
    put_calls = [
        c
        for c in session_client_mock.return_value.put_object.call_args_list
        if not c.kwargs["Key"].endswith(".lock")
    ]
    manifest_calls = [c for c in put_calls if c.kwargs["Key"].endswith("manifest.json")]

    manifest_body = manifest_calls[0].kwargs["Body"]
    manifest = json.loads(manifest_body.decode("utf-8"))
    assert manifest["checkpoint"]["sha"] == SHA3  # New checkpoint
    assert manifest["chain"] == []  # Chain reset

    # Verify old bundles were scheduled for cleanup (delete_object called)
    # Deletes: 1 old checkpoint + 30 chain bundles = 31
    del_calls = [
        c
        for c in session_client_mock.return_value.delete_object.call_args_list
        if not c.kwargs["Key"].endswith(".lock")
    ]
    assert len(del_calls) == s3_remote.checkpoint_interval + 1


@patch("git_remote_s3.git.unbundle")
@patch("boto3.Session.client")
def test_cmd_fetch_with_manifest_downloads_all_bundles(
    session_client_mock, unbundle_mock
):
    """Fetch with manifest downloads checkpoint + all chain bundles in order."""
    s3_remote = S3Remote(UriScheme.S3, None, "test_bucket", "test_prefix")

    # Build a long chain (use checkpoint_interval entries)
    chain = []
    prev_sha = SHA1
    expected_keys = [
        f"test_prefix/refs/heads/{BRANCH}/{SHA1}.bundle"
    ]  # checkpoint first

    for i in range(s3_remote.checkpoint_interval):
        next_sha = f"{i:040x}"
        chain.append(
            {
                "from": prev_sha,
                "to": next_sha,
                "key": f"test_prefix/refs/heads/{BRANCH}/{next_sha}.bundle",
            }
        )
        expected_keys.append(f"test_prefix/refs/heads/{BRANCH}/{next_sha}.bundle")
        prev_sha = next_sha

    final_sha = prev_sha  # Last sha in chain

    manifest = create_manifest(
        SHA1,
        f"test_prefix/refs/heads/{BRANCH}/{SHA1}.bundle",
        chain=chain,
    )

    session_client_mock.return_value.get_object.side_effect = create_manifest_mock(
        "test_prefix", BRANCH, manifest
    )

    # Track download order
    downloaded_keys = []

    def download_file_side_effect(Bucket, Key, Filename, Config=None):
        downloaded_keys.append(Key)
        with open(Filename, "wb") as f:
            f.write(MOCK_BUNDLE_CONTENT)

    session_client_mock.return_value.download_file.side_effect = (
        download_file_side_effect
    )

    s3_remote.cmd_fetch(f"fetch {final_sha} refs/heads/{BRANCH}")

    # Should download checkpoint + all chain entries (1 + 30 = 31)
    total_bundles = 1 + s3_remote.checkpoint_interval
    assert session_client_mock.return_value.download_file.call_count == total_bundles
    assert unbundle_mock.call_count == total_bundles

    # Verify download order: checkpoint first, then chain in order
    assert downloaded_keys == expected_keys

    # Verify unbundle was called with correct refs
    for call in unbundle_mock.call_args_list:
        assert call.kwargs["ref"] == f"refs/heads/{BRANCH}"


@patch("git_remote_s3.git.is_ancestor")
@patch("git_remote_s3.git.rev_parse")
@patch("git_remote_s3.git.bundle")
@patch("boto3.Session.client")
def test_cmd_push_legacy_to_incremental_transition(
    session_client_mock, bundle_mock, rev_parse_mock, is_ancestor_mock
):
    """Push to repo with legacy bundle (no manifest) creates manifest."""
    s3_remote = S3Remote(UriScheme.S3, None, "test_bucket", "test_prefix")
    rev_parse_mock.return_value = SHA2
    is_ancestor_mock.return_value = True

    temp_dir = tempfile.mkdtemp("test_temp")
    temp_file = tempfile.NamedTemporaryFile(dir=temp_dir, suffix=BUNDLE_SUFFIX)
    with open(temp_file.name, "wb") as f:
        f.write(MOCK_BUNDLE_CONTENT)
    bundle_mock.return_value = temp_file.name

    # No manifest exists (legacy mode)
    def get_object_side_effect(Bucket, Key):
        if Key == "test_prefix/HEAD":
            return {"Body": BytesIO(f"refs/heads/{BRANCH}".encode("utf-8"))}
        raise ClientError({"Error": {"Code": "NoSuchKey"}}, "get_object")

    session_client_mock.return_value.get_object.side_effect = get_object_side_effect

    # Legacy bundle exists
    session_client_mock.return_value.list_objects_v2.return_value = {
        "Contents": [
            {
                "Key": f"test_prefix/refs/heads/{BRANCH}/{SHA1}.bundle",
                "LastModified": datetime.datetime.now(),
            },
        ],
        "NextContinuationToken": None,
    }

    res = s3_remote.cmd_push(f"push refs/heads/{BRANCH}:refs/heads/{BRANCH}")

    assert res == f"ok refs/heads/{BRANCH}\n"

    # Should create manifest
    put_calls = [
        c
        for c in session_client_mock.return_value.put_object.call_args_list
        if not c.kwargs["Key"].endswith(".lock")
    ]
    manifest_calls = [c for c in put_calls if c.kwargs["Key"].endswith("manifest.json")]
    assert len(manifest_calls) == 1

    manifest_body = manifest_calls[0].kwargs["Body"]
    manifest = json.loads(manifest_body.decode("utf-8"))
    assert manifest["version"] == 1
    assert manifest["checkpoint"]["sha"] == SHA2


@patch("git_remote_s3.git.is_ancestor")
@patch("git_remote_s3.git.rev_parse")
@patch("git_remote_s3.git.bundle")
@patch("boto3.Session.client")
def test_cmd_push_force_push_resets_manifest(
    session_client_mock, bundle_mock, rev_parse_mock, is_ancestor_mock
):
    """Force push creates new manifest and cleans up old manifest's bundles."""
    s3_remote = S3Remote(UriScheme.S3, None, "test_bucket", "test_prefix")
    rev_parse_mock.return_value = SHA2
    is_ancestor_mock.return_value = False  # Not a fast-forward

    temp_dir = tempfile.mkdtemp("test_temp")
    temp_file = tempfile.NamedTemporaryFile(dir=temp_dir, suffix=BUNDLE_SUFFIX)
    with open(temp_file.name, "wb") as f:
        f.write(MOCK_BUNDLE_CONTENT)
    bundle_mock.return_value = temp_file.name

    # Existing manifest with checkpoint and chain - should be cleaned up on force push
    existing_manifest = create_manifest(
        SHA1,
        f"test_prefix/refs/heads/{BRANCH}/{SHA1}.bundle",
        chain=[
            {
                "from": SHA1,
                "to": "a" * 40,
                "key": f"test_prefix/refs/heads/{BRANCH}/{'a' * 40}.bundle",
            }
        ],
    )

    session_client_mock.return_value.get_object.side_effect = create_manifest_mock(
        "test_prefix", BRANCH, existing_manifest
    )

    # Mock list_objects_v2 to return empty for PROTECTED# prefix check, contents otherwise
    def list_objects_v2_side_effect(Bucket, Prefix, **kwargs):
        if "PROTECTED#" in Prefix:
            return {"Contents": [], "NextContinuationToken": None}
        return {
            "Contents": [
                {
                    "Key": f"test_prefix/refs/heads/{BRANCH}/manifest.json",
                    "LastModified": datetime.datetime.now(),
                },
                {
                    "Key": f"test_prefix/refs/heads/{BRANCH}/{SHA1}.bundle",
                    "LastModified": datetime.datetime.now(),
                },
                {
                    "Key": f"test_prefix/refs/heads/{BRANCH}/{'a' * 40}.bundle",
                    "LastModified": datetime.datetime.now(),
                },
            ],
            "NextContinuationToken": None,
        }

    session_client_mock.return_value.list_objects_v2.side_effect = (
        list_objects_v2_side_effect
    )

    # Force push with +
    res = s3_remote.cmd_push(f"push +refs/heads/{BRANCH}:refs/heads/{BRANCH}")

    assert res == f"ok refs/heads/{BRANCH}\n"

    # Verify full bundle was created (no basis)
    bundle_mock.assert_called_once()
    call_kwargs = bundle_mock.call_args.kwargs
    assert call_kwargs.get("basis") is None

    # Force push should upload bundle AND create new manifest
    put_calls = [
        c
        for c in session_client_mock.return_value.put_object.call_args_list
        if not c.kwargs["Key"].endswith(".lock")
    ]
    bundle_calls = [c for c in put_calls if c.kwargs["Key"].endswith(".bundle")]
    manifest_calls = [c for c in put_calls if c.kwargs["Key"].endswith("manifest.json")]

    assert len(bundle_calls) == 1  # Bundle uploaded
    assert len(manifest_calls) == 1  # New manifest created

    # Verify new manifest has correct content
    manifest_body = manifest_calls[0].kwargs["Body"]
    manifest = json.loads(manifest_body.decode("utf-8"))
    assert manifest["checkpoint"]["sha"] == SHA2
    assert manifest["chain"] == []

    # Verify old bundles and manifest were cleaned up (no duplicates)
    del_calls = [
        c
        for c in session_client_mock.return_value.delete_object.call_args_list
        if not c.kwargs["Key"].endswith(".lock")
    ]
    deleted_keys = [c.kwargs["Key"] for c in del_calls]
    # Should delete: old checkpoint bundle (SHA1), manifest, and chain bundle (aaa...)
    assert f"test_prefix/refs/heads/{BRANCH}/{SHA1}.bundle" in deleted_keys
    assert f"test_prefix/refs/heads/{BRANCH}/manifest.json" in deleted_keys
    assert f"test_prefix/refs/heads/{BRANCH}/{'a' * 40}.bundle" in deleted_keys
    # Verify no duplicate deletions
    assert len(deleted_keys) == 3


@patch("git_remote_s3.git.is_ancestor")
@patch("git_remote_s3.git.rev_parse")
@patch("git_remote_s3.git.bundle")
@patch("boto3.Session.client")
def test_cmd_push_incremental_already_up_to_date(
    session_client_mock, bundle_mock, rev_parse_mock, is_ancestor_mock
):
    """Push when remote already has the same sha returns ok without uploading."""
    s3_remote = S3Remote(UriScheme.S3, None, "test_bucket", "test_prefix")
    rev_parse_mock.return_value = SHA1  # Same as checkpoint

    existing_manifest = create_manifest(
        SHA1, f"test_prefix/refs/heads/{BRANCH}/{SHA1}.bundle"
    )

    session_client_mock.return_value.get_object.side_effect = create_manifest_mock(
        "test_prefix", BRANCH, existing_manifest
    )
    session_client_mock.return_value.list_objects_v2.return_value = {
        "Contents": [
            {
                "Key": f"test_prefix/refs/heads/{BRANCH}/manifest.json",
                "LastModified": datetime.datetime.now(),
            },
        ],
        "NextContinuationToken": None,
    }

    res = s3_remote.cmd_push(f"push refs/heads/{BRANCH}:refs/heads/{BRANCH}")

    assert res == f"ok refs/heads/{BRANCH}\n"

    # Bundle should not be created
    bundle_mock.assert_not_called()

    # No put_object for bundle or manifest (only lock operations)
    put_calls = [
        c
        for c in session_client_mock.return_value.put_object.call_args_list
        if not c.kwargs["Key"].endswith(".lock")
    ]
    assert len(put_calls) == 0


@patch("sys.stdout", new_callable=StringIO)
@patch("boto3.Session.client")
def test_cmd_list_with_manifest(session_client_mock, stdout_mock):
    """cmd_list reports sha from manifest chain (latest commit)."""
    s3_remote = S3Remote(UriScheme.S3, None, "test_bucket", "test_prefix")

    # Manifest with chain - should report SHA2 (latest in chain)
    manifest = create_manifest(
        SHA1,
        f"test_prefix/refs/heads/{BRANCH}/{SHA1}.bundle",
        chain=[
            {
                "from": SHA1,
                "to": SHA2,
                "key": f"test_prefix/refs/heads/{BRANCH}/{SHA2}.bundle",
            }
        ],
    )

    session_client_mock.return_value.get_object.side_effect = create_manifest_mock(
        "test_prefix", BRANCH, manifest
    )
    session_client_mock.return_value.list_objects_v2.return_value = {
        "Contents": [
            {
                "Key": f"test_prefix/refs/heads/{BRANCH}/manifest.json",
                "LastModified": datetime.datetime.now(),
            },
            {
                "Key": f"test_prefix/refs/heads/{BRANCH}/{SHA1}.bundle",
                "LastModified": datetime.datetime.now(),
            },
            {
                "Key": f"test_prefix/refs/heads/{BRANCH}/{SHA2}.bundle",
                "LastModified": datetime.datetime.now(),
            },
        ],
        "NextContinuationToken": None,
    }

    s3_remote.cmd_list()

    output = stdout_mock.getvalue()
    # Should list SHA2 (from chain), not SHA1 (checkpoint)
    assert f"{SHA2} refs/heads/{BRANCH}" in output
    # SHA1 should NOT appear separately (it's part of manifest, not a standalone ref)
    lines = [l for l in output.strip().split("\n") if l and not l.startswith("@")]
    assert len(lines) == 1  # Only one ref listed
