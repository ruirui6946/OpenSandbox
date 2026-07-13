#
# Copyright 2025 Alibaba Group Holding Ltd.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
"""Unit tests for the shell-command builders behind sandbox mount syntax sugar."""

from __future__ import annotations

import re

import pytest

from opensandbox.exceptions import (
    InvalidArgumentException,
    MountFailedException,
)
from opensandbox.models.execd import (
    Execution,
    ExecutionError,
    ExecutionLogs,
    OutputMessage,
)
from opensandbox.mount import (
    DEFAULT_NFS_OPTIONS,
    NfsMountOptions,
    OssfsMountOptions,
    OssfsVersion,
)
from opensandbox.mount._shell import (
    build_nfs_command,
    build_ossfs1_command,
    build_ossfs2_conf_entry,
    build_ossfs2_plan,
    build_umount_command,
    ensure_success,
    select_ossfs_version,
    validate_nfs,
    validate_ossfs,
)

_OSSFS1_PASSWD_RE = re.compile(r"/tmp/opensandbox-ossfspass-[0-9a-f-]{36}")

# -------- NFS command builder --------


def test_build_nfs_command_uses_default_options_and_quotes_paths() -> None:
    cmd = build_nfs_command(
        NfsMountOptions(
            endpoint="nas-server.example.com",
            nas_path="/share",
            mount_point="/mnt/nas",
        )
    )
    assert "mkdir -p /mnt/nas" in cmd
    assert "mount -t nfs -o " in cmd
    assert DEFAULT_NFS_OPTIONS in cmd
    # source and mount_point are safe tokens; shlex.quote leaves them unquoted.
    assert "nas-server.example.com:/share /mnt/nas" in cmd


def test_build_nfs_command_honors_custom_options_and_installation() -> None:
    cmd = build_nfs_command(
        NfsMountOptions(
            endpoint="nas",
            nas_path="/",
            mount_point="/mnt/x",
            options="vers=4,proto=tcp",
            installation="apt-get install -y nfs-common",
        )
    )
    assert cmd.startswith("apt-get install -y nfs-common && ")
    # NFS options string is passed to `-o`; shlex.quote leaves the safe form unquoted.
    assert "-o vers=4,proto=tcp " in cmd
    assert DEFAULT_NFS_OPTIONS not in cmd


def test_validate_nfs_rejects_blank_endpoint() -> None:
    with pytest.raises(InvalidArgumentException):
        validate_nfs(
            NfsMountOptions(endpoint="  ", nas_path="/", mount_point="/mnt/x")
        )


def test_validate_nfs_rejects_blank_nas_path() -> None:
    with pytest.raises(InvalidArgumentException):
        validate_nfs(
            NfsMountOptions(endpoint="nas", nas_path="", mount_point="/mnt/x")
        )


# -------- ossfs 1.x command builder --------


def test_build_ossfs1_command_uses_install_dash_m_600_and_cleans_up() -> None:
    cmd = build_ossfs1_command(
        OssfsMountOptions(
            endpoint="https://oss-cn-hangzhou.aliyuncs.com",
            bucket="my-bucket",
            mount_point="/mnt/oss",
            access_key_id="AK",
            access_key_secret="SK",
        )
    )
    match = _OSSFS1_PASSWD_RE.search(cmd)
    assert match, f"expected a unique passwd path under /tmp, got: {cmd}"
    passwd_path = match.group()
    assert f"install -m 600 /dev/null {passwd_path}" in cmd, cmd
    # shlex.quote leaves ':' and safe tokens unquoted; only the entire passwd token is guaranteed present.
    assert f"printf %s my-bucket:AK:SK > {passwd_path}" in cmd, cmd
    assert (
        f"__rc=$?; rm -f {passwd_path}; exit $__rc" in cmd
    ), "ossfs1 must always clean up the password file"
    assert "ossfs my-bucket /mnt/oss" in cmd
    assert "-ourl=https://oss-cn-hangzhou.aliyuncs.com" in cmd
    assert f"-opasswd_file={passwd_path}" in cmd


def test_build_ossfs1_command_uses_a_unique_passwd_path_per_call() -> None:
    def _passwd_path() -> str:
        cmd = build_ossfs1_command(
            OssfsMountOptions(
                endpoint="e",
                bucket="b",
                mount_point="/mnt/x",
                access_key_id="AK",
                access_key_secret="SK",
            )
        )
        match = _OSSFS1_PASSWD_RE.search(cmd)
        assert match, cmd
        return match.group()

    assert _passwd_path() != _passwd_path(), (
        "concurrent ossfs1 mounts must not share the same passwd file"
    )


def test_build_ossfs1_command_supports_sts_and_bucket_directory_and_options() -> None:
    cmd = build_ossfs1_command(
        OssfsMountOptions(
            endpoint="https://oss-cn-hangzhou.aliyuncs.com",
            bucket="b",
            bucket_directory="subdir",
            mount_point="/mnt/oss",
            access_key_id="AK",
            access_key_secret="SK",
            security_token="TOKEN",
            options=["use_cache=/tmp/ossfs", "allow_other"],
            version=OssfsVersion.OSSFS_1_0,
        )
    )
    # shlex.quote skips quoting for safe tokens: raw form stays intact.
    assert "b:AK:SK:TOKEN" in cmd
    assert "ossfs b:/subdir /mnt/oss" in cmd
    assert "-ouse_cache=/tmp/ossfs" in cmd
    assert "-oallow_other" in cmd


def test_validate_ossfs_rejects_blank_credentials() -> None:
    base = {
        "endpoint": "e",
        "bucket": "b",
        "mount_point": "/mnt/x",
        "access_key_id": "AK",
        "access_key_secret": "SK",
    }
    with pytest.raises(InvalidArgumentException):
        validate_ossfs(OssfsMountOptions(**{**base, "access_key_id": " "}))
    with pytest.raises(InvalidArgumentException):
        validate_ossfs(OssfsMountOptions(**{**base, "access_key_secret": ""}))


# -------- ossfs 2.x plan --------


def test_build_ossfs2_plan_writes_conf_under_tmp_and_exports_credentials() -> None:
    plan = build_ossfs2_plan(
        OssfsMountOptions(
            endpoint="https://oss-cn-hangzhou.aliyuncs.com",
            bucket="b",
            mount_point="/mnt/oss2",
            access_key_id="AK",
            access_key_secret="SK",
            options=["cache_dir=/tmp/ossfs2"],
            version=OssfsVersion.OSSFS_2_0,
        )
    )
    assert plan.conf_path.startswith("/tmp/opensandbox-ossfs-")
    assert plan.conf_path.endswith(".conf")

    assert "--oss_endpoint=https://oss-cn-hangzhou.aliyuncs.com" in plan.conf_content
    assert "--oss_bucket=b" in plan.conf_content
    assert "--cache_dir=/tmp/ossfs2" in plan.conf_content

    assert "ossfs2 --version" in plan.command
    assert "export OSS_ACCESS_KEY_ID=AK" in plan.command
    assert "export OSS_ACCESS_KEY_SECRET=SK" in plan.command
    assert f"ossfs2 mount /mnt/oss2 -c {plan.conf_path}" in plan.command


def test_build_ossfs2_plan_maps_bucket_directory_to_prefix() -> None:
    plan = build_ossfs2_plan(
        OssfsMountOptions(
            endpoint="e",
            bucket="b",
            bucket_directory="sub/dir",
            mount_point="/mnt/x",
            access_key_id="AK",
            access_key_secret="SK",
            version=OssfsVersion.OSSFS_2_0,
        )
    )
    assert "--oss_bucket_prefix=sub/dir/" in plan.conf_content, plan.conf_content


def test_build_ossfs2_plan_exports_session_token_when_set() -> None:
    plan = build_ossfs2_plan(
        OssfsMountOptions(
            endpoint="e",
            bucket="b",
            mount_point="/mnt/x",
            access_key_id="AK",
            access_key_secret="SK",
            security_token="TOKEN",
            version=OssfsVersion.OSSFS_2_0,
        )
    )
    assert "export OSS_SESSION_TOKEN=TOKEN" in plan.command


def test_build_ossfs2_conf_entry_uses_mode_600() -> None:
    plan = build_ossfs2_plan(
        OssfsMountOptions(
            endpoint="e",
            bucket="b",
            mount_point="/mnt/x",
            access_key_id="AK",
            access_key_secret="SK",
            version=OssfsVersion.OSSFS_2_0,
        )
    )
    entry = build_ossfs2_conf_entry(plan)
    assert entry.path == plan.conf_path
    assert entry.data == plan.conf_content
    assert entry.mode == 600, "ossfs2 conf must be mode 600 (contains credentials context)"


def test_select_ossfs_version_defaults_to_1_0() -> None:
    opts = OssfsMountOptions(
        endpoint="e",
        bucket="b",
        mount_point="/mnt/x",
        access_key_id="AK",
        access_key_secret="SK",
    )
    assert select_ossfs_version(opts) is OssfsVersion.OSSFS_1_0


# -------- umount --------


def test_build_umount_command_quotes_paths() -> None:
    assert build_umount_command("/mnt/nas") == "umount /mnt/nas"
    # Path containing whitespace must be quoted
    assert build_umount_command("/mnt/with space") == "umount '/mnt/with space'"


def test_build_umount_command_rejects_blank() -> None:
    with pytest.raises(InvalidArgumentException):
        build_umount_command("  ")


# -------- ensure_success --------


def test_ensure_success_passes_for_zero_exit() -> None:
    ensure_success(Execution(exit_code=0), "prefix")


def test_ensure_success_raises_when_execution_error_present() -> None:
    execution = Execution(
        exit_code=None,
        error=ExecutionError(name="MountError", value="denied", timestamp=0),
        logs=ExecutionLogs(stderr=[OutputMessage(text="perm denied", timestamp=0)]),
    )
    with pytest.raises(MountFailedException) as exc:
        ensure_success(execution, "NAS mount failure")
    assert "NAS mount failure" in str(exc.value)
    assert "MountError" in str(exc.value)
    assert "stderr=perm denied" in str(exc.value)
    assert exc.value.execution is execution


def test_ensure_success_raises_on_nonzero_exit_without_error_field() -> None:
    execution = Execution(exit_code=1, logs=ExecutionLogs())
    with pytest.raises(MountFailedException):
        ensure_success(execution, "ossfs mount failure")
