import assert from "node:assert/strict";
import test from "node:test";

import {
  buildNfsCommand,
  buildOssfs1Command,
  buildOssfs2ConfEntry,
  buildOssfs2Plan,
  buildUmountCommand,
  ensureSuccess,
  OSSFS1_PASSWD_PATH_PREFIX,
  selectOssfsVersion,
  shQuote,
  validateNfs,
  validateOssfs,
} from "../dist/internal.js";

const OSSFS1_PASSWD_RE = /'\/tmp\/opensandbox-ossfspass-[0-9a-f-]{32,36}'/;
import {
  DEFAULT_NFS_OPTIONS,
  InvalidArgumentException,
  MountFailedException,
} from "../dist/index.js";

// -------- NFS builder --------

test("buildNfsCommand uses DEFAULT_NFS_OPTIONS and quotes paths", () => {
  const cmd = buildNfsCommand({
    endpoint: "nas-server.example.com",
    nasPath: "/share",
    mountPoint: "/mnt/nas",
  });
  assert.ok(cmd.includes("mkdir -p '/mnt/nas'"), cmd);
  assert.ok(cmd.includes(`mount -t nfs -o '${DEFAULT_NFS_OPTIONS}' 'nas-server.example.com:/share' '/mnt/nas'`), cmd);
});

test("buildNfsCommand prepends installation and honors custom options", () => {
  const cmd = buildNfsCommand({
    endpoint: "nas",
    nasPath: "/",
    mountPoint: "/mnt/x",
    options: "vers=4,proto=tcp",
    installation: "apt-get install -y nfs-common",
  });
  assert.ok(cmd.startsWith("apt-get install -y nfs-common && "), cmd);
  assert.ok(cmd.includes("'vers=4,proto=tcp'"), cmd);
  assert.ok(!cmd.includes(DEFAULT_NFS_OPTIONS), "should not fall back to default when custom opts provided");
});

test("validateNfs rejects blank fields", () => {
  assert.throws(
    () => validateNfs({ endpoint: "  ", nasPath: "/", mountPoint: "/mnt/x" }),
    InvalidArgumentException,
  );
  assert.throws(
    () => validateNfs({ endpoint: "nas", nasPath: "", mountPoint: "/mnt/x" }),
    InvalidArgumentException,
  );
});

// -------- ossfs 1.x builder --------

test("buildOssfs1Command uses install -m 600 and always cleans up passwd file", () => {
  const cmd = buildOssfs1Command({
    endpoint: "https://oss-cn-hangzhou.aliyuncs.com",
    bucket: "my-bucket",
    mountPoint: "/mnt/oss",
    accessKeyId: "AK",
    accessKeySecret: "SK",
  });
  const match = cmd.match(OSSFS1_PASSWD_RE);
  assert.ok(match, `expected a unique passwd path under /tmp, got: ${cmd}`);
  const quotedPasswdPath = match[0];
  assert.ok(quotedPasswdPath.startsWith(`'${OSSFS1_PASSWD_PATH_PREFIX}`), quotedPasswdPath);
  assert.ok(cmd.includes(`install -m 600 /dev/null ${quotedPasswdPath}`), cmd);
  assert.ok(cmd.includes(`printf %s 'my-bucket:AK:SK' > ${quotedPasswdPath}`), cmd);
  assert.ok(
    cmd.includes(`__rc=$?; rm -f ${quotedPasswdPath}; exit $__rc`),
    "ossfs1 must always clean up password file regardless of ossfs exit code",
  );
  assert.ok(cmd.includes("ossfs 'my-bucket' '/mnt/oss'"), cmd);
  assert.ok(cmd.includes("-ourl='https://oss-cn-hangzhou.aliyuncs.com'"), cmd);
  assert.ok(cmd.includes(`-opasswd_file=${quotedPasswdPath}`), cmd);
});

test("buildOssfs1Command uses a distinct passwd path per call", () => {
  function passwdPath() {
    const cmd = buildOssfs1Command({
      endpoint: "e",
      bucket: "b",
      mountPoint: "/mnt/x",
      accessKeyId: "AK",
      accessKeySecret: "SK",
    });
    const m = cmd.match(OSSFS1_PASSWD_RE);
    assert.ok(m, cmd);
    return m[0];
  }
  assert.notEqual(passwdPath(), passwdPath(),
    "concurrent ossfs1 mounts must not share the same passwd file");
});

test("buildOssfs1Command supports STS token, bucketDirectory and options", () => {
  const cmd = buildOssfs1Command({
    endpoint: "https://oss.example.com",
    bucket: "b",
    bucketDirectory: "subdir",
    mountPoint: "/mnt/oss",
    accessKeyId: "AK",
    accessKeySecret: "SK",
    securityToken: "TOKEN",
    options: ["use_cache=/tmp/ossfs", "allow_other"],
  });
  assert.ok(cmd.includes("'b:AK:SK:TOKEN'"), cmd);
  assert.ok(cmd.includes("ossfs 'b:/subdir' '/mnt/oss'"), cmd);
  assert.ok(cmd.includes("-o'use_cache=/tmp/ossfs'"), cmd);
  assert.ok(cmd.includes("-o'allow_other'"), cmd);
});

test("validateOssfs rejects blank credentials", () => {
  const base = {
    endpoint: "e",
    bucket: "b",
    mountPoint: "/mnt/x",
    accessKeyId: "AK",
    accessKeySecret: "SK",
  };
  assert.throws(
    () => validateOssfs({ ...base, accessKeyId: " " }),
    InvalidArgumentException,
  );
  assert.throws(
    () => validateOssfs({ ...base, accessKeySecret: "" }),
    InvalidArgumentException,
  );
});

// -------- ossfs 2.x plan --------

test("buildOssfs2Plan writes conf under /tmp and exports credentials", () => {
  const plan = buildOssfs2Plan({
    endpoint: "https://oss.example.com",
    bucket: "b",
    mountPoint: "/mnt/oss2",
    accessKeyId: "AK",
    accessKeySecret: "SK",
    options: ["cache_dir=/tmp/ossfs2"],
    version: "2.0",
  });
  assert.ok(plan.confPath.startsWith("/tmp/opensandbox-ossfs-"), plan.confPath);
  assert.ok(plan.confPath.endsWith(".conf"));
  assert.ok(plan.confContent.includes("--oss_endpoint=https://oss.example.com\n"));
  assert.ok(plan.confContent.includes("--oss_bucket=b\n"));
  assert.ok(plan.confContent.includes("--cache_dir=/tmp/ossfs2\n"));

  assert.ok(plan.command.includes("ossfs2 --version"));
  assert.ok(plan.command.includes("export OSS_ACCESS_KEY_ID='AK'"));
  assert.ok(plan.command.includes("export OSS_ACCESS_KEY_SECRET='SK'"));
  assert.ok(plan.command.includes(`ossfs2 mount '/mnt/oss2' -c '${plan.confPath}'`));
});

test("buildOssfs2Plan encodes bucketDirectory as oss_bucket_prefix with trailing slash", () => {
  const plan = buildOssfs2Plan({
    endpoint: "e",
    bucket: "b",
    bucketDirectory: "sub/dir",
    mountPoint: "/mnt/x",
    accessKeyId: "AK",
    accessKeySecret: "SK",
    version: "2.0",
  });
  assert.ok(plan.confContent.includes("--oss_bucket_prefix=sub/dir/\n"), plan.confContent);
});

test("buildOssfs2Plan exports OSS_SESSION_TOKEN when securityToken is set", () => {
  const plan = buildOssfs2Plan({
    endpoint: "e",
    bucket: "b",
    mountPoint: "/mnt/x",
    accessKeyId: "AK",
    accessKeySecret: "SK",
    securityToken: "TOKEN",
    version: "2.0",
  });
  assert.ok(plan.command.includes("export OSS_SESSION_TOKEN='TOKEN'"), plan.command);
});

test("buildOssfs2ConfEntry uses mode 0o600", () => {
  const plan = buildOssfs2Plan({
    endpoint: "e",
    bucket: "b",
    mountPoint: "/mnt/x",
    accessKeyId: "AK",
    accessKeySecret: "SK",
    version: "2.0",
  });
  const entry = buildOssfs2ConfEntry(plan);
  assert.equal(entry.path, plan.confPath);
  assert.equal(entry.data, plan.confContent);
  assert.equal(entry.mode, 600, "ossfs2 conf must be mode 600 (wire format is decimal parsed as octal by execd)");
});

test("selectOssfsVersion defaults to 1.0", () => {
  assert.equal(
    selectOssfsVersion({
      endpoint: "e",
      bucket: "b",
      mountPoint: "/mnt/x",
      accessKeyId: "AK",
      accessKeySecret: "SK",
    }),
    "1.0",
  );
});

test("selectOssfsVersion rejects unsupported version strings", () => {
  const base = {
    endpoint: "e",
    bucket: "b",
    mountPoint: "/mnt/x",
    accessKeyId: "AK",
    accessKeySecret: "SK",
  };
  for (const bad of ["1", "3.0", "", "v1.0", "1.0.0"]) {
    assert.throws(
      () => selectOssfsVersion({ ...base, version: bad }),
      InvalidArgumentException,
      `expected InvalidArgumentException for version=${JSON.stringify(bad)}`,
    );
  }
});

// -------- umount --------

test("buildUmountCommand quotes and rejects blank", () => {
  assert.equal(buildUmountCommand("/mnt/nas"), "umount '/mnt/nas'");
  assert.throws(() => buildUmountCommand("   "), InvalidArgumentException);
});

// -------- shell quoting --------

test("shQuote escapes embedded single quotes safely", () => {
  assert.equal(shQuote("/mnt/wei'rd"), `'/mnt/wei'\\''rd'`);
});

// -------- ensureSuccess --------

test("ensureSuccess passes on zero exit and empty error", () => {
  ensureSuccess({ logs: { stdout: [], stderr: [] }, result: [], exitCode: 0 }, "prefix");
});

test("ensureSuccess throws MountFailedException with execution attached on error", () => {
  const execution = {
    id: "e-1",
    exitCode: 1,
    error: { name: "MountError", value: "denied", timestamp: 0, traceback: [] },
    result: [],
    logs: { stdout: [], stderr: [{ text: "stderr text", timestamp: 0 }] },
  };
  let caught;
  try {
    ensureSuccess(execution, "NAS mount failure");
  } catch (err) {
    caught = err;
  }
  assert.ok(caught instanceof MountFailedException, `expected MountFailedException, got ${caught}`);
  assert.ok(caught.message.includes("NAS mount failure"));
  assert.ok(caught.message.includes("MountError"));
  assert.ok(caught.message.includes("stderr=stderr text"));
  assert.equal(caught.execution, execution);
});

test("ensureSuccess throws on non-zero exit even without error field", () => {
  assert.throws(
    () => ensureSuccess({ logs: { stdout: [], stderr: [] }, result: [], exitCode: 2 }, "prefix"),
    MountFailedException,
  );
});
