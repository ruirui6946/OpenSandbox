// Copyright 2026 Alibaba Group Holding Ltd.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

import {
  InvalidArgumentException,
  MountFailedException,
} from "../core/exceptions.js";
import type { Execution } from "../models/execution.js";
import type { WriteEntry } from "../models/filesystem.js";
import { DEFAULT_NFS_OPTIONS, type NfsMountOptions, type OssfsMountOptions, type OssfsVersion } from "./models.js";

/**
 * Prefix used for the per-call ossfs 1.x password file. A UUID is appended per
 * mount so that concurrent ossfs 1.x mounts in the same sandbox do not
 * overwrite or delete each other's credentials.
 */
export const OSSFS1_PASSWD_PATH_PREFIX = "/tmp/opensandbox-ossfspass-";

/** Plan for an ossfs 2.x mount: a conf file to upload plus a mount command. */
export interface Ossfs2Plan {
  confPath: string;
  confContent: string;
  command: string;
}

/**
 * Quote a value for POSIX shell single-quoted context.
 *
 * `'` inside the value is escaped as `'\''`. The result is always safe to embed
 * as one argument to a `sh -c` string. Unlike Python's `shlex.quote`, this
 * always adds quotes so that behavior is consistent across engines.
 */
export function shQuote(value: string): string {
  return `'${value.replace(/'/g, "'\\''")}'`;
}

export function validateNfs(options: NfsMountOptions): void {
  if (!options.endpoint?.trim()) {
    throw new InvalidArgumentException({ message: "endpoint must not be blank" });
  }
  if (!options.mountPoint?.trim()) {
    throw new InvalidArgumentException({ message: "mountPoint must not be blank" });
  }
  if (!options.nasPath?.trim()) {
    throw new InvalidArgumentException({ message: "nasPath must not be blank" });
  }
}

export function validateOssfs(options: OssfsMountOptions): void {
  if (!options.endpoint?.trim()) {
    throw new InvalidArgumentException({ message: "endpoint must not be blank" });
  }
  if (!options.bucket?.trim()) {
    throw new InvalidArgumentException({ message: "bucket must not be blank" });
  }
  if (!options.mountPoint?.trim()) {
    throw new InvalidArgumentException({ message: "mountPoint must not be blank" });
  }
  if (!options.accessKeyId?.trim()) {
    throw new InvalidArgumentException({ message: "accessKeyId must not be blank" });
  }
  if (!options.accessKeySecret?.trim()) {
    throw new InvalidArgumentException({ message: "accessKeySecret must not be blank" });
  }
}

export function buildNfsCommand(options: NfsMountOptions): string {
  const optString = options.options?.trim() ? options.options : DEFAULT_NFS_OPTIONS;
  const source = `${options.endpoint}:${options.nasPath}`;
  const core =
    `mkdir -p ${shQuote(options.mountPoint)} && ` +
    `mount -t nfs -o ${shQuote(optString)} ` +
    `${shQuote(source)} ${shQuote(options.mountPoint)}`;
  return prependInstallation(options.installation, core);
}

export function buildOssfs1Command(options: OssfsMountOptions): string {
  let passwd = `${options.bucket}:${options.accessKeyId}:${options.accessKeySecret}`;
  if (options.securityToken?.trim()) {
    passwd = `${passwd}:${options.securityToken}`;
  }

  let bucketArg = options.bucket;
  if (options.bucketDirectory?.trim()) {
    bucketArg = `${options.bucket}:/${options.bucketDirectory}`;
  }

  const optionFlags = (options.options ?? [])
    .map((opt) => ` -o${shQuote(opt)}`)
    .join("");

  // Use a unique per-call password file under /tmp so that concurrent
  // ossfs 1.x mounts do not overwrite or delete each other's credentials.
  // Create it with mode 0600 in one atomic step (avoids the world-readable
  // window that a naive `echo > ; chmod 600` would create). Always clean it
  // up even if ossfs fails, by preserving the subshell exit code.
  const passwdPath = `${OSSFS1_PASSWD_PATH_PREFIX}${randomUuid()}`;
  const quotedPasswdPath = shQuote(passwdPath);
  const core =
    "ossfs --version && " +
    `install -m 600 /dev/null ${quotedPasswdPath} && ` +
    `printf %s ${shQuote(passwd)} > ${quotedPasswdPath} && ` +
    `mkdir -p ${shQuote(options.mountPoint)} && ` +
    `( ossfs ${shQuote(bucketArg)} ${shQuote(options.mountPoint)} ` +
    `-ourl=${shQuote(options.endpoint)} ` +
    `-opasswd_file=${quotedPasswdPath}${optionFlags} ); ` +
    `__rc=$?; rm -f ${quotedPasswdPath}; exit $__rc`;

  return prependInstallation(options.installation, core);
}

export function buildOssfs2Plan(options: OssfsMountOptions): Ossfs2Plan {
  const lines: string[] = [
    `--oss_endpoint=${options.endpoint}`,
    `--oss_bucket=${options.bucket}`,
  ];
  if (options.bucketDirectory?.trim()) {
    const prefix = options.bucketDirectory.replace(/\/+$/, "") + "/";
    lines.push(`--oss_bucket_prefix=${prefix}`);
  }
  for (const opt of options.options ?? []) {
    lines.push(`--${opt}`);
  }
  const confContent = lines.join("\n") + "\n";

  const confPath = `/tmp/opensandbox-ossfs-${randomUuid()}.conf`;

  const stsExport =
    options.securityToken?.trim()
      ? ` && export OSS_SESSION_TOKEN=${shQuote(options.securityToken)}`
      : "";

  const core =
    "ossfs2 --version && " +
    `mkdir -p ${shQuote(options.mountPoint)} && ` +
    `export OSS_ACCESS_KEY_ID=${shQuote(options.accessKeyId)} && ` +
    `export OSS_ACCESS_KEY_SECRET=${shQuote(options.accessKeySecret)}` +
    stsExport +
    ` && ossfs2 mount ${shQuote(options.mountPoint)} -c ${shQuote(confPath)}`;

  const command = prependInstallation(options.installation, core);
  return { confPath, confContent, command };
}

export function buildOssfs2ConfEntry(plan: Ossfs2Plan): WriteEntry {
  return {
    path: plan.confPath,
    data: plan.confContent,
    // Mode is serialized as a JSON number and parsed by execd as an octal
    // string (see components/execd/pkg/web/controller/utils.go); pass the
    // decimal literal 600 rather than the JavaScript octal literal 0o600.
    mode: 600,
  };
}

export function buildUmountCommand(mountPoint: string): string {
  if (!mountPoint?.trim()) {
    throw new InvalidArgumentException({ message: "mountPoint must not be blank" });
  }
  return `umount ${shQuote(mountPoint)}`;
}

export function selectOssfsVersion(options: OssfsMountOptions): OssfsVersion {
  const v = options.version;
  if (v == null) {
    return "1.0";
  }
  if (v !== "1.0" && v !== "2.0") {
    // TypeScript's structural typing means a plain JS caller (or any caller
    // that has widened the value to a string) can pass "1", "3.0", etc. Fail
    // fast rather than silently dispatching to ossfs2, matching the stricter
    // Kotlin / Python / Go / C# implementations.
    throw new InvalidArgumentException({
      message: `Unsupported ossfs version: ${String(v)} (expected "1.0" or "2.0")`,
    });
  }
  return v;
}

export function ensureSuccess(execution: Execution, failurePrefix: string): void {
  const error = execution.error;
  const exitCode = execution.exitCode;
  const failed = error != null || (exitCode != null && exitCode !== 0);
  if (!failed) {
    return;
  }
  const stderrText = execution.logs.stderr.map((m) => m.text).join("\n");
  const parts: string[] = [];
  if (error) {
    parts.push(`[${error.name}] ${error.value}`);
  }
  if (stderrText) {
    parts.push(`stderr=${stderrText}`);
  }
  const detail = parts.join(" | ");
  const message = detail ? `${failurePrefix}: ${detail}` : failurePrefix;
  throw new MountFailedException({ message, execution });
}

function prependInstallation(installation: string | undefined, core: string): string {
  if (installation?.trim()) {
    return `${installation} && ${core}`;
  }
  return core;
}

function randomUuid(): string {
  // Prefer Web Crypto (Node 20+ / browsers). Fall back to a compact hex string.
  const g = globalThis as { crypto?: { randomUUID?: () => string } };
  if (g.crypto && typeof g.crypto.randomUUID === "function") {
    return g.crypto.randomUUID();
  }
  const rand = Math.random().toString(16).slice(2) + Math.random().toString(16).slice(2);
  return rand.slice(0, 32);
}
