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

using System.Globalization;
using System.Text;
using OpenSandbox.Core;
using OpenSandbox.Models;

namespace OpenSandbox.Internal;

/// <summary>
/// Internal builders that translate mount option objects into shell commands.
/// Exposed as <c>internal</c> so the unit tests in <c>OpenSandbox.Tests</c> can
/// call them directly via <c>InternalsVisibleTo</c>.
/// </summary>
internal static class MountShell
{
    /// <summary>
    /// Prefix for the per-call ossfs 1.x password file under <c>/tmp</c>. A
    /// unique suffix is appended per mount so that concurrent ossfs 1.x
    /// mounts in the same sandbox do not overwrite or delete each other's
    /// credentials.
    /// </summary>
    public const string Ossfs1PasswdPathPrefix = "/tmp/opensandbox-ossfspass-";

    public sealed record Ossfs2Plan(string ConfPath, string ConfContent, string Command);

    public static void ValidateNfs(NfsMountOptions options)
    {
        if (options is null)
        {
            throw new ArgumentNullException(nameof(options));
        }
        if (string.IsNullOrWhiteSpace(options.Endpoint))
        {
            throw new InvalidArgumentException("endpoint must not be blank");
        }
        if (string.IsNullOrWhiteSpace(options.MountPoint))
        {
            throw new InvalidArgumentException("mountPoint must not be blank");
        }
        if (string.IsNullOrWhiteSpace(options.NasPath))
        {
            throw new InvalidArgumentException("nasPath must not be blank");
        }
    }

    public static void ValidateOssfs(OssfsMountOptions options)
    {
        if (options is null)
        {
            throw new ArgumentNullException(nameof(options));
        }
        if (string.IsNullOrWhiteSpace(options.Endpoint))
        {
            throw new InvalidArgumentException("endpoint must not be blank");
        }
        if (string.IsNullOrWhiteSpace(options.Bucket))
        {
            throw new InvalidArgumentException("bucket must not be blank");
        }
        if (string.IsNullOrWhiteSpace(options.MountPoint))
        {
            throw new InvalidArgumentException("mountPoint must not be blank");
        }
        if (string.IsNullOrWhiteSpace(options.AccessKeyId))
        {
            throw new InvalidArgumentException("accessKeyId must not be blank");
        }
        if (string.IsNullOrWhiteSpace(options.AccessKeySecret))
        {
            throw new InvalidArgumentException("accessKeySecret must not be blank");
        }
    }

    public static string BuildNfsCommand(NfsMountOptions options)
    {
        var optString = string.IsNullOrWhiteSpace(options.Options)
            ? NfsMountOptions.DefaultNfsOptions
            : options.Options!;
        var source = options.Endpoint + ":" + options.NasPath;
        var core = string.Format(
            CultureInfo.InvariantCulture,
            "mkdir -p {0} && mount -t nfs -o {1} {2} {3}",
            ShQuote(options.MountPoint),
            ShQuote(optString),
            ShQuote(source),
            ShQuote(options.MountPoint));
        return PrependInstallation(options.Installation, core);
    }

    public static string BuildOssfs1Command(OssfsMountOptions options)
    {
        var useSts = !string.IsNullOrWhiteSpace(options.SecurityToken);
        // ossfs 1.x password file format:
        //   AK/SK mode : bucket:accessKeyId:accessKeySecret
        //   STS mode   : bucket:accessKeyId:accessKeySecret:securityToken
        var passwd = new StringBuilder();
        passwd.Append(options.Bucket).Append(':')
              .Append(options.AccessKeyId).Append(':')
              .Append(options.AccessKeySecret);
        if (useSts)
        {
            passwd.Append(':').Append(options.SecurityToken);
        }

        var bucketArg = string.IsNullOrWhiteSpace(options.BucketDirectory)
            ? options.Bucket
            : $"{options.Bucket}:/{options.BucketDirectory}";

        var optionFlags = new StringBuilder();
        if (options.Options is { Count: > 0 } opts)
        {
            foreach (var opt in opts)
            {
                optionFlags.Append(" -o").Append(ShQuote(opt));
            }
        }

        // Use a unique per-call password file under /tmp so that concurrent
        // ossfs 1.x mounts do not overwrite or delete each other's credentials.
        // Create it with mode 0600 in one atomic step (avoids the world-readable
        // window that a naive `echo > ; chmod 600` would create). Always clean
        // it up even if ossfs fails, by preserving the subshell exit code
        // via __rc.
        var passwdPath = Ossfs1PasswdPathPrefix + Guid.NewGuid().ToString("N");
        var quotedPasswdPath = ShQuote(passwdPath);
        var core = string.Format(
            CultureInfo.InvariantCulture,
            "ossfs --version && " +
            "install -m 600 /dev/null {0} && " +
            "printf %s {1} > {0} && " +
            "mkdir -p {2} && " +
            "( ossfs {3} {2} -ourl={4} -opasswd_file={0}{5} ); " +
            "__rc=$?; rm -f {0}; exit $__rc",
            quotedPasswdPath,
            ShQuote(passwd.ToString()),
            ShQuote(options.MountPoint),
            ShQuote(bucketArg),
            ShQuote(options.Endpoint),
            optionFlags);
        return PrependInstallation(options.Installation, core);
    }

    public static Ossfs2Plan BuildOssfs2Plan(OssfsMountOptions options)
    {
        var conf = new StringBuilder();
        conf.Append("--oss_endpoint=").Append(options.Endpoint).Append('\n');
        conf.Append("--oss_bucket=").Append(options.Bucket).Append('\n');
        if (!string.IsNullOrWhiteSpace(options.BucketDirectory))
        {
            // ossfs2 mounts a bucket root; a subdirectory is expressed as a
            // prefix (trailing slash makes it a directory boundary).
            var prefix = options.BucketDirectory!.TrimEnd('/') + "/";
            conf.Append("--oss_bucket_prefix=").Append(prefix).Append('\n');
        }
        if (options.Options is { Count: > 0 } opts)
        {
            foreach (var opt in opts)
            {
                conf.Append("--").Append(opt).Append('\n');
            }
        }

        var confPath = "/tmp/opensandbox-ossfs-" + Guid.NewGuid().ToString("N") + ".conf";

        // ossfs 2.x reads credentials from environment variables:
        //   AK/SK mode : OSS_ACCESS_KEY_ID + OSS_ACCESS_KEY_SECRET
        //   STS mode   : additionally OSS_SESSION_TOKEN
        var stsExport = string.IsNullOrWhiteSpace(options.SecurityToken)
            ? string.Empty
            : $" && export OSS_SESSION_TOKEN={ShQuote(options.SecurityToken!)}";

        var core = string.Format(
            CultureInfo.InvariantCulture,
            "ossfs2 --version && " +
            "mkdir -p {0} && " +
            "export OSS_ACCESS_KEY_ID={1} && " +
            "export OSS_ACCESS_KEY_SECRET={2}{3}" +
            " && ossfs2 mount {0} -c {4}",
            ShQuote(options.MountPoint),
            ShQuote(options.AccessKeyId),
            ShQuote(options.AccessKeySecret),
            stsExport,
            ShQuote(confPath));

        return new Ossfs2Plan(
            ConfPath: confPath,
            ConfContent: conf.ToString(),
            Command: PrependInstallation(options.Installation, core));
    }

    public static WriteEntry BuildOssfs2ConfEntry(Ossfs2Plan plan)
    {
        if (plan is null)
        {
            throw new ArgumentNullException(nameof(plan));
        }
        return new WriteEntry
        {
            Path = plan.ConfPath,
            Data = plan.ConfContent,
            // Mode is serialized as a JSON number and parsed by execd as an
            // octal string (see components/execd/pkg/web/controller/utils.go);
            // pass the literal decimal 600 rather than the C# hex/binary form
            // for octal 0o600.
            Mode = 600,
        };
    }

    public static string BuildUmountCommand(string mountPoint)
    {
        if (string.IsNullOrWhiteSpace(mountPoint))
        {
            throw new InvalidArgumentException("mountPoint must not be blank");
        }
        return "umount " + ShQuote(mountPoint);
    }

    public static OssfsVersion SelectOssfsVersion(OssfsMountOptions options)
    {
        return options.Version ?? OssfsVersion.Ossfs10;
    }

    public static void EnsureSuccess(Execution? execution, string failurePrefix)
    {
        if (execution is null)
        {
            throw new MountFailedException(failurePrefix + ": nil execution result");
        }
        var error = execution.Error;
        var exitCode = execution.ExitCode;
        var failed = error != null || (exitCode.HasValue && exitCode.Value != 0);
        if (!failed)
        {
            return;
        }
        var parts = new List<string>(2);
        if (error != null)
        {
            parts.Add($"[{error.Name}] {error.Value}");
        }
        if (execution.Logs.Stderr.Count > 0)
        {
            var sb = new StringBuilder();
            for (var i = 0; i < execution.Logs.Stderr.Count; i++)
            {
                if (i > 0)
                {
                    sb.Append('\n');
                }
                sb.Append(execution.Logs.Stderr[i].Text);
            }
            parts.Add("stderr=" + sb);
        }
        var message = parts.Count == 0
            ? failurePrefix
            : failurePrefix + ": " + string.Join(" | ", parts);
        throw new MountFailedException(message, execution);
    }

    private static string PrependInstallation(string? installation, string core)
    {
        return string.IsNullOrWhiteSpace(installation) ? core : installation + " && " + core;
    }

    /// <summary>
    /// Quotes <paramref name="value"/> for POSIX shell single-quoted context.
    /// Embedded <c>'</c> is escaped as <c>'\''</c>. The result is always safe to
    /// embed as one argument to a <c>sh -c</c> string.
    /// </summary>
    public static string ShQuote(string value)
    {
        if (value is null)
        {
            throw new ArgumentNullException(nameof(value));
        }
        // string.Replace(string, string) is available on all target frameworks
        // (including netstandard2.0). Ordinal comparison is the default for
        // this overload.
        return "'" + value.Replace("'", "'\\''") + "'";
    }
}
