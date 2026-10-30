# macOS first run and verification warnings

[Documentation](README.md) / macOS first run

When launching a downloaded SkillGuard binary, including one installed through
the Homebrew cask, macOS may show:

> “skillguard” Not Opened
>
> Apple could not verify “skillguard” is free of malware that may harm your Mac or compromise your privacy.

## Why this happens

macOS Gatekeeper checks downloaded executables. SkillGuard's v0.15.0 release
pipeline does not include Apple Developer ID signing or notarization. Signed Git
commits and signed container images do not supply those checks for the macOS
binary. Homebrew's `brew trust` command approves the tap or cask definition, not
the executable for Gatekeeper.

This message reports missing verification; it does not establish that the binary
is safe. See Apple's [guidance on opening downloaded software](https://support.apple.com/en-us/102445).

## Verify the download first

Use the [official releases](https://github.com/OSSAfrica/skillguard/releases) or
the [`ossafrica/skillguard` cask](homebrew.md). For a manual download, obtain the
archive and `checksums.txt` from the same release. Calculate its SHA-256 and
compare it with the matching filename's entry in `checksums.txt`.

For example, for the v0.15.0 Apple Silicon archive:

```sh
shasum -a 256 skillguard_0.15.0_darwin_arm64.tar.gz
```

Use your downloaded version and `darwin_amd64` for Intel Macs. A checksum match
establishes archive integrity against the published checksum, not Apple approval.
See the [release verification guide](../VERIFICATION.md).

## Approve this executable if you choose to run it

After verifying the source and download, follow Apple's per-app approval process:

1. Attempt to run `skillguard --version` so macOS records the blocked launch.
2. In **System Settings → Privacy & Security**, find the blocked SkillGuard entry
   under **Security** and select **Open Anyway**.
3. Confirm the prompt, authenticating if requested, then retry
   `skillguard --version` in Terminal.

Availability depends on macOS and device-management policy. If the entry is
unavailable on a managed Mac, contact your administrator. Keep Gatekeeper enabled
for other software.

These instructions address the verification warning above. If macOS reports
detected malware, says the software will damage your computer, or the checksum
does not match, stop and [report the exact message and release version](https://github.com/OSSAfrica/skillguard/issues).
