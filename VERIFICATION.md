# Release Verification Guide

This guide explains how to verify the authenticity and integrity of SkillGuard releases.

## Verifying Downloads

### Method 1: SHA-256 Checksum Verification

All SkillGuard releases include a `checksums.txt` file containing SHA-256 checksums of all artifacts.

#### Steps

1. **Download the release** from [GitHub Releases](https://github.com/OSSAfrica/skillguard/releases)

2. **Download checksums file**
   ```bash
   curl -sL https://github.com/OSSAfrica/skillguard/releases/download/v0.1.0/checksums.txt -o checksums.txt
   ```

3. **Verify your downloaded binary**
   ```bash
   # For Linux/macOS
   sha256sum -c checksums.txt

   # For macOS (alternative)
   shasum -a 256 -c checksums.txt

   # For Windows (PowerShell)
   Get-FileHash -Algorithm SHA256 skillguard.exe | Format-List
   ```

4. **Expected output**
   ```
   skillguard_0.1.0_darwin_arm64: OK
   skillguard_0.1.0_darwin_amd64: OK
   skillguard_0.1.0_linux_amd64: OK
   skillguard_0.1.0_linux_arm64: OK
   skillguard_0.1.0_windows_amd64.exe: OK
   ```

5. **Verify specific binary only**
   ```bash
   sha256sum skillguard_0.1.0_linux_amd64.tar.gz
   # Compare output with checksum in checksums.txt
   ```

### Method 2: GPG Signature Verification (Future)

Once Sigstore/Cosign signing is implemented, you will be able to verify signatures using:

```bash
# Install Cosign
brew install cosign/tap/cosign

# Verify release signature
cosign verify --key ossf://skillguard/skillguard ghcr.io/ossafrica/skillguard:v0.1.0
```

## Docker Image Verification

### Verify Chainguard Base Image

SkillGuard containers are built on Chainguard images which are signed and verified:

```bash
# Pull the image
docker pull ghcr.io/ossafrica/skillguard:latest

# Verify image signature (requires Cosign)
cosign verify ghcr.io/ossafrica/skillguard:latest
```

### Verify Image Provenance

Chainguard images include provenance attestations:

```bash
# Install Chainctl (Chainguard CLI)
brew install chainguard-dev/chainguard/chainctl

# Verify image provenance
chainctl images verify ghcr.io/ossafrica/skillguard:latest
```

## Security Best Practices

1. **Always verify checksums** before running downloaded binaries
2. **Prefer HTTPS downloads** - never use HTTP
3. **Check the release date** - be wary of very old releases
4. **Review release notes** - verify the changelog matches expected changes

## Reporting Issues

If you encounter verification failures:

1. Do NOT run the binary
2. Check if the issue is already reported at https://github.com/OSSAfrica/skillguard/issues
3. Report the issue with:
   - The exact error message
   - Your operating system
   - The release version you attempted to download

## Trust Chain

```
Source Code (GitHub)
       ↓
Build (GitHub Actions)
       ↓
Sign (Cosign/Sigstore - Future)
       ↓
Release (GitHub Releases)
       ↓
Verify (User - This Guide)
```

---

For more information on SkillGuard's security practices, see [SECURITY.md](SECURITY.md).
