# Homebrew installation and trust

[Documentation](README.md) / Homebrew installation and trust

SkillGuard is distributed as a cask in the third-party
[`ossafrica/skillguard` tap](https://github.com/OSSAfrica/homebrew-skillguard).
Homebrew requires user consent before loading untrusted third-party package
definitions. The tap's publisher cannot grant trust on a user's behalf.

## Install SkillGuard

Use the fully qualified cask name to install and trust only SkillGuard:

```sh
brew install --cask ossafrica/skillguard/skillguard
```

This also adds the tap when needed. See Homebrew's
[tap installation guide](https://docs.brew.sh/How-to-Create-and-Maintain-a-Tap).

On macOS, launching the installed binary may also trigger Apple's “could not
verify” warning. Follow the [macOS first-run guide](macos.md). Homebrew tap trust
and Apple's Gatekeeper approval are separate; `brew trust` does not resolve that
macOS warning.

## Upgrade an existing installation

If `brew upgrade skillguard` reports that the tap is untrusted, grant cask-only
trust once, then retry the upgrade:

```sh
brew trust --cask ossafrica/skillguard/skillguard
brew upgrade --cask ossafrica/skillguard/skillguard
```

After granting trust, the short upgrade command is also available:

```sh
brew upgrade skillguard
```

The fully qualified command identifies the intended package explicitly.
`skillguard update` also delegates Homebrew upgrades to this cask; if it encounters
the same trust error, grant trust as above and retry `skillguard update`.

## Alternative: trust the whole tap

Choose **one** of these equivalent commands if you want to trust every current and
future formula, cask and external command in the OSSAfrica tap:

```sh
brew trust ossafrica/skillguard
```

Or use the explicit tap option:

```sh
brew trust --tap ossafrica/skillguard
```

Then upgrade normally:

```sh
brew upgrade --cask ossafrica/skillguard/skillguard
```

Cask-only trust is narrower and sufficient for SkillGuard. Whole-tap trust is an
alternative, not an additional required step.

## Alternative: tap, trust and install separately

```sh
brew tap ossafrica/skillguard
brew trust --cask ossafrica/skillguard/skillguard
brew install --cask ossafrica/skillguard/skillguard
```

Adding the tap alone does not grant trust.

## Inspect or remove trust

List trusted entries:

```sh
brew trust
```

Remove the specific cask grant or the whole-tap grant, as applicable:

```sh
brew untrust --cask ossafrica/skillguard/skillguard
brew untrust ossafrica/skillguard
```

If you granted both, remove both to revoke access through either grant. These
commands change trust settings; they do not uninstall SkillGuard.

See Homebrew's [Tap Trust policy](https://docs.brew.sh/Tap-Trust) for the consent
model and [`brew` manual](https://docs.brew.sh/Manpage) for
command options.
