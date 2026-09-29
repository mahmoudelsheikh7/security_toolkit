# Security Toolkit (C++)

A cross-distribution Linux security utility with one command-line interface for installing security tools, scanning directories for suspicious files, and applying safe firewall defaults. Pure C++17 plus POSIX, no external dependencies.

Repo: https://github.com/mahmoudelsheikh7/security_toolkit

## Supported systems

| Family | Package manager | Firewall |
|---|---|---|
| Debian, Ubuntu, Mint | apt | ufw |
| Fedora, RHEL, Rocky, Alma | dnf / yum | firewalld |
| Arch, Manjaro, EndeavourOS | pacman | ufw |
| openSUSE, SLES | zypper | firewalld |
| Alpine | apk | ufw |
| Void | xbps | ufw |

Detection uses `/etc/os-release` first, then probes for package-manager commands, so derivatives work too.

## Build

```bash
git clone https://github.com/mahmoudelsheikh7/security_toolkit.git
cd security_toolkit
make                # adds -lstdc++fs automatically when needed
sudo make install   # optional, installs to /usr/local/sbin
```

Manual: `g++ -std=c++17 -Wall -Wextra -O2 security_toolkit.cpp -o security_toolkit` (GCC 8: append `-lstdc++fs`).

## Usage

```bash
sudo ./security_toolkit                 # interactive menu
sudo ./security_toolkit --install       # install tools
./security_toolkit --scan /home         # scan (root not required)
sudo ./security_toolkit --firewall      # apply firewall defaults
sudo ./security_toolkit --all /var      # everything
./security_toolkit --help
```

Options: `-y/--yes` skips confirmation prompts (required when stdin is not a terminal), `--no-color` disables colour.

## What changed in v2.0

Fixes
* `--help`, `--version` and `--scan` no longer demand root; only install and firewall do.
* Interactive menu no longer loops forever on EOF (Ctrl-D or piped input).
* Exit codes are real exit codes (previously raw `system()` wait status).
* Commands run via `fork`/`execvp`, not a shell, so nothing is subject to quoting or injection problems.
* `which` is no longer required (missing on some minimal images); PATH is searched natively and `/usr/sbin` is added, so `su` without `-` works.
* Directory scan no longer aborts on the first error, does not follow symlinks, and skips `/proc`, `/sys` and `/dev`.
* `tolower` undefined behaviour on non-ASCII bytes, non-thread-safe `localtime`, static-initialisation-order log path.
* Log falls back to `~/.local/state/sec_toolkit/` or `/tmp` when `/var/log` is not writable.
* Colour codes are dropped when output is not a terminal.

Compatibility
* Added Alpine (apk) and Void (xbps).
* Non-interactive apt (`--no-install-recommends`, no debconf prompts, avoids pulling in a mail server for rkhunter).
* EPEL is enabled automatically on RHEL derivatives; failed packages produce a distro-specific hint.
* pacman no longer uses `-Sy` (unsupported partial upgrade).
* Services are enabled on systemd, OpenRC or runit.

Safety
* Firewall keeps every sshd `Port` (from `sshd_config` and `sshd_config.d`) and the port of your current SSH session open.
* Existing ufw rules are no longer wiped (`ufw reset` removed).
* firewalld no longer forces the `DROP` target (which broke ICMP); it sets the `public` zone and adds SSH.
* Firewall changes ask for confirmation. An already-running firewall is preferred over a second one.

Scanner
* Also flags setuid, setgid and world-writable files.

## Limitations

* Heuristics only: not antivirus, no signatures, no real-time monitoring.
* Some tools live in extra repositories (EPEL, AUR, security:tools) on certain distros.
* Firewall setup switches firewalld's default zone to `public`; review before using on servers with custom zones.
* Not tested on every distro release: test on a non-production machine first.

## License

Provided as-is for educational and research purposes. Use at your own risk.
