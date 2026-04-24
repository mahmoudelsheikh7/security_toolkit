# Security Toolkit (C++)

## Overview

Security Toolkit is a cross-distribution Linux security utility written in C++. It provides a unified command-line interface for installing essential security tools, scanning files and directories for suspicious patterns, and configuring the system firewall.

The project is designed to be lightweight, portable, and dependency-free, using only the C++17 standard library and basic POSIX APIs.

---

## Features

* Cross-distribution support (Debian/Ubuntu, Fedora/RHEL, Arch, openSUSE)
* Automatic package manager detection (apt, dnf, yum, pacman, zypper)
* Installation of common security tools:

  * nmap
  * fail2ban
  * rkhunter
  * lynis
  * clamav
* Recursive file and directory scanning using std::filesystem
* Detection of potentially suspicious files:

  * hidden files
  * executable files
  * predefined suspicious extensions
* Firewall configuration:

  * ufw support (Debian/Ubuntu/Arch)
  * firewalld support (Fedora/RHEL/SUSE)
  * secure default rules (deny incoming, allow outgoing)
  * automatic SSH allowance to prevent lockout
* Logging system with timestamps

  * console output
  * file output (/var/log/sec_toolkit.log)
* Dual interface:

  * interactive menu mode
  * command-line argument mode

---

## Requirements

* Linux operating system
* GCC 8+ or Clang 7+ with C++17 support
* Root privileges for:

  * installing packages
  * configuring firewall
  * writing logs to /var/log

---

## Build Instructions

Compile using g++:

```bash
g++ -std=c++17 -Wall -Wextra -O2 security_toolkit.cpp -o security_toolkit
```

If you encounter filesystem linking errors on older compilers:

```bash
g++ -std=c++17 security_toolkit.cpp -lstdc++fs -o security_toolkit
```

---

## Usage

### Interactive Mode

```bash
sudo ./security_toolkit
```

---

### Command-Line Mode

Install security tools:

```bash
sudo ./security_toolkit --install
```

Scan a directory:

```bash
./security_toolkit --scan /home
```

Configure firewall:

```bash
sudo ./security_toolkit --firewall
```

Run all modules:

```bash
sudo ./security_toolkit --all /var
```

Display help:

```bash
./security_toolkit --help
```

---

## Architecture

### Logger

Handles timestamped logging to both standard output and a log file.

### PackageManager

Detects the system package manager and abstracts installation commands.

### SecurityToolInstaller

Defines per-distribution package lists and installs security-related tools.

### FileScanner

Performs recursive directory traversal using std::filesystem and flags suspicious files based on:

* file extension
* hidden status
* executable permissions

### FirewallManager

Detects and configures ufw or firewalld depending on availability. Applies secure default rules and ensures SSH access is preserved.

### main()

Provides a unified entry point supporting both interactive and argument-based execution.

---

## Design Decisions

* Uses only standard C++17 and POSIX APIs to avoid external dependencies
* Implements cross-distribution compatibility through runtime detection
* Avoids blocking on permission errors using error_code and safe iteration
* Separates responsibilities into logical modules for maintainability
* Applies secure firewall defaults while preventing SSH lockout

---

## Limitations

* Not a full antivirus solution
* Does not include signature-based malware detection
* No real-time monitoring or intrusion detection
* Relies on external tools (e.g., nmap, clamav) for advanced functionality
* Package names may vary slightly across distributions

---

## Security Notes

* Always review commands before running as root
* Ensure your system repositories are properly configured
* Test firewall rules in a safe environment before deploying on remote systems

---

## Future Improvements

* SHA256 hashing and file integrity checks
* Integration with ClamAV for malware detection
* Parallel scanning using multithreading
* Structured output (JSON reports)
* Plugin system for extensibility
* Network scanning integration

---

## License

This project is provided as-is for educational and research purposes. Use at your own risk.

---

## Contribution

Contributions are welcome. Please open an issue or submit a pull request with improvements or bug fixes.
