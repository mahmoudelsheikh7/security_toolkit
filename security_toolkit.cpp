/**
 * ============================================================
 *  Linux Security Toolkit — security_toolkit.cpp
 *  Cross-distribution CLI security utility
 *
 *  Features:
 *    1. Package-manager detection & security-tool installation
 *    2. Recursive file/folder scanning (extensions, hidden, +x)
 *    3. Firewall detection, enablement, and basic rule-sets
 *    4. Action logging to /var/log/sec_toolkit.log
 *    5. Menu-based and argument-based CLI
 *
 *  Build:
 *    g++ -std=c++17 -Wall -Wextra -o security_toolkit security_toolkit.cpp
 *  Run:
 *    sudo ./security_toolkit          # interactive menu
 *    sudo ./security_toolkit --help   # argument usage
 * ============================================================
 */

#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>
#include <set>
#include <map>
#include <filesystem>
#include <chrono>
#include <ctime>
#include <cstdlib>
#include <cstring>
#include <stdexcept>
#include <algorithm>
#include <sys/stat.h>
#include <unistd.h>

namespace fs = std::filesystem;

// ============================================================
//  ANSI colour helpers
// ============================================================
namespace Color {
    const std::string RESET   = "\033[0m";
    const std::string RED     = "\033[1;31m";
    const std::string GREEN   = "\033[1;32m";
    const std::string YELLOW  = "\033[1;33m";
    const std::string CYAN    = "\033[1;36m";
    const std::string BOLD    = "\033[1m";
}

// ============================================================
//  Logger
//  Writes timestamped entries to LOG_PATH and to stdout.
// ============================================================
class Logger {
public:
    static const std::string LOG_PATH;

    static void log(const std::string& level, const std::string& msg) {
        std::string entry = "[" + timestamp() + "] [" + level + "] " + msg;
        // stdout
        if      (level == "INFO")  std::cout << Color::GREEN  << entry << Color::RESET << "\n";
        else if (level == "WARN")  std::cout << Color::YELLOW << entry << Color::RESET << "\n";
        else if (level == "ERROR") std::cerr << Color::RED    << entry << Color::RESET << "\n";
        else                       std::cout << entry << "\n";
        // file
        std::ofstream ofs(LOG_PATH, std::ios::app);
        if (ofs.is_open()) ofs << entry << "\n";
    }

    static void info (const std::string& m) { log("INFO",  m); }
    static void warn (const std::string& m) { log("WARN",  m); }
    static void error(const std::string& m) { log("ERROR", m); }

private:
    static std::string timestamp() {
        auto now  = std::chrono::system_clock::now();
        std::time_t t = std::chrono::system_clock::to_time_t(now);
        char buf[32];
        std::strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", std::localtime(&t));
        return buf;
    }
};

const std::string Logger::LOG_PATH = "/var/log/sec_toolkit.log";

// ============================================================
//  Helper: run a shell command and return exit code
// ============================================================
int runCmd(const std::string& cmd) {
    Logger::info("Executing: " + cmd);
    int ret = std::system(cmd.c_str());
    if (ret != 0)
        Logger::warn("Command returned non-zero exit code: " + std::to_string(ret));
    return ret;
}

// ============================================================
//  Helper: check whether an executable exists in PATH
// ============================================================
bool cmdExists(const std::string& name) {
    return std::system(("which " + name + " > /dev/null 2>&1").c_str()) == 0;
}

// ============================================================
//  Helper: read the first line of a file
// ============================================================
std::string readFileLine(const std::string& path) {
    std::ifstream f(path);
    std::string line;
    if (f.is_open()) std::getline(f, line);
    return line;
}

// ============================================================
//  Section 1 — Package Manager Detection & Tool Installation
// ============================================================

/**
 * PackageManager
 * Detects the distro family and wraps install commands.
 */
class PackageManager {
public:
    enum class Kind { APT, DNF, YUM, PACMAN, ZYPPER, UNKNOWN };

    PackageManager() : kind_(detect()) {}

    Kind kind() const { return kind_; }

    std::string name() const {
        switch (kind_) {
            case Kind::APT:    return "apt";
            case Kind::DNF:    return "dnf";
            case Kind::YUM:    return "yum";
            case Kind::PACMAN: return "pacman";
            case Kind::ZYPPER: return "zypper";
            default:           return "unknown";
        }
    }

    /**
     * Install a list of packages.
     * Returns true if all succeeded.
     */
    bool install(const std::vector<std::string>& pkgs) const {
        if (kind_ == Kind::UNKNOWN) {
            Logger::error("No supported package manager found.");
            return false;
        }
        std::string cmd = buildInstallCmd(pkgs);
        Logger::info("Installing packages via " + name() + ": " + joinPkgs(pkgs));
        return (runCmd(cmd) == 0);
    }

    /** Refresh package index (best-effort). */
    void update() const {
        switch (kind_) {
            case Kind::APT:    runCmd("apt-get update -y"); break;
            case Kind::DNF:    runCmd("dnf check-update -y || true"); break;
            case Kind::YUM:    runCmd("yum check-update -y || true"); break;
            case Kind::PACMAN: runCmd("pacman -Sy --noconfirm"); break;
            case Kind::ZYPPER: runCmd("zypper refresh"); break;
            default: break;
        }
    }

private:
    Kind kind_;

    static Kind detect() {
        if (cmdExists("apt-get")) return Kind::APT;
        if (cmdExists("dnf"))     return Kind::DNF;
        if (cmdExists("yum"))     return Kind::YUM;
        if (cmdExists("pacman"))  return Kind::PACMAN;
        if (cmdExists("zypper"))  return Kind::ZYPPER;
        return Kind::UNKNOWN;
    }

    std::string buildInstallCmd(const std::vector<std::string>& pkgs) const {
        std::string list = joinPkgs(pkgs);
        switch (kind_) {
            case Kind::APT:    return "apt-get install -y " + list;
            case Kind::DNF:    return "dnf install -y "     + list;
            case Kind::YUM:    return "yum install -y "     + list;
            case Kind::PACMAN: return "pacman -S --noconfirm " + list;
            case Kind::ZYPPER: return "zypper install -y "  + list;
            default:           return "";
        }
    }

    static std::string joinPkgs(const std::vector<std::string>& pkgs) {
        std::string s;
        for (size_t i = 0; i < pkgs.size(); ++i) {
            if (i) s += " ";
            s += pkgs[i];
        }
        return s;
    }
};

/**
 * SecurityToolInstaller
 * Knows which package names map to each distro family and
 * installs a curated set of security utilities.
 */
class SecurityToolInstaller {
public:
    explicit SecurityToolInstaller(const PackageManager& pm) : pm_(pm) {}

    void installAll() {
        Logger::info("=== Starting security-tool installation ===");
        pm_.update();

        auto pkgs = selectPackages();
        if (pkgs.empty()) {
            Logger::warn("No package list available for this distro.");
            return;
        }

        // Install individually so one failure doesn't block the rest
        int ok = 0, fail = 0;
        for (const auto& p : pkgs) {
            if (pm_.install({p})) ++ok;
            else                  ++fail;
        }

        Logger::info("Installation complete. Success: " + std::to_string(ok) +
                     "  Failed: " + std::to_string(fail));
    }

private:
    const PackageManager& pm_;

    /**
     * Returns the correct package names for the active distro.
     * Firewall tool selection: ufw for Debian/Ubuntu, firewalld elsewhere.
     */
    std::vector<std::string> selectPackages() const {
        using K = PackageManager::Kind;
        switch (pm_.kind()) {
            case K::APT:
                return { "nmap", "ufw", "fail2ban", "rkhunter",
                         "chkrootkit", "lynis", "clamav", "net-tools",
                         "tcpdump", "curl", "wget", "unzip" };

            case K::DNF:
            case K::YUM:
                return { "nmap", "firewalld", "fail2ban", "rkhunter",
                         "lynis", "clamav", "net-tools",
                         "tcpdump", "curl", "wget", "unzip" };

            case K::PACMAN:
                return { "nmap", "ufw", "fail2ban", "rkhunter",
                         "lynis", "clamav", "net-tools",
                         "tcpdump", "curl", "wget", "unzip" };

            case K::ZYPPER:
                return { "nmap", "firewalld", "fail2ban", "rkhunter",
                         "clamav", "net-tools",
                         "tcpdump", "curl", "wget", "unzip" };

            default:
                return {};
        }
    }
};

// ============================================================
//  Section 2 — File and Folder Scanner
// ============================================================

/**
 * ScanResult — holds details about one suspicious file entry.
 */
struct ScanResult {
    std::string path;
    std::string reason;     // "suspicious_ext | hidden | executable"
};

/**
 * FileScanner
 * Recursively walks a directory tree and flags files that
 * match any of three heuristics:
 *   - Suspicious extension (shells, scripts, known malware exts)
 *   - Hidden file (name starts with '.')
 *   - Executable bit set (and is a regular file)
 */
class FileScanner {
public:
    // Extensions to flag (expand as needed)
    static const std::set<std::string> SUSPICIOUS_EXTS;

    std::vector<ScanResult> scan(const std::string& rootPath) {
        results_.clear();
        scannedCount_ = 0;

        Logger::info("=== Starting file scan on: " + rootPath + " ===");

        fs::path root(rootPath);
        if (!fs::exists(root) || !fs::is_directory(root)) {
            Logger::error("Path does not exist or is not a directory: " + rootPath);
            return {};
        }

        try {
            scanDir(root);
        } catch (const std::exception& ex) {
            Logger::error(std::string("Scan error: ") + ex.what());
        }

        Logger::info("Scan complete. Files inspected: " + std::to_string(scannedCount_) +
                     "  Suspicious: " + std::to_string(results_.size()));
        return results_;
    }

    void printReport(const std::vector<ScanResult>& results) const {
        std::cout << "\n" << Color::BOLD << Color::CYAN
                  << "====== File Scan Report ======" << Color::RESET << "\n";

        if (results.empty()) {
            std::cout << Color::GREEN << "  No suspicious files found.\n" << Color::RESET;
        } else {
            std::cout << Color::YELLOW << "  Suspicious files detected: "
                      << results.size() << "\n" << Color::RESET;
            for (const auto& r : results) {
                std::cout << Color::RED << "  [!] " << Color::RESET
                          << r.path << "\n"
                          << "       Reason: " << r.reason << "\n";
            }
        }
        std::cout << Color::BOLD << Color::CYAN
                  << "==============================\n" << Color::RESET;

        // Append report to log
        std::ofstream ofs(Logger::LOG_PATH, std::ios::app);
        if (ofs.is_open()) {
            ofs << "\n--- File Scan Report ---\n";
            for (const auto& r : results)
                ofs << "[SUSPICIOUS] " << r.path << " | " << r.reason << "\n";
            ofs << "--- End Report ---\n\n";
        }
    }

private:
    std::vector<ScanResult> results_;
    size_t scannedCount_ = 0;

    void scanDir(const fs::path& dir) {
        // Use recursive_directory_iterator with error_code to skip permission errors
        std::error_code ec;
        for (auto& entry : fs::recursive_directory_iterator(
                 dir,
                 fs::directory_options::skip_permission_denied,
                 ec)) {
            if (ec) { ec.clear(); continue; }
            if (!entry.is_regular_file(ec)) { ec.clear(); continue; }

            ++scannedCount_;
            std::string reason = evaluateFile(entry.path());
            if (!reason.empty())
                results_.push_back({ entry.path().string(), reason });
        }
    }

    static std::string evaluateFile(const fs::path& p) {
        std::vector<std::string> flags;

        // 1. Suspicious extension
        std::string ext = p.extension().string();
        std::transform(ext.begin(), ext.end(), ext.begin(), ::tolower);
        if (!ext.empty() && SUSPICIOUS_EXTS.count(ext))
            flags.push_back("suspicious_ext(" + ext + ")");

        // 2. Hidden file (Unix convention: name starts with '.')
        std::string fname = p.filename().string();
        if (!fname.empty() && fname[0] == '.')
            flags.push_back("hidden");

        // 3. Executable bit for regular files
        struct stat st{};
        if (::stat(p.c_str(), &st) == 0) {
            if (st.st_mode & (S_IXUSR | S_IXGRP | S_IXOTH))
                flags.push_back("executable");
        }

        if (flags.empty()) return "";

        // Join reasons
        std::string r;
        for (size_t i = 0; i < flags.size(); ++i) {
            if (i) r += " | ";
            r += flags[i];
        }
        return r;
    }
};

const std::set<std::string> FileScanner::SUSPICIOUS_EXTS = {
    ".sh", ".bash", ".zsh", ".py", ".pl", ".rb",
    ".php", ".js", ".lua", ".tcl", ".awk",
    ".exe", ".elf", ".bin", ".out",
    ".ko",                              // kernel module
    ".so",                              // shared object
    ".bat", ".cmd",                     // windows scripts (unusual on Linux)
    ".enc", ".crypt", ".gpg",           // encrypted blobs
    ".b64",                             // base64 blobs
    ".tmp", ".swp"                      // editor temporaries
};

// ============================================================
//  Section 3 — Firewall Manager
// ============================================================

/**
 * FirewallManager
 * Detects whether ufw or firewalld is available, enables it,
 * and applies a minimal secure policy:
 *   - Default deny incoming
 *   - Default allow outgoing
 *   - Allow SSH (port 22) so the admin doesn't lock herself out
 */
class FirewallManager {
public:
    enum class FW { UFW, FIREWALLD, NONE };

    FirewallManager() : fw_(detect()) {}

    void configure() {
        Logger::info("=== Firewall Configuration ===");
        switch (fw_) {
            case FW::UFW:       configureUfw();       break;
            case FW::FIREWALLD: configureFirewalld(); break;
            case FW::NONE:
                Logger::warn("No supported firewall found (ufw / firewalld)."
                             " Install one first.");
                break;
        }
    }

    std::string fwName() const {
        switch (fw_) {
            case FW::UFW:       return "ufw";
            case FW::FIREWALLD: return "firewalld";
            default:            return "none";
        }
    }

private:
    FW fw_;

    static FW detect() {
        if (cmdExists("ufw"))           return FW::UFW;
        if (cmdExists("firewall-cmd"))  return FW::FIREWALLD;
        return FW::NONE;
    }

    static void configureUfw() {
        Logger::info("Detected firewall: ufw");
        runCmd("ufw --force reset");            // clear existing rules
        runCmd("ufw default deny incoming");
        runCmd("ufw default allow outgoing");
        runCmd("ufw allow ssh");                // allow port 22 (avoid lockout)
        runCmd("ufw --force enable");
        runCmd("ufw status verbose");
        Logger::info("ufw configured and enabled.");
    }

    static void configureFirewalld() {
        Logger::info("Detected firewall: firewalld");
        runCmd("systemctl enable --now firewalld");
        runCmd("firewall-cmd --set-default-zone=public");
        runCmd("firewall-cmd --permanent --zone=public --set-target=DROP");
        runCmd("firewall-cmd --permanent --zone=public --add-service=ssh");
        runCmd("firewall-cmd --permanent --zone=public --add-service=dhcpv6-client");
        runCmd("firewall-cmd --reload");
        runCmd("firewall-cmd --list-all");
        Logger::info("firewalld configured and enabled.");
    }
};

// ============================================================
//  Section 5 — CLI Interface
// ============================================================

static void printBanner() {
    std::cout << Color::BOLD << Color::CYAN
              << R"(
  ╔════════════════════════════════════════╗
  ║     Linux Security Toolkit v1.0        ║
  ║  Cross-distro CLI security utility     ║
  ╚════════════════════════════════════════╝
)" << Color::RESET;
}

static void printMenu() {
    std::cout << "\n" << Color::BOLD << "Main Menu" << Color::RESET << "\n"
              << "  [1] Install security tools\n"
              << "  [2] Scan a directory\n"
              << "  [3] Configure firewall\n"
              << "  [4] Run all (install → scan → firewall)\n"
              << "  [5] Show log path\n"
              << "  [0] Exit\n"
              << "Choose an option: ";
}

static void printHelp(const char* argv0) {
    std::cout << Color::BOLD << "Usage:" << Color::RESET << "\n"
              << "  " << argv0 << "                  Launch interactive menu\n"
              << "  " << argv0 << " --install         Install security tools\n"
              << "  " << argv0 << " --scan <path>     Scan a directory\n"
              << "  " << argv0 << " --firewall        Configure firewall\n"
              << "  " << argv0 << " --all [<path>]    Run all modules\n"
              << "  " << argv0 << " --help            Show this help\n"
              << "\nLog file: " << Logger::LOG_PATH << "\n";
}

// ============================================================
//  Module runners (re-used by both menu and argument paths)
// ============================================================

static void moduleInstall() {
    PackageManager pm;
    Logger::info("Detected package manager: " + pm.name());
    SecurityToolInstaller installer(pm);
    installer.installAll();
}

static void moduleScan(const std::string& path) {
    FileScanner scanner;
    auto results = scanner.scan(path);
    scanner.printReport(results);
}

static void moduleFirewall() {
    FirewallManager fw;
    Logger::info("Detected firewall tool: " + fw.fwName());
    fw.configure();
}

static void moduleAll(const std::string& scanPath) {
    moduleInstall();
    moduleScan(scanPath);
    moduleFirewall();
}

// ============================================================
//  main()
// ============================================================
int main(int argc, char* argv[]) {

    // Privilege check
    if (::getuid() != 0) {
        std::cerr << Color::RED
                  << "[ERROR] This toolkit requires root privileges. "
                     "Please run with sudo.\n"
                  << Color::RESET;
        return 1;
    }

    printBanner();
    Logger::info("Security Toolkit started.");

    // ── Argument-based mode ──────────────────────────────────
    if (argc > 1) {
        std::string arg = argv[1];

        if (arg == "--help" || arg == "-h") {
            printHelp(argv[0]);

        } else if (arg == "--install") {
            moduleInstall();

        } else if (arg == "--scan") {
            std::string path = (argc > 2) ? argv[2] : "/home";
            moduleScan(path);

        } else if (arg == "--firewall") {
            moduleFirewall();

        } else if (arg == "--all") {
            std::string path = (argc > 2) ? argv[2] : "/home";
            moduleAll(path);

        } else {
            std::cerr << Color::RED << "Unknown argument: " << arg
                      << Color::RESET << "\n";
            printHelp(argv[0]);
            return 1;
        }

        Logger::info("Security Toolkit finished.");
        return 0;
    }

    // ── Interactive menu mode ────────────────────────────────
    while (true) {
        printMenu();

        std::string choice;
        std::getline(std::cin, choice);

        if      (choice == "0") { Logger::info("Exiting."); break; }
        else if (choice == "1") { moduleInstall(); }
        else if (choice == "2") {
            std::cout << "Enter directory path to scan [/home]: ";
            std::string path;
            std::getline(std::cin, path);
            if (path.empty()) path = "/home";
            moduleScan(path);
        }
        else if (choice == "3") { moduleFirewall(); }
        else if (choice == "4") {
            std::cout << "Enter directory path to scan [/home]: ";
            std::string path;
            std::getline(std::cin, path);
            if (path.empty()) path = "/home";
            moduleAll(path);
        }
        else if (choice == "5") {
            std::cout << "Log file: " << Logger::LOG_PATH << "\n";
        }
        else {
            std::cout << Color::YELLOW
                      << "Invalid option. Please enter 0–5.\n"
                      << Color::RESET;
        }
    }

    Logger::info("Security Toolkit finished.");
    return 0;
}
