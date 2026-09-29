/**
 * ============================================================
 *  Linux Security Toolkit v2.0 - security_toolkit.cpp
 *  Cross-distribution CLI security utility
 *
 *  Features:
 *    1. Package-manager detection & security-tool installation
 *       (apt, dnf, yum, pacman, zypper, apk, xbps)
 *    2. Recursive file/folder scanning (extensions, hidden, +x,
 *       setuid/setgid, world-writable)
 *    3. Firewall detection and secure defaults (ufw / firewalld)
 *       with SSH-lockout protection
 *    4. Action logging (/var/log/sec_toolkit.log, with fallback
 *       to a user-writable location when not root)
 *    5. Menu-based and argument-based CLI
 *
 *  Build (GCC 8+ / Clang 7+):
 *    g++ -std=c++17 -Wall -Wextra -O2 security_toolkit.cpp -o security_toolkit
 *    (GCC 8 only: add -lstdc++fs)
 *  Run:
 *    sudo ./security_toolkit          # interactive menu
 *    ./security_toolkit --help
 * ============================================================
 */

#include <algorithm>
#include <cctype>
#include <cerrno>
#include <chrono>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <fstream>
#include <iostream>
#include <map>
#include <set>
#include <sstream>
#include <string>
#include <vector>
#include <filesystem>

#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

namespace fs = std::filesystem;

static const char* const VERSION = "2.0";

// ============================================================
//  Terminal colours (disabled automatically when not a TTY,
//  when NO_COLOR is set, or with --no-color)
// ============================================================
namespace Color {
    static bool enabled = false;
    static const char* const RESET  = "\033[0m";
    static const char* const RED    = "\033[1;31m";
    static const char* const GREEN  = "\033[1;32m";
    static const char* const YELLOW = "\033[1;33m";
    static const char* const CYAN   = "\033[1;36m";
    static const char* const BOLD   = "\033[1m";
    static const char* p(const char* code) { return enabled ? code : ""; }
}

// ============================================================
//  Small string helpers
// ============================================================
static std::string toLower(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return s;
}

static std::string trim(const std::string& s) {
    size_t b = s.find_first_not_of(" \t\r\n");
    if (b == std::string::npos) return "";
    size_t e = s.find_last_not_of(" \t\r\n");
    return s.substr(b, e - b + 1);
}

static std::string join(const std::vector<std::string>& v, const std::string& sep) {
    std::string out;
    for (size_t i = 0; i < v.size(); ++i) {
        if (i) out += sep;
        out += v[i];
    }
    return out;
}

// ============================================================
//  Logger
//  Writes timestamped entries to the console and to a log file.
//  Tries /var/log/sec_toolkit.log first; if that is not
//  writable (non-root), falls back to a per-user location.
// ============================================================
class Logger {
public:
    static void init() {
        for (const std::string& candidate : candidates()) {
            std::error_code ec;
            fs::path p(candidate);
            if (p.has_parent_path()) fs::create_directories(p.parent_path(), ec);
            const bool existed = fs::exists(p, ec);
            file().open(candidate, std::ios::app);
            if (file().is_open()) {
                path() = candidate;
                if (!existed)   // log contains file paths: keep it private-ish
                    fs::permissions(p, fs::perms::owner_read | fs::perms::owner_write |
                                       fs::perms::group_read, ec);
                return;
            }
            file().clear();
        }
        path() = "(console only - no writable log location)";
    }

    static const std::string& logPath() { return path(); }

    static void info (const std::string& m) { log("INFO",  m); }
    static void warn (const std::string& m) { log("WARN",  m); }
    static void error(const std::string& m) { log("ERROR", m); }

    /** Append raw text to the log file only. */
    static void raw(const std::string& text) {
        if (file().is_open()) { file() << text; file().flush(); }
    }

private:
    static std::ofstream& file() { static std::ofstream f; return f; }
    static std::string&   path() { static std::string p; return p; }

    static std::vector<std::string> candidates() {
        std::vector<std::string> c{"/var/log/sec_toolkit.log"};
        if (const char* xdg = std::getenv("XDG_STATE_HOME"); xdg && *xdg)
            c.push_back(std::string(xdg) + "/sec_toolkit/sec_toolkit.log");
        if (const char* home = std::getenv("HOME"); home && *home)
            c.push_back(std::string(home) + "/.local/state/sec_toolkit/sec_toolkit.log");
        c.push_back("/tmp/sec_toolkit-" + std::to_string(::getuid()) + ".log");
        return c;
    }

    static std::string timestamp() {
        std::time_t t = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
        std::tm tmv{};
        ::localtime_r(&t, &tmv);                       // thread-safe variant
        char buf[32];
        std::strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", &tmv);
        return buf;
    }

    static void log(const std::string& level, const std::string& msg) {
        const std::string entry = "[" + timestamp() + "] [" + level + "] " + msg;
        if (level == "INFO")
            std::cout << Color::p(Color::GREEN) << entry << Color::p(Color::RESET) << "\n";
        else if (level == "WARN")
            std::cout << Color::p(Color::YELLOW) << entry << Color::p(Color::RESET) << "\n";
        else
            std::cerr << Color::p(Color::RED) << entry << Color::p(Color::RESET) << "\n";
        raw(entry + "\n");
    }
};

// ============================================================
//  Process / environment helpers
// ============================================================

/** Make sure sbin directories are searched (e.g. `su` without `-` on Debian). */
static void augmentPath() {
    std::string path = std::getenv("PATH") ? std::getenv("PATH") : "";
    std::set<std::string> present;
    {
        std::stringstream ss(path);
        std::string tok;
        while (std::getline(ss, tok, ':')) present.insert(tok);
    }
    for (const char* d : {"/usr/local/sbin", "/usr/local/bin", "/usr/sbin",
                          "/usr/bin", "/sbin", "/bin"}) {
        if (!present.count(d)) {
            if (!path.empty()) path += ':';
            path += d;
        }
    }
    ::setenv("PATH", path.c_str(), 1);
}

/** Look up an executable in PATH without relying on `which` (not always installed). */
static bool cmdExists(const std::string& name) {
    if (name.find('/') != std::string::npos) return ::access(name.c_str(), X_OK) == 0;
    const char* p = std::getenv("PATH");
    if (!p) return false;
    std::stringstream ss(p);
    std::string dir;
    while (std::getline(ss, dir, ':')) {
        if (dir.empty()) continue;
        const std::string full = dir + "/" + name;
        struct stat st{};
        if (::stat(full.c_str(), &st) == 0 && S_ISREG(st.st_mode) &&
            ::access(full.c_str(), X_OK) == 0)
            return true;
    }
    return false;
}

/**
 * Run a command WITHOUT a shell (no quoting/injection issues).
 * Returns the real exit code (not the raw wait status).
 */
static int runCmd(const std::vector<std::string>& args, bool quiet = false) {
    if (args.empty()) return -1;
    if (!quiet) Logger::info("Executing: " + join(args, " "));

    std::cout.flush();
    std::cerr.flush();

    const pid_t pid = ::fork();
    if (pid < 0) {
        Logger::error(std::string("fork() failed: ") + std::strerror(errno));
        return -1;
    }
    if (pid == 0) {
        ::setenv("DEBIAN_FRONTEND", "noninteractive", 1);
        if (quiet) {
            int fd = ::open("/dev/null", O_RDWR);
            if (fd >= 0) { ::dup2(fd, 1); ::dup2(fd, 2); if (fd > 2) ::close(fd); }
        }
        std::vector<char*> argv;
        for (const auto& a : args) argv.push_back(const_cast<char*>(a.c_str()));
        argv.push_back(nullptr);
        ::execvp(argv[0], argv.data());
        ::_exit(127);
    }

    int status = 0;
    while (::waitpid(pid, &status, 0) < 0) {
        if (errno != EINTR) return -1;
    }
    const int code = WIFEXITED(status) ? WEXITSTATUS(status) : 128 + WTERMSIG(status);
    if (!quiet) {
        if (code == 127) Logger::warn("Command not found: " + args[0]);
        else if (code != 0) Logger::warn("Command exited with code " + std::to_string(code));
    }
    return code;
}

/** Parse /etc/os-release (fallback /usr/lib/os-release) into key/value pairs. */
static std::map<std::string, std::string> readOsRelease() {
    std::map<std::string, std::string> kv;
    std::ifstream f("/etc/os-release");
    if (!f.is_open()) f.open("/usr/lib/os-release");
    std::string line;
    while (std::getline(f, line)) {
        const size_t eq = line.find('=');
        if (eq == std::string::npos || line[0] == '#') continue;
        std::string val = trim(line.substr(eq + 1));
        if (val.size() >= 2 && (val.front() == '"' || val.front() == '\'') &&
            val.back() == val.front())
            val = val.substr(1, val.size() - 2);
        kv[line.substr(0, eq)] = val;
    }
    return kv;
}

static bool isRoot() { return ::geteuid() == 0; }

static bool requireRoot(const std::string& what) {
    if (isRoot()) return true;
    Logger::error(what + " requires root privileges. Re-run with sudo.");
    return false;
}

static bool g_assumeYes = false;

/** Ask before making changes that could affect remote access. */
static bool confirm(const std::string& question) {
    if (g_assumeYes) return true;
    if (!::isatty(STDIN_FILENO)) {
        Logger::error("Confirmation required but stdin is not a terminal. "
                      "Re-run with --yes to proceed non-interactively.");
        return false;
    }
    std::cout << Color::p(Color::YELLOW) << question << " [y/N]: " << Color::p(Color::RESET);
    std::string ans;
    if (!std::getline(std::cin, ans)) return false;
    ans = toLower(trim(ans));
    return ans == "y" || ans == "yes";
}

/** Enable and start a service on systemd, OpenRC or runit systems. */
static void enableService(const std::string& name) {
    if (cmdExists("systemctl") && fs::exists("/run/systemd/system")) {
        runCmd({"systemctl", "enable", "--now", name});
    } else if (cmdExists("rc-update")) {
        runCmd({"rc-update", "add", name, "default"});
        runCmd({"rc-service", name, "start"});
    } else if (cmdExists("sv") && fs::exists("/etc/sv/" + name)) {
        runCmd({"ln", "-sf", "/etc/sv/" + name, "/var/service/" + name});
    } else {
        Logger::warn("No supported init system found; start '" + name + "' manually.");
    }
}

// ============================================================
//  Section 1 - Package Manager Detection & Tool Installation
// ============================================================
class PackageManager {
public:
    enum class Kind { APT, DNF, YUM, PACMAN, ZYPPER, APK, XBPS, UNKNOWN };

    PackageManager() {
        auto rel = readOsRelease();
        osId_   = toLower(rel["ID"]);
        osLike_ = toLower(rel["ID_LIKE"]);
        prettyName_ = rel["PRETTY_NAME"];
        kind_ = detect();
    }

    Kind kind() const { return kind_; }
    const std::string& prettyName() const { return prettyName_; }

    std::string name() const {
        switch (kind_) {
            case Kind::APT:    return "apt";
            case Kind::DNF:    return "dnf";
            case Kind::YUM:    return "yum";
            case Kind::PACMAN: return "pacman";
            case Kind::ZYPPER: return "zypper";
            case Kind::APK:    return "apk";
            case Kind::XBPS:   return "xbps";
            default:           return "unknown";
        }
    }

    /** RHEL, CentOS, Rocky, Alma, Oracle... (needs EPEL for several tools). */
    bool isRhelDerivative() const {
        if (osId_ == "fedora") return false;
        const std::string all = osId_ + " " + osLike_;
        return all.find("rhel") != std::string::npos || all.find("centos") != std::string::npos;
    }

    bool install(const std::string& pkg) const {
        std::vector<std::string> cmd;
        switch (kind_) {
            case Kind::APT:
                cmd = {"apt-get", "install", "-y", "--no-install-recommends", pkg}; break;
            case Kind::DNF:    cmd = {"dnf", "install", "-y", pkg}; break;
            case Kind::YUM:    cmd = {"yum", "install", "-y", pkg}; break;
            // No -Sy here: refreshing the DB without a full upgrade is an
            // unsupported partial upgrade on Arch.
            case Kind::PACMAN: cmd = {"pacman", "-S", "--needed", "--noconfirm", pkg}; break;
            case Kind::ZYPPER: cmd = {"zypper", "--non-interactive", "install", pkg}; break;
            case Kind::APK:    cmd = {"apk", "add", pkg}; break;
            case Kind::XBPS:   cmd = {"xbps-install", "-y", pkg}; break;
            default:
                Logger::error("No supported package manager found.");
                return false;
        }
        return runCmd(cmd) == 0;
    }

    /** Refresh package metadata (best effort). */
    void update() const {
        switch (kind_) {
            case Kind::APT:    runCmd({"apt-get", "update"}); break;
            case Kind::DNF:    runCmd({"dnf", "makecache", "-y"}); break;
            case Kind::YUM:    runCmd({"yum", "makecache"}); break;
            case Kind::PACMAN: /* intentionally no -Sy, see install() */ break;
            case Kind::ZYPPER: runCmd({"zypper", "--non-interactive",
                                       "--gpg-auto-import-keys", "refresh"}); break;
            case Kind::APK:    runCmd({"apk", "update"}); break;
            case Kind::XBPS:   runCmd({"xbps-install", "-S", "-y"}); break;
            default: break;
        }
    }

    /** Distro-specific hint shown when some packages could not be installed. */
    std::string failureHint() const {
        switch (kind_) {
            case Kind::DNF:
            case Kind::YUM:
                return isRhelDerivative()
                    ? "Enable EPEL (dnf install epel-release) - fail2ban, lynis and clamav live there."
                    : "Check that the 'updates' repository is enabled.";
            case Kind::PACMAN:
                return "If you saw 404 errors run 'sudo pacman -Syu' first; some tools may be AUR-only.";
            case Kind::ZYPPER:
                return "Some tools (lynis, rkhunter) live in the security:tools or Packman repos.";
            case Kind::APK:
                return "Enable the 'community' repository in /etc/apk/repositories.";
            default:
                return "Check your enabled repositories.";
        }
    }

private:
    Kind kind_ = Kind::UNKNOWN;
    std::string osId_, osLike_, prettyName_;

    static const char* commandFor(Kind k) {
        switch (k) {
            case Kind::APT:    return "apt-get";
            case Kind::DNF:    return "dnf";
            case Kind::YUM:    return "yum";
            case Kind::PACMAN: return "pacman";
            case Kind::ZYPPER: return "zypper";
            case Kind::APK:    return "apk";
            case Kind::XBPS:   return "xbps-install";
            default:           return "";
        }
    }

    Kind detect() const {
        const std::string all = osId_ + " " + osLike_;
        auto has = [&](const char* w) { return all.find(w) != std::string::npos; };

        std::vector<Kind> order;
        if (has("debian") || has("ubuntu"))                        order.push_back(Kind::APT);
        if (has("fedora") || has("rhel") || has("centos"))       { order.push_back(Kind::DNF);
                                                                   order.push_back(Kind::YUM); }
        if (has("arch"))                                           order.push_back(Kind::PACMAN);
        if (has("suse") || has("sles"))                            order.push_back(Kind::ZYPPER);
        if (has("alpine"))                                         order.push_back(Kind::APK);
        if (has("void"))                                           order.push_back(Kind::XBPS);

        // Fallback: probe for commands (also covers unknown derivatives)
        for (Kind k : {Kind::APT, Kind::DNF, Kind::YUM, Kind::PACMAN,
                       Kind::ZYPPER, Kind::APK, Kind::XBPS})
            order.push_back(k);

        for (Kind k : order)
            if (cmdExists(commandFor(k))) return k;
        return Kind::UNKNOWN;
    }
};

class SecurityToolInstaller {
public:
    explicit SecurityToolInstaller(const PackageManager& pm) : pm_(pm) {}

    void installAll() {
        Logger::info("=== Starting security-tool installation ===");
        if (pm_.kind() == PackageManager::Kind::UNKNOWN) {
            Logger::error("No supported package manager found "
                          "(apt, dnf, yum, pacman, zypper, apk, xbps).");
            return;
        }
        pm_.update();

        if ((pm_.kind() == PackageManager::Kind::DNF ||
             pm_.kind() == PackageManager::Kind::YUM) && pm_.isRhelDerivative()) {
            Logger::info("RHEL-family system detected: trying to enable EPEL.");
            pm_.install("epel-release");
        }

        const auto pkgs = selectPackages();
        std::vector<std::string> failed;
        int ok = 0;
        for (const auto& p : pkgs) {          // one at a time: a missing package
            if (pm_.install(p)) ++ok;         // must not block the others
            else failed.push_back(p);
        }

        Logger::info("Installation complete. Success: " + std::to_string(ok) +
                     "  Failed: " + std::to_string(failed.size()));
        if (!failed.empty()) {
            Logger::warn("Could not install: " + join(failed, ", "));
            Logger::warn(pm_.failureHint());
        }
    }

private:
    const PackageManager& pm_;

    std::vector<std::string> selectPackages() const {
        using K = PackageManager::Kind;
        std::vector<std::string> pkgs = {"nmap", "fail2ban", "rkhunter", "lynis",
                                         "clamav", "net-tools", "tcpdump",
                                         "curl", "wget", "unzip"};
        if (pm_.kind() == K::APT) pkgs.push_back("chkrootkit");

        // Only add a firewall if none is present (avoids ufw/firewalld conflicts)
        if (!cmdExists("ufw") && !cmdExists("firewall-cmd")) {
            switch (pm_.kind()) {
                case K::DNF: case K::YUM: case K::ZYPPER:
                    pkgs.push_back("firewalld"); break;
                default:
                    pkgs.push_back("ufw"); break;
            }
        }
        return pkgs;
    }
};

// ============================================================
//  Section 2 - File and Folder Scanner
// ============================================================
struct ScanResult {
    std::string path;
    std::string reason;
};

class FileScanner {
public:
    static const std::set<std::string> SUSPICIOUS_EXTS;

    std::vector<ScanResult> scan(const std::string& rootPath) {
        results_.clear();
        scanned_ = 0;
        skippedDirs_ = 0;

        Logger::info("=== Starting file scan on: " + rootPath + " ===");

        std::error_code ec;
        fs::path root = fs::absolute(rootPath, ec).lexically_normal();
        if (ec || !fs::is_directory(root, ec)) {
            Logger::error("Path does not exist or is not a directory: " + rootPath);
            return {};
        }

        // Iterative traversal: an error in one directory never aborts the scan,
        // symlinks are never followed, virtual filesystems are skipped.
        std::vector<fs::path> stack{root};
        while (!stack.empty()) {
            fs::path dir = std::move(stack.back());
            stack.pop_back();

            if (dir != root && isVirtualFs(dir)) continue;

            fs::directory_iterator it(dir, fs::directory_options::skip_permission_denied, ec);
            if (ec) { ++skippedDirs_; ec.clear(); continue; }

            for (const fs::directory_iterator end; it != end;) {
                std::error_code sec;
                const fs::file_status st = it->symlink_status(sec);
                if (!sec) {
                    if (fs::is_directory(st))         stack.push_back(it->path());
                    else if (fs::is_regular_file(st)) inspect(it->path());
                }
                it.increment(ec);
                if (ec) { ++skippedDirs_; ec.clear(); break; }
            }
        }

        Logger::info("Scan complete. Files inspected: " + std::to_string(scanned_) +
                     "  Suspicious: " + std::to_string(results_.size()) +
                     "  Unreadable dirs skipped: " + std::to_string(skippedDirs_));
        return results_;
    }

    void printReport(const std::vector<ScanResult>& results) const {
        std::cout << "\n" << Color::p(Color::BOLD) << Color::p(Color::CYAN)
                  << "====== File Scan Report ======" << Color::p(Color::RESET) << "\n";

        if (results.empty()) {
            std::cout << Color::p(Color::GREEN) << "  No suspicious files found.\n"
                      << Color::p(Color::RESET);
        } else {
            std::cout << Color::p(Color::YELLOW) << "  Suspicious files detected: "
                      << results.size() << "\n" << Color::p(Color::RESET);
            for (const auto& r : results)
                std::cout << Color::p(Color::RED) << "  [!] " << Color::p(Color::RESET)
                          << r.path << "\n       Reason: " << r.reason << "\n";
        }
        std::cout << Color::p(Color::BOLD) << Color::p(Color::CYAN)
                  << "==============================\n" << Color::p(Color::RESET);

        std::string block = "\n--- File Scan Report ---\n";
        for (const auto& r : results)
            block += "[SUSPICIOUS] " + r.path + " | " + r.reason + "\n";
        block += "--- End Report ---\n\n";
        Logger::raw(block);
    }

private:
    std::vector<ScanResult> results_;
    size_t scanned_ = 0;
    size_t skippedDirs_ = 0;

    static bool isVirtualFs(const fs::path& p) {
        static const std::set<std::string> skip = {"/proc", "/sys", "/dev"};
        return skip.count(p.string()) > 0;
    }

    void inspect(const fs::path& p) {
        struct stat st{};
        if (::lstat(p.c_str(), &st) != 0) return;
        ++scanned_;

        std::vector<std::string> flags;

        std::string ext = toLower(p.extension().string());
        if (!ext.empty() && SUSPICIOUS_EXTS.count(ext))
            flags.push_back("suspicious_ext(" + ext + ")");

        const std::string fname = p.filename().string();
        if (!fname.empty() && fname[0] == '.')      flags.push_back("hidden");
        if (st.st_mode & (S_IXUSR | S_IXGRP | S_IXOTH)) flags.push_back("executable");
        if (st.st_mode & S_ISUID)                   flags.push_back("setuid");
        if (st.st_mode & S_ISGID)                   flags.push_back("setgid");
        if (st.st_mode & S_IWOTH)                   flags.push_back("world_writable");

        if (!flags.empty())
            results_.push_back({p.string(), join(flags, " | ")});
    }
};

const std::set<std::string> FileScanner::SUSPICIOUS_EXTS = {
    ".sh", ".bash", ".zsh", ".py", ".pl", ".rb",
    ".php", ".js", ".lua", ".tcl", ".awk",
    ".exe", ".elf", ".bin", ".out",
    ".ko",                       // kernel module
    ".so",                       // shared object
    ".bat", ".cmd",              // Windows scripts (unusual on Linux)
    ".enc", ".crypt", ".gpg",    // encrypted blobs
    ".b64",                      // base64 blobs
    ".tmp", ".swp"               // editor temporaries
};

// ============================================================
//  Section 3 - Firewall Manager
//    - default deny incoming / allow outgoing
//    - keeps every SSH port open (config + current session)
//    - does NOT wipe existing rules
// ============================================================
class FirewallManager {
public:
    enum class FW { UFW, FIREWALLD, NONE };

    FirewallManager() : fw_(detect()) {}

    std::string fwName() const {
        switch (fw_) {
            case FW::UFW:       return "ufw";
            case FW::FIREWALLD: return "firewalld";
            default:            return "none";
        }
    }

    void configure() {
        Logger::info("=== Firewall Configuration ===");
        if (fw_ == FW::NONE) {
            Logger::warn("No supported firewall found (ufw / firewalld). "
                         "Run the install step first.");
            return;
        }

        const std::vector<int> ports = sshPorts();
        std::string plist;
        for (int p : ports) plist += (plist.empty() ? "" : ", ") + std::to_string(p);

        if (!confirm("This will set '" + fwName() + "' to deny incoming / allow outgoing "
                     "and keep SSH port(s) " + plist + " open. Continue?")) {
            Logger::warn("Firewall configuration cancelled.");
            return;
        }
        if (fw_ == FW::UFW) configureUfw(ports);
        else                configureFirewalld(ports);
    }

private:
    FW fw_;

    static FW detect() {
        const bool hasUfw = cmdExists("ufw");
        const bool hasFwd = cmdExists("firewall-cmd");
        // Prefer whichever is already running, to avoid fighting an active firewall
        if (hasFwd && cmdExists("systemctl") &&
            runCmd({"systemctl", "is-active", "--quiet", "firewalld"}, true) == 0)
            return FW::FIREWALLD;
        if (hasUfw) return FW::UFW;
        if (hasFwd) return FW::FIREWALLD;
        return FW::NONE;
    }

    /** Ports sshd listens on, plus the port of the current SSH session. */
    static std::vector<int> sshPorts() {
        std::set<int> ports;

        auto parse = [&](const fs::path& file) {
            std::ifstream f(file);
            std::string line;
            while (std::getline(f, line)) {
                const size_t hash = line.find('#');
                if (hash != std::string::npos) line.resize(hash);
                std::istringstream iss(line);
                std::string key; int port = 0;
                if ((iss >> key >> port) && toLower(key) == "port" && port > 0 && port < 65536)
                    ports.insert(port);
            }
        };
        parse("/etc/ssh/sshd_config");
        std::error_code ec;
        if (fs::is_directory("/etc/ssh/sshd_config.d", ec))
            for (const auto& e : fs::directory_iterator("/etc/ssh/sshd_config.d", ec))
                if (e.path().extension() == ".conf") parse(e.path());

        // SSH_CONNECTION="client_ip client_port server_ip server_port"
        if (const char* sc = std::getenv("SSH_CONNECTION")) {
            std::istringstream iss(sc);
            std::string a, b, c; int serverPort = 0;
            if ((iss >> a >> b >> c >> serverPort) && serverPort > 0 && serverPort < 65536)
                ports.insert(serverPort);
        }
        if (ports.empty()) ports.insert(22);
        return {ports.begin(), ports.end()};
    }

    static void configureUfw(const std::vector<int>& ports) {
        Logger::info("Detected firewall: ufw");
        runCmd({"ufw", "default", "deny", "incoming"});
        runCmd({"ufw", "default", "allow", "outgoing"});
        for (int p : ports) runCmd({"ufw", "allow", std::to_string(p) + "/tcp"});  // before enabling
        runCmd({"ufw", "--force", "enable"});
        enableService("ufw");                       // start at boot (Arch, Alpine, Void)
        runCmd({"ufw", "status", "verbose"});
        Logger::info("ufw configured and enabled.");
    }

    static void configureFirewalld(const std::vector<int>& ports) {
        Logger::info("Detected firewall: firewalld");
        enableService("firewalld");
        if (runCmd({"firewall-cmd", "--state"}, true) != 0) {
            Logger::error("firewalld is not running; aborting to avoid a half-applied policy.");
            return;
        }
        runCmd({"firewall-cmd", "--set-default-zone=public"});
        for (int p : ports) {
            if (p == 22) runCmd({"firewall-cmd", "--permanent", "--zone=public", "--add-service=ssh"});
            else         runCmd({"firewall-cmd", "--permanent", "--zone=public",
                                 "--add-port=" + std::to_string(p) + "/tcp"});
        }
        runCmd({"firewall-cmd", "--reload"});
        runCmd({"firewall-cmd", "--list-all"});
        Logger::info("firewalld configured and enabled.");
    }
};

// ============================================================
//  Section 4 - CLI
// ============================================================
static void printBanner() {
    std::cout << Color::p(Color::BOLD) << Color::p(Color::CYAN)
              << "\n  +----------------------------------------+\n"
                 "  |     Linux Security Toolkit v" << VERSION << "        |\n"
                 "  |  Cross-distro CLI security utility     |\n"
                 "  +----------------------------------------+\n"
              << Color::p(Color::RESET);
}

static void printMenu() {
    std::cout << "\n" << Color::p(Color::BOLD) << "Main Menu" << Color::p(Color::RESET) << "\n"
              << "  [1] Install security tools\n"
              << "  [2] Scan a directory\n"
              << "  [3] Configure firewall\n"
              << "  [4] Run all (install, scan, firewall)\n"
              << "  [5] Show log path\n"
              << "  [0] Exit\n"
              << "Choose an option: ";
}

static void printHelp(const char* argv0) {
    std::cout << Color::p(Color::BOLD) << "Usage:" << Color::p(Color::RESET) << "\n"
              << "  " << argv0 << "                    Interactive menu\n"
              << "  " << argv0 << " --install           Install security tools   (root)\n"
              << "  " << argv0 << " --scan [path]       Scan a directory         (default: /home)\n"
              << "  " << argv0 << " --firewall          Configure firewall       (root)\n"
              << "  " << argv0 << " --all [path]        Run all modules          (root)\n"
              << "  " << argv0 << " --help | --version\n"
              << "\nOptions:\n"
              << "  -y, --yes       Skip confirmation prompts (needed for non-interactive use)\n"
              << "      --no-color  Disable coloured output\n";
}

static void moduleInstall() {
    if (!requireRoot("Installing packages")) return;
    PackageManager pm;
    Logger::info("Detected system: " + (pm.prettyName().empty() ? "unknown" : pm.prettyName()) +
                 "  (package manager: " + pm.name() + ")");
    SecurityToolInstaller(pm).installAll();
}

static void moduleScan(const std::string& path) {
    FileScanner scanner;
    auto results = scanner.scan(path);
    scanner.printReport(results);
}

static void moduleFirewall() {
    if (!requireRoot("Configuring the firewall")) return;
    FirewallManager fw;
    Logger::info("Detected firewall tool: " + fw.fwName());
    fw.configure();
}

static void moduleAll(const std::string& scanPath) {
    if (!requireRoot("Running all modules")) return;
    moduleInstall();
    moduleScan(scanPath);
    moduleFirewall();
}

static std::string promptPath() {
    std::cout << "Enter directory path to scan [/home]: ";
    std::string path;
    std::getline(std::cin, path);
    path = trim(path);
    return path.empty() ? "/home" : path;
}

struct Options {
    std::string cmd;              // install | scan | firewall | all | help | version | ""
    std::string path = "/home";
    bool noColor = false;
    bool bad = false;
    std::string badArg;
};

static Options parseArgs(int argc, char* argv[]) {
    Options o;
    for (int i = 1; i < argc; ++i) {
        const std::string a = argv[i];
        if      (a == "--help" || a == "-h")    o.cmd = "help";
        else if (a == "--version" || a == "-V") o.cmd = "version";
        else if (a == "--yes" || a == "-y")     g_assumeYes = true;
        else if (a == "--no-color")             o.noColor = true;
        else if (a == "--install")              o.cmd = "install";
        else if (a == "--firewall")             o.cmd = "firewall";
        else if (a == "--scan")                 o.cmd = "scan";
        else if (a == "--all")                  o.cmd = "all";
        else if (!a.empty() && a[0] != '-' && (o.cmd == "scan" || o.cmd == "all"))
            o.path = a;
        else { o.bad = true; o.badArg = a; break; }
    }
    return o;
}

int main(int argc, char* argv[]) {
    Options opt = parseArgs(argc, argv);

    Color::enabled = !opt.noColor && ::isatty(STDOUT_FILENO) && !std::getenv("NO_COLOR");
    augmentPath();

    if (opt.bad) {
        std::cerr << Color::p(Color::RED) << "Unknown argument: " << opt.badArg
                  << Color::p(Color::RESET) << "\n";
        printHelp(argv[0]);
        return 1;
    }
    if (opt.cmd == "help")    { printHelp(argv[0]); return 0; }
    if (opt.cmd == "version") { std::cout << "security_toolkit " << VERSION << "\n"; return 0; }

    Logger::init();
    printBanner();
    Logger::info("Security Toolkit started (log: " + Logger::logPath() + ").");

    // ---- Argument mode ------------------------------------------------
    if (!opt.cmd.empty()) {
        if      (opt.cmd == "install")  moduleInstall();
        else if (opt.cmd == "scan")     moduleScan(opt.path);
        else if (opt.cmd == "firewall") moduleFirewall();
        else if (opt.cmd == "all")      moduleAll(opt.path);
        Logger::info("Security Toolkit finished.");
        return 0;
    }

    // ---- Interactive mode ---------------------------------------------
    if (!isRoot())
        Logger::warn("Not running as root: only the scan option will work.");

    while (true) {
        printMenu();
        std::string choice;
        if (!std::getline(std::cin, choice)) { std::cout << "\n"; break; }   // EOF / Ctrl-D
        choice = trim(choice);

        if      (choice == "0") { Logger::info("Exiting."); break; }
        else if (choice == "1") moduleInstall();
        else if (choice == "2") moduleScan(promptPath());
        else if (choice == "3") moduleFirewall();
        else if (choice == "4") { if (requireRoot("Running all modules")) moduleAll(promptPath()); }
        else if (choice == "5") std::cout << "Log file: " << Logger::logPath() << "\n";
        else std::cout << Color::p(Color::YELLOW) << "Invalid option. Please enter 0-5.\n"
                       << Color::p(Color::RESET);
    }

    Logger::info("Security Toolkit finished.");
    return 0;
}
