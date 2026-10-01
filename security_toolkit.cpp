/**
 * ============================================================
 *  Linux Security Toolkit v3.0 - security_toolkit.cpp
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
#include <functional>
#include <iostream>
#include <map>
#include <regex>
#include <set>
#include <sstream>
#include <string>
#include <vector>
#include <filesystem>

#include <fcntl.h>
#include <fnmatch.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

namespace fs = std::filesystem;

static const char* const VERSION = "3.0";

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

/** Run a command and capture stdout+stderr. Returns exit code. */
static int captureCmd(const std::vector<std::string>& args, std::string& out) {
    out.clear();
    if (args.empty()) return -1;
    int fds[2];
    if (::pipe(fds) != 0) return -1;
    std::cout.flush();
    const pid_t pid = ::fork();
    if (pid < 0) { ::close(fds[0]); ::close(fds[1]); return -1; }
    if (pid == 0) {
        ::close(fds[0]);
        ::dup2(fds[1], 1);
        ::dup2(fds[1], 2);
        ::close(fds[1]);
        std::vector<char*> argv;
        for (const auto& a : args) argv.push_back(const_cast<char*>(a.c_str()));
        argv.push_back(nullptr);
        ::execvp(argv[0], argv.data());
        ::_exit(127);
    }
    ::close(fds[1]);
    char buf[4096];
    ssize_t n;
    while ((n = ::read(fds[0], buf, sizeof(buf))) > 0 || (n < 0 && errno == EINTR))
        if (n > 0) out.append(buf, static_cast<size_t>(n));
    ::close(fds[0]);
    int status = 0;
    while (::waitpid(pid, &status, 0) < 0)
        if (errno != EINTR) return -1;
    return WIFEXITED(status) ? WEXITSTATUS(status) : 128 + WTERMSIG(status);
}

// ---------- prompts ----------
static bool readLine(std::string& out) {
    if (!std::getline(std::cin, out)) return false;
    out = trim(out);
    return true;
}
static bool ask(const std::string& q, std::string& out) {
    std::cout << q;
    std::cout.flush();
    return readLine(out);
}
/** Ask for a value that must match `re`. Empty input / EOF / invalid = cancel. */
static bool askValid(const std::string& q, const std::regex& re,
                     const std::string& hint, std::string& out) {
    if (!ask(q, out) || out.empty()) return false;
    if (!std::regex_match(out, re)) {
        Logger::warn("Invalid value. " + hint);
        return false;
    }
    return true;
}
static bool isNumber(const std::string& s) {
    return !s.empty() && s.size() < 6 && std::all_of(s.begin(), s.end(),
        [](unsigned char c) { return std::isdigit(c) != 0; });
}

// ---------- services (systemd / OpenRC / runit) ----------
static bool haveSystemd() { return cmdExists("systemctl") && fs::exists("/run/systemd/system"); }

static bool serviceExists(const std::string& n) {
    if (haveSystemd()) return runCmd({"systemctl", "cat", n + ".service"}, true) == 0;
    return fs::exists("/etc/init.d/" + n) || fs::exists("/etc/sv/" + n);
}

static std::string resolveService(const std::vector<std::string>& candidates) {
    for (const auto& c : candidates)
        if (serviceExists(c)) return c;
    return "";
}

/** "active", "inactive", "failed", ... or "unknown". */
static std::string serviceState(const std::string& n) {
    std::string out;
    if (haveSystemd()) {
        captureCmd({"systemctl", "is-active", n}, out);
        out = trim(out);
        return out.empty() ? "unknown" : out;
    }
    if (cmdExists("rc-service"))
        return runCmd({"rc-service", n, "status"}, true) == 0 ? "active" : "inactive";
    if (cmdExists("sv")) {
        captureCmd({"sv", "status", n}, out);
        return out.rfind("run", 0) == 0 ? "active" : "inactive";
    }
    return "unknown";
}

static std::string serviceEnabled(const std::string& n) {
    if (!haveSystemd()) return "-";
    std::string out;
    captureCmd({"systemctl", "is-enabled", n}, out);
    out = trim(out);
    return out.empty() ? "-" : out;
}

/** act: start | stop | restart | enable | disable | enable-now */
static bool serviceAction(const std::string& act, const std::string& n) {
    if (haveSystemd()) {
        if (act == "enable-now") return runCmd({"systemctl", "enable", "--now", n}) == 0;
        return runCmd({"systemctl", act, n}) == 0;
    }
    if (cmdExists("rc-update")) {
        if (act == "enable")  return runCmd({"rc-update", "add", n, "default"}) == 0;
        if (act == "disable") return runCmd({"rc-update", "del", n, "default"}) == 0;
        if (act == "enable-now") {
            runCmd({"rc-update", "add", n, "default"});
            return runCmd({"rc-service", n, "start"}) == 0;
        }
        return runCmd({"rc-service", n, act}) == 0;
    }
    if (cmdExists("sv") && fs::exists("/etc/sv/" + n)) {
        const std::string link = "/var/service/" + n;
        if (act == "enable" || act == "enable-now") return runCmd({"ln", "-sf", "/etc/sv/" + n, link}) == 0;
        if (act == "disable") return runCmd({"rm", "-f", link}) == 0;
        if (act == "start")   return runCmd({"sv", "up", n}) == 0;
        if (act == "stop")    return runCmd({"sv", "down", n}) == 0;
        return runCmd({"sv", "restart", n}) == 0;
    }
    Logger::warn("No supported init system found; manage '" + n + "' manually.");
    return false;
}

static void enableService(const std::string& name) { serviceAction("enable-now", name); }

// ---------- config-file editing ----------
static std::vector<std::string> readLines(const std::string& file) {
    std::vector<std::string> lines;
    std::ifstream f(file);
    std::string l;
    while (std::getline(f, l)) lines.push_back(l);
    return lines;
}

static bool writeLines(const std::string& file, const std::vector<std::string>& lines) {
    std::error_code ec;
    const fs::path p(file);
    if (p.has_parent_path()) fs::create_directories(p.parent_path(), ec);
    std::ofstream f(file, std::ios::trunc);
    if (!f.is_open()) { Logger::error("Cannot write " + file); return false; }
    for (const auto& l : lines) f << l << "\n";
    return true;
}

/** Keep a one-time copy of the original file as <file>.sectk.bak */
static void backupOnce(const std::string& file) {
    std::error_code ec;
    if (fs::exists(file, ec) && !fs::exists(file + ".sectk.bak", ec)) {
        fs::copy_file(file, file + ".sectk.bak", ec);
        if (!ec) Logger::info("Backup saved: " + file + ".sectk.bak");
    }
}

/** Set "key <sep> value" in a flat config file (replaces the line or appends). */
static bool setConfLine(const std::string& file, const std::string& key,
                        const std::string& sep, const std::string& value) {
    backupOnce(file);
    auto lines = readLines(file);
    bool done = false;
    for (auto& l : lines) {
        const std::string t = trim(l);
        if (t.empty() || t[0] == '#' || t[0] == ';') continue;
        const size_t eq = t.find('=');
        if (eq != std::string::npos && trim(t.substr(0, eq)) == key) {
            l = key + sep + value;
            done = true;
            break;
        }
    }
    if (!done) lines.push_back(key + sep + value);
    if (!writeLines(file, lines)) return false;
    Logger::info("Set " + key + " = " + value + " in " + file);
    return true;
}

/** Set key = value inside [section] of an INI-style file (creates section/file). */
static bool setIniValue(const std::string& file, const std::string& section,
                        const std::string& key, const std::string& value) {
    backupOnce(file);
    auto lines = readLines(file);
    const std::string hdr = "[" + section + "]";
    size_t start = std::string::npos;
    for (size_t i = 0; i < lines.size(); ++i)
        if (trim(lines[i]) == hdr) { start = i; break; }

    if (start == std::string::npos) {
        if (!lines.empty() && !trim(lines.back()).empty()) lines.push_back("");
        lines.push_back(hdr);
        lines.push_back(key + " = " + value);
    } else {
        size_t end = lines.size();
        for (size_t j = start + 1; j < lines.size(); ++j) {
            const std::string t = trim(lines[j]);
            if (!t.empty() && t[0] == '[') { end = j; break; }
        }
        bool done = false;
        for (size_t j = start + 1; j < end && !done; ++j) {
            const std::string t = trim(lines[j]);
            if (t.empty() || t[0] == '#' || t[0] == ';') continue;
            const size_t eq = t.find_first_of("=:");
            if (eq != std::string::npos && trim(t.substr(0, eq)) == key) {
                lines[j] = key + " = " + value;
                done = true;
            }
        }
        if (!done) {
            size_t ins = end;
            while (ins > start + 1 && trim(lines[ins - 1]).empty()) --ins;
            lines.insert(lines.begin() + static_cast<std::ptrdiff_t>(ins), key + " = " + value);
        }
    }
    if (!writeLines(file, lines)) return false;
    Logger::info("Set " + key + " = " + value + " in [" + section + "] of " + file);
    return true;
}

/** Replace group 2 of the first match of `re`; group 1 is kept (prefix). */
static bool replaceFirstRegex(const std::string& file, const std::regex& re,
                              const std::string& value) {
    std::ifstream f(file);
    if (!f.is_open()) return false;
    std::stringstream ss;
    ss << f.rdbuf();
    std::string s = ss.str();
    f.close();
    std::smatch m;
    if (!std::regex_search(s, m, re)) return false;
    backupOnce(file);
    s = m.prefix().str() + m[1].str() + value + m.suffix().str();
    std::ofstream o(file, std::ios::trunc);
    o << s;
    return o.good();
}

/** Replace (or append) a block delimited by marker lines. */
static bool writeManagedBlock(const std::string& file, const std::string& begin,
                              const std::string& end, const std::vector<std::string>& body) {
    backupOnce(file);
    auto lines = readLines(file);
    std::vector<std::string> out;
    bool skipping = false;
    for (const auto& l : lines) {
        if (trim(l) == begin) { skipping = true; continue; }
        if (skipping && trim(l) == end) { skipping = false; continue; }
        if (!skipping) out.push_back(l);
    }
    out.push_back(begin);
    out.insert(out.end(), body.begin(), body.end());
    out.push_back(end);
    return writeLines(file, out);
}

/** Open a file in $VISUAL/$EDITOR (or nano/vim/vi) after making a backup. */
static void editFile(const std::string& file) {
    std::error_code ec;
    if (!fs::exists(file, ec)) {
        if (!confirm(file + " does not exist. Create it?")) return;
        writeLines(file, {});
    }
    backupOnce(file);
    std::vector<std::string> cmd;
    for (const char* env : {"VISUAL", "EDITOR"}) {
        if (const char* e = std::getenv(env); e && *e) {
            std::istringstream iss(e);
            std::string tok;
            while (iss >> tok) cmd.push_back(tok);
            if (!cmd.empty() && cmdExists(cmd[0])) break;
            cmd.clear();
        }
    }
    if (cmd.empty())
        for (const char* ed : {"nano", "vim", "nvim", "vi", "micro", "emacs"})
            if (cmdExists(ed)) { cmd = {ed}; break; }
    if (cmd.empty()) { Logger::error("No text editor found. Set $EDITOR or install nano."); return; }
    cmd.push_back(file);
    runCmd(cmd);
}

static std::string regexEscape(const std::string& s) {
    static const std::string special = R"(\.^$|()[]{}*+?)";
    std::string out;
    for (char c : s) {
        if (special.find(c) != std::string::npos) out += '\\';
        out += c;
    }
    return out;
}

static std::string globToRegex(const std::string& g) {
    std::string out;
    for (char c : g) {
        if (c == '*') out += ".*";
        else if (c == '?') out += '.';
        else out += regexEscape(std::string(1, c));
    }
    return out;
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

    bool remove(const std::string& pkg) const {
        std::vector<std::string> cmd;
        switch (kind_) {
            case Kind::APT:    cmd = {"apt-get", "remove", "-y", pkg}; break;
            case Kind::DNF:    cmd = {"dnf", "remove", "-y", pkg}; break;
            case Kind::YUM:    cmd = {"yum", "remove", "-y", pkg}; break;
            case Kind::PACMAN: cmd = {"pacman", "-R", "--noconfirm", pkg}; break;
            case Kind::ZYPPER: cmd = {"zypper", "--non-interactive", "remove", pkg}; break;
            case Kind::APK:    cmd = {"apk", "del", pkg}; break;
            case Kind::XBPS:   cmd = {"xbps-remove", "-y", pkg}; break;
            default: return false;
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

// ============================================================
//  Scan exclusions (persistent, shared by scanner, ClamAV, AIDE)
//  Stored in /etc/sec_toolkit/toolkit.conf (root) or
//  ~/.config/sec_toolkit/toolkit.conf (non-root).
// ============================================================
class Exclusions {
public:
    std::vector<std::string> dirs, exts, names;

    static std::string sysFile() { return "/etc/sec_toolkit/toolkit.conf"; }
    static std::string userFile() {
        if (const char* x = std::getenv("XDG_CONFIG_HOME"); x && *x)
            return std::string(x) + "/sec_toolkit/toolkit.conf";
        if (const char* h = std::getenv("HOME"); h && *h)
            return std::string(h) + "/.config/sec_toolkit/toolkit.conf";
        return "";
    }
    static std::string editableFile() { return isRoot() ? sysFile() : userFile(); }

    /** Everything that applies when scanning (system + user file). */
    void loadEffective() {
        clear();
        readFile(sysFile());
        if (!isRoot()) readFile(userFile());
    }
    /** Only the file the current user can change. */
    void loadEditable() { clear(); readFile(editableFile()); }

    bool save() const {
        const std::string f = editableFile();
        if (f.empty()) { Logger::error("No writable config location (HOME not set)."); return false; }
        std::vector<std::string> lines = {"# Security Toolkit configuration",
                                          "# exclude_dir  = absolute folder path",
                                          "# exclude_ext  = file extension, e.g. .log",
                                          "# exclude_name = file/folder name or pattern, e.g. node_modules, *.bak"};
        for (const auto& d : dirs)  lines.push_back("exclude_dir=" + d);
        for (const auto& e : exts)  lines.push_back("exclude_ext=" + e);
        for (const auto& n : names) lines.push_back("exclude_name=" + n);
        return writeLines(f, lines);
    }

    size_t total() const { return dirs.size() + exts.size() + names.size(); }

    bool addDir(const std::string& in) {
        if (in.empty() || in.find_first_of("\n\r") != std::string::npos) return false;
        std::error_code ec;
        fs::path p = fs::absolute(in, ec).lexically_normal();
        std::string s = p.string();
        while (s.size() > 1 && s.back() == '/') s.pop_back();
        if (s == "/") { Logger::warn("Excluding '/' would disable the scan."); return false; }
        return addUnique(dirs, s);
    }
    bool addExt(std::string e) {
        e = toLower(trim(e));
        while (!e.empty() && e[0] == '*') e.erase(0, 1);
        if (e.empty() || e.find_first_of("/ \n\r") != std::string::npos) return false;
        if (e[0] != '.') e = "." + e;
        return addUnique(exts, e);
    }
    bool addName(const std::string& n) {
        if (n.empty() || n.find_first_of("/\n\r") != std::string::npos) return false;
        return addUnique(names, n);
    }
    /** idx is 0-based over dirs, then exts, then names. */
    bool removeAt(size_t idx) {
        if (idx < dirs.size()) { dirs.erase(dirs.begin() + static_cast<std::ptrdiff_t>(idx)); return true; }
        idx -= dirs.size();
        if (idx < exts.size()) { exts.erase(exts.begin() + static_cast<std::ptrdiff_t>(idx)); return true; }
        idx -= exts.size();
        if (idx < names.size()) { names.erase(names.begin() + static_cast<std::ptrdiff_t>(idx)); return true; }
        return false;
    }
    void clear() { dirs.clear(); exts.clear(); names.clear(); }

    bool nameExcluded(const fs::path& p) const {
        const std::string n = p.filename().string();
        for (const auto& pat : names)
            if (::fnmatch(pat.c_str(), n.c_str(), 0) == 0) return true;
        return false;
    }
    bool dirExcluded(const fs::path& p) const {
        const std::string s = p.string();
        for (const auto& d : dirs)
            if (s == d || (s.size() > d.size() && s.compare(0, d.size(), d) == 0 && s[d.size()] == '/'))
                return true;
        return nameExcluded(p);
    }
    bool fileExcluded(const fs::path& p) const {
        if (nameExcluded(p)) return true;
        if (!exts.empty()) {
            const std::string e = toLower(p.extension().string());
            if (std::find(exts.begin(), exts.end(), e) != exts.end()) return true;
        }
        return false;
    }

    /** Regexes (for ClamAV / AIDE) */
    std::vector<std::string> dirRegexes() const {
        std::vector<std::string> r;
        for (const auto& d : dirs) r.push_back("^" + regexEscape(d) + "(/|$)");
        for (const auto& n : names) r.push_back("/" + globToRegex(n) + "(/|$)");
        return r;
    }
    std::vector<std::string> fileRegexes() const {
        std::vector<std::string> r;
        for (const auto& e : exts)  r.push_back(regexEscape(e) + "$");
        for (const auto& n : names) r.push_back("/" + globToRegex(n) + "$");
        return r;
    }

private:
    static bool addUnique(std::vector<std::string>& v, const std::string& s) {
        if (std::find(v.begin(), v.end(), s) != v.end()) return false;
        v.push_back(s);
        return true;
    }
    void readFile(const std::string& f) {
        if (f.empty()) return;
        std::ifstream in(f);
        std::string line;
        while (std::getline(in, line)) {
            line = trim(line);
            if (line.empty() || line[0] == '#') continue;
            const size_t eq = line.find('=');
            if (eq == std::string::npos) continue;
            const std::string k = trim(line.substr(0, eq)), v = trim(line.substr(eq + 1));
            if      (k == "exclude_dir")  addUnique(dirs, v);
            else if (k == "exclude_ext")  addUnique(exts, toLower(v));
            else if (k == "exclude_name") addUnique(names, v);
        }
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

    std::vector<ScanResult> scan(const std::string& rootPath, const Exclusions& ex = Exclusions(),
                                 bool oneFs = false) {
        results_.clear();
        scanned_ = 0;
        skippedDirs_ = 0;
        excluded_ = 0;

        Logger::info("=== Starting file scan on: " + rootPath + " ===");

        std::error_code ec;
        fs::path root = fs::absolute(rootPath, ec).lexically_normal();
        if (ec || !fs::is_directory(root, ec)) {
            Logger::error("Path does not exist or is not a directory: " + rootPath);
            return {};
        }

        // Iterative traversal: an error in one directory never aborts the scan,
        // symlinks are never followed, virtual filesystems are skipped.
        dev_t rootDev = 0;
        { struct stat rs{}; if (::stat(root.c_str(), &rs) == 0) rootDev = rs.st_dev; }
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
                    if (fs::is_directory(st)) {
                        struct stat ds{};
                        if (ex.dirExcluded(it->path())) ++excluded_;
                        else if (oneFs && (::lstat(it->path().c_str(), &ds) != 0 || ds.st_dev != rootDev)) ++excluded_;
                        else stack.push_back(it->path());
                    } else if (fs::is_regular_file(st)) {
                        if (ex.fileExcluded(it->path())) ++excluded_;
                        else inspect(it->path());
                    }
                }
                it.increment(ec);
                if (ec) { ++skippedDirs_; ec.clear(); break; }
            }
        }

        Logger::info("Scan complete. Files inspected: " + std::to_string(scanned_) +
                     "  Suspicious: " + std::to_string(results_.size()) +
                     "  Unreadable dirs skipped: " + std::to_string(skippedDirs_) +
                     "  Excluded: " + std::to_string(excluded_));
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
    size_t excluded_ = 0;

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

    void configure() const { applyDefaults(fw_); }

    /** SSH ports that must stay reachable (sshd_config + current session). */
    static std::vector<int> ports() { return sshPorts(); }

    /** Apply secure defaults with the chosen firewall (NONE = report only). */
    static void applyDefaults(FW fw) {
        Logger::info("=== Firewall Configuration ===");
        if (!requireRoot("Configuring the firewall")) return;
        if (fw == FW::NONE || (fw == FW::UFW && !cmdExists("ufw")) ||
            (fw == FW::FIREWALLD && !cmdExists("firewall-cmd"))) {
            Logger::warn("The selected firewall is not installed. Install it from the tool catalog first.");
            return;
        }

        const std::vector<int> ports = sshPorts();
        std::string plist;
        for (int p : ports) plist += (plist.empty() ? "" : ", ") + std::to_string(p);

        const std::string name = (fw == FW::UFW) ? "ufw" : "firewalld";
        if (!confirm("This will set '" + name + "' to deny incoming / allow outgoing "
                     "and keep SSH port(s) " + plist + " open. Continue?")) {
            Logger::warn("Firewall configuration cancelled.");
            return;
        }
        if (fw == FW::UFW) configureUfw(ports);
        else               configureFirewalld(ports);
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
//  Section 4 - Tool catalog
// ============================================================
using PK = PackageManager::Kind;

struct PkgSet { std::vector<std::string> apt, rpm, arch, suse, apk, xbps; };

struct Tool {
    std::string id, name, category, summary, details, caution;
    PkgSet pkgs;
    std::vector<std::string> bins;       // any present => installed
    std::vector<std::string> services;   // candidate service names
    std::string config;                  // main config file
    bool recommended;
    std::string manual;                  // where to get it if repos lack it
};

static PkgSet allPk(const std::vector<std::string>& p) { return {p, p, p, p, p, p}; }

static const std::vector<std::string>& pkgsFor(const Tool& t, PK k) {
    static const std::vector<std::string> none;
    switch (k) {
        case PK::APT:    return t.pkgs.apt;
        case PK::DNF:
        case PK::YUM:    return t.pkgs.rpm;
        case PK::PACMAN: return t.pkgs.arch;
        case PK::ZYPPER: return t.pkgs.suse;
        case PK::APK:    return t.pkgs.apk;
        case PK::XBPS:   return t.pkgs.xbps;
        default:         return none;
    }
}

static const std::vector<Tool>& catalog() {
    static const std::vector<Tool> c = {
    {"lynis", "Lynis", "Auditing",
     "Security auditor: scans the whole system and gives a hardening score with concrete suggestions.",
     "Runs several hundred read-only checks (SSH, users, kernel, services, file permissions,\n"
     "firewall, packages...). It changes nothing by itself; it tells you what to fix.\n"
     "Best first tool to install: use its report to decide what else you need.",
     "", allPk({"lynis"}), {"lynis"}, {}, "/etc/lynis/custom.prf", true,
     "Ubuntu/Debian/Fedora(EPEL)/Arch/openSUSE ship it; otherwise see https://cisofy.com/lynis/"},

    {"openscap", "OpenSCAP", "Auditing",
     "Compliance scanner: checks the system against security benchmarks (CIS, STIG, PCI-DSS...).",
     "Uses the SCAP Security Guide content to test your configuration against a chosen profile\n"
     "and writes an HTML report listing every passed/failed rule. Good for audits and servers\n"
     "that must meet a standard. Report-only by default (no automatic changes).",
     "Content is matched to your distro/version; some distros ship no content for their release.",
     {{"openscap-scanner", "ssg-base", "ssg-debderived", "ssg-debian", "ssg-applications"},
      {"openscap-scanner", "scap-security-guide"}, {"openscap"},
      {"openscap-utils", "scap-security-guide"}, {"openscap"}, {"openscap"}},
     {"oscap"}, {}, "", false, "https://www.open-scap.org/"},

    {"apparmor", "AppArmor", "Access control (MAC)",
     "Confines each program to a profile of files/capabilities it may use, limiting damage from exploits.",
     "Path-based mandatory access control built into the kernel. Ubuntu, Debian and openSUSE\n"
     "use it by default. A compromised service can only touch what its profile allows.\n"
     "You can put profiles in 'complain' (log only) or 'enforce' (block) mode.",
     "Use ONE access-control system: do not combine with SELinux. May need a reboot and the "
     "kernel parameters apparmor=1 security=apparmor. Not packaged for Fedora/RHEL.",
     {{"apparmor", "apparmor-utils"}, {}, {"apparmor"},
      {"apparmor-parser", "apparmor-utils", "apparmor-profiles"}, {"apparmor", "apparmor-utils"}, {}},
     {"aa-status", "apparmor_status"}, {"apparmor"}, "/etc/apparmor/parser.conf", false,
     "https://wiki.archlinux.org/title/AppArmor"},

    {"selinux", "SELinux", "Access control (MAC)",
     "Label-based access control enforced by the kernel (default on Fedora/RHEL).",
     "Every file and process gets a security label; policy decides which labels may interact.\n"
     "Very strong containment, but stricter and harder to troubleshoot than AppArmor.\n"
     "Modes: enforcing (blocks), permissive (logs only), disabled.",
     "Do not combine with AppArmor. Going from disabled to enforcing needs a full relabel and "
     "reboot: switch to permissive first. Practical mainly on Fedora/RHEL; poor fit for Debian/Ubuntu/Arch.",
     {{"selinux-basics", "selinux-policy-default", "auditd"},
      {"selinux-policy-targeted", "policycoreutils", "policycoreutils-python-utils"}, {},
      {"selinux-tools", "selinux-policy-targeted"}, {}, {}},
     {"sestatus", "getenforce"}, {}, "/etc/selinux/config", false,
     "Arch: AUR packages; see https://wiki.archlinux.org/title/SELinux"},

    {"ufw", "UFW", "Firewall",
     "Uncomplicated Firewall: simple commands to allow or block ports.",
     "Friendly front-end for the kernel firewall. Default policy here: deny incoming, allow outgoing,\n"
     "keep SSH open. Ideal for desktops and simple servers.",
     "Use only one firewall manager (ufw OR firewalld OR raw nftables).",
     allPk({"ufw"}), {"ufw"}, {"ufw"}, "/etc/ufw/ufw.conf", false, ""},

    {"firewalld", "firewalld", "Firewall",
     "Dynamic firewall with zones (public, home, work...) and named services.",
     "Default on Fedora/RHEL/openSUSE. Rules change at runtime without dropping connections;\n"
     "you allow 'services' (ssh, http) or ports per zone.",
     "Use only one firewall manager (ufw OR firewalld OR raw nftables).",
     allPk({"firewalld"}), {"firewall-cmd"}, {"firewalld"}, "/etc/firewalld/firewalld.conf", false, ""},

    {"nftables", "nftables", "Firewall",
     "The modern Linux packet filter (successor of iptables). Powerful, script-based.",
     "ufw and firewalld are front-ends for it. Install it directly if you want to write and\n"
     "manage your own ruleset. This toolkit can load a safe baseline ruleset for you.",
     "Loading a baseline replaces the whole ruleset (Docker/VPN/libvirt rules would be dropped). "
     "Do not run alongside ufw/firewalld.",
     allPk({"nftables"}), {"nft"}, {"nftables"}, "/etc/nftables.conf", false, ""},

    {"fail2ban", "Fail2ban", "Intrusion prevention",
     "Bans IP addresses that repeatedly fail to log in (SSH brute-force and similar attacks).",
     "Reads service logs, and when an address fails too many times within a time window it is\n"
     "blocked in the firewall for a while. Settings you can change here: ban time, find time,\n"
     "max retries, whitelist.",
     "", allPk({"fail2ban"}), {"fail2ban-client"}, {"fail2ban"}, "/etc/fail2ban/jail.local", true,
     "On RHEL-family distros it lives in EPEL."},

    {"clamav", "ClamAV", "Malware & rootkits",
     "Open-source antivirus: finds viruses, trojans and malicious documents in files.",
     "Signature-based scanner. Use it for on-demand scans (your exclusions are applied) and\n"
     "for mail/file servers. Signatures are refreshed with freshclam.",
     "Uses a few hundred MB of RAM when the daemon runs. Not a real-time protector by default.",
     {{"clamav", "clamav-daemon"}, {"clamav", "clamav-update", "clamd"}, {"clamav"},
      {"clamav"}, {"clamav", "clamav-daemon", "freshclam"}, {"clamav"}},
     {"clamscan"}, {"clamav-daemon", "clamd@scan", "clamd"}, "", true,
     "RHEL-family: EPEL."},

    {"rkhunter", "rkhunter", "Malware & rootkits",
     "Rootkit Hunter: looks for rootkits, backdoors and suspicious changes to system files.",
     "Compares system binaries with known-good hashes, checks hidden files, odd ports and\n"
     "known rootkit signatures. Run 'update' and 'baseline' once on a clean system.",
     "Can produce false warnings after package updates: refresh the baseline afterwards.",
     {{"rkhunter"}, {"rkhunter"}, {"rkhunter"}, {"rkhunter"}, {"rkhunter"}, {"rkhunter"}},
     {"rkhunter"}, {}, "/etc/rkhunter.conf", true,
     "Arch: AUR. RHEL-family: EPEL."},

    {"chkrootkit", "chkrootkit", "Malware & rootkits",
     "A second-opinion rootkit checker (simple, fast, independent from rkhunter).",
     "Runs a set of tests for known rootkits and suspicious processes/interfaces.\n"
     "Using both rkhunter and chkrootkit reduces blind spots.",
     "", {{"chkrootkit"}, {"chkrootkit"}, {}, {"chkrootkit"}, {}, {}},
     {"chkrootkit"}, {}, "", false, "Arch: AUR (chkrootkit). Alpine/Void: build from https://www.chkrootkit.org/"},

    {"aide", "AIDE", "Integrity & auditing",
     "File-integrity monitor: detects files that were added, removed or modified.",
     "Builds a database of hashes/permissions of important files, then reports every difference\n"
     "on later checks. This is how you notice tampered binaries or config files.",
     "Initial database creation takes minutes. After legitimate updates you must accept changes "
     "(update database). Uses your exclusions.",
     {{"aide", "aide-common"}, {"aide"}, {"aide"}, {"aide"}, {"aide"}, {"aide"}},
     {"aide"}, {}, "/etc/aide/aide.conf", false, ""},

    {"auditd", "auditd", "Integrity & auditing",
     "Linux Audit daemon: records who did what (file changes, logins, privileged commands).",
     "Kernel-level event recording. Add watch rules on sensitive files (passwd, shadow, sudoers,\n"
     "ssh config) and search the trail later. Foundation for compliance and forensics.",
     "Logs can grow large: set a maximum log size.",
     {{"auditd"}, {"audit"}, {"audit"}, {"audit"}, {"audit"}, {"audit"}},
     {"auditctl", "auditd"}, {"auditd"}, "/etc/audit/auditd.conf", true, ""},

    {"suricata", "Suricata", "Network monitoring (IDS)",
     "Network intrusion detection: inspects traffic and alerts on attacks, scans and malware.",
     "Matches network packets against thousands of rules (Emerging Threats, etc.). Runs as a\n"
     "service watching one network interface; alerts go to /var/log/suricata.",
     "Needs CPU/RAM proportional to traffic. Set the interface, then update the rules.",
     allPk({"suricata"}), {"suricata"}, {"suricata"}, "/etc/suricata/suricata.yaml", false,
     "RHEL-family: EPEL. Other: https://suricata.io/download/"},

    {"wazuh", "Wazuh", "Network monitoring (IDS)",
     "Open-source XDR/SIEM: an agent on each host reports logs, integrity and vulnerabilities to a server.",
     "The agent watches logs, file integrity, rootkits and installed-software vulnerabilities,\n"
     "and sends everything to a Wazuh manager with a dashboard. Suited to fleets and servers.",
     "Not in normal distro repositories: add the official Wazuh repository first. The agent "
     "needs a manager server to report to. Do not run together with OSSEC.",
     {{"wazuh-agent"}, {"wazuh-agent"}, {}, {"wazuh-agent"}, {}, {}},
     {"/var/ossec/bin/wazuh-control"}, {"wazuh-agent", "wazuh-manager"}, "/var/ossec/etc/ossec.conf", false,
     "Follow https://documentation.wazuh.com/current/installation-guide/ (adds the repo)."},

    {"ossec", "OSSEC", "Network monitoring (IDS)",
     "The original host-based IDS: log analysis, integrity checking, rootkit detection, active response.",
     "Lightweight agent/server design. Wazuh started as a fork of OSSEC and is more actively\n"
     "developed; choose OSSEC only if you specifically need it.",
     "Not in normal distro repositories. Do not run together with Wazuh.",
     {{}, {}, {}, {}, {}, {}},
     {"/var/ossec/bin/ossec-control"}, {"ossec", "ossec-hids"}, "/var/ossec/etc/ossec.conf", false,
     "Install from https://www.ossec.net/ (Atomicorp repositories)."},

    {"utils", "Network utilities", "Utilities",
     "nmap, tcpdump, net-tools, curl, wget, unzip: everyday helpers for checking your own exposure.",
     "nmap shows which ports your machine exposes; tcpdump captures packets; net-tools/curl/wget/\n"
     "unzip are basics that many security tools and installers expect.",
     "", allPk({"nmap", "tcpdump", "net-tools", "curl", "wget", "unzip"}), {"nmap"}, {}, "", true, ""},
    };
    return c;
}

static const Tool* findTool(const std::string& id) {
    const std::string l = toLower(id);
    for (const auto& t : catalog())
        if (t.id == l || toLower(t.name) == l) return &t;
    return nullptr;
}

static bool isInstalled(const Tool& t) {
    for (const auto& b : t.bins)
        if (cmdExists(b)) return true;
    return false;
}

struct ToolStatus { bool installed; std::string service, state, enabled; };

static ToolStatus toolStatus(const Tool& t) {
    ToolStatus s{isInstalled(t), "", "-", "-"};
    if (!t.services.empty() && s.installed) {
        s.service = resolveService(t.services);
        if (!s.service.empty()) { s.state = serviceState(s.service); s.enabled = serviceEnabled(s.service); }
    }
    return s;
}

static void restartIfActive(const Tool& t) {
    const std::string svc = resolveService(t.services);
    if (!svc.empty() && serviceState(svc) == "active") {
        Logger::info("Restarting " + svc + " to apply the change.");
        serviceAction("restart", svc);
    } else {
        Logger::info("Saved. Start or enable the service from 'Manage tools' to apply.");
    }
}

static void printToolInfo(const Tool& t, const PackageManager& pm) {
    std::cout << "\n" << Color::p(Color::BOLD) << Color::p(Color::CYAN) << "== " << t.name
              << "  [" << t.category << "] ==" << Color::p(Color::RESET) << "\n"
              << Color::p(Color::BOLD) << t.summary << Color::p(Color::RESET) << "\n";
    std::istringstream d(t.details);
    std::string line;
    while (std::getline(d, line)) std::cout << "  " << line << "\n";
    if (!t.caution.empty())
        std::cout << Color::p(Color::YELLOW) << "  Caution: " << t.caution << Color::p(Color::RESET) << "\n";
    const auto& pk = pkgsFor(t, pm.kind());
    if (pk.empty()) {
        std::cout << "  Packages: none in the " << pm.name() << " repositories.\n";
        if (!t.manual.empty()) std::cout << "  Get it: " << t.manual << "\n";
    } else {
        std::cout << "  Packages (" << pm.name() << "): " << join(pk, ", ") << "\n";
    }
    if (!t.config.empty()) std::cout << "  Config: " << t.config << "\n";
    std::cout << "  Installed: " << (isInstalled(t) ? "yes" : "no") << "\n";
}

static void printCatalog(const PackageManager&) {
    std::string cat;
    int i = 1;
    for (const auto& t : catalog()) {
        if (t.category != cat) {
            cat = t.category;
            std::cout << "\n" << Color::p(Color::BOLD) << cat << Color::p(Color::RESET) << "\n";
        }
        std::cout << "  [" << (i < 10 ? " " : "") << i << "] " << t.name
                  << (t.recommended ? " *" : "") << (isInstalled(t) ? "  (installed)" : "")
                  << "\n        " << t.summary << "\n";
        ++i;
    }
    std::cout << "\n  * = recommended baseline\n";
}

// ---------- installing ----------
static std::vector<std::string> conflictWarnings(const std::vector<const Tool*>& sel) {
    std::set<std::string> ids;
    for (const auto* t : sel) ids.insert(t->id);
    auto has = [&](const char* id) { return ids.count(id) > 0; };
    auto installed = [&](const char* id) { const Tool* t = findTool(id); return t && isInstalled(*t); };

    std::vector<std::string> w;
    if ((has("apparmor") && (has("selinux") || installed("selinux"))) ||
        (has("selinux") && installed("apparmor")))
        w.push_back("AppArmor and SELinux are alternatives. Use only one.");
    if ((has("wazuh") && (has("ossec") || installed("ossec"))) ||
        (has("ossec") && installed("wazuh")))
        w.push_back("Wazuh and OSSEC use the same directory (/var/ossec). Use only one.");

    int fws = 0;
    for (const char* f : {"ufw", "firewalld", "nftables"}) if (has(f)) ++fws;
    if (fws > 1) w.push_back("You selected more than one firewall manager (ufw/firewalld/nftables). Pick one.");
    for (const char* f : {"ufw", "firewalld", "nftables"}) {
        if (!has(f)) continue;
        for (const char* other : {"ufw", "firewalld", "nftables"}) {
            if (std::string(other) == f || has(other)) continue;
            const Tool* o = findTool(other);
            if (o && isInstalled(*o) && toolStatus(*o).state == "active")
                w.push_back(std::string(other) + " is already running; adding " + f + " can conflict with it.");
        }
    }
    return w;
}

static bool installTool(const PackageManager& pm, const Tool& t) {
    Logger::info("--- " + t.name + " ---");
    const auto& pk = pkgsFor(t, pm.kind());
    if (pk.empty()) {
        Logger::warn(t.name + " is not available in the " + pm.name() + " repositories.");
        if (!t.manual.empty()) Logger::warn("How to get it: " + t.manual);
        return false;
    }
    for (const auto& p : pk) pm.install(p);            // extra packages are best effort
    if (!isInstalled(t)) {
        Logger::warn(t.name + " could not be installed.");
        if (!t.manual.empty()) Logger::warn("Manual option: " + t.manual);
        Logger::warn(pm.failureHint());
        return false;
    }
    Logger::info(t.name + " installed.");
    return true;
}

static void installTools(const PackageManager& pm, const std::vector<const Tool*>& sel) {
    if (sel.empty()) return;
    if (!requireRoot("Installing packages")) return;
    if (pm.kind() == PK::UNKNOWN) {
        Logger::error("No supported package manager found (apt, dnf, yum, pacman, zypper, apk, xbps).");
        return;
    }
    for (const auto& w : conflictWarnings(sel)) Logger::warn(w);

    std::string names;
    for (const auto* t : sel) names += (names.empty() ? "" : ", ") + t->name;
    if (!confirm("Install: " + names + "?")) { Logger::warn("Installation cancelled."); return; }

    pm.update();
    if ((pm.kind() == PK::DNF || pm.kind() == PK::YUM) && pm.isRhelDerivative()) {
        Logger::info("RHEL-family system: trying to enable EPEL.");
        pm.install("epel-release");
    }
    std::vector<std::string> failed;
    int ok = 0;
    for (const auto* t : sel) {
        if (installTool(pm, *t)) ++ok; else failed.push_back(t->name);
    }
    Logger::info("Done. Installed: " + std::to_string(ok) + "  Failed: " + std::to_string(failed.size()));
    if (!failed.empty()) Logger::warn("Failed: " + join(failed, ", "));
    if (ok > 0) Logger::info("Next: open 'Manage tools' to enable services, run them and change settings.");
}

static void removeTool(const PackageManager& pm, const Tool& t) {
    if (!requireRoot("Removing packages")) return;
    const auto& pk = pkgsFor(t, pm.kind());
    if (pk.empty()) { Logger::warn("Nothing to remove via " + pm.name() + "; remove " + t.name + " manually."); return; }
    if (!confirm("Remove " + t.name + " (" + join(pk, ", ") + ")?")) return;
    const std::string svc = resolveService(t.services);
    if (!svc.empty()) serviceAction("stop", svc);
    for (const auto& p : pk) pm.remove(p);
}

static std::vector<const Tool*> parseSelection(const std::string& in) {
    std::vector<const Tool*> out;
    std::set<std::string> seen;
    auto add = [&](const Tool& t) { if (seen.insert(t.id).second) out.push_back(&t); };
    const auto& cat = catalog();
    std::string norm = in;
    for (char& c : norm) if (c == ',' || c == ';') c = ' ';
    std::istringstream iss(norm);
    std::string tok;
    while (iss >> tok) {
        tok = toLower(tok);
        const size_t dash = tok.find('-');
        if (tok == "all") { for (const auto& t : cat) add(t); }
        else if (tok == "rec" || tok == "recommended") { for (const auto& t : cat) if (t.recommended) add(t); }
        else if (isNumber(tok)) {
            const size_t n = std::stoul(tok);
            if (n >= 1 && n <= cat.size()) add(cat[n - 1]); else Logger::warn("No tool number " + tok);
        } else if (dash != std::string::npos && isNumber(tok.substr(0, dash)) && isNumber(tok.substr(dash + 1))) {
            size_t a = std::stoul(tok.substr(0, dash)), b = std::stoul(tok.substr(dash + 1));
            for (size_t n = a; n <= b && n <= cat.size(); ++n) if (n >= 1) add(cat[n - 1]);
        } else if (const Tool* t = findTool(tok)) add(*t);
        else Logger::warn("Unknown selection: " + tok);
    }
    return out;
}

static void installerMenu(const PackageManager& pm) {
    while (true) {
        printCatalog(pm);
        std::cout << "\nSelect tools to install: numbers or names (e.g. 1,4,7-9 fail2ban),\n"
                     "'rec' = recommended baseline, 'all', 'i <n>' = details, 0 = back\n> ";
        std::string in;
        if (!readLine(in) || in == "0" || in.empty()) return;
        if (in.size() > 2 && (in[0] == 'i' || in[0] == 'I') && in[1] == ' ') {
            for (const auto* t : parseSelection(in.substr(2))) printToolInfo(*t, pm);
            continue;
        }
        installTools(pm, parseSelection(in));
    }
}

// ============================================================
//  Section 5 - Running, configuring and managing tools
// ============================================================
struct Action { std::string label; std::function<void()> fn; };

static std::function<void()> cmdAction(std::vector<std::string> args) {
    return [args] { runCmd(args); };
}

static void runActionMenu(const std::string& title, const std::vector<Action>& acts) {
    if (acts.empty()) { Logger::warn("Nothing available here."); return; }
    while (true) {
        std::cout << "\n" << Color::p(Color::BOLD) << title << Color::p(Color::RESET) << "\n";
        for (size_t i = 0; i < acts.size(); ++i) std::cout << "  [" << i + 1 << "] " << acts[i].label << "\n";
        std::cout << "  [0] Back\nChoose: ";
        std::string in;
        if (!readLine(in) || in == "0") return;
        if (isNumber(in) && std::stoul(in) >= 1 && std::stoul(in) <= acts.size()) acts[std::stoul(in) - 1].fn();
        else std::cout << Color::p(Color::YELLOW) << "Invalid option.\n" << Color::p(Color::RESET);
    }
}

/** Ask for a value and store it in a config file (INI section or flat file). */
static Action valueAction(const Tool& t, const std::string& label, const std::string& file,
                          const std::string& section, const std::string& key, const std::string& sep,
                          const std::string& prompt, const std::string& pattern, const std::string& hint) {
    return {label, [&t, file, section, key, sep, prompt, pattern, hint] {
        std::string v;
        if (!askValid(prompt + " (empty = cancel): ", std::regex(pattern), hint, v)) return;
        const bool ok = section.empty() ? setConfLine(file, key, sep, v) : setIniValue(file, section, key, v);
        if (ok) restartIfActive(t);
    }};
}

static std::vector<std::string> portList() {
    std::vector<std::string> r;
    for (int p : FirewallManager::ports()) r.push_back(std::to_string(p));
    return r;
}

// ---------- nftables baseline ----------
static void applyNftBaseline() {
    const auto ports = portList();
    const std::string file = fs::exists("/etc/sysconfig/nftables.conf") ? "/etc/sysconfig/nftables.conf"
                                                                         : "/etc/nftables.conf";
    if (!confirm("Replace the whole nftables ruleset (drop incoming except SSH " + join(ports, ",") +
                 "; forwarding blocked, so Docker/VPN routing stops working)?")) return;
    const std::string cand = "/tmp/sectk-nft-" + std::to_string(::getpid()) + ".nft";
    const std::vector<std::string> rules = {
        "#!/usr/sbin/nft -f", "# Managed by Security Toolkit", "flush ruleset", "",
        "table inet filter {",
        "  chain input {",
        "    type filter hook input priority 0; policy drop;",
        "    ct state established,related accept",
        "    ct state invalid drop",
        "    iif \"lo\" accept",
        "    ip protocol icmp accept",
        "    ip6 nexthdr icmpv6 accept",
        "    tcp dport { " + join(ports, ", ") + " } accept",
        "  }",
        "  chain forward { type filter hook forward priority 0; policy drop; }",
        "  chain output  { type filter hook output priority 0; policy accept; }",
        "}"};
    writeLines(cand, rules);
    if (runCmd({"nft", "-c", "-f", cand}) != 0) {
        Logger::error("Ruleset failed validation; nothing was changed.");
        std::error_code ec; fs::remove(cand, ec);
        return;
    }
    backupOnce(file);
    writeLines(file, rules);
    std::error_code ec; fs::remove(cand, ec);
    if (runCmd({"nft", "-f", file}) != 0) { Logger::error("Loading the ruleset failed."); return; }
    enableService("nftables");
    runCmd({"nft", "list", "ruleset"});
}

// ---------- OpenSCAP ----------
static void runOpenScap() {
    std::vector<std::string> sets;
    std::error_code ec;
    for (const auto& e : fs::directory_iterator("/usr/share/xml/scap/ssg/content", ec)) {
        const std::string n = e.path().filename().string();
        if (n.size() > 7 && n.compare(n.size() - 7, 7, "-ds.xml") == 0) sets.push_back(e.path().string());
    }
    if (sets.empty()) {
        Logger::error("No SCAP Security Guide content found in /usr/share/xml/scap/ssg/content. "
                      "Install scap-security-guide (or ssg-* on Debian/Ubuntu).");
        return;
    }
    std::sort(sets.begin(), sets.end());
    auto rel = readOsRelease();
    std::string ver = rel["VERSION_ID"];
    ver.erase(std::remove(ver.begin(), ver.end(), '.'), ver.end());
    std::string ds;
    int best = 0;
    for (const auto& s : sets) {
        int score = 0;
        const std::string b = fs::path(s).filename().string();
        if (b.find(toLower(rel["ID"])) != std::string::npos) score += 1;
        if (!ver.empty() && b.find(ver) != std::string::npos) score += 2;
        if (score > best) { best = score; ds = s; }
    }
    if (best < 3) {
        std::cout << "Choose the content that matches your system:\n";
        for (size_t i = 0; i < sets.size(); ++i) std::cout << "  [" << i + 1 << "] " << fs::path(sets[i]).filename().string() << "\n";
        std::string in;
        if (!ask("Number (empty = cancel): ", in) || !isNumber(in) || std::stoul(in) < 1 || std::stoul(in) > sets.size()) return;
        ds = sets[std::stoul(in) - 1];
    }
    std::string out;
    captureCmd({"oscap", "info", "--profiles", ds}, out);
    std::vector<std::string> profiles;
    std::istringstream iss(out);
    std::string line;
    while (std::getline(iss, line)) {
        const size_t c = line.find(':');
        if (c != std::string::npos && line.find(' ') != 0) profiles.push_back(line);
    }
    if (profiles.empty()) { Logger::error("No profiles found in " + ds); return; }
    std::cout << "Profiles in " << fs::path(ds).filename().string() << ":\n";
    for (size_t i = 0; i < profiles.size(); ++i) std::cout << "  [" << i + 1 << "] " << profiles[i] << "\n";
    std::string in;
    if (!ask("Profile number (empty = cancel): ", in) || !isNumber(in) || std::stoul(in) < 1 || std::stoul(in) > profiles.size()) return;
    const std::string prof = profiles[std::stoul(in) - 1].substr(0, profiles[std::stoul(in) - 1].find(':'));
    fs::create_directories("/var/log/sec_toolkit", ec);
    const int rc = runCmd({"oscap", "xccdf", "eval", "--profile", prof,
                           "--results", "/var/log/sec_toolkit/oscap-results.xml",
                           "--report", "/var/log/sec_toolkit/oscap-report.html", ds});
    if (rc == 2) Logger::warn("Some rules failed (normal). Open the report to review them.");
    Logger::info("HTML report: /var/log/sec_toolkit/oscap-report.html");
}

// ---------- Lynis report summary ----------
static void showLynisReport() {
    std::ifstream f("/var/log/lynis-report.dat");
    if (!f.is_open()) { Logger::warn("No report yet. Run a system audit first."); return; }
    std::string line;
    int w = 0, s = 0;
    while (std::getline(f, line)) {
        if (line.rfind("hardening_index=", 0) == 0) std::cout << "Hardening index: " << line.substr(16) << " / 100\n";
        else if (line.rfind("warning[]=", 0) == 0) { ++w; std::cout << "  [WARN] " << line.substr(10) << "\n"; }
        else if (line.rfind("suggestion[]=", 0) == 0 && s < 25) { ++s; std::cout << "  [TIP]  " << line.substr(13) << "\n"; }
    }
    std::cout << w << " warning(s); first " << s << " suggestion(s) shown. Full report: /var/log/lynis-report.dat\n";
}

// ---------- ClamAV scan ----------
static void clamScanPath(const std::string& path, bool oneFs);
static void clamScan() {
    std::string path;
    if (!ask("Directory or file to scan [/home] : ", path)) return;
    clamScanPath(path.empty() ? "/home" : path, false);
}

// ---------- AIDE ----------
static std::string aideConfig() { return fs::exists("/etc/aide/aide.conf") ? "/etc/aide/aide.conf" : "/etc/aide.conf"; }
static std::vector<std::string> aideBase() {
    std::vector<std::string> a = {"aide"};
    if (fs::exists("/etc/aide/aide.conf")) { a.push_back("--config"); a.push_back("/etc/aide/aide.conf"); }
    return a;
}
static void aidePromoteDb() {
    for (const char* dir : {"/var/lib/aide/", "/var/lib/aide/"}) {
        for (const char* ext : {".gz", ""}) {
            const std::string nu = std::string(dir) + "aide.db.new" + ext, cur = std::string(dir) + "aide.db" + ext;
            std::error_code ec;
            if (fs::exists(nu, ec)) {
                fs::copy_file(nu, cur, fs::copy_options::overwrite_existing, ec);
                if (!ec) { Logger::info("Database activated: " + cur); return; }
            }
        }
    }
    Logger::warn("Could not find the new AIDE database to activate; check /var/lib/aide/.");
}
static void aideSyncExclusions() {
    Exclusions ex; ex.loadEffective();
    std::vector<std::string> body;
    for (const auto& d : ex.dirs)  body.push_back("!" + d);
    for (const auto& r : ex.fileRegexes()) body.push_back("!.*" + r);
    body.push_back("!/proc"); body.push_back("!/sys");
    if (writeManagedBlock(aideConfig(), "# BEGIN sectk-exclusions", "# END sectk-exclusions", body))
        Logger::info("Wrote " + std::to_string(body.size()) + " exclusion line(s) to " + aideConfig() +
                     ". Re-initialise the AIDE database to apply.");
}

// ---------- auditd ----------
static void auditPresets() {
    const std::vector<std::pair<std::string, std::string>> watch = {
        {"/etc/passwd", "identity"}, {"/etc/shadow", "identity"}, {"/etc/group", "identity"},
        {"/etc/gshadow", "identity"}, {"/etc/sudoers", "sudoers"}, {"/etc/sudoers.d", "sudoers"},
        {"/etc/ssh/sshd_config", "sshd"}, {"/etc/crontab", "cron"}, {"/etc/cron.d", "cron"},
        {"/var/log/lastlog", "logins"}, {"/var/log/faillog", "logins"}};
    std::vector<std::string> lines = {"# Managed by Security Toolkit"};
    for (const auto& w : watch)
        if (fs::exists(w.first)) lines.push_back("-w " + w.first + " -p wa -k " + w.second);
    const std::string file = "/etc/audit/rules.d/99-sectk.rules";
    if (!writeLines(file, lines)) return;
    Logger::info("Wrote " + std::to_string(lines.size() - 1) + " watch rules to " + file);
    if (cmdExists("augenrules")) runCmd({"augenrules", "--load"});
    else runCmd({"auditctl", "-R", file});
}

// ---------- fail2ban ----------
static void f2bEnableSsh(const Tool& t) {
    const std::string jail = "/etc/fail2ban/jail.local";
    setIniValue(jail, "sshd", "enabled", "true");
    setIniValue(jail, "sshd", "port", join(portList(), ","));
    if (!fs::exists("/var/log/auth.log") && !fs::exists("/var/log/secure") && haveSystemd())
        setIniValue(jail, "sshd", "backend", "systemd");
    const std::string svc = resolveService(t.services);
    if (!svc.empty()) { serviceAction("enable", svc); serviceAction("restart", svc); }
}

// ---------- suricata ----------
static void suricataInterface(const Tool& t) {
    std::vector<std::string> ifs;
    std::error_code ec;
    for (const auto& e : fs::directory_iterator("/sys/class/net", ec))
        if (e.path().filename() != "lo") ifs.push_back(e.path().filename().string());
    std::sort(ifs.begin(), ifs.end());
    if (ifs.empty()) { Logger::error("No network interfaces found."); return; }
    for (size_t i = 0; i < ifs.size(); ++i) std::cout << "  [" << i + 1 << "] " << ifs[i] << "\n";
    std::string in;
    if (!ask("Interface number (empty = cancel): ", in) || !isNumber(in) || std::stoul(in) < 1 || std::stoul(in) > ifs.size()) return;
    const std::string ifc = ifs[std::stoul(in) - 1];
    if (!replaceFirstRegex("/etc/suricata/suricata.yaml", std::regex(R"((\n\s*-\s*interface:\s*)\S+)"), ifc))
        Logger::warn("Could not find the af-packet interface line in suricata.yaml; edit it manually.");
    else Logger::info("suricata.yaml interface set to " + ifc);
    if (fs::exists("/etc/default/suricata")) setConfLine("/etc/default/suricata", "IFACE", "=", ifc);
    restartIfActive(t);
}

static std::vector<Action> runActions(const Tool& t) {
    using A = Action;
    std::vector<A> a;
    const std::string& id = t.id;
    if (id == "lynis") {
        std::vector<std::string> audit = {"lynis", "audit", "system", "--quick"};
        if (!Color::enabled) audit.push_back("--no-colors");
        a = {{"Full system audit", cmdAction(audit)},
             {"Show warnings and suggestions from the last audit", showLynisReport},
             {"Update Lynis release info", cmdAction({"lynis", "update", "info"})}};
    } else if (id == "openscap") {
        a = {{"Evaluate the system against a benchmark profile (HTML report)", runOpenScap}};
    } else if (id == "apparmor") {
        a = {{"Show status and loaded profiles", cmdAction({"aa-status"})},
             {"Put a profile in ENFORCE mode", [] { std::string p; if (ask("Profile name or path: ", p) && !p.empty()) runCmd({"aa-enforce", p}); }},
             {"Put a profile in COMPLAIN mode (log only)", [] { std::string p; if (ask("Profile name or path: ", p) && !p.empty()) runCmd({"aa-complain", p}); }},
             {"Reload all profiles", [&t] { const std::string s = resolveService(t.services); if (!s.empty()) serviceAction("restart", s); }}};
    } else if (id == "selinux") {
        a = {{"Show status", cmdAction({"sestatus"})},
             {"Show recent denials", [] { if (cmdExists("ausearch")) runCmd({"ausearch", "-m", "avc", "-ts", "recent"}); else Logger::warn("Install auditd to read denials."); }}};
    } else if (id == "ufw") {
        a = {{"Show status and rules", cmdAction({"ufw", "status", "numbered"})},
             {"Apply secure defaults (deny in, allow out, keep SSH)", [] { FirewallManager::applyDefaults(FirewallManager::FW::UFW); }}};
    } else if (id == "firewalld") {
        a = {{"Show everything active", cmdAction({"firewall-cmd", "--list-all"})},
             {"Apply secure defaults (public zone, keep SSH)", [] { FirewallManager::applyDefaults(FirewallManager::FW::FIREWALLD); }}};
    } else if (id == "nftables") {
        a = {{"Show current ruleset", cmdAction({"nft", "list", "ruleset"})},
             {"Load a safe baseline ruleset (deny in, allow out, keep SSH)", applyNftBaseline}};
    } else if (id == "fail2ban") {
        a = {{"Overall status (active jails)", cmdAction({"fail2ban-client", "status"})},
             {"SSH jail status (banned IPs)", cmdAction({"fail2ban-client", "status", "sshd"})},
             {"Unban an IP address", [] { std::string ip; if (askValid("IP to unban: ", std::regex("[0-9a-fA-F:.]+"), "Enter an IP address.", ip)) runCmd({"fail2ban-client", "unban", ip}); }},
             {"Reload configuration", cmdAction({"fail2ban-client", "reload"})}};
    } else if (id == "clamav") {
        a = {{"Scan a directory (applies your exclusions)", clamScan},
             {"Update virus signatures (freshclam)", cmdAction({"freshclam"})}};
    } else if (id == "rkhunter") {
        a = {{"Update rkhunter data files", cmdAction({"rkhunter", "--update"})},
             {"Create/refresh baseline (run on a clean system)", cmdAction({"rkhunter", "--propupd"})},
             {"Run a check", cmdAction({"rkhunter", "--check", "--sk", "--rwo"})}};
    } else if (id == "chkrootkit") {
        a = {{"Run a rootkit check", cmdAction({"chkrootkit", "-q"})}};
    } else if (id == "aide") {
        a = {{"Initialise the database (do this on a clean system)", [] {
                 auto c = aideBase();
                 if (cmdExists("aideinit")) runCmd({"aideinit", "-y", "-f"});
                 else { c.push_back("--init"); runCmd(c); aidePromoteDb(); }
             }},
             {"Check for changes", [] { auto c = aideBase(); c.push_back("--check"); runCmd(c); }},
             {"Accept current state (update database after legitimate changes)", [] {
                 auto c = aideBase(); c.push_back("--update"); runCmd(c); aidePromoteDb(); }}};
    } else if (id == "auditd") {
        a = {{"List active rules", cmdAction({"auditctl", "-l"})},
             {"Summary report", cmdAction({"aureport", "--summary"})},
             {"Search events by rule key (identity, sudoers, sshd, cron, logins)", [] {
                 std::string k; if (askValid("Key: ", std::regex("[A-Za-z0-9_-]+"), "Letters, digits, _ and -.", k)) runCmd({"ausearch", "-k", k, "-i"}); }}};
    } else if (id == "suricata") {
        a = {{"Update detection rules (suricata-update)", cmdAction({"suricata-update"})},
             {"Test the configuration", cmdAction({"suricata", "-T", "-c", "/etc/suricata/suricata.yaml", "-v"})},
             {"Show latest alerts", [] { runCmd({"tail", "-n", "20", "/var/log/suricata/fast.log"}); }}};
    } else if (id == "wazuh") {
        a = {{"Show agent/manager status", cmdAction({"/var/ossec/bin/wazuh-control", "status"})}};
    } else if (id == "ossec") {
        a = {{"Show status", cmdAction({"/var/ossec/bin/ossec-control", "status"})}};
    } else if (id == "utils") {
        a = {{"Show which ports this machine exposes (nmap localhost)", cmdAction({"nmap", "-sT", "localhost"})},
             {"List listening sockets", cmdAction({"ss", "-tulpn"})}};
    }
    return a;
}

static std::vector<Action> settingsActions(const Tool& t) {
    std::vector<Action> a;
    const std::string& id = t.id;
    const std::string dur = "[0-9]+[smhdw]?";
    if (id == "fail2ban") {
        const std::string jail = "/etc/fail2ban/jail.local";
        a.push_back(valueAction(t, "Ban time (e.g. 1h, 30m, 86400, -1 = permanent)", jail, "DEFAULT", "bantime", " = ", "Ban time", "-?" + dur, "Examples: 10m, 1h, 1d, -1."));
        a.push_back(valueAction(t, "Find time (window in which failures are counted)", jail, "DEFAULT", "findtime", " = ", "Find time", dur, "Examples: 10m, 1h."));
        a.push_back(valueAction(t, "Max retries before a ban", jail, "DEFAULT", "maxretry", " = ", "Max retries", "[0-9]{1,3}", "A number, e.g. 5."));
        a.push_back(valueAction(t, "Whitelist (IPs never banned, space-separated)", jail, "DEFAULT", "ignoreip", " = ", "Addresses, e.g. 127.0.0.1/8 ::1 192.168.1.0/24", "[0-9a-fA-F:./ ]+", "Only IPs/CIDRs separated by spaces."));
        a.push_back({"Enable SSH protection (sshd jail on your SSH ports)", [&t] { f2bEnableSsh(t); }});
    } else if (id == "ufw") {
        a = {{"Allow a port (e.g. 80/tcp, 443, 51820/udp)", [] { std::string p; if (askValid("Port[/tcp|udp]: ", std::regex("[0-9]{1,5}(/(tcp|udp))?"), "Example: 443 or 51820/udp.", p)) runCmd({"ufw", "allow", p}); }},
             {"Deny a port", [] { std::string p; if (askValid("Port[/tcp|udp]: ", std::regex("[0-9]{1,5}(/(tcp|udp))?"), "Example: 23 or 5000/tcp.", p)) runCmd({"ufw", "deny", p}); }},
             {"Delete a rule (by number from the status list)", [] { runCmd({"ufw", "status", "numbered"}); std::string n; if (askValid("Rule number: ", std::regex("[0-9]{1,3}"), "A rule number.", n)) runCmd({"ufw", "--force", "delete", n}); }},
             {"Set logging level (off, low, medium, high)", [] { std::string l; if (askValid("Level: ", std::regex("off|low|medium|high"), "off, low, medium or high.", l)) runCmd({"ufw", "logging", l}); }},
             {"Enable the firewall", [] { if (confirm("Enable ufw now?")) runCmd({"ufw", "--force", "enable"}); }},
             {"Disable the firewall", [] { if (confirm("Disable ufw (no filtering)?")) runCmd({"ufw", "disable"}); }}};
    } else if (id == "firewalld") {
        a = {{"Open a port permanently (e.g. 8080/tcp)", [] { std::string p; if (askValid("Port/proto: ", std::regex("[0-9]{1,5}/(tcp|udp)"), "Example: 8080/tcp.", p)) { runCmd({"firewall-cmd", "--permanent", "--add-port=" + p}); runCmd({"firewall-cmd", "--reload"}); } }},
             {"Close a port permanently", [] { std::string p; if (askValid("Port/proto: ", std::regex("[0-9]{1,5}/(tcp|udp)"), "Example: 8080/tcp.", p)) { runCmd({"firewall-cmd", "--permanent", "--remove-port=" + p}); runCmd({"firewall-cmd", "--reload"}); } }},
             {"Allow a service (http, https, ssh, ...)", [] { std::string s; if (askValid("Service: ", std::regex("[a-z0-9-]+"), "Example: https.", s)) { runCmd({"firewall-cmd", "--permanent", "--add-service=" + s}); runCmd({"firewall-cmd", "--reload"}); } }},
             {"Remove a service", [] { std::string s; if (askValid("Service: ", std::regex("[a-z0-9-]+"), "Example: cockpit.", s)) { runCmd({"firewall-cmd", "--permanent", "--remove-service=" + s}); runCmd({"firewall-cmd", "--reload"}); } }}};
    } else if (id == "clamav") {
        a = {{"Enable automatic signature updates (freshclam service)", [] {
                 const std::string s = resolveService({"clamav-freshclam"});
                 if (s.empty()) Logger::warn("No freshclam service found; run 'freshclam' from cron instead."); else serviceAction("enable-now", s); }},
             {"Enable the ClamAV daemon (needs signatures first)", [&t] {
                 const std::string s = resolveService(t.services);
                 if (s.empty()) Logger::warn("No clamd service found."); else serviceAction("enable-now", s); }}};
    } else if (id == "rkhunter") {
        a.push_back(valueAction(t, "Send warnings by e-mail to (address)", "/etc/rkhunter.conf", "", "MAIL-ON-WARNING", "=", "E-mail address", "[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+", "Enter a valid e-mail address."));
        a.push_back(valueAction(t, "Tell rkhunter whether root SSH login is allowed (yes / no / unset)", "/etc/rkhunter.conf", "", "ALLOW_SSH_ROOT_USER", "=", "Value", "yes|no|unset", "yes, no or unset."));
    } else if (id == "auditd") {
        a.push_back({"Install watch rules for identity, sudo, ssh, cron and login files", auditPresets});
        a.push_back(valueAction(t, "Maximum size of one log file in MB", "/etc/audit/auditd.conf", "", "max_log_file", " = ", "Size in MB", "[0-9]{1,4}", "A number of megabytes."));
        a.push_back(valueAction(t, "Number of rotated logs to keep", "/etc/audit/auditd.conf", "", "num_logs", " = ", "Count", "[0-9]{1,3}", "A number."));
    } else if (id == "selinux") {
        a = {{"Set mode now (runtime): enforcing / permissive", [] { std::string m; if (askValid("Mode: ", std::regex("enforcing|permissive"), "enforcing or permissive.", m)) runCmd({"setenforce", m == "enforcing" ? "1" : "0"}); }},
             {"Set mode at boot (/etc/selinux/config)", [&t] {
                 std::string m;
                 if (!askValid("Mode (enforcing/permissive/disabled): ", std::regex("enforcing|permissive|disabled"), "enforcing, permissive or disabled.", m)) return;
                 if (m == "enforcing" && !confirm("If SELinux was disabled you must relabel and reboot first. Continue?")) return;
                 setConfLine(t.config, "SELINUX", "=", m); }},
             {"Schedule a full filesystem relabel on next boot", [] { if (confirm("Create /.autorelabel (next boot will be slow)?")) runCmd({"touch", "/.autorelabel"}); }}};
    } else if (id == "suricata") {
        a = {{"Choose the network interface to monitor", [&t] { suricataInterface(t); }}};
    } else if (id == "wazuh") {
        a = {{"Set the Wazuh manager address (IP or hostname)", [&t] {
                 std::string ip;
                 if (!askValid("Manager address: ", std::regex("[A-Za-z0-9._:-]+"), "IP address or hostname.", ip)) return;
                 if (!replaceFirstRegex(t.config, std::regex(R"((<address>)[^<]*)"), ip)) Logger::warn("No <address> entry found in ossec.conf; edit it manually.");
                 else restartIfActive(t); }}};
    } else if (id == "lynis") {
        a = {{"Skip a test permanently (add to custom profile)", [] {
                 std::string tid;
                 if (!askValid("Test ID (e.g. KRNL-5820): ", std::regex("[A-Z0-9-]+"), "Uppercase test ID like SSH-7440.", tid)) return;
                 auto lines = readLines("/etc/lynis/custom.prf");
                 lines.push_back("skip-test=" + tid);
                 backupOnce("/etc/lynis/custom.prf");
                 if (writeLines("/etc/lynis/custom.prf", lines)) Logger::info("Added skip-test=" + tid); }}};
    } else if (id == "aide") {
        a = {{"Write your scan exclusions into the AIDE config", aideSyncExclusions}};
    }
    return a;
}

static void serviceMenu(const Tool& t) {
    const std::string svc = resolveService(t.services);
    if (svc.empty()) { Logger::warn(t.name + " has no service on this system."); return; }
    std::vector<Action> a;
    for (const char* act : {"start", "stop", "restart", "enable", "disable", "enable-now"}) {
        const std::string s = act;
        std::string label = s == "enable-now" ? "Enable at boot and start now" : s;
        if (s != "enable-now") label[0] = static_cast<char>(std::toupper(static_cast<unsigned char>(label[0])));
        a.push_back({label + " (" + svc + ")", [s, svc] { serviceAction(s, svc); }});
    }
    a.push_back({"Show service status", [svc] { if (haveSystemd()) runCmd({"systemctl", "status", "--no-pager", svc}); else std::cout << serviceState(svc) << "\n"; }});
    runActionMenu(t.name + " service: " + serviceState(svc), a);
}

static void toolMenu(const Tool& t, const PackageManager& pm) {
    while (true) {
        const ToolStatus st = toolStatus(t);
        std::cout << "\n" << Color::p(Color::BOLD) << Color::p(Color::CYAN) << "== " << t.name << " ==" << Color::p(Color::RESET)
                  << "  " << (st.installed ? "installed" : "not installed");
        if (!st.service.empty()) std::cout << "  | service " << st.service << ": " << st.state << " (" << st.enabled << ")";
        std::cout << "\n  [1] About this tool\n"
                  << "  [2] " << (st.installed ? "Remove" : "Install") << "\n"
                  << "  [3] Service: start / stop / enable...\n"
                  << "  [4] Run / use the tool\n"
                  << "  [5] Change settings\n"
                  << "  [6] Edit config file" << (t.config.empty() ? " (n/a)" : " (" + t.config + ")") << "\n"
                  << "  [0] Back\nChoose: ";
        std::string in;
        if (!readLine(in) || in == "0") return;
        const bool need = in == "3" || in == "4" || in == "5" || in == "6";
        if (need && !st.installed) { Logger::warn(t.name + " is not installed. Choose [2] to install it."); continue; }
        if (in == "1") printToolInfo(t, pm);
        else if (in == "2") { if (st.installed) removeTool(pm, t); else installTools(pm, {&t}); }
        else if (in == "3") { if (requireRoot("Managing services")) serviceMenu(t); }
        else if (in == "4") runActionMenu(t.name + ": run", runActions(t));
        else if (in == "5") { if (requireRoot("Changing settings")) runActionMenu(t.name + ": settings", settingsActions(t)); }
        else if (in == "6") { if (t.config.empty()) Logger::warn("No config file for this tool."); else if (requireRoot("Editing configuration")) { editFile(t.config); restartIfActive(t); } }
        else std::cout << Color::p(Color::YELLOW) << "Invalid option.\n" << Color::p(Color::RESET);
    }
}

static void printStatusTable() {
    std::cout << "\n" << Color::p(Color::BOLD) << "Tool status" << Color::p(Color::RESET) << "\n";
    int i = 1;
    for (const auto& t : catalog()) {
        const ToolStatus s = toolStatus(t);
        std::cout << "  [" << (i < 10 ? " " : "") << i << "] " << t.name;
        ++i;
        for (size_t k = t.name.size(); k < 18; ++k) std::cout << ' ';
        std::cout << (s.installed ? "installed    " : "not installed");
        if (!s.service.empty()) std::cout << "  " << s.service << ": " << s.state << " (" << s.enabled << ")";
        std::cout << "\n";
    }
}

static void manageMenu(const PackageManager& pm) {
    while (true) {
        printStatusTable();
        std::cout << "\nOpen a tool (number or name), 0 = back: ";
        std::string in;
        if (!readLine(in) || in == "0" || in.empty()) return;
        const auto sel = parseSelection(in);
        if (!sel.empty()) toolMenu(*sel.front(), pm);
    }
}

// ---------- scan exclusions menu ----------
static void exclusionsMenu() {
    while (true) {
        Exclusions ex; ex.loadEditable();
        std::cout << "\n" << Color::p(Color::BOLD) << "Scan exclusions" << Color::p(Color::RESET)
                  << "  (saved in " << Exclusions::editableFile() << ")\n";
        size_t n = 1;
        for (const auto& d : ex.dirs)  std::cout << "  " << n++ << ". folder     " << d << "\n";
        for (const auto& e : ex.exts)  std::cout << "  " << n++ << ". file type  " << e << "\n";
        for (const auto& s : ex.names) std::cout << "  " << n++ << ". name       " << s << "\n";
        if (ex.total() == 0) std::cout << "  (none yet)\n";
        std::cout << "\n  [1] Exclude a folder (everything inside it)\n"
                     "  [2] Exclude a file type (e.g. .log, .iso)\n"
                     "  [3] Exclude a name or pattern (e.g. node_modules, *.bak)\n"
                     "  [4] Add common noise (node_modules, .git, .cache, __pycache__)\n"
                     "  [5] Remove an entry\n"
                     "  [6] Remove all\n"
                     "  [0] Back\nChoose: ";
        std::string in, v;
        if (!readLine(in) || in == "0") return;
        bool changed = false;
        if (in == "1") { if (ask("Folder path: ", v)) changed = ex.addDir(v); }
        else if (in == "2") { if (ask("File extension (e.g. .log): ", v)) changed = ex.addExt(v); }
        else if (in == "3") { if (ask("Name or pattern: ", v)) changed = ex.addName(v); }
        else if (in == "4") { for (const char* c : {"node_modules", ".git", ".cache", "__pycache__"}) changed |= ex.addName(c); }
        else if (in == "5") {
            if (ask("Number to remove: ", v) && isNumber(v) && std::stoul(v) >= 1) changed = ex.removeAt(std::stoul(v) - 1);
        } else if (in == "6") { if (confirm("Remove all exclusions?")) { ex.clear(); changed = true; } }
        else { std::cout << "Invalid option.\n"; continue; }
        if (changed) { if (ex.save()) Logger::info("Exclusions saved."); }
        else if (in != "5" && in != "6") Logger::warn("Nothing added (empty, invalid or already listed).");
    }
}

// ============================================================
//  Section 6 - CLI
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
              << "  [1] Tool catalog: learn what each tool does and choose what to install\n"
              << "  [2] Manage tools: status, services, run, settings, edit config\n"
              << "  [3] Scan a directory for suspicious files\n"
              << "  [4] Scan exclusions: folders, file types, names\n"
              << "  [5] Quick firewall setup (secure defaults)\n"
              << "  [6] Quick setup: recommended tools + scan + firewall\n"
              << "  [7] Show log path\n"
              << "  [8] Run only selected tools\n"
              << "  [9] Scan whole partitions / disks\n"
              << "  [0] Exit\n"
              << "Choose an option: ";
}

static void printHelp(const char* argv0) {
    const std::string a = argv0;
    std::cout << Color::p(Color::BOLD) << "Usage:" << Color::p(Color::RESET) << "\n"
              << "  " << a << "                       Interactive menu\n"
              << "  " << a << " --tools                List every supported tool and what it does\n"
              << "  " << a << " --info <tool>          Explain one tool\n"
              << "  " << a << " --status               Show installed tools and service state\n"
              << "  " << a << " --install [tools]      Install tools (menu if none given; ids or 'rec')  (root)\n"
              << "  " << a << " --manage <tool>        Manage one tool: run, settings, edit config       (root)\n"
              << "  " << a << " --run <tools> [path]   Run only these tools (ids, numbers, 'rec', 'scan')\n"
              << "  " << a << " --list-disks            List disks, partitions and mount points\n"
              << "  " << a << " --scan-disks [devs]     Scan whole partitions/disks (e.g. sdb, /dev/sda1);\n"
              << "                             no device = every mounted disk filesystem  (root)\n"
              << "  " << a << " --scan [path]          Scan a directory (default: /home)\n"
              << "  " << a << " --exclusions           Edit saved scan exclusions\n"
              << "  " << a << " --firewall             Configure firewall defaults                     (root)\n"
              << "  " << a << " --all [path]           Recommended tools + scan + firewall             (root)\n"
              << "  " << a << " --help | --version\n"
              << "\nOptions:\n"
              << "  --exclude-dir <path>    Skip a folder in this scan (repeatable)\n"
              << "  --exclude-ext <.ext>    Skip a file type in this scan (repeatable)\n"
              << "  --exclude-name <pat>    Skip a name/pattern in this scan (repeatable)\n"
              << "      --clamav            Also run ClamAV during --scan-disks\n"
              << "  -y, --yes               Skip confirmation prompts (needed when not interactive)\n"
              << "      --no-color          Disable coloured output\n"
              << "\nTool ids:";
    for (const auto& t : catalog()) std::cout << " " << t.id;
    std::cout << "\n";
}

static std::vector<const Tool*> baselineTools(const PackageManager& pm) {
    std::vector<const Tool*> sel;
    for (const auto& t : catalog()) if (t.recommended) sel.push_back(&t);
    if (!cmdExists("ufw") && !cmdExists("firewall-cmd")) {
        const bool rpm = pm.kind() == PK::DNF || pm.kind() == PK::YUM || pm.kind() == PK::ZYPPER;
        if (const Tool* fw = findTool(rpm ? "firewalld" : "ufw")) sel.push_back(fw);
    }
    return sel;
}

static void moduleInstall(const PackageManager& pm, const std::vector<std::string>& ids) {
    if (!requireRoot("Installing packages")) return;
    Logger::info("System: " + (pm.prettyName().empty() ? std::string("unknown") : pm.prettyName()) +
                 "  (package manager: " + pm.name() + ")");
    if (ids.empty()) {
        if (::isatty(STDIN_FILENO)) installerMenu(pm);
        else installTools(pm, baselineTools(pm));
        return;
    }
    installTools(pm, parseSelection(join(ids, " ")));
}

static void moduleScan(const std::string& path, const Exclusions& extra) {
    Exclusions ex; ex.loadEffective();
    for (const auto& d : extra.dirs)  ex.addDir(d);
    for (const auto& e : extra.exts)  ex.addExt(e);
    for (const auto& n : extra.names) ex.addName(n);
    FileScanner scanner;
    auto results = scanner.scan(path, ex);
    scanner.printReport(results);
}

// ---------- partitions and disks ----------
struct Mnt { std::string src, target, fstype; };

static std::string decodeMountField(const std::string& s) {
    std::string out;
    for (size_t i = 0; i < s.size(); ++i) {
        if (s[i] == '\\' && i + 3 < s.size() + 0 && std::isdigit(static_cast<unsigned char>(s[i + 1])) &&
            std::isdigit(static_cast<unsigned char>(s[i + 2])) && std::isdigit(static_cast<unsigned char>(s[i + 3]))) {
            out += static_cast<char>(std::stoi(s.substr(i + 1, 3), nullptr, 8));
            i += 3;
        } else out += s[i];
    }
    return out;
}

static std::vector<Mnt> readMounts() {
    std::vector<Mnt> v;
    std::ifstream f("/proc/mounts");
    std::string a, b, c, rest;
    while (f >> a >> b >> c && std::getline(f, rest))
        v.push_back({decodeMountField(a), decodeMountField(b), c});
    return v;
}

static bool scannableFs(const std::string& t) {
    static const std::set<std::string> ok = {"ext2", "ext3", "ext4", "xfs", "btrfs", "f2fs", "vfat", "exfat",
        "ntfs", "ntfs3", "fuseblk", "jfs", "reiserfs", "hfsplus", "udf", "iso9660", "zfs"};
    return ok.count(t) > 0;
}

struct BlockDev {
    std::string kname, type, size, fstype, pk, model;
    std::vector<std::string> mounts;
    std::string path() const { return "/dev/" + kname; }
};

static std::string canon(const std::string& p) {
    std::error_code ec;
    fs::path c = fs::canonical(p, ec);
    return ec ? p : c.string();
}

static std::vector<BlockDev> listBlockDevices() {
    std::vector<BlockDev> devs;
    if (!cmdExists("lsblk")) return devs;
    std::string out;
    if (captureCmd({"lsblk", "-P", "-o", "KNAME,TYPE,SIZE,FSTYPE,PKNAME,MODEL"}, out) != 0) return devs;
    const auto mounts = readMounts();
    std::istringstream iss(out);
    std::string line;
    static const std::regex kv(R"re((\w+)="([^"]*)")re");
    while (std::getline(iss, line)) {
        BlockDev d;
        for (auto it = std::sregex_iterator(line.begin(), line.end(), kv); it != std::sregex_iterator(); ++it) {
            const std::string k = (*it)[1], v = (*it)[2];
            if (k == "KNAME") d.kname = v; else if (k == "TYPE") d.type = v; else if (k == "SIZE") d.size = v;
            else if (k == "FSTYPE") d.fstype = v; else if (k == "PKNAME") d.pk = v; else if (k == "MODEL") d.model = trim(v);
        }
        if (d.kname.empty() || d.type == "loop" || d.type == "rom") continue;
        const std::string me = canon(d.path());
        for (const auto& m : mounts)
            if (m.src.rfind("/dev/", 0) == 0 && canon(m.src) == me) d.mounts.push_back(m.target);
        devs.push_back(d);
    }
    return devs;
}

static void printDisks(const std::vector<BlockDev>& devs) {
    std::cout << "\n" << Color::p(Color::BOLD) << "Disks and partitions" << Color::p(Color::RESET) << "\n";
    for (size_t i = 0; i < devs.size(); ++i) {
        const auto& d = devs[i];
        std::cout << "  [" << (i + 1 < 10 ? " " : "") << i + 1 << "] " << (d.pk.empty() ? "" : "  ") << d.path()
                  << "  " << d.type << "  " << d.size;
        if (!d.fstype.empty()) std::cout << "  " << d.fstype;
        if (!d.model.empty())  std::cout << "  " << d.model;
        if (!d.mounts.empty()) std::cout << "  mounted: " << join(d.mounts, ", ");
        std::cout << "\n";
    }
}

/** Disk -> all descendant devices that carry a filesystem; partition -> itself. */
static void collectLeaves(const std::vector<BlockDev>& devs, const BlockDev& d, std::vector<const BlockDev*>& out) {
    if (!d.fstype.empty() || !d.mounts.empty()) out.push_back(&d);
    for (const auto& c : devs)
        if (c.pk == d.kname) collectLeaves(devs, c, out);
}

static void clamScanPath(const std::string& path, bool oneFs) {
    Exclusions ex; ex.loadEffective();
    std::vector<std::string> cmd = {"clamscan", "-r", "-i",
                                    "--exclude-dir=^/proc", "--exclude-dir=^/sys", "--exclude-dir=^/dev"};
    if (oneFs) cmd.push_back("--cross-fs=no");
    for (const auto& r : ex.dirRegexes())  cmd.push_back("--exclude-dir=" + r);
    for (const auto& r : ex.fileRegexes()) cmd.push_back("--exclude=" + r);
    cmd.push_back(path);
    Logger::info("ClamAV scan of " + path + " (" + std::to_string(ex.total()) + " exclusion(s) applied).");
    runCmd(cmd);
}

static void scanMountPoint(const std::string& label, const std::string& mp, bool clam, const Exclusions& ex) {
    Logger::info("##### " + label + "  ->  " + mp);
    FileScanner scanner;
    scanner.printReport(scanner.scan(mp, ex, true));
    if (clam) clamScanPath(mp, true);
}

/** Scan devices (e.g. /dev/sdb, sda1). Empty list = every mounted real filesystem. */
static void scanDevices(const std::vector<std::string>& args, bool clam) {
    if (!requireRoot("Scanning whole partitions and disks")) return;
    if (clam && !cmdExists("clamscan")) { Logger::warn("ClamAV is not installed; using the built-in scanner only."); clam = false; }
    Exclusions ex; ex.loadEffective();
    std::set<std::string> done;

    if (args.empty()) {
        for (const auto& m : readMounts()) {
            if (!scannableFs(m.fstype) || !done.insert(m.target).second) continue;
            scanMountPoint(m.src + " (" + m.fstype + ")", m.target, clam, ex);
        }
        if (done.empty()) Logger::warn("No mounted disk filesystems found.");
        return;
    }

    const auto devs = listBlockDevices();
    if (devs.empty()) { Logger::error("Cannot list block devices (lsblk missing?)."); return; }
    for (std::string a : args) {
        if (a.rfind("/dev/", 0) == 0) a = a.substr(5);
        const BlockDev* d = nullptr;
        for (const auto& x : devs) if (x.kname == a) { d = &x; break; }
        if (!d) { Logger::error("Unknown device: " + a + " (see --list-disks)"); continue; }

        std::vector<const BlockDev*> leaves;
        collectLeaves(devs, *d, leaves);
        if (leaves.empty()) { Logger::warn(d->path() + " has no filesystem to scan."); continue; }
        for (const BlockDev* l : leaves) {
            if (!l->mounts.empty()) {
                for (const auto& mp : l->mounts)
                    if (done.insert(mp).second) scanMountPoint(l->path() + (l->fstype.empty() ? "" : " (" + l->fstype + ")"), mp, clam, ex);
                continue;
            }
            if (!scannableFs(l->fstype)) {
                Logger::warn("Skipping " + l->path() + ": " + l->fstype + " cannot be scanned directly "
                             "(unlock/activate it first, then scan the mapped device).");
                continue;
            }
            std::string opts = "ro,noexec,nosuid,nodev";
            if (l->fstype.rfind("ext", 0) == 0) opts += ",noload";
            else if (l->fstype == "xfs")        opts += ",norecovery";
            const std::string mp = "/mnt/sectk-" + l->kname;
            std::error_code ec;
            fs::create_directories(mp, ec);
            Logger::info("Mounting " + l->path() + " read-only at " + mp);
            if (runCmd({"mount", "-o", opts, l->path(), mp}) != 0) {
                Logger::error("Could not mount " + l->path() + "; skipped.");
                fs::remove(mp, ec);
                continue;
            }
            scanMountPoint(l->path() + " (" + l->fstype + ", temporary read-only mount)", mp, clam, ex);
            runCmd({"umount", mp});
            fs::remove(mp, ec);
        }
    }
}

static void diskMenu() {
    if (!requireRoot("Scanning partitions and disks")) return;
    const auto devs = listBlockDevices();
    printDisks(devs);
    std::cout << "\nChoose what to scan: numbers (e.g. 1 3), 'a' = every mounted disk filesystem, 0 = back\n"
                 "A whole disk scans all its partitions; unmounted ones are mounted read-only temporarily.\n> ";
    std::string in;
    if (!readLine(in) || in.empty() || in == "0") return;
    std::vector<std::string> args;
    if (in != "a" && in != "all") {
        std::istringstream iss(in);
        std::string tok;
        while (iss >> tok) {
            if (isNumber(tok) && std::stoul(tok) >= 1 && std::stoul(tok) <= devs.size()) args.push_back(devs[std::stoul(tok) - 1].kname);
            else Logger::warn("Ignoring: " + tok);
        }
        if (args.empty()) return;
    }
    bool clam = false;
    if (cmdExists("clamscan")) {
        std::string y;
        clam = ask("Also run ClamAV on each? (slow on big disks) [y/N]: ", y) && toLower(y).rfind("y", 0) == 0;
    }
    scanDevices(args, clam);
}

// ---------- run chosen tools only ----------
static void runToolDefault(const Tool& t, const std::string& path, const Exclusions& ex) {
    const std::string& id = t.id;
    Logger::info("===== Running " + t.name + " =====");
    if (!isInstalled(t)) { Logger::warn(t.name + " is not installed; skipped."); return; }
    if (id == "lynis") {
        std::vector<std::string> c = {"lynis", "audit", "system", "--quick"};
        if (!Color::enabled) c.push_back("--no-colors");
        runCmd(c);
    }
    else if (id == "openscap") { if (::isatty(STDIN_FILENO)) runOpenScap(); else Logger::warn("OpenSCAP needs you to pick a profile: use --manage openscap."); }
    else if (id == "apparmor")  runCmd({"aa-status"});
    else if (id == "selinux")   runCmd({"sestatus"});
    else if (id == "ufw")       runCmd({"ufw", "status", "verbose"});
    else if (id == "firewalld") runCmd({"firewall-cmd", "--list-all"});
    else if (id == "nftables")  runCmd({"nft", "list", "ruleset"});
    else if (id == "fail2ban")  runCmd({"fail2ban-client", "status"});
    else if (id == "clamav")    clamScanPath(path, false);
    else if (id == "rkhunter")  runCmd({"rkhunter", "--check", "--sk", "--rwo"});
    else if (id == "chkrootkit") runCmd({"chkrootkit", "-q"});
    else if (id == "aide")      { auto c = aideBase(); c.push_back("--check"); runCmd(c); }
    else if (id == "auditd")    runCmd({"aureport", "--summary"});
    else if (id == "suricata")  runCmd({"suricata", "-T", "-c", "/etc/suricata/suricata.yaml", "-v"});
    else if (id == "wazuh")     runCmd({"/var/ossec/bin/wazuh-control", "status"});
    else if (id == "ossec")     runCmd({"/var/ossec/bin/ossec-control", "status"});
    else if (id == "utils")     runCmd({"nmap", "-sT", "localhost"});
    (void)ex;
}

/** tokens: tool ids/numbers, plus the pseudo-tool "scan" (built-in file scanner). */
static void runToolsOnly(const std::vector<std::string>& tokens, const std::string& path, const Exclusions& extra) {
    bool withScan = false;
    std::vector<std::string> rest;
    for (const auto& tk : tokens) {
        std::string n = tk;
        for (char& c : n) if (c == ',' || c == ';') c = ' ';
        std::istringstream iss(n);
        std::string w;
        while (iss >> w) {
            if (toLower(w) == "scan" || toLower(w) == "filescan") withScan = true; else rest.push_back(w);
        }
    }
    const auto sel = parseSelection(join(rest, " "));
    if (sel.empty() && !withScan) { Logger::error("No valid tools selected. See --tools for ids (add 'scan' for the file scanner)."); return; }
    Exclusions ex; ex.loadEffective();
    for (const auto& d : extra.dirs) ex.addDir(d);
    for (const auto& e : extra.exts) ex.addExt(e);
    for (const auto& s : extra.names) ex.addName(s);
    if (!sel.empty() && !isRoot()) Logger::warn("Not root: some tools need sudo and may fail.");
    if (withScan) moduleScan(path, extra);
    for (const auto* t : sel) runToolDefault(*t, path, ex);
    Logger::info("Finished running " + std::to_string(sel.size() + (withScan ? 1 : 0)) + " item(s).");
}

static void runToolsMenu() {
    printStatusTable();
    std::cout << "\nRun only these tools: numbers or names (e.g. 1 4 clamav), add 'scan' for the file scanner,\n"
                 "'rec' = recommended, 0 = back\n> ";
    std::string in;
    if (!readLine(in) || in.empty() || in == "0") return;
    std::string path = "/home";
    std::string low = toLower(in);
    if (low.find("scan") != std::string::npos || low.find("clamav") != std::string::npos || low.find('9') != std::string::npos) {
        std::string p;
        if (ask("Directory for scans [/home]: ", p) && !p.empty()) path = p;
    }
    runToolsOnly({in}, path, Exclusions());
}

static void moduleFirewall() {
    if (!requireRoot("Configuring the firewall")) return;
    FirewallManager fw;
    Logger::info("Detected firewall tool: " + fw.fwName());
    fw.configure();
}

static void moduleAll(const PackageManager& pm, const std::string& path, const Exclusions& extra) {
    if (!requireRoot("Running all modules")) return;
    installTools(pm, baselineTools(pm));
    moduleScan(path, extra);
    moduleFirewall();
}

static std::string promptPath() {
    std::string path;
    ask("Enter directory path to scan [/home]: ", path);
    return path.empty() ? "/home" : path;
}

struct Options {
    std::string cmd;
    std::string path = "/home";
    std::vector<std::string> args;
    Exclusions extra;
    bool noColor = false, bad = false, clam = false;
    std::string badArg;
};

static Options parseArgs(int argc, char* argv[]) {
    Options o;
    auto need = [&](int& i, std::string& out) {
        if (i + 1 >= argc) { o.bad = true; o.badArg = std::string(argv[i]) + " (missing value)"; return false; }
        out = argv[++i];
        return true;
    };
    for (int i = 1; i < argc && !o.bad; ++i) {
        const std::string a = argv[i];
        std::string v;
        if      (a == "--help" || a == "-h")    o.cmd = "help";
        else if (a == "--version" || a == "-V") o.cmd = "version";
        else if (a == "--yes" || a == "-y")     g_assumeYes = true;
        else if (a == "--no-color")             o.noColor = true;
        else if (a == "--tools")                o.cmd = "tools";
        else if (a == "--status")               o.cmd = "status";
        else if (a == "--info")                 o.cmd = "info";
        else if (a == "--manage")               o.cmd = "manage";
        else if (a == "--install")              o.cmd = "install";
        else if (a == "--firewall")             o.cmd = "firewall";
        else if (a == "--exclusions")           o.cmd = "exclusions";
        else if (a == "--scan")                 o.cmd = "scan";
        else if (a == "--run")                  o.cmd = "run";
        else if (a == "--list-disks")           o.cmd = "disks";
        else if (a == "--scan-disks")           o.cmd = "scandisks";
        else if (a == "--clamav")               o.clam = true;
        else if (a == "--all")                  o.cmd = "all";
        else if (a == "--exclude-dir")  { if (need(i, v)) o.extra.dirs.push_back(v); }
        else if (a == "--exclude-ext")  { if (need(i, v)) o.extra.exts.push_back(v); }
        else if (a == "--exclude-name") { if (need(i, v)) o.extra.names.push_back(v); }
        else if (!a.empty() && a[0] != '-') {
            if (o.cmd == "scan" || o.cmd == "all" || (o.cmd == "run" && a[0] == '/')) o.path = a;
            else o.args.push_back(a);
        } else { o.bad = true; o.badArg = a; }
    }
    return o;
}

int main(int argc, char* argv[]) {
    Options opt = parseArgs(argc, argv);

    Color::enabled = !opt.noColor && ::isatty(STDOUT_FILENO) && !std::getenv("NO_COLOR");
    augmentPath();

    if (opt.bad) {
        std::cerr << Color::p(Color::RED) << "Unknown or incomplete argument: " << opt.badArg
                  << Color::p(Color::RESET) << "\n";
        printHelp(argv[0]);
        return 1;
    }
    if (opt.cmd == "help")    { printHelp(argv[0]); return 0; }
    if (opt.cmd == "version") { std::cout << "security_toolkit " << VERSION << "\n"; return 0; }

    Logger::init();
    PackageManager pm;

    // ---- read-only informational commands (no root, no banner) --------
    if (opt.cmd == "tools") { printCatalog(pm); return 0; }
    if (opt.cmd == "status") { printStatusTable(); return 0; }
    if (opt.cmd == "info") {
        if (opt.args.empty()) { std::cerr << "Usage: --info <tool>\n"; return 1; }
        int rc = 0;
        for (const auto& id : opt.args) {
            if (const Tool* t = findTool(id)) printToolInfo(*t, pm);
            else { std::cerr << "Unknown tool: " << id << "\n"; rc = 1; }
        }
        return rc;
    }

    if (opt.cmd == "disks") { printDisks(listBlockDevices()); return 0; }

    printBanner();
    Logger::info("Security Toolkit started (log: " + Logger::logPath() + ").");

    // ---- argument mode ----------------------------------------------
    if (!opt.cmd.empty()) {
        if      (opt.cmd == "install")    moduleInstall(pm, opt.args);
        else if (opt.cmd == "scan")       moduleScan(opt.path, opt.extra);
        else if (opt.cmd == "firewall")   moduleFirewall();
        else if (opt.cmd == "all")        moduleAll(pm, opt.path, opt.extra);
        else if (opt.cmd == "exclusions") exclusionsMenu();
        else if (opt.cmd == "run")        runToolsOnly(opt.args, opt.path, opt.extra);
        else if (opt.cmd == "scandisks")  scanDevices(opt.args, opt.clam);
        else if (opt.cmd == "manage") {
            const Tool* t = opt.args.empty() ? nullptr : findTool(opt.args[0]);
            if (!t) { Logger::error("Usage: --manage <tool>. See --tools for ids."); return 1; }
            toolMenu(*t, pm);
        }
        Logger::info("Security Toolkit finished.");
        return 0;
    }

    // ---- interactive mode -------------------------------------------
    if (!isRoot()) Logger::warn("Not running as root: scanning works, installing/managing tools needs sudo.");

    while (true) {
        printMenu();
        std::string choice;
        if (!readLine(choice)) { std::cout << "\n"; break; }

        if      (choice == "0") { Logger::info("Exiting."); break; }
        else if (choice == "1") { if (requireRoot("Installing tools")) installerMenu(pm); else { printCatalog(pm); } }
        else if (choice == "2") manageMenu(pm);
        else if (choice == "3") moduleScan(promptPath(), Exclusions());
        else if (choice == "4") exclusionsMenu();
        else if (choice == "5") moduleFirewall();
        else if (choice == "6") { if (requireRoot("Quick setup")) moduleAll(pm, promptPath(), Exclusions()); }
        else if (choice == "7") std::cout << "Log file: " << Logger::logPath() << "\n";
        else if (choice == "8") runToolsMenu();
        else if (choice == "9") diskMenu();
        else std::cout << Color::p(Color::YELLOW) << "Invalid option. Please enter 0-9.\n" << Color::p(Color::RESET);
    }

    Logger::info("Security Toolkit finished.");
    return 0;
}
