#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <sys/ioctl.h>
#include <sys/mount.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <unistd.h>

#include <arpa/inet.h>
#include <atomic>
#include <cerrno>
#include <cstdint>
#include <cstring>
#include <fcntl.h>
#include <grp.h>
#include <poll.h>
#include <string>
#include <vector>

#include <base.hpp>
#include <consts.hpp>
#include <sqlite.hpp>

namespace {

// Keep numeric values aligned with `native/src/core/lib.rs` cxx::bridge enum order.
enum class RequestCode : int32_t {
    START_DAEMON = 0,
    CHECK_VERSION = 1,
    CHECK_VERSION_CODE = 2,
    STOP_DAEMON = 3,

    _SYNC_BARRIER_ = 4,

    SUPERUSER = 5,
    ZYGOTE_RESTART = 6,
    DENYLIST = 7,
    SQLITE_CMD = 8,
    REMOVE_MODULES = 9,
    ZYGISK = 10,

    _STAGE_BARRIER_ = 11,

    POST_FS_DATA = 12,
    LATE_START = 13,
    BOOT_COMPLETE = 14,

    END = 15,
};

enum class RespondCode : int32_t {
    ERROR = -1,
    OK = 0,
    ROOT_REQUIRED = 1,
    ACCESS_DENIED = 2,
    END = 3,
};

enum class SuPolicy : int32_t {
    Query = 0,
    Deny = 1,
    Allow = 2,
    Restrict = 3,
};

enum class RootAccess : int32_t {
    Disabled = 0,
    AppsOnly = 1,
    AdbOnly = 2,
    AppsAndAdb = 3,
};

enum class MultiuserMode : int32_t {
    OwnerOnly = 0,
    OwnerManaged = 1,
    User = 2,
};

enum class MntNsMode : int32_t {
    Global = 0,
    Requester = 1,
    Isolate = 2,
};

namespace DenyRequest {
enum : int32_t {
    ENFORCE = 0,
    DISABLE = 1,
    ADD = 2,
    REMOVE = 3,
    LIST = 4,
    STATUS = 5,
    END = 6,
};
}

namespace DenyResponse {
enum : int32_t {
    OK = 0,
    ENFORCED = 1,
    NOT_ENFORCED = 2,
    ITEM_EXIST = 3,
    ITEM_NOT_EXIST = 4,
    INVALID_PKG = 5,
    NO_NS = 6,
    ERROR = 7,
    END = 8,
};
}

namespace ZygiskRequest {
enum : int32_t {
    GetInfo = 0,
    ConnectCompanion = 1,
    GetModDir = 2,
};
}

namespace ZygiskStateFlags {
static constexpr uint32_t ProcessGrantedRoot = 0x00000001;
static constexpr uint32_t ProcessOnDenyList = 0x00000002;
static constexpr uint32_t DenyListEnforced = 0x40000000;
static constexpr uint32_t ProcessIsMagiskApp = 0x80000000;
}

static constexpr int32_t AID_ROOT = 0;
static constexpr int32_t AID_SHELL = 2000;
static constexpr int32_t AID_USER_OFFSET = 100000;

static inline int32_t to_app_id(int32_t uid) { return uid % AID_USER_OFFSET; }
static inline int32_t to_user_id(int32_t uid) { return uid / AID_USER_OFFSET; }

static std::atomic<bool> denylist_enforced{false};

struct ExeAttr {
    dev_t dev{};
    ino_t ino{};
    bool valid = false;
};

static ExeAttr g_self_exe{};

static bool is_valid_request(int32_t code) {
    if (code < 0 || code >= static_cast<int32_t>(RequestCode::END)) return false;
    if (code == static_cast<int32_t>(RequestCode::_SYNC_BARRIER_)) return false;
    if (code == static_cast<int32_t>(RequestCode::_STAGE_BARRIER_)) return false;
    return true;
}

static bool is_client_process(pid_t pid) {
    // Best-effort parity with Rust `check-client` feature:
    // compare /proc/<pid>/exe dev+ino to current process exe dev+ino.
    if (!g_self_exe.valid) return true; // allow in bring-up if unknown
    if (pid <= 0) return false;

    char path[64];
    ssprintf(path, sizeof(path), "/proc/%d/exe", pid);
    struct stat st{};
    if (stat(path, &st) != 0) return false;
    return st.st_dev == g_self_exe.dev && st.st_ino == g_self_exe.ino;
}

static const char *detect_magisk_tmp() {
    if (access("/debug_ramdisk/" INTLROOT, F_OK) == 0) return "/debug_ramdisk";
    if (access("/sbin/" INTLROOT, F_OK) == 0) return "/sbin";
    return "";
}

static std::string sock_path() {
    // Keep identical to Rust daemon path:
    //   join_path(get_magisk_tmp()).join_path(MAIN_SOCKET)
    return std::string(detect_magisk_tmp()) + MAIN_SOCKET;
}

static std::string sock_dir() {
    // MAIN_SOCKET = DEVICEDIR "/socket"
    // DEVICEDIR   = INTLROOT "/device"
    // INTLROOT    = ".magisk"
    return std::string(detect_magisk_tmp()) + DEVICEDIR;
}

static bool write_pod_i32(int fd, int32_t v) {
    return xwrite(fd, &v, sizeof(v)) == sizeof(v);
}

static bool read_pod_i32(int fd, int32_t &out) {
    return xxread(fd, &out, sizeof(out)) == sizeof(out);
}

static bool write_string(int fd, const std::string &s) {
    // Match Rust Encodable for str/String:
    //   (len as i32) then bytes
    auto len = static_cast<int32_t>(s.size());
    if (!write_pod_i32(fd, len)) return false;
    return xwrite(fd, s.data(), s.size()) == static_cast<ssize_t>(s.size());
}

static bool read_u8(int fd, uint8_t &out) {
    return xxread(fd, &out, sizeof(out)) == sizeof(out);
}

static bool read_u32(int fd, uint32_t &out) {
    return xxread(fd, &out, sizeof(out)) == sizeof(out);
}

static bool read_string(int fd, std::string &out) {
    int32_t len = 0;
    if (!read_pod_i32(fd, len)) return false;
    if (len < 0) return false;
    out.assign(static_cast<size_t>(len), '\0');
    if (len == 0) return true;
    return xxread(fd, out.data(), static_cast<size_t>(len)) == len;
}

static std::string read_string(int fd) {
    std::string out;
    (void)read_string(fd, out);
    return out;
}

static bool write_pod_u32(int fd, uint32_t v) {
    return xwrite(fd, &v, sizeof(v)) == sizeof(v);
}

static std::string get_peer_context(int fd) {
#ifdef SO_PEERSEC
    char buf[256] = {};
    socklen_t len = sizeof(buf);
    if (getsockopt(fd, SOL_SOCKET, SO_PEERSEC, buf, &len) == 0) {
        // `len` may include trailing NUL, clamp safely.
        size_t n = strnlen(buf, sizeof(buf));
        return std::string(buf, n);
    }
#endif
    (void)fd;
    return {};
}

static bool set_db_setting_i32(const char *key, int32_t value) {
    return db_exec(
        "INSERT OR REPLACE INTO settings (key,value) VALUES(?,?)",
        DbArgs{key, static_cast<int64_t>(value)}
    );
}

static void init_denylist_state_from_db() {
    // settings key matches DbEntryKey::DenylistConfig -> "denylist"
    const int32_t v = db_get_setting_i32("denylist", 0);
    denylist_enforced.store(v != 0, std::memory_order_relaxed);
}

static bool denylist_row_exists(const std::string &pkg, const std::string &proc) {
    bool exists = false;
    auto cb = [&](StringSlice, const DbValues &) {
        exists = true;
    };
    (void)db_exec(
        "SELECT 1 FROM denylist WHERE package_name=? AND process=? LIMIT 1",
        DbArgs{pkg.c_str(), proc.c_str()},
        cb
    );
    return exists;
}

static int32_t denylist_enable() {
    if (denylist_enforced.load(std::memory_order_relaxed)) {
        (void)set_db_setting_i32("denylist", 1);
        return DenyResponse::OK;
    }
    if (access("/proc/self/ns/mnt", F_OK) != 0) {
        return DenyResponse::NO_NS;
    }
    denylist_enforced.store(true, std::memory_order_relaxed);
    (void)set_db_setting_i32("denylist", 1);
    return DenyResponse::OK;
}

static int32_t denylist_disable() {
    denylist_enforced.store(false, std::memory_order_relaxed);
    (void)set_db_setting_i32("denylist", 0);
    return DenyResponse::OK;
}

static void handle_denylist_cmd(int fd) {
    int32_t req = -1;
    if (!read_pod_i32(fd, req)) return;
    int32_t res = DenyResponse::ERROR;

    switch (req) {
        case DenyRequest::ENFORCE:
            res = denylist_enable();
            write_pod_i32(fd, res);
            break;
        case DenyRequest::DISABLE:
            res = denylist_disable();
            write_pod_i32(fd, res);
            break;
        case DenyRequest::STATUS:
            res = denylist_enforced.load(std::memory_order_relaxed) ? DenyResponse::ENFORCED
                                                                    : DenyResponse::NOT_ENFORCED;
            write_pod_i32(fd, res);
            break;
        case DenyRequest::ADD: {
            std::string pkg = read_string(fd);
            std::string proc = read_string(fd);
            if (proc.empty()) proc = pkg;
            if (pkg.empty() || proc.empty()) {
                write_pod_i32(fd, DenyResponse::INVALID_PKG);
                break;
            }
            if (denylist_row_exists(pkg, proc)) {
                write_pod_i32(fd, DenyResponse::ITEM_EXIST);
                break;
            }
            bool ok = db_exec(
                "INSERT OR IGNORE INTO denylist (package_name, process) VALUES (?,?)",
                DbArgs{pkg.c_str(), proc.c_str()}
            );
            write_pod_i32(fd, ok ? DenyResponse::OK : DenyResponse::ERROR);
            break;
        }
        case DenyRequest::REMOVE: {
            std::string pkg = read_string(fd);
            std::string proc = read_string(fd);
            if (pkg.empty()) {
                write_pod_i32(fd, DenyResponse::INVALID_PKG);
                break;
            }
            if (proc.empty()) {
                bool any = false;
                auto cb = [&](StringSlice, const DbValues &) { any = true; };
                (void)db_exec(
                    "SELECT 1 FROM denylist WHERE package_name=? LIMIT 1",
                    DbArgs{pkg.c_str()},
                    cb
                );
                if (!any) {
                    write_pod_i32(fd, DenyResponse::ITEM_NOT_EXIST);
                    break;
                }
                bool ok = db_exec("DELETE FROM denylist WHERE package_name=?", DbArgs{pkg.c_str()});
                write_pod_i32(fd, ok ? DenyResponse::OK : DenyResponse::ERROR);
            } else {
                if (!denylist_row_exists(pkg, proc)) {
                    write_pod_i32(fd, DenyResponse::ITEM_NOT_EXIST);
                    break;
                }
                bool ok = db_exec(
                    "DELETE FROM denylist WHERE package_name=? AND process=?",
                    DbArgs{pkg.c_str(), proc.c_str()}
                );
                write_pod_i32(fd, ok ? DenyResponse::OK : DenyResponse::ERROR);
            }
            break;
        }
        case DenyRequest::LIST: {
            // Follow deny/utils.cpp framing: first a response int, then repeated (len+iobuf), ending with len=0.
            write_pod_i32(fd, DenyResponse::OK);
            auto cb = [&](StringSlice columns, const DbValues &values) {
                const char *pkg = "";
                const char *proc = "";
                for (int i = 0; i < columns.size(); ++i) {
                    if (columns[i] == "package_name") pkg = values.get_text(i);
                    else if (columns[i] == "process") proc = values.get_text(i);
                }
                std::string out = std::string(pkg) + "|" + std::string(proc);
                (void)write_string(fd, out);
            };
            (void)db_exec("SELECT package_name, process FROM denylist", {}, cb);
            (void)write_string(fd, "");
            break;
        }
        default:
            // Unknown request code
            write_pod_i32(fd, DenyResponse::ERROR);
            break;
    }
}

static void handle_sqlite_cmd(int fd) {
    auto sql = read_string(fd);
    if (sql.empty()) {
        (void)write_string(fd, "");
        return;
    }

    auto cb = [&](StringSlice columns, const DbValues &values) {
        std::string out;
        for (int i = 0; i < columns.size(); ++i) {
            if (i != 0) out.push_back('|');
            out += columns[i].c_str();
            out.push_back('=');
            out += values.get_text(i);
        }
        (void)write_string(fd, out);
    };

    (void)db_exec(sql.c_str(), {}, cb);
    (void)write_string(fd, "");
}

static int recv_fd_once(int sock) {
    int32_t fd_count = 0;

    alignas(cmsghdr) char control[CMSG_SPACE(sizeof(int))] = {};
    iovec iov{};
    iov.iov_base = &fd_count;
    iov.iov_len = sizeof(fd_count);

    msghdr msg{};
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    msg.msg_control = control;
    msg.msg_controllen = sizeof(control);

    auto n = recvmsg(sock, &msg, 0);
    if (n != static_cast<ssize_t>(sizeof(fd_count))) return -1;

    if (fd_count < 1) return -1;

    for (cmsghdr *cmsg = CMSG_FIRSTHDR(&msg); cmsg; cmsg = CMSG_NXTHDR(&msg, cmsg)) {
        if (cmsg->cmsg_level == SOL_SOCKET && cmsg->cmsg_type == SCM_RIGHTS) {
            int fd = -1;
            std::memcpy(&fd, CMSG_DATA(cmsg), sizeof(fd));
            return fd;
        }
    }
    return -1;
}

static bool send_fd_once(int sock, int fd) {
    int32_t fd_count = (fd >= 0) ? 1 : 0;

    iovec iov{};
    iov.iov_base = &fd_count;
    iov.iov_len = sizeof(fd_count);

    msghdr msg{};
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;

    alignas(cmsghdr) char control[CMSG_SPACE(sizeof(int))] = {};
    if (fd >= 0) {
        msg.msg_control = control;
        msg.msg_controllen = sizeof(control);
        cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
        cmsg->cmsg_level = SOL_SOCKET;
        cmsg->cmsg_type = SCM_RIGHTS;
        cmsg->cmsg_len = CMSG_LEN(sizeof(int));
        std::memcpy(CMSG_DATA(cmsg), &fd, sizeof(fd));
    }

    return sendmsg(sock, &msg, 0) == static_cast<ssize_t>(sizeof(fd_count));
}

static int get_pty_num(int fd) {
    int pty = -1;
#ifdef TIOCGPTN
    if (ioctl(fd, TIOCGPTN, &pty) == 0) return pty;
#endif
    return -1;
}

struct SuRequestCpp {
    int32_t target_uid = AID_ROOT;
    int32_t target_pid = -1;
    bool login = false;
    bool keep_env = false;
    bool drop_cap = false;
    std::string shell = "/system/bin/sh";
    std::string command;
    std::string context;
    std::vector<uint32_t> gids;
};

static bool read_su_request(int fd, SuRequestCpp &req) {
    if (!read_pod_i32(fd, req.target_uid)) return false;
    if (!read_pod_i32(fd, req.target_pid)) return false;

    uint8_t b = 0;
    if (!read_u8(fd, b)) return false;
    req.login = (b != 0);
    if (!read_u8(fd, b)) return false;
    req.keep_env = (b != 0);
    if (!read_u8(fd, b)) return false;
    req.drop_cap = (b != 0);

    if (!read_string(fd, req.shell)) return false;
    if (!read_string(fd, req.command)) return false;
    if (!read_string(fd, req.context)) return false;

    int32_t gids_len = 0;
    if (!read_pod_i32(fd, gids_len)) return false;
    if (gids_len < 0) return false;
    req.gids.clear();
    req.gids.reserve(static_cast<size_t>(gids_len));
    for (int32_t i = 0; i < gids_len; ++i) {
        uint32_t gid = 0;
        if (!read_u32(fd, gid)) return false;
        req.gids.push_back(gid);
    }
    return true;
}

static int32_t db_get_setting_i32(const char *key, int32_t def) {
    int32_t out = def;
    bool got = false;
    auto cb = [&](StringSlice, const DbValues &v) {
        out = v.get_int(0);
        got = true;
    };
    (void)db_exec("SELECT value FROM settings WHERE key=?", DbArgs{key}, cb);
    (void)got;
    return out;
}

struct RootSettingsCpp {
    SuPolicy policy = SuPolicy::Query;
    bool log = false;
    bool notify = false;
};

static RootSettingsCpp db_get_root_settings_for_uid(int32_t uid) {
    RootSettingsCpp out{};
    auto cb = [&](StringSlice columns, const DbValues &v) {
        for (int i = 0; i < columns.size(); ++i) {
            const auto &col = columns[i];
            const int val = v.get_int(i);
            if (col == "policy") out.policy = static_cast<SuPolicy>(val);
            else if (col == "logging") out.log = (val != 0);
            else if (col == "notification") out.notify = (val != 0);
        }
    };
    (void)db_exec(
        "SELECT policy, logging, notification FROM policies "
        "WHERE uid=? AND (until=0 OR until>strftime('%s', 'now'))",
        DbArgs{static_cast<int64_t>(uid)},
        cb
    );
    return out;
}

static std::string db_get_string_value(const char *key) {
    std::string out;
    auto cb = [&](StringSlice, const DbValues &v) {
        const char *s = v.get_text(0);
        if (s) out.assign(s);
    };
    (void)db_exec("SELECT value FROM strings WHERE key=?", DbArgs{key}, cb);
    return out;
}

static int32_t get_package_uid_guess(int32_t user, const std::string &pkg) {
    struct stat st{};
    // Try both /data/user_de and /data/user
    {
        std::string p = std::string("/data/user_de/") + std::to_string(user) + "/" + pkg;
        if (stat(p.c_str(), &st) == 0) return static_cast<int32_t>(st.st_uid);
    }
    {
        std::string p = std::string("/data/user/") + std::to_string(user) + "/" + pkg;
        if (stat(p.c_str(), &st) == 0) return static_cast<int32_t>(st.st_uid);
    }
    return -1;
}

static std::pair<int32_t, std::string> get_manager_for_user(int32_t user, bool /*install*/) {
    // Bring-up: only use DB string + package uid heuristic (no signature checks / stub install).
    std::string pkg = db_get_string_value("requester");
    if (pkg.empty()) {
        pkg = JAVA_PACKAGE_NAME;
    }
    int32_t uid = get_package_uid_guess(user, pkg);
    if (uid < 0) return {-1, ""};
    return {uid, pkg};
}

static SuPolicy query_su_manager(
    int32_t mgr_uid,
    const std::string &mgr_pkg,
    int32_t user,
    int32_t eval_uid,
    int32_t pid
) {
    // Best-effort implementation matching Rust FIFO handshake shape.
    // If anything fails, deny for safety.
    if (mgr_uid < 0 || mgr_pkg.empty()) return SuPolicy::Deny;

    // Ensure tmp/.magisk exists
    std::string intl = std::string(detect_magisk_tmp()) + "/" INTLROOT;
    mkdirs(intl.c_str(), 0755);

    std::string fifo = intl + "/su_request_" + std::to_string(pid);
    unlink(fifo.c_str());
    if (mkfifo(fifo.c_str(), 0600) != 0) {
        return SuPolicy::Deny;
    }
    // Chown to manager so it can open it
    (void)chown(fifo.c_str(), mgr_uid, mgr_uid);

    // Trigger manager UI: equivalent to SuAppContext::app_request() -> am start
    std::string user_s = std::to_string(user);
    std::string uid_s = std::to_string(eval_uid);
    std::string pid_s = std::to_string(pid);

    // We don't parse output; just fire once (bring-up).
    // Must set CLASSPATH for app_process main class.
    std::vector<const char *> argv = {
        "/system/bin/app_process",
        "/system/bin",
        "com.android.commands.am.Am",
        "start",
        "-p",
        mgr_pkg.c_str(),
        "--user",
        user_s.c_str(),
        "-a",
        "android.intent.action.VIEW",
        "-f",
        // FLAG_ACTIVITY_NEW_TASK|FLAG_ACTIVITY_MULTIPLE_TASK|
        // FLAG_ACTIVITY_EXCLUDE_FROM_RECENTS|FLAG_INCLUDE_STOPPED_PACKAGES
        "0x18800020",
        "--es",
        "action",
        "request",
        "--es",
        "fifo",
        fifo.c_str(),
        "--ei",
        "uid",
        uid_s.c_str(),
        "--ei",
        "pid",
        pid_s.c_str(),
        nullptr,
    };
    exec_t exec{};
    exec.argv = argv.data();
    exec.pre_exec = []() { setenv("CLASSPATH", "/system/framework/am.jar", 1); };
    (void)exec_command_sync(exec);

    // Open with O_RDWR to prevent FIFO open block
    int fd = xopen(fifo.c_str(), O_RDWR | O_CLOEXEC);
    if (fd < 0) {
        unlink(fifo.c_str());
        return SuPolicy::Deny;
    }

    pollfd pfd{};
    pfd.fd = fd;
    pfd.events = POLLIN;
    int prc = poll(&pfd, 1, 70 * 1000);
    if (prc <= 0) {
        close(fd);
        unlink(fifo.c_str());
        return SuPolicy::Deny;
    }

    int32_t be = 0;
    if (xxread(fd, &be, sizeof(be)) != sizeof(be)) {
        close(fd);
        unlink(fifo.c_str());
        return SuPolicy::Deny;
    }

    close(fd);
    unlink(fifo.c_str());

    uint32_t u = static_cast<uint32_t>(be);
    int32_t pol = static_cast<int32_t>(ntohl(u));
    if (pol < static_cast<int32_t>(SuPolicy::Query) || pol > static_cast<int32_t>(SuPolicy::Restrict)) {
        return SuPolicy::Deny;
    }
    return static_cast<SuPolicy>(pol);
}

static std::string escape_extra_string(std::string_view s) {
    std::string out;
    out.reserve(s.size() + 8);
    for (char c : s) {
        if (c == '\\' || c == ':') out.push_back('\\');
        out.push_back(c);
    }
    return out;
}

static void su_log_notify_async(
    const RootSettingsCpp &settings,
    const std::string &mgr_pkg,
    int32_t user,
    int32_t from_uid,
    int32_t pid,
    const SuRequestCpp &req
) {
    if (!settings.log && !settings.notify) return;
    if (mgr_pkg.empty()) return;
    if (fork_dont_care() != 0) return;

    // In child
    std::string provider = "content://" + mgr_pkg + ".provider";
    std::string user_s = std::to_string(user);
    std::string from_uid_s = std::to_string(from_uid);
    std::string to_uid_s = std::to_string(req.target_uid);
    std::string pid_s = std::to_string(pid);
    std::string policy_s = std::to_string(static_cast<int32_t>(settings.policy));
    std::string target_s = std::to_string(req.target_pid);
    std::string notify_s = settings.notify ? "true" : "false";

    std::string gids_csv;
    if (!req.gids.empty()) {
        for (auto g : req.gids) {
            gids_csv += std::to_string(g);
            gids_csv.push_back(',');
        }
        gids_csv.pop_back();
    }

    const std::string command = req.command.empty() ? req.shell : req.command;

    auto mk_extra_i = [](const char *key, const std::string &v) {
        return std::string(key) + ":i:" + v;
    };
    auto mk_extra_b = [](const char *key, const std::string &v) {
        return std::string(key) + ":b:" + v;
    };
    auto mk_extra_s = [](const char *key, std::string_view v) {
        return std::string(key) + ":s:" + escape_extra_string(v);
    };

    std::vector<std::string> extras;
    const char *method = nullptr;

    if (settings.log) {
        method = "log";
        extras.emplace_back(mk_extra_i("from.uid", from_uid_s));
        extras.emplace_back(mk_extra_i("to.uid", to_uid_s));
        extras.emplace_back(mk_extra_i("pid", pid_s));
        extras.emplace_back(mk_extra_i("policy", policy_s));
        extras.emplace_back(mk_extra_i("target", target_s));
        extras.emplace_back(mk_extra_s("context", req.context));
        extras.emplace_back(mk_extra_s("gids", gids_csv));
        extras.emplace_back(mk_extra_s("command", command));
        extras.emplace_back(mk_extra_b("notify", notify_s));
    } else {
        method = "notify";
        extras.emplace_back(mk_extra_i("from.uid", from_uid_s));
        extras.emplace_back(mk_extra_i("pid", pid_s));
        extras.emplace_back(mk_extra_i("policy", policy_s));
    }

    // Build argv for: app_process ... Content call --uri ... --user ... --method ... --extra <k:t:v>...
    std::vector<const char *> argv;
    argv.reserve(16 + extras.size() * 2);
    argv.push_back("/system/bin/app_process");
    argv.push_back("/system/bin");
    argv.push_back("com.android.commands.content.Content");
    argv.push_back("call");
    argv.push_back("--uri");
    argv.push_back(provider.c_str());
    argv.push_back("--user");
    argv.push_back(user_s.c_str());
    argv.push_back("--method");
    argv.push_back(method);

    for (auto &e : extras) {
        argv.push_back("--extra");
        argv.push_back(e.c_str());
    }
    argv.push_back(nullptr);

    exec_t exec{};
    exec.argv = argv.data();
    exec.pre_exec = []() { setenv("CLASSPATH", "/system/framework/content.jar", 1); };
    (void)exec_command_sync(exec);
    exit(0);
}

static bool su_allowed_by_settings(int32_t uid, int32_t eval_uid) {
    auto root_access = static_cast<RootAccess>(db_get_setting_i32("root_access",
        static_cast<int32_t>(RootAccess::AppsAndAdb)));

    switch (root_access) {
        case RootAccess::Disabled:
            return false;
        case RootAccess::AppsOnly:
            return uid != AID_SHELL;
        case RootAccess::AdbOnly:
            return uid == AID_SHELL;
        case RootAccess::AppsAndAdb:
        default:
            (void)eval_uid;
            return true;
    }
}

static bool eval_su_access(
    int32_t uid,
    const SuRequestCpp &req,
    RootSettingsCpp &settings_out,
    MntNsMode &mntns_out,
    int32_t pid
) {
    if (uid == AID_ROOT) {
        settings_out.policy = SuPolicy::Allow;
        mntns_out = MntNsMode::Requester;
        return true;
    }

    auto multiuser = static_cast<MultiuserMode>(db_get_setting_i32("multiuser_mode",
        static_cast<int32_t>(MultiuserMode::OwnerOnly)));
    auto mntns = static_cast<MntNsMode>(db_get_setting_i32("mnt_ns",
        static_cast<int32_t>(MntNsMode::Requester)));

    int32_t eval_uid = uid;
    switch (multiuser) {
        case MultiuserMode::OwnerOnly:
            if (to_user_id(uid) != 0) return false;
            eval_uid = uid;
            break;
        case MultiuserMode::OwnerManaged:
            eval_uid = to_app_id(uid);
            break;
        case MultiuserMode::User:
        default:
            eval_uid = uid;
            break;
    }

    if (!su_allowed_by_settings(uid, eval_uid)) return false;

    auto settings = db_get_root_settings_for_uid(eval_uid);

    // If it's the manager itself, allow silently (match Rust behavior).
    auto [mgr_uid, mgr_pkg] = get_manager_for_user(to_user_id(eval_uid), true);
    if (mgr_uid >= 0 && to_app_id(uid) == to_app_id(mgr_uid)) {
        settings.policy = SuPolicy::Allow;
        settings.log = false;
        settings.notify = false;
    }

    // If policy is Query, ask manager (best-effort bring-up).
    if (settings.policy == SuPolicy::Query) {
        if (mgr_uid < 0) {
            settings.policy = SuPolicy::Deny;
        } else {
            settings.policy = query_su_manager(mgr_uid, mgr_pkg, to_user_id(eval_uid), eval_uid, pid);
        }
    }

    // Notify/log to manager asynchronously (best-effort).
    // In Rust, this happens after Query resolution but before returning to caller.
    su_log_notify_async(settings, mgr_pkg, to_user_id(eval_uid), uid, pid, req);

    settings_out = settings;
    mntns_out = mntns;
    return settings.policy == SuPolicy::Allow || settings.policy == SuPolicy::Restrict;
}

static bool uid_granted_root(int32_t uid) {
    if (uid == AID_ROOT) return true;

    // Root access gate
    auto root_access = static_cast<RootAccess>(db_get_setting_i32("root_access",
        static_cast<int32_t>(RootAccess::AppsAndAdb)));
    switch (root_access) {
        case RootAccess::Disabled:
            return false;
        case RootAccess::AppsOnly:
            if (uid == AID_SHELL) return false;
            break;
        case RootAccess::AdbOnly:
            if (uid != AID_SHELL) return false;
            break;
        case RootAccess::AppsAndAdb:
        default:
            break;
    }

    // Multiuser evaluation
    auto multiuser = static_cast<MultiuserMode>(db_get_setting_i32("multiuser_mode",
        static_cast<int32_t>(MultiuserMode::OwnerOnly)));
    int32_t eval_uid = uid;
    switch (multiuser) {
        case MultiuserMode::OwnerOnly:
            if (to_user_id(uid) != 0) return false;
            eval_uid = uid;
            break;
        case MultiuserMode::OwnerManaged:
            eval_uid = to_app_id(uid);
            break;
        case MultiuserMode::User:
        default:
            eval_uid = uid;
            break;
    }

    auto pol = db_get_su_policy_for_uid(eval_uid);
    return pol == SuPolicy::Allow || pol == SuPolicy::Restrict;
}

static void handle_zygisk_cmd(int fd) {
    int32_t req = -1;
    if (!read_pod_i32(fd, req)) return;

    if (req != ZygiskRequest::GetInfo) {
        // Bring-up: only support GetInfo now.
        return;
    }

    int32_t uid = -1;
    if (!read_pod_i32(fd, uid)) return;
    std::string process = read_string(fd);
    uint8_t is64 = 0;
    if (!read_u8(fd, is64)) return;

    uint32_t flags = 0;
    if (uid_granted_root(uid)) {
        flags |= ZygiskStateFlags::ProcessGrantedRoot;
    }
    if (denylist_enforced.load(std::memory_order_relaxed)) {
        flags |= ZygiskStateFlags::DenyListEnforced;
    }
    // TODO: ProcessOnDenyList and ProcessIsMagiskApp parity.

    (void)is64;
    (void)process;

    write_pod_u32(fd, flags);
}

static void set_identity(int uid, const std::vector<uint32_t> &groups) {
    gid_t gid = static_cast<gid_t>(uid);
    if (!groups.empty()) {
        std::vector<gid_t> gs;
        gs.reserve(groups.size());
        for (auto g : groups) gs.push_back(static_cast<gid_t>(g));
        (void)setgroups(gs.size(), gs.data());
        gid = gs[0];
    }
    (void)setresgid(gid, gid, gid);
    (void)setresuid(uid, uid, uid);
}

static void run_root_shell(int client, int pid, const SuRequestCpp &req, MntNsMode mode) {
    // Receive stdio fds
    int infd = recv_fd_once(client);
    int outfd = recv_fd_once(client);
    int errfd = recv_fd_once(client);

    int ptsfd = -1;
    if (infd < 0 || outfd < 0 || errfd < 0) {
        // Allocate PTY
        int ptmx = xopen("/dev/ptmx", O_RDWR | O_CLOEXEC);
        grantpt(ptmx);
        unlockpt(ptmx);
        int pty_num = get_pty_num(ptmx);
        send_fd_once(client, ptmx);
        close(ptmx);

        std::string pts_slave = std::string("/dev/pts/") + std::to_string(pty_num);
        ptsfd = xopen(pts_slave.c_str(), O_RDWR);
    }

    xdup2(infd < 0 ? ptsfd : infd, STDIN_FILENO);
    xdup2(outfd < 0 ? ptsfd : outfd, STDOUT_FILENO);
    xdup2(errfd < 0 ? ptsfd : errfd, STDERR_FILENO);

    close(infd);
    close(outfd);
    close(errfd);
    close(ptsfd);
    close(client);

    // Mount namespace handling (subset)
    int target_pid = (req.target_pid == -1) ? pid : req.target_pid;
    if (req.target_pid == 0) mode = MntNsMode::Global;
    if (mode == MntNsMode::Requester) {
        switch_mnt_ns(target_pid);
    } else if (mode == MntNsMode::Isolate) {
        switch_mnt_ns(target_pid);
        xunshare(CLONE_NEWNS);
        xmount(nullptr, "/", nullptr, MS_PRIVATE | MS_REC, nullptr);
    }

    // Identity + exec
    if (req.target_uid != AID_ROOT || !req.gids.empty()) {
        set_identity(req.target_uid, req.gids);
    }

    std::vector<const char *> argv;
    argv.push_back(req.login ? "-" : req.shell.c_str());
    if (!req.command.empty()) {
        argv.push_back("-c");
        argv.push_back(req.command.c_str());
    }
    argv.push_back(nullptr);

    execvp(req.shell.c_str(), const_cast<char **>(argv.data()));
    _exit(127);
}

static void handle_client(int cfd) {
    ucred cred{};
    socklen_t cred_len = sizeof(cred);
    bool has_cred =
        getsockopt(cfd, SOL_SOCKET, SO_PEERCRED, &cred, &cred_len) == 0 && cred_len == sizeof(cred);

    const auto context = get_peer_context(cfd);
    const bool is_root = has_cred && cred.uid == 0;
    const bool is_shell = has_cred && cred.uid == AID_SHELL;
    const bool is_zygote = (context == "u:r:zygote:s0");

    const bool is_client = has_cred && is_client_process(cred.pid);

    if (!is_root && !is_zygote && !is_client) {
        write_pod_i32(cfd, static_cast<int32_t>(RespondCode::ACCESS_DENIED));
        return;
    }

    int32_t code = -1;
    if (!read_pod_i32(cfd, code)) return;
    if (!is_valid_request(code)) return;

    // Permission checks (match daemon.rs).
    switch (static_cast<RequestCode>(code)) {
        case RequestCode::POST_FS_DATA:
        case RequestCode::LATE_START:
        case RequestCode::BOOT_COMPLETE:
        case RequestCode::ZYGOTE_RESTART:
        case RequestCode::SQLITE_CMD:
        case RequestCode::DENYLIST:
        case RequestCode::STOP_DAEMON:
            if (!is_root) {
                write_pod_i32(cfd, static_cast<int32_t>(RespondCode::ROOT_REQUIRED));
                return;
            }
            break;
        case RequestCode::REMOVE_MODULES:
            if (!is_root && !is_shell) {
                write_pod_i32(cfd, static_cast<int32_t>(RespondCode::ACCESS_DENIED));
                return;
            }
            break;
        case RequestCode::ZYGISK:
            if (!is_zygote) {
                write_pod_i32(cfd, static_cast<int32_t>(RespondCode::ACCESS_DENIED));
                return;
            }
            break;
        default:
            break;
    }

    if (!write_pod_i32(cfd, static_cast<int32_t>(RespondCode::OK))) return;

    switch (static_cast<RequestCode>(code)) {
        case RequestCode::CHECK_VERSION: {
            // Keep compatible shape, but not necessarily identical content yet.
#ifdef MAGISK_VERSION
            // Match Rust daemon string format:
            //   debug:   "<ver>:MAGISK:D"
            //   release: "<ver>:MAGISK:R"
#ifdef MAGISK_DEBUG
            std::string s = std::string(MAGISK_VERSION) + (MAGISK_DEBUG ? ":MAGISK:D" : ":MAGISK:R");
#else
            std::string s = std::string(MAGISK_VERSION) + ":MAGISK:CPP";
#endif
#else
            std::string s = "unknown:MAGISK:CPP";
#endif
            write_string(cfd, s);
            break;
        }
        case RequestCode::CHECK_VERSION_CODE: {
#ifdef MAGISK_VER_CODE
            int32_t v = static_cast<int32_t>(MAGISK_VER_CODE);
#else
            int32_t v = 0;
#endif
            write_pod_i32(cfd, v);
            break;
        }
        case RequestCode::STOP_DAEMON: {
            // Match daemon.rs: write 0 then exit.
            write_pod_i32(cfd, 0);
            _exit(0);
        }
        case RequestCode::SQLITE_CMD: {
            handle_sqlite_cmd(cfd);
            break;
        }
        case RequestCode::DENYLIST: {
            handle_denylist_cmd(cfd);
            break;
        }
        case RequestCode::ZYGISK: {
            handle_zygisk_cmd(cfd);
            break;
        }
        case RequestCode::SUPERUSER: {
            SuRequestCpp req{};
            if (!read_su_request(cfd, req)) {
                // Match client behavior: non-zero ack means denied/failed.
                write_pod_i32(cfd, static_cast<int32_t>(SuPolicy::Deny));
                break;
            }

            RootSettingsCpp settings{};
            MntNsMode mntns = MntNsMode::Requester;
            bool allowed = has_cred && eval_su_access(
                static_cast<int32_t>(cred.uid),
                req,
                settings,
                mntns,
                has_cred ? cred.pid : -1
            );
            if (!allowed) {
                write_pod_i32(cfd, static_cast<int32_t>(SuPolicy::Deny));
                break;
            }

            if (settings.policy == SuPolicy::Restrict) {
                req.drop_cap = true;
            }

            // ack success
            write_pod_i32(cfd, 0);

            int child = fork();
            if (child == 0) {
                run_root_shell(cfd, has_cred ? cred.pid : -1, req, mntns);
                _exit(127);
            }
            int status = 0;
            int code_out = -1;
            if (child > 0 && waitpid(child, &status, 0) > 0) {
                code_out = WEXITSTATUS(status);
            }
            write_pod_i32(cfd, code_out);
            break;
        }
        default:
            break;
    }
}

} // namespace

int main(int argc, char *argv[]) {
    (void)argc;
    (void)argv;

    // Capture self /proc/self/exe dev+ino for client validation
    {
        struct stat st{};
        if (stat("/proc/self/exe", &st) == 0) {
            g_self_exe.dev = st.st_dev;
            g_self_exe.ino = st.st_ino;
            g_self_exe.valid = true;
        }
    }

    // Initialize denylist cached state from DB so status/zygisk flags reflect reality.
    init_denylist_state_from_db();

    // Ensure directory exists: <tmp> + DEVICEDIR (".magisk/device")
    mkdirs(sock_dir().c_str(), 0755);

    auto path = sock_path();
    // Remove stale socket if any
    unlink(path.c_str());

    owned_fd sfd{socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0)};
    if (sfd < 0) {
        PLOGE("socket");
        return 1;
    }

    sockaddr_un addr{};
    addr.sun_family = AF_UNIX;
    if (path.size() >= sizeof(addr.sun_path)) {
        LOGE("socket path too long\n");
        return 1;
    }
    std::strncpy(addr.sun_path, path.c_str(), sizeof(addr.sun_path) - 1);

    if (bind(sfd, reinterpret_cast<sockaddr *>(&addr), sizeof(addr)) < 0) {
        PLOGE("bind %s", path.c_str());
        return 1;
    }

    // Be permissive for bring-up; Magiskd applies SELinux labeling in Rust.
    chmod(path.c_str(), 0666);

    if (listen(sfd, 64) < 0) {
        PLOGE("listen");
        return 1;
    }

    LOGI("magiskd-cpp listening: %s\n", path.c_str());

    for (;;) {
        int cfd = accept4(sfd, nullptr, nullptr, SOCK_CLOEXEC);
        if (cfd < 0) {
            if (errno == EINTR) continue;
            PLOGE("accept");
            return 1;
        }
        handle_client(cfd);
        close(cfd);
    }
}

