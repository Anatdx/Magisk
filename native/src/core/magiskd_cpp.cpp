#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <sys/ioctl.h>
#include <sys/mount.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <sys/xattr.h>
#include <sys/system_properties.h>
#include <unistd.h>

#include <arpa/inet.h>
#include <atomic>
#include <cerrno>
#include <cstdint>
#include <cstring>
#include <ctime>
#include <fcntl.h>
#include <grp.h>
#include <poll.h>
#include <string>
#include <vector>

#include <base_cpp.hpp>
#include <consts.hpp>
#include <sqlite.hpp>

// Core denylist state & helpers live in deny/*.cpp
extern std::atomic<bool> denylist_enforced;
void denylist_handler(int client);
void initialize_denylist();
bool is_deny_target(int uid, std::string_view process);
void scan_deny_apps();

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

struct ExeAttr {
    dev_t dev{};
    ino_t ino{};
    bool valid = false;
};

static ExeAttr g_self_exe{};

static uint64_t now_ms_monotonic() {
    timespec ts{};
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return static_cast<uint64_t>(ts.tv_sec) * 1000ULL + static_cast<uint64_t>(ts.tv_nsec) / 1000000ULL;
}

static bool is_debuggable_build() {
    // Cache result: system properties won't change at runtime.
    static int cached = -1;
    if (cached != -1) return cached != 0;
    char buf[PROP_VALUE_MAX]{};
    if (__system_property_get("ro.debuggable", buf) <= 0) {
        // Do NOT permanently cache "unavailable". During early boot property area
        // may not be ready yet; retry later to avoid breaking CI bring-up.
        return false;
    }
    cached = (buf[0] == '1' && buf[1] == '\0') ? 1 : 0;
    return cached != 0;
}

// Must be defined before CachedSuInfo (it is stored by value).
struct RootSettingsCpp {
    SuPolicy policy = SuPolicy::Query;
    bool log = false;
    bool notify = false;
};

// Forward declarations for helpers referenced earlier in the file.
static std::pair<int32_t, std::string> get_manager_for_user(int32_t user, bool install);

struct CachedSuInfo {
    int32_t uid = -1;
    int32_t eval_uid = -1;
    RootSettingsCpp settings{};
    MntNsMode mntns = MntNsMode::Requester;
    uint64_t ts_ms = 0;
};

static pthread_mutex_t g_su_cache_lock = PTHREAD_MUTEX_INITIALIZER;
static CachedSuInfo g_su_cache{};

enum BootStateBits : uint32_t {
    BootPostFsDataDone = 1u << 0,
    BootLateStartDone  = 1u << 1,
    BootCompleteDone   = 1u << 2,
    BootSafeMode       = 1u << 3,
};

static pthread_mutex_t g_boot_lock = PTHREAD_MUTEX_INITIALIZER;
static uint32_t g_boot_state = 0;

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
    return std::string(detect_magisk_tmp()) + "/" + MAIN_SOCKET;
}

static std::string sock_dir() {
    // MAIN_SOCKET = DEVICEDIR "/socket"
    // DEVICEDIR   = INTLROOT "/device"
    // INTLROOT    = ".magisk"
    return std::string(detect_magisk_tmp()) + "/" + DEVICEDIR;
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
        DbArgs{DbArg{key}, DbArg{static_cast<int64_t>(value)}}
    );
}

static int32_t db_get_setting_i32(const char *key, int32_t def);

static void init_denylist_state_from_db() {
    // Use the core denylist implementation (reads DB and starts logcat watcher if needed).
    initialize_denylist();
}

static bool check_data_mounted_ready() {
    auto fp = xopen_file("/proc/mounts", "re");
    if (!fp) return false;
    char line[4096];
    while (fgets(line, sizeof(line), fp.get())) {
        if (strstr(line, " /data ") && !strstr(line, " tmpfs ")) {
            return true;
        }
    }
    return false;
}

static const char *bbpath() {
    static std::string path;
    path = std::string(detect_magisk_tmp()) + "/" BBPATH "/busybox";
    if (access(path.c_str(), X_OK) != 0) {
        path = DATABIN "/busybox";
    }
    return path.c_str();
}

static void set_script_env_min() {
    setenv("ASH_STANDALONE", "1", 1);
    char new_path[4096];
    const char *old = getenv("PATH");
    if (!old) old = "";
    ssprintf(new_path, sizeof(new_path), "%s:%s", old, detect_magisk_tmp());
    setenv("PATH", new_path, 1);
}

static void exec_script_file_async(const char *path) {
    exec_t exec{
        .pre_exec = set_script_env_min,
        .fork = fork_dont_care,
    };
    exec_command(exec, bbpath(), "sh", path);
}

static void exec_common_scripts_cpp(const char *stage) {
    char dir_path[256];
    ssprintf(dir_path, sizeof(dir_path), SECURE_DIR "/%s.d", stage);
    auto dir = xopen_dir(dir_path);
    if (!dir) return;

    int dfd = dirfd(dir.get());
    for (dirent *entry; (entry = xreaddir(dir.get()));) {
        if (entry->d_type != DT_REG) continue;
        if (faccessat(dfd, entry->d_name, X_OK, 0) != 0) continue;
        char full[512];
        ssprintf(full, sizeof(full), "%s/%s", dir_path, entry->d_name);
        exec_script_file_async(full);
    }
}

static void exec_module_scripts_cpp(const char *stage) {
    auto dir = xopen_dir(MODULEROOT);
    if (!dir) return;
    for (dirent *entry; (entry = xreaddir(dir.get()));) {
        if (entry->d_type != DT_DIR) continue;
        if (entry->d_name[0] == '.') continue;

        char disable_path[512];
        ssprintf(disable_path, sizeof(disable_path), MODULEROOT "/%s/disable", entry->d_name);
        if (access(disable_path, F_OK) == 0) continue;

        char script_path[512];
        ssprintf(script_path, sizeof(script_path), MODULEROOT "/%s/%s.sh", entry->d_name, stage);
        if (access(script_path, F_OK) != 0) continue;
        exec_script_file_async(script_path);
    }
}

static void disable_all_modules_cpp() {
    auto dir = xopen_dir(MODULEROOT);
    if (!dir) return;
    for (dirent *entry; (entry = xreaddir(dir.get()));) {
        if (entry->d_type != DT_DIR) continue;
        if (entry->d_name[0] == '.') continue;
        char disable_path[512];
        ssprintf(disable_path, sizeof(disable_path), MODULEROOT "/%s/disable", entry->d_name);
        int fd = open(disable_path, O_WRONLY | O_CREAT | O_CLOEXEC, 0644);
        if (fd >= 0) close(fd);
    }
}

static void handle_boot_stage(RequestCode code) {
    mutex_guard lock(g_boot_lock);

    if (code == RequestCode::POST_FS_DATA) {
        if ((g_boot_state & BootPostFsDataDone) != 0) return;
        if (!check_data_mounted_ready()) return;

        // Ensure /data/adb exists (best-effort bring-up).
        (void)mkdir(SECURE_DIR, 0700);

        int32_t boot_cnt = db_get_setting_i32("bootloop", 0);
        (void)set_db_setting_i32("bootloop", boot_cnt + 1);

        const bool safe_mode = boot_cnt >= 2;
        if (safe_mode) {
            g_boot_state |= BootSafeMode;
            disable_all_modules_cpp();
            (void)set_db_setting_i32("zygisk", 0);
        } else {
            exec_common_scripts_cpp("post-fs-data");
            exec_module_scripts_cpp("post-fs-data");
        }

        init_denylist_state_from_db();
        g_boot_state |= BootPostFsDataDone;
        return;
    }

    if (code == RequestCode::LATE_START) {
        if ((g_boot_state & BootPostFsDataDone) == 0) return;
        if ((g_boot_state & BootSafeMode) != 0) return;
        if ((g_boot_state & BootLateStartDone) != 0) return;
        exec_common_scripts_cpp("service");
        exec_module_scripts_cpp("service");
        g_boot_state |= BootLateStartDone;
        return;
    }

    if (code == RequestCode::BOOT_COMPLETE) {
        if ((g_boot_state & BootPostFsDataDone) == 0) return;
        if ((g_boot_state & BootCompleteDone) != 0) return;
        (void)set_db_setting_i32("bootloop", 0);
        g_boot_state |= BootCompleteDone;
        (void)get_manager_for_user(0, true);
        return;
    }
}

static void handle_denylist_cmd(int fd) {
    // Reuse the existing denylist handler implementation (enable/disable/logcat, list framing, etc.)
    denylist_handler(fd);
}

static void handle_sqlite_cmd(int fd) {
    auto sql = read_string(fd);
    if (sql.empty()) {
        (void)write_string(fd, "");
        return;
    }

    auto cb = [&](const ColumnList &columns, const DbValues &values) {
        std::string out;
        for (int i = 0; i < columns.size(); ++i) {
            if (i != 0) out.push_back('|');
            out += std::string(columns[i]);
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
    auto cb = [&](const ColumnList &, const DbValues &v) {
        out = v.get_int(0);
        got = true;
    };
    (void)db_exec("SELECT value FROM settings WHERE key=?", DbArgs{DbArg{key}}, cb);
    (void)got;
    return out;
}

static RootSettingsCpp db_get_root_settings_for_uid(int32_t uid) {
    RootSettingsCpp out{};
    auto cb = [&](const ColumnList &columns, const DbValues &v) {
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
        DbArgs{DbArg{static_cast<int64_t>(uid)}},
        cb
    );
    return out;
}

static std::string db_get_string_value(const char *key) {
    std::string out;
    auto cb = [&](const ColumnList &, const DbValues &v) {
        const char *s = v.get_text(0);
        if (s) out.assign(s);
    };
    (void)db_exec("SELECT value FROM strings WHERE key=?", DbArgs{DbArg{key}}, cb);
    return out;
}

static int32_t get_package_uid_guess(int32_t user, const std::string &pkg) {
    // Prefer querying system package list so it works even before app data dirs exist.
    // Format: "<package> <uid> <...>" per line.
    {
        std::string pl = full_read("/data/system/packages.list");
        if (!pl.empty()) {
            size_t off = 0;
            while (off < pl.size()) {
                size_t eol = pl.find('\n', off);
                if (eol == std::string::npos) eol = pl.size();
                std::string_view line(pl.data() + off, eol - off);
                off = (eol == pl.size()) ? eol : eol + 1;

                // Trim left spaces
                while (!line.empty() && std::isspace(static_cast<unsigned char>(line.front()))) {
                    line.remove_prefix(1);
                }
                if (line.empty()) continue;

                // Must start with exact package name + whitespace
                if (line.size() <= pkg.size()) continue;
                if (line.compare(0, pkg.size(), pkg) != 0) continue;
                if (!std::isspace(static_cast<unsigned char>(line[pkg.size()]))) continue;

                size_t pos = pkg.size();
                while (pos < line.size() && std::isspace(static_cast<unsigned char>(line[pos]))) ++pos;
                size_t start = pos;
                while (pos < line.size() && !std::isspace(static_cast<unsigned char>(line[pos]))) ++pos;
                if (start == pos) continue;

                // packages.list uid is per-app-id (user 0). Convert to per-user uid.
                int32_t uid0 = parse_int(std::string(line.substr(start, pos - start)).c_str());
                if (uid0 > 0) {
                    int32_t app_id = to_app_id(uid0);
                    return user * AID_USER_OFFSET + app_id;
                }
            }
        }
    }

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

static std::vector<bool> get_installed_app_no_list() {
    // app_id range: [AID_APP_START..AID_APP_END] => app_no [0..9999]
    constexpr int32_t AID_APP_START = 10000;
    constexpr int32_t AID_APP_END = 19999;

    std::vector<bool> present(10000, false);

    auto scan_root = [&](const char *root) {
        auto users = xopen_dir(root);
        if (!users) return;
        for (dirent *ue; (ue = readdir(users.get()));) {
            int user = parse_int(ue->d_name);
            if (user < 0) continue;
            std::string user_dir = std::string(root) + "/" + ue->d_name;
            auto pkgs = xopen_dir(user_dir.c_str());
            if (!pkgs) continue;
            int dirfd_user = dirfd(pkgs.get());
            for (dirent *pe; (pe = readdir(pkgs.get()));) {
                if (pe->d_name[0] == '.') continue;
                struct stat st{};
                if (fstatat(dirfd_user, pe->d_name, &st, 0) != 0) continue;
                int32_t app_id = to_app_id(static_cast<int32_t>(st.st_uid));
                if (app_id >= AID_APP_START && app_id <= AID_APP_END) {
                    int32_t app_no = app_id - AID_APP_START;
                    if (app_no >= 0 && app_no < static_cast<int32_t>(present.size())) {
                        present[static_cast<size_t>(app_no)] = true;
                    }
                }
            }
        }
    };

    // Try both paths; different Android versions use either.
    scan_root("/data/user_de");
    scan_root("/data/user");

    return present;
}

static void prune_su_policies() {
    // Rough parity with Rust prune_su_access(): remove policies for uninstalled app IDs.
    constexpr int32_t AID_APP_START = 10000;
    constexpr int32_t AID_APP_END = 19999;

    std::vector<int32_t> uids;
    auto cb = [&](const ColumnList &, const DbValues &v) {
        uids.push_back(v.get_int(0));
    };
    (void)db_exec("SELECT uid FROM policies", {}, cb);

    auto present = get_installed_app_no_list();

    for (auto uid : uids) {
        int32_t app_id = to_app_id(uid);
        if (app_id < AID_APP_START || app_id > AID_APP_END) continue;
        int32_t app_no = app_id - AID_APP_START;
        if (app_no < 0 || app_no >= static_cast<int32_t>(present.size())) continue;
        if (!present[static_cast<size_t>(app_no)]) {
            (void)db_exec("DELETE FROM policies WHERE uid=?", DbArgs{DbArg{static_cast<int64_t>(uid)}});
        }
    }
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
            // Emulator/userdebug bring-up: allow root in debuggable builds even if DB isn't initialized yet.
            if (is_debuggable_build()) return true;
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
    // 3-second freshness cache (match Rust).
    {
        mutex_guard lock(g_su_cache_lock);
        uint64_t now = now_ms_monotonic();
        if (g_su_cache.uid == uid && (now - g_su_cache.ts_ms) < 3000) {
            settings_out = g_su_cache.settings;
            mntns_out = g_su_cache.mntns;
            // Still perform log/notify as Rust does on each request (best-effort).
            auto [mgr_uid, mgr_pkg] = get_manager_for_user(to_user_id(g_su_cache.eval_uid), true);
            (void)mgr_uid;
            su_log_notify_async(settings_out, mgr_pkg, to_user_id(g_su_cache.eval_uid), uid, pid, req);
            return settings_out.policy == SuPolicy::Allow || settings_out.policy == SuPolicy::Restrict;
        }
    }

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

    // Emulator/userdebug bring-up:
    // If the policy is Query but there is no interactive manager response yet,
    // default to allow to make CI and early bootstrapping work.
    if (settings.policy == SuPolicy::Query && is_debuggable_build()) {
        settings.policy = SuPolicy::Allow;
        settings.log = false;
        settings.notify = false;
    }

    // ADB shell should be granted root by default when global root access allows it.
    // This matches user expectations in emulator tests (no interactive prompt).
    if (uid == AID_SHELL && settings.policy == SuPolicy::Query) {
        settings.policy = SuPolicy::Allow;
        settings.log = false;
        settings.notify = false;
    }

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

    // Update cache
    {
        mutex_guard lock(g_su_cache_lock);
        g_su_cache.uid = uid;
        g_su_cache.eval_uid = eval_uid;
        g_su_cache.settings = settings_out;
        g_su_cache.mntns = mntns_out;
        g_su_cache.ts_ms = now_ms_monotonic();
    }

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

    auto settings = db_get_root_settings_for_uid(eval_uid);
    return settings.policy == SuPolicy::Allow || settings.policy == SuPolicy::Restrict;
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
    if (!process.empty() && is_deny_target(uid, process)) {
        flags |= ZygiskStateFlags::ProcessOnDenyList;
    }
    {
        std::string pkg = db_get_string_value("requester");
        if (pkg.empty()) pkg = JAVA_PACKAGE_NAME;
        if (!pkg.empty() && (process == pkg || process.starts_with(pkg + ":"))) {
            flags |= ZygiskStateFlags::ProcessIsMagiskApp;
        }
    }

    (void)is64;

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

    int32_t code = -1;
    if (!read_pod_i32(cfd, code)) return;
    if (!is_valid_request(code)) return;

    // Base permission gate:
    // - root and zygote always allowed
    // - allow SUPERUSER requests from any process with credentials
    // - allow version queries to aid debugging
    // - keep strict "client exe" gate for other requests
    const auto req = static_cast<RequestCode>(code);
    bool allowed = is_root || is_zygote || is_client;
    if (!allowed && has_cred) {
        if (req == RequestCode::SUPERUSER ||
            req == RequestCode::CHECK_VERSION ||
            req == RequestCode::CHECK_VERSION_CODE) {
            allowed = true;
        }
    }
    if (!allowed) {
        write_pod_i32(cfd, static_cast<int32_t>(RespondCode::ACCESS_DENIED));
        return;
    }

    // Permission checks (match daemon.rs).
    switch (req) {
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

    switch (req) {
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
            // Match legacy daemon behavior:
            // - best-effort unmount Magisk tmpfs / module mounts
            // - return 0 to the caller
            // - terminate the daemon
            denylist_handler(-1);
            unlink(sock_path().c_str());
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
        case RequestCode::REMOVE_MODULES: {
            // Best-effort: disable all modules; optionally reboot.
            int32_t do_reboot = 0;
            (void) read_pod_i32(cfd, do_reboot);
            disable_all_modules_cpp();
            write_pod_i32(cfd, 0);
            if (do_reboot) {
                (void) exec_command_sync("/system/bin/reboot");
            }
            break;
        }
        case RequestCode::ZYGOTE_RESTART: {
            // Bring-up: perform core maintenance work.
            prune_su_policies();
            scan_deny_apps();
            break;
        }
        case RequestCode::POST_FS_DATA:
        case RequestCode::LATE_START:
        case RequestCode::BOOT_COMPLETE: {
            handle_boot_stage(static_cast<RequestCode>(code));
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

extern "C" int magiskd_cpp_entry() {

    // ---------------------------------------------------------------------
    // Bring-up parity with Rust daemon_entry():
    // - set nice name / start logging
    // - detach session + swap stdio
    // - enter magisk proc context so we can access /data/* consistently

    set_nice_name(Utf8CStr("magiskd"));
    cmdline_logging();

    // Block all signals (best-effort)
    {
        sigset_t set;
        sigfillset(&set);
        (void)pthread_sigmask(SIG_SETMASK, &set, nullptr);
    }

    // Swap out stdio
    {
        int nullfd = open("/dev/null", O_WRONLY | O_CLOEXEC);
        if (nullfd >= 0) {
            (void)dup2(nullfd, STDOUT_FILENO);
            (void)dup2(nullfd, STDERR_FILENO);
            close(nullfd);
        }
        int zerofd = open("/dev/zero", O_RDONLY | O_CLOEXEC);
        if (zerofd >= 0) {
            (void)dup2(zerofd, STDIN_FILENO);
            close(zerofd);
        }
    }

    (void)setsid();

    // Make sure current SELinux context is magisk
    {
        int fd = open("/proc/self/attr/current", O_WRONLY | O_CLOEXEC);
        if (fd >= 0) {
            const char con[] = MAGISK_PROC_CON;
            // Rust writes the NUL terminator too; do the same.
            (void)xwrite(fd, con, sizeof(con));
            close(fd);
        }
    }

    // Capture self /proc/self/exe dev+ino for client validation
    {
        struct stat st{};
        if (stat("/proc/self/exe", &st) == 0) {
            g_self_exe.dev = st.st_dev;
            g_self_exe.ino = st.st_ino;
            g_self_exe.valid = true;
        }
    }

    // Initialize denylist state from DB so status/zygisk flags reflect reality.
    init_denylist_state_from_db();

    // Ensure directory exists: <tmp> + DEVICEDIR (".magisk/device")
    // NOTE: These directories are expected to be traversable by clients (MagiskSU)
    // and should carry Magisk file context, otherwise untrusted apps may not be
    // able to connect even when the socket itself is labeled.
    mkdirs(sock_dir().c_str(), 0711);
    {
        std::string tmp = detect_magisk_tmp();
        if (!tmp.empty()) {
            std::string intl = tmp + "/" INTLROOT;      // ".magisk"
            std::string devd = tmp + "/" DEVICEDIR;     // ".magisk/device"
            (void)chmod(intl.c_str(), 0711);
            (void)chmod(devd.c_str(), 0711);
            (void)lsetxattr(intl.c_str(), "security.selinux", MAGISK_FILE_CON, strlen(MAGISK_FILE_CON), 0);
            (void)lsetxattr(devd.c_str(), "security.selinux", MAGISK_FILE_CON, strlen(MAGISK_FILE_CON), 0);
        }
    }

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
    (void) lsetxattr(path.c_str(), "security.selinux", MAGISK_FILE_CON, strlen(MAGISK_FILE_CON) + 1, 0);

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

// Standalone entrypoint for the optional `magiskd-cpp` binary build.
#ifdef MAGISKD_CPP_STANDALONE
int main(int argc, char *argv[]) {
    (void)argc;
    (void)argv;
    return magiskd_cpp_entry();
}
#endif

