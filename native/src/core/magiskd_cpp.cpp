#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <sys/ioctl.h>
#include <sys/mount.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <unistd.h>

#include <cerrno>
#include <cstdint>
#include <cstring>
#include <fcntl.h>
#include <grp.h>
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

static constexpr int32_t AID_ROOT = 0;
static constexpr int32_t AID_SHELL = 2000;
static constexpr int32_t AID_USER_OFFSET = 100000;

static inline int32_t to_app_id(int32_t uid) { return uid % AID_USER_OFFSET; }
static inline int32_t to_user_id(int32_t uid) { return uid / AID_USER_OFFSET; }

static bool is_valid_request(int32_t code) {
    if (code < 0 || code >= static_cast<int32_t>(RequestCode::END)) return false;
    if (code == static_cast<int32_t>(RequestCode::_SYNC_BARRIER_)) return false;
    if (code == static_cast<int32_t>(RequestCode::_STAGE_BARRIER_)) return false;
    return true;
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

static SuPolicy db_get_su_policy_for_uid(int32_t uid) {
    int32_t pol = static_cast<int32_t>(SuPolicy::Query);
    bool got = false;
    auto cb = [&](StringSlice, const DbValues &v) {
        pol = v.get_int(0);
        got = true;
    };
    db_exec(
        "SELECT policy FROM policies WHERE uid=? AND (until=0 OR until>strftime('%s', 'now'))",
        DbArgs{static_cast<int64_t>(uid)},
        cb
    );
    (void)got;
    return static_cast<SuPolicy>(pol);
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

static bool eval_su_access(int32_t uid, SuPolicy &policy_out, MntNsMode &mntns_out) {
    if (uid == AID_ROOT) {
        policy_out = SuPolicy::Allow;
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

    auto policy = db_get_su_policy_for_uid(eval_uid);
    policy_out = policy;
    mntns_out = mntns;
    return policy == SuPolicy::Allow || policy == SuPolicy::Restrict;
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
    // Minimal auth based on SO_PEERCRED (skeleton bring-up).
    // Full parity will add SO_PEERSEC checks and stricter gating.
    ucred cred{};
    socklen_t cred_len = sizeof(cred);
    bool has_cred =
        getsockopt(cfd, SOL_SOCKET, SO_PEERCRED, &cred, &cred_len) == 0 && cred_len == sizeof(cred);

    int32_t code = -1;
    if (!read_pod_i32(cfd, code)) return;
    if (!is_valid_request(code)) return;

    // Permission checks (subset).
    if (static_cast<RequestCode>(code) == RequestCode::STOP_DAEMON) {
        if (!has_cred || cred.uid != 0) {
            write_pod_i32(cfd, static_cast<int32_t>(RespondCode::ROOT_REQUIRED));
            return;
        }
    }

    if (!write_pod_i32(cfd, static_cast<int32_t>(RespondCode::OK))) return;

    switch (static_cast<RequestCode>(code)) {
        case RequestCode::CHECK_VERSION: {
            // Keep compatible shape, but not necessarily identical content yet.
#ifdef MAGISK_VERSION
            std::string s = std::string(MAGISK_VERSION) + ":MAGISK:CPP";
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
        case RequestCode::SUPERUSER: {
            SuRequestCpp req{};
            if (!read_su_request(cfd, req)) {
                // Match client behavior: non-zero ack means denied/failed.
                write_pod_i32(cfd, static_cast<int32_t>(SuPolicy::Deny));
                break;
            }

            SuPolicy policy = SuPolicy::Deny;
            MntNsMode mntns = MntNsMode::Requester;
            bool allowed = has_cred && eval_su_access(static_cast<int32_t>(cred.uid), policy, mntns);
            if (!allowed) {
                write_pod_i32(cfd, static_cast<int32_t>(SuPolicy::Deny));
                break;
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

