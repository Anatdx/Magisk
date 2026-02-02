#include "core-compat.hpp"

#include <sys/socket.h>
#include <sys/un.h>
#include <sys/xattr.h>
#include <sys/ioctl.h>
#include <sys/system_properties.h>

#include <fcntl.h>
#include <poll.h>
#include <sched.h>
#include <unistd.h>

#include <cerrno>
#include <cinttypes>
#include <cstring>
#include <string>
#include <string_view>
#include <vector>

#include <consts.hpp>
#include <core.hpp>
#include <sqlite.hpp>

#include <flags.h>

using namespace std;

// -------------------------------------------------------------------------
// Small helpers

static inline bool write_pod_i32(int fd, int32_t v) {
    return xwrite(fd, &v, sizeof(v)) == sizeof(v);
}

static inline bool read_pod_i32(int fd, int32_t &v) {
    return xxread(fd, &v, sizeof(v)) == sizeof(v);
}

static inline string sock_path() {
    const char *tmp = get_magisk_tmp();
    if (tmp == nullptr || tmp[0] == '\0') {
        return string(MAIN_SOCKET);
    }
    string p(tmp);
    p.push_back('/');
    p += MAIN_SOCKET;
    return p;
}

// Weak daemon entry (provided by core/magiskd_cpp.cpp after refactor).
extern "C" __attribute__((weak)) int magiskd_cpp_entry();

// -------------------------------------------------------------------------
// SuRequest (encode format must match magiskd_cpp.cpp::read_su_request)

SuRequest SuRequest::New() noexcept {
    SuRequest r{};
    r.target_uid = 0;
    r.target_pid = -1;
    r.login = false;
    r.keep_env = false;
    r.drop_cap = false;
    r.shell = "/system/bin/sh";
    r.command = "";
    r.context = "";
    r.gids.clear();
    return r;
}

void SuRequest::write_to_fd(int32_t fd) const noexcept {
    if (fd < 0) return;
    write_any<int32_t>(fd, target_uid);
    write_any<int32_t>(fd, target_pid);
    write_any<uint8_t>(fd, login ? 1 : 0);
    write_any<uint8_t>(fd, keep_env ? 1 : 0);
    write_any<uint8_t>(fd, drop_cap ? 1 : 0);
    // `rust::String::c_str()` is non-const; use data/size instead.
    write_string(fd, std::string_view(shell.data(), shell.size()));
    write_string(fd, std::string_view(command.data(), command.size()));
    write_string(fd, std::string_view(context.data(), context.size()));
    write_any<int32_t>(fd, static_cast<int32_t>(gids.size()));
    for (auto g : gids) {
        write_any<uint32_t>(fd, g);
    }
}

// -------------------------------------------------------------------------
// MagiskD minimal facade (only what C++ core expects)

MagiskD const &MagiskD::Get() noexcept {
    static MagiskD g{};
    return g;
}

int32_t MagiskD::sdk_int() const noexcept {
    char buf[PROP_VALUE_MAX]{};
    if (__system_property_get("ro.build.version.sdk", buf) <= 0) {
        return 0;
    }
    return atoi(buf);
}

bool MagiskD::zygisk_enabled() const noexcept {
    return get_db_setting(DbEntryKey::ZygiskConfig) != 0;
}

static const char *db_key_name(DbEntryKey k) {
    // Keep aligned with Rust key strings.
    // We only need keys referenced by current C++ core sources.
    switch (k) {
        case DbEntryKey::RootAccess: return "root_access";
        case DbEntryKey::SuMultiuserMode: return "su_multiuser_mode";
        case DbEntryKey::SuMntNs: return "su_mnt_ns";
        case DbEntryKey::DenylistConfig: return "denylist_config";
        case DbEntryKey::ZygiskConfig: return "zygisk_config";
        case DbEntryKey::BootloopCount: return "bootloop_count";
        case DbEntryKey::SuManager: return "su_manager";
        default: return "";
    }
}

int32_t MagiskD::get_db_setting(DbEntryKey key) const noexcept {
    int32_t out = 0;
    bool got = false;
    const char *k = db_key_name(key);
    auto cb = [&](StringSlice, const DbValues &v) {
        out = v.get_int(0);
        got = true;
    };
    (void)db_exec("SELECT value FROM settings WHERE key=?", DbArgs{k}, cb);
    (void)got;
    return out;
}

bool MagiskD::set_db_setting(DbEntryKey key, int32_t value) const noexcept {
    const char *k = db_key_name(key);
    return db_exec(
        "INSERT OR REPLACE INTO settings(key,value) VALUES(?,?)",
        DbArgs{k, static_cast<int64_t>(value)}
    );
}

// -------------------------------------------------------------------------
// Logging stubs (core-only no-rust milestone)

void android_logging() noexcept { cmdline_logging(); }
void zygisk_logging() noexcept { cmdline_logging(); }
void zygisk_close_logd() noexcept {}
int32_t zygisk_get_logd() noexcept { return -1; }
bool zygisk_should_load_module(uint32_t) noexcept { return false; }

// -------------------------------------------------------------------------
// Denylist unmount revert (stub for now; full behavior lives in daemon side)

void revert_unmount(int) noexcept {}

// -------------------------------------------------------------------------
// FD passing (match Rust socket.rs framing: i32 count + SCM_RIGHTS)

bool send_fd(int32_t socket, int32_t fd) noexcept {
    int32_t count = (fd >= 0) ? 1 : 0;
    if (count == 0) {
        return write_pod_i32(socket, 0);
    }

    char cmsgbuf[CMSG_SPACE(sizeof(int))];
    memset(cmsgbuf, 0, sizeof(cmsgbuf));

    msghdr msg{};
    iovec iov{};
    iov.iov_base = &count;
    iov.iov_len = sizeof(count);
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;

    msg.msg_control = cmsgbuf;
    msg.msg_controllen = sizeof(cmsgbuf);

    cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
    cmsg->cmsg_level = SOL_SOCKET;
    cmsg->cmsg_type = SCM_RIGHTS;
    cmsg->cmsg_len = CMSG_LEN(sizeof(int));
    memcpy(CMSG_DATA(cmsg), &fd, sizeof(int));

    ssize_t n = sendmsg(socket, &msg, MSG_NOSIGNAL);
    return n == (ssize_t)sizeof(count);
}

int32_t recv_fd(int32_t socket) noexcept {
    int32_t count = 0;
    // Peek framing
    if (recv(socket, &count, sizeof(count), MSG_PEEK) != (ssize_t)sizeof(count)) {
        return -1;
    }
    if (count < 1) {
        // Consume framing and return none
        if (xxread(socket, &count, sizeof(count)) != (ssize_t)sizeof(count)) {
            return -1;
        }
        return -1;
    }

    char cmsgbuf[CMSG_SPACE(sizeof(int) * 16)];
    memset(cmsgbuf, 0, sizeof(cmsgbuf));

    msghdr msg{};
    iovec iov{};
    iov.iov_base = &count;
    iov.iov_len = sizeof(count);
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    msg.msg_control = cmsgbuf;
    msg.msg_controllen = sizeof(cmsgbuf);

    if (recvmsg(socket, &msg, 0) < 0) return -1;

    for (cmsghdr *cmsg = CMSG_FIRSTHDR(&msg); cmsg; cmsg = CMSG_NXTHDR(&msg, cmsg)) {
        if (cmsg->cmsg_level == SOL_SOCKET && cmsg->cmsg_type == SCM_RIGHTS) {
            int *fds = (int *)CMSG_DATA(cmsg);
            int fd0 = fds[0];
            // Close all other received fds if any
            size_t nfds = (cmsg->cmsg_len - CMSG_LEN(0)) / sizeof(int);
            for (size_t i = 1; i < nfds; ++i) close(fds[i]);
            return fd0;
        }
    }
    return -1;
}

rust::Vec<int32_t> recv_fds(int32_t socket) noexcept {
    int32_t count = 0;
    char cmsgbuf[CMSG_SPACE(sizeof(int) * 64)];
    memset(cmsgbuf, 0, sizeof(cmsgbuf));

    msghdr msg{};
    iovec iov{};
    iov.iov_base = &count;
    iov.iov_len = sizeof(count);
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    msg.msg_control = cmsgbuf;
    msg.msg_controllen = sizeof(cmsgbuf);

    if (recvmsg(socket, &msg, 0) < 0) {
        return {};
    }

    rust::Vec<int32_t> out;
    out.reserve(count > 0 ? (size_t)count : 0);

    for (cmsghdr *cmsg = CMSG_FIRSTHDR(&msg); cmsg; cmsg = CMSG_NXTHDR(&msg, cmsg)) {
        if (cmsg->cmsg_level == SOL_SOCKET && cmsg->cmsg_type == SCM_RIGHTS) {
            int *fds = (int *)CMSG_DATA(cmsg);
            size_t nfds = (cmsg->cmsg_len - CMSG_LEN(0)) / sizeof(int);
            for (size_t i = 0; i < nfds; ++i) out.push_back(fds[i]);
        }
    }
    return out;
}

// -------------------------------------------------------------------------
// PTY helpers (minimal implementation; good enough for core build)

int32_t get_pty_num(int32_t fd) noexcept {
    int pty = -1;
#ifdef TIOCGPTN
    if (ioctl(fd, TIOCGPTN, &pty) == 0) return pty;
#endif
    return -1;
}

void pump_tty(int32_t ptmx, bool pump_stdin) noexcept {
    pollfd pfds[2]{};
    int nfds = 0;

    if (pump_stdin) {
        pfds[nfds++] = pollfd{STDIN_FILENO, POLLIN, 0};
    }
    pfds[nfds++] = pollfd{ptmx, POLLIN, 0};

    char buf[4096];
    for (;;) {
        int r = poll(pfds, nfds, -1);
        if (r <= 0) continue;

        for (int i = 0; i < nfds; ++i) {
            if (!(pfds[i].revents & POLLIN)) continue;

            int in_fd = pfds[i].fd;
            int out_fd = (in_fd == ptmx) ? STDOUT_FILENO : ptmx;

            ssize_t n = read(in_fd, buf, sizeof(buf));
            if (n <= 0) return;

            ssize_t off = 0;
            while (off < n) {
                ssize_t w = write(out_fd, buf + off, (size_t)(n - off));
                if (w <= 0) return;
                off += w;
            }
        }
    }
}

// -------------------------------------------------------------------------
// Mount namespace

int switch_mnt_ns(int pid) {
    char path[64];
    ssprintf(path, sizeof(path), "/proc/%d/ns/mnt", pid);
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return -1;
    int r = setns(fd, 0);
    close(fd);
    return r;
}

// -------------------------------------------------------------------------
// SELinux context via xattr (avoids linking libselinux)

bool lgetfilecon(Utf8CStr path, MutByteSlice con) noexcept {
    if (con.size() == 0) return false;
    ssize_t n = lgetxattr(path.c_str(), "security.selinux", con.data(), con.size() - 1);
    if (n <= 0) {
        con.data()[0] = '\0';
        return false;
    }
    con.data()[min<size_t>((size_t)n, con.size() - 1)] = '\0';
    return true;
}

bool setfilecon(Utf8CStr path, Utf8CStr con) noexcept {
    return lsetxattr(path.c_str(), "security.selinux", con.c_str(), strlen(con.c_str()), 0) == 0;
}

// -------------------------------------------------------------------------
// Properties

rust::String get_prop(Utf8CStr name) noexcept {
    char buf[PROP_VALUE_MAX]{};
    if (__system_property_get(name.c_str(), buf) <= 0) {
        return rust::String();
    }
    return rust::String(buf);
}

// resetprop is still Rust in upstream; for the "core no-rust" milestone,
// provide a minimal stub so the `resetprop` applet continues to link.
int32_t resetprop_main(int32_t, char **) noexcept {
    fprintf(stderr, "resetprop: not implemented in core C++ no-rust build\n");
    return 1;
}

// -------------------------------------------------------------------------
// connect_daemon (match daemon.rs framing and spawn behavior)

int32_t connect_daemon(RequestCode code, bool create) noexcept {
    const string path = sock_path();

    auto send_request = [&](int fd) -> int {
        int32_t c = static_cast<int32_t>(code);
        if (!write_pod_i32(fd, c)) return -1;
        int32_t res = -1;
        if (!read_pod_i32(fd, res)) return -1;
        if (res == static_cast<int32_t>(RespondCode::OK)) {
            return fd;
        }
        close(fd);
        return -1;
    };

    auto try_connect = [&]() -> int {
        int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
        if (fd < 0) return -1;

        sockaddr_un addr{};
        addr.sun_family = AF_UNIX;
        if (path.size() >= sizeof(addr.sun_path)) {
            close(fd);
            return -1;
        }
        memcpy(addr.sun_path, path.c_str(), path.size() + 1);
        if (connect(fd, (sockaddr *)&addr, sizeof(addr)) != 0) {
            close(fd);
            return -1;
        }
        return send_request(fd);
    };

    int fd = try_connect();
    if (fd >= 0) return fd;

    if (!create || getuid() != 0) {
        return -1;
    }

    // Ensure we start daemon on magisk tmpfs (same as daemon.rs)
    char exe[256]{};
    ssize_t n = readlink("/proc/self/exe", exe, sizeof(exe) - 1);
    if (n <= 0) return -1;
    exe[n] = '\0';
    const char *tmp = get_magisk_tmp();
    if (tmp == nullptr || tmp[0] == '\0' || strncmp(exe, tmp, strlen(tmp)) != 0) {
        return -1;
    }

    if (fork_dont_care() == 0) {
        if (&magiskd_cpp_entry) {
            (void)magiskd_cpp_entry();
        }
        _exit(0);
    }

    for (;;) {
        fd = try_connect();
        if (fd >= 0) return fd;
        usleep(100000);
    }
}

// -------------------------------------------------------------------------
// magisk_main minimal C++ CLI dispatcher

static void print_usage() {
    fprintf(stderr,
        "Magisk - Multi-purpose Utility\n\n"
        "Usage: magisk [options]...\n\n"
        "Options:\n"
        "  -c                  print current binary version\n"
        "  -v                  print running daemon version\n"
        "  -V                  print running daemon version code\n"
        "  --list              list all available applets\n"
        "  --daemon            manually start magisk daemon\n"
        "  --stop              stop daemon\n"
        "  --post-fs-data       callback on init trigger\n"
        "  --service            callback on init trigger\n"
        "  --boot-complete      callback on init trigger\n"
        "  --zygote-restart     callback on init trigger\n"
        "  --sqlite SQL         exec SQL commands to Magisk database\n"
        "  --path              print Magisk tmpfs mount path\n"
        "  --denylist ARGS...   denylist config CLI\n"
    );
}

int32_t magisk_main(int32_t argc, char **argv) noexcept {
    if (argc < 2) {
        print_usage();
        return 1;
    }

    string_view a1 = argv[1] ? argv[1] : "";

    if (a1 == "-c") {
#ifdef MAGISK_VERSION
#ifdef MAGISK_DEBUG
        printf("%s:MAGISK:%c (%d)\n", MAGISK_VERSION, (MAGISK_DEBUG ? 'D' : 'R'), (int)MAGISK_VER_CODE);
#else
        printf("%s:MAGISK:CPP (%d)\n", MAGISK_VERSION, (int)MAGISK_VER_CODE);
#endif
#else
        printf("unknown:MAGISK:CPP (0)\n");
#endif
        return 0;
    }

    if (a1 == "-v") {
        int fd = connect_daemon(RequestCode::CHECK_VERSION, false);
        if (fd < 0) return 1;
        string ver = read_string(fd);
        close(fd);
        printf("%s\n", ver.c_str());
        return 0;
    }

    if (a1 == "-V") {
        int fd = connect_daemon(RequestCode::CHECK_VERSION_CODE, false);
        if (fd < 0) return 1;
        int v = read_int(fd);
        close(fd);
        printf("%d\n", v);
        return 0;
    }

    if (a1 == "--list") {
        for (const char *const *p = applet_names; p && *p; ++p) {
            printf("%s\n", *p);
        }
        return 0;
    }

    if (a1 == "--daemon") {
        int fd = connect_daemon(RequestCode::START_DAEMON, true);
        if (fd >= 0) close(fd);
        return 0;
    }

    if (a1 == "--stop") {
        int fd = connect_daemon(RequestCode::STOP_DAEMON, false);
        if (fd < 0) return 1;
        int rc = read_int(fd);
        close(fd);
        return rc;
    }

    if (a1 == "--post-fs-data") {
        int fd = connect_daemon(RequestCode::POST_FS_DATA, true);
        if (fd < 0) return 1;
        pollfd pfd{fd, POLLIN, 0};
        poll(&pfd, 1, POST_FS_DATA_WAIT_TIME * 1000);
        close(fd);
        return 0;
    }

    if (a1 == "--service") {
        int fd = connect_daemon(RequestCode::LATE_START, true);
        if (fd >= 0) close(fd);
        return 0;
    }

    if (a1 == "--boot-complete") {
        int fd = connect_daemon(RequestCode::BOOT_COMPLETE, false);
        if (fd >= 0) close(fd);
        return 0;
    }

    if (a1 == "--zygote-restart") {
        int fd = connect_daemon(RequestCode::ZYGOTE_RESTART, false);
        if (fd >= 0) close(fd);
        return 0;
    }

    if (a1 == "--path") {
        const char *tmp = get_magisk_tmp();
        if (tmp && tmp[0]) {
            printf("%s\n", tmp);
            return 0;
        }
        return 1;
    }

    if (a1 == "--sqlite") {
        if (argc < 3 || argv[2] == nullptr) return 1;
        int fd = connect_daemon(RequestCode::SQLITE_CMD, false);
        if (fd < 0) return 1;
        write_string(fd, argv[2]);
        for (;;) {
            string line = read_string(fd);
            if (line.empty()) break;
            printf("%s\n", line.c_str());
        }
        close(fd);
        return 0;
    }

    if (a1 == "--denylist") {
        if (argc < 3) return 1;
        rust::Vec<rust::String> args;
        for (int i = 2; i < argc; ++i) {
            args.push_back(rust::String(argv[i]));
        }
        return denylist_cli(args);
    }

    print_usage();
    return 1;
}

