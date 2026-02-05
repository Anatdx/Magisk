#pragma once

#include <sys/socket.h>
#include <string>
#include <atomic>
#include <functional>

#include <base_cpp.hpp>

#include "../core-compat.hpp"

#define AID_ROOT   0
#define AID_SHELL  2000
#define AID_USER_OFFSET 100000

#define to_app_id(uid)  (uid % AID_USER_OFFSET)
#define to_user_id(uid) (uid / AID_USER_OFFSET)

#define SDK_INT      (MagiskD::Get().sdk_int())
#define APP_DATA_DIR (SDK_INT >= 24 ? "/data/user_de" : "/data/user")

inline int connect_daemon(RequestCode req) {
    // Default behavior should match upstream: if the socket isn't up yet,
    // attempt to spawn `magiskd` (works because MagiskSU is suid-root).
    return connect_daemon(req, true);
}

// Multi-call entrypoints
int su_client_main(int argc, char *argv[]);
int zygisk_main(int argc, char *argv[]);

struct ModuleInfo;

// Utils
const char *get_magisk_tmp();
void unlock_blocks();
bool check_key_combo();
template<typename T> requires(std::is_trivially_copyable_v<T>)
T read_any(int fd) {
    T val;
    if (xxread(fd, &val, sizeof(val)) != sizeof(val))
        return -1;
    return val;
}
template<typename T> requires(std::is_trivially_copyable_v<T>)
void write_any(int fd, T val) {
    if (fd < 0) return;
    xwrite(fd, &val, sizeof(val));
}
inline int read_int(int fd) { return read_any<int>(fd); }
inline void write_int(int fd, int val) { write_any(fd, val); }
std::string read_string(int fd);
bool read_string(int fd, std::string &str);
void write_string(int fd, std::string_view str);
template<typename T> requires(std::is_trivially_copyable_v<T>)
void write_vector(int fd, const std::vector<T> &vec) {
    write_int(fd, vec.size());
    xwrite(fd, vec.data(), vec.size() * sizeof(T));
}
template<typename T> requires(std::is_trivially_copyable_v<T>)
bool read_vector(int fd, std::vector<T> &vec) {
    int size = read_int(fd);
    vec.resize(size);
    return xread(fd, vec.data(), size * sizeof(T)) == size * sizeof(T);
}

// Scripting
void install_apk(Utf8CStr apk);
void uninstall_pkg(Utf8CStr pkg);
void exec_common_scripts(Utf8CStr stage);
void exec_module_scripts(Utf8CStr stage, const std::vector<ModuleInfo> &module_list);
void exec_script(Utf8CStr script);
void clear_pkg(const char *pkg, int user_id);
[[noreturn]] void install_module(Utf8CStr file);

// Denylist
extern std::atomic<bool> denylist_enforced;
int denylist_cli(const std::vector<std::string> &args);
void denylist_handler(int client);
void initialize_denylist();
void scan_deny_apps();
bool is_deny_target(int uid, std::string_view process);
void revert_unmount(int pid = -1) noexcept;
void update_deny_flags(int uid, std::string_view process, uint32_t &flags);

// MagiskSU
void exec_root_shell(int client, int pid, SuRequest &req, MntNsMode mode);

// (Rust bindings removed in core C++ migration)
