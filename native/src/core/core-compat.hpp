#pragma once

#include <cstdint>

#include <base_cpp.hpp>

// C++-only compatibility layer for core.
// This replaces the historical Rust-generated `cxx::bridge` artifacts.

enum class RequestCode : std::int32_t {
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

enum class RespondCode : std::int32_t {
    ERROR = -1,
    OK = 0,
    ROOT_REQUIRED = 1,
    ACCESS_DENIED = 2,
    END = 3,
};

enum class DbEntryKey : std::uint8_t {
    RootAccess = 0,
    SuMultiuserMode = 1,
    SuMntNs = 2,
    DenylistConfig = 3,
    ZygiskConfig = 4,
    BootloopCount = 5,
    SuManager = 6,
};

enum class MntNsMode : std::int32_t {
    Global = 0,
    Requester = 1,
    Isolate = 2,
};

enum class SuPolicy : std::int32_t {
    Query = 0,
    Deny = 1,
    Allow = 2,
    Restrict = 3,
};

struct ModuleInfo {
    std::string name;
    std::int32_t z32 = 0;
    std::int32_t z64 = 0;
};

enum class ZygiskRequest : std::int32_t {
    GetInfo = 0,
    ConnectCompanion = 1,
    GetModDir = 2,
};

enum class ZygiskStateFlags : std::uint32_t {
    ProcessGrantedRoot = 1u,
    ProcessOnDenyList = 2u,
    DenyListEnforced = 0x40000000u,
    ProcessIsMagiskApp = 0x80000000u,
};

struct SuRequest {
    std::int32_t target_uid = 0;
    std::int32_t target_pid = 0;
    bool login = false;
    bool keep_env = false;
    bool drop_cap = false;
    std::string shell;
    std::string command;
    std::string context;
    std::vector<std::uint32_t> gids;

    void write_to_fd(std::int32_t fd) const noexcept;
    static SuRequest New() noexcept;
};

class MagiskD {
public:
    static MagiskD const &Get() noexcept;

    std::int32_t sdk_int() const noexcept;
    bool zygisk_enabled() const noexcept;

    std::int32_t get_db_setting(DbEntryKey key) const noexcept;
    bool set_db_setting(DbEntryKey key, std::int32_t value) const noexcept;

private:
    MagiskD() = default;
};

// Logging (zygisk / cmdline)
void android_logging() noexcept;
void zygisk_logging() noexcept;
void zygisk_close_logd() noexcept;
std::int32_t zygisk_get_logd() noexcept;
bool zygisk_should_load_module(std::uint32_t flags) noexcept;

// FD passing helpers (SCM_RIGHTS), used by su/zygisk.
bool send_fd(std::int32_t socket, std::int32_t fd) noexcept;
std::int32_t recv_fd(std::int32_t socket) noexcept;
std::vector<std::int32_t> recv_fds(std::int32_t socket) noexcept;

// PTY helpers (used by su)
void pump_tty(std::int32_t ptmx, bool pump_stdin) noexcept;
std::int32_t get_pty_num(std::int32_t fd) noexcept;

// SELinux helpers
bool lgetfilecon(Utf8CStr path, byte_data con) noexcept;
bool setfilecon(Utf8CStr path, Utf8CStr con) noexcept;

// Property & resetprop
std::string get_prop(Utf8CStr name) noexcept;
std::int32_t resetprop_main(std::int32_t argc, char **argv) noexcept;

// Core entry points
std::int32_t connect_daemon(RequestCode code, bool create) noexcept;
std::int32_t magisk_main(std::int32_t argc, char **argv) noexcept;

