#pragma once

#include <sys/stat.h>
#include <unistd.h>
#include <dirent.h>
#include <fcntl.h>
#include <pthread.h>

#include <array>
#include <algorithm>
#include <cctype>
#include <cerrno>
#include <cstdarg>
#include <cstdio>
#include <cstring>
#include <functional>
#include <memory>
#include <string>
#include <string_view>
#include <type_traits>
#include <utility>
#include <vector>

// NOTE: This header is the C++-only subset of `base.hpp` intended for the
// "core" process side (magisk/magiskd/su/denylist/resetprop) during the Rust
// removal migration. It must not include any Rust/CXX headers or types.

void cmdline_logging();

void LOGD(const char *fmt, ...) __printflike(1, 2);
void LOGI(const char *fmt, ...) __printflike(1, 2);
void LOGW(const char *fmt, ...) __printflike(1, 2);
void LOGE(const char *fmt, ...) __printflike(1, 2);
#define PLOGE(fmt, args...) LOGE(fmt " failed with %d: %s\n", ##args, errno, std::strerror(errno))

extern "C" {

// xwraps (ported from `base/xwrap.rs`)
FILE *xfopen(const char *pathname, const char *mode);
FILE *xfdopen(int fd, const char *mode);
int xopen(const char *pathname, int flags, mode_t mode = 0);
int xopenat(int dirfd, const char *pathname, int flags, mode_t mode = 0);
ssize_t xwrite(int fd, const void *buf, size_t count);
ssize_t xread(int fd, void *buf, size_t count);
ssize_t xxread(int fd, void *buf, size_t count);
int xsetns(int fd, int nstype);
int xunshare(int flags);
DIR *xopendir(const char *name);
DIR *xfdopendir(int fd);
dirent *xreaddir(DIR *dirp);
pid_t xsetsid();
int xfstat(int fd, struct stat *buf);
int xdup2(int oldfd, int newfd);
ssize_t xreadlinkat(int dirfd, const char *__restrict__ pathname, char *__restrict__ buf, size_t bufsiz);
int xsymlink(const char *target, const char *linkpath);
int xmount(const char *source, const char *target, const char *filesystemtype,
           unsigned long mountflags, const void *data);
int xumount2(const char *target, int flags);
int xrename(const char *oldpath, const char *newpath);
int xmkdir(const char *pathname, mode_t mode);
int xmkdirs(const char *pathname, mode_t mode);
ssize_t xsendfile(int out_fd, int in_fd, off_t *offset, size_t count);
pid_t xfork();
ssize_t xrealpath(const char *__restrict__ path, char *__restrict__ buf, size_t bufsiz);
int xmknod(const char *pathname, mode_t mode, dev_t dev);
int xpipe2(int fds[2], int flags);

// Utils (minimal subset used by core)
int mkdirs(const char *path, mode_t mode);
ssize_t canonical_path(const char *__restrict__ path, char *__restrict__ buf, size_t bufsiz);

} // extern "C"

#define DISALLOW_COPY_AND_MOVE(clazz) \
clazz(const clazz&) = delete;        \
clazz(clazz &&) = delete;

#define ALLOW_MOVE_ONLY(clazz) \
clazz(const clazz&) = delete;  \
clazz(clazz &&o) : clazz() { swap(o); }  \
clazz& operator=(clazz &&o) { swap(o); return *this; }

class mutex_guard {
    DISALLOW_COPY_AND_MOVE(mutex_guard)
public:
    explicit mutex_guard(pthread_mutex_t &m): mutex(&m) {
        pthread_mutex_lock(mutex);
    }
    void unlock() {
        pthread_mutex_unlock(mutex);
        mutex = nullptr;
    }
    ~mutex_guard() {
        if (mutex) pthread_mutex_unlock(mutex);
    }
private:
    pthread_mutex_t *mutex;
};

template <class Func>
class run_finally {
    DISALLOW_COPY_AND_MOVE(run_finally)
public:
    explicit run_finally(Func &&fn) : fn(std::move(fn)) {}
    ~run_finally() { fn(); }
private:
    Func fn;
};

template<class T>
static void default_new(T *&p) { p = new T(); }

template<class T>
static void default_new(std::unique_ptr<T> &p) { p.reset(new T()); }

template <typename T>
constexpr auto operator+(T e) noexcept ->
    std::enable_if_t<std::is_enum<T>::value, std::underlying_type_t<T>> {
    return static_cast<std::underlying_type_t<T>>(e);
}

struct StringCmp {
    using is_transparent = void;
    bool operator()(std::string_view a, std::string_view b) const { return a < b; }
};

// C++-only buffer views used by SELinux / misc helpers.
struct byte_view {
    byte_view() : ptr(nullptr), sz(0) {}
    byte_view(const void *buf, size_t sz) : ptr((const uint8_t *) buf), sz(sz) {}
    byte_view(const char *s) : byte_view(s, std::strlen(s) + 1) {}
    const uint8_t *data() const { return ptr; }
    size_t size() const { return sz; }
protected:
    const uint8_t *ptr;
    size_t sz;
};

struct byte_data {
    byte_data() : ptr(nullptr), sz(0) {}
    byte_data(void *buf, size_t sz) : ptr((uint8_t *) buf), sz(sz) {}
    uint8_t *data() const { return ptr; }
    size_t size() const { return sz; }
private:
    uint8_t *ptr;
    size_t sz;
};

struct owned_fd {
    ALLOW_MOVE_ONLY(owned_fd)

    owned_fd() : fd(-1) {}
    owned_fd(int fd) : fd(fd) {}
    ~owned_fd() { if (fd >= 0) close(fd); fd = -1; }

    operator int() const { return fd; }
    int release() { int f = fd; fd = -1; return f; }
    void swap(owned_fd &owned) { std::swap(fd, owned.fd); }

private:
    int fd;
};

// Similar to vsnprintf, but the return value is the written number of bytes
__printflike(3, 0) int vssprintf(char *dest, size_t size, const char *fmt, va_list ap);
// Similar to snprintf, but the return value is the written number of bytes
__printflike(3, 4) int ssprintf(char *dest, size_t size, const char *fmt, ...);
// This is not actually the strscpy from the Linux kernel.
// Silently truncates, and returns the number of bytes written.
extern "C" size_t strscpy(char *dest, const char *src, size_t size);

// Ban usage of unsafe cstring functions (kept for parity with upstream)
#define vsnprintf  __use_vssprintf_instead__
#define snprintf   __use_ssprintf_instead__
#define strlcpy    __use_strscpy_instead__

// Utf8CStr: C++-only lightweight string view for core.
// Requirements:
// - Must be trivially copyable / cheap to pass by value
// - `c_str()` must return a NUL-terminated string pointer
struct Utf8CStr {
    Utf8CStr() : ptr(""), len(0) {}
    Utf8CStr(const char *s) : ptr(s ? s : ""), len(s ? std::strlen(s) : 0) {}
    Utf8CStr(const char *s, size_t len_with_nul) : ptr(s ? s : ""), len(len_with_nul ? len_with_nul - 1 : 0) {}
    Utf8CStr(std::string_view sv) : ptr(sv.data()), len(sv.size()) {}

    const char *data() const { return ptr; }
    const char *c_str() const { return ptr; }
    size_t length() const { return len; }
    size_t size() const { return len; }
    bool empty() const { return len == 0; }
    std::string_view sv() const { return {ptr, len}; }
    operator std::string_view() const { return sv(); }
    bool operator==(std::string_view rhs) const { return sv() == rhs; }

private:
    const char *ptr;
    size_t len;
};

uint32_t parse_uint32_hex(std::string_view s);
int parse_int(std::string_view s);

using thread_entry = void *(*)(void *);
extern "C" int new_daemon_thread(thread_entry entry, void *arg = nullptr);

struct exec_t {
    bool err = false;
    int fd = -2;
    void (*pre_exec)() = nullptr;
    int (*fork)() = xfork;
    const char **argv = nullptr;
};

int fork_dont_care();
int fork_no_orphan();
void init_argv0(int argc, char **argv);
void set_nice_name(Utf8CStr name);
int switch_mnt_ns(int pid);

int exec_command(exec_t &exec);
int exec_command_sync(exec_t &exec);

template <class ...Args>
int exec_command(exec_t &exec, Args &&...args) {
    const char *argv[] = {args..., nullptr};
    exec.argv = argv;
    return exec_command(exec);
}
template <class ...Args>
int exec_command_sync(exec_t &exec, Args &&...args) {
    const char *argv[] = {args..., nullptr};
    exec.argv = argv;
    return exec_command_sync(exec);
}
template <class ...Args>
int exec_command_sync(Args &&...args) {
    exec_t exec;
    return exec_command_sync(exec, args...);
}
template <class ...Args>
void exec_command_async(Args &&...args) {
    const char *argv[] = {args..., nullptr};
    exec_t exec {
        .fork = fork_dont_care,
        .argv = argv,
    };
    (void) exec_command(exec);
}

std::string full_read(int fd);
std::string full_read(const char *filename);

// Iterate lines from a file descriptor and invoke `fn(line)` until it returns false.
// This is a C++ replacement for the Rust-exported `file_readline`.
template <typename Functor>
void file_readline(int fd, Functor &&fn) {
    std::string content = full_read(fd);
    size_t start = 0;
    while (start < content.size()) {
        size_t end = content.find('\n', start);
        if (end == std::string::npos) end = content.size();
        std::string line = content.substr(start, end - start);
        // Trim trailing '\r' if present.
        if (!line.empty() && line.back() == '\r') line.pop_back();
        if (!fn(Utf8CStr(line.c_str()))) return;
        start = (end == content.size()) ? end : end + 1;
    }
}

using sFILE = std::unique_ptr<FILE, decltype(&fclose)>;
using sDIR = std::unique_ptr<DIR, decltype(&closedir)>;
sDIR make_dir(DIR *dp);
sFILE make_file(FILE *fp);

static inline sDIR open_dir(const char *path) { return make_dir(opendir(path)); }
static inline sDIR xopen_dir(const char *path) { return make_dir(xopendir(path)); }
static inline sDIR xopen_dir(int dirfd) { return make_dir(xfdopendir(dirfd)); }
static inline sFILE open_file(const char *path, const char *mode) { return make_file(fopen(path, mode)); }
static inline sFILE xopen_file(const char *path, const char *mode) { return make_file(xfopen(path, mode)); }
static inline sFILE xopen_file(int fd, const char *mode) { return make_file(xfdopen(fd, mode)); }

