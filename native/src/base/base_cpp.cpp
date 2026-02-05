#include <sys/mount.h>
#include <sys/sendfile.h>
#include <sys/wait.h>
#include <sys/prctl.h>
#include <sys/syscall.h>

#include <android/log.h>

#include <cerrno>
#include <climits>
#include <cstdarg>
#include <cstdio>
#include <cstdlib>
#include <cstring>

#include <base_cpp.hpp>

using namespace std;

static constexpr const char *kLogTag = "Magisk";

// Allow using libc formatting APIs inside this implementation unit.
#undef vsnprintf
#undef snprintf
#undef strlcpy

void cmdline_logging() {
    // Minimal stub for core: keep behavior simple during migration.
    // Upstream `base.cpp` routes logs through Rust; we intentionally do not.
}

static int vlog_print(int prio, const char *fmt, va_list ap) {
    // Ensure newline for readability (many callsites already pass '\n').
    __android_log_vprint(prio, kLogTag, fmt, ap);
    return 0;
}

#if MAGISK_DEBUG
void LOGD(const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    vlog_print(ANDROID_LOG_DEBUG, fmt, ap);
    va_end(ap);
}
#else
void LOGD(const char *fmt, ...) { (void)fmt; }
#endif

void LOGI(const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    vlog_print(ANDROID_LOG_INFO, fmt, ap);
    va_end(ap);
}

void LOGW(const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    vlog_print(ANDROID_LOG_WARN, fmt, ap);
    va_end(ap);
}

void LOGE(const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    vlog_print(ANDROID_LOG_ERROR, fmt, ap);
    va_end(ap);
}

extern "C" {

FILE *xfopen(const char *pathname, const char *mode) {
    FILE *fp = fopen(pathname, mode);
    if (!fp) PLOGE("fopen %s", pathname ? pathname : "(null)");
    return fp;
}

FILE *xfdopen(int fd, const char *mode) {
    FILE *fp = fdopen(fd, mode);
    if (!fp) PLOGE("fdopen");
    return fp;
}

int xopen(const char *pathname, int flags, mode_t mode) {
    int fd = open(pathname, flags, mode);
    if (fd < 0) PLOGE("open %s", pathname ? pathname : "(null)");
    return fd;
}

int xopenat(int dirfd, const char *pathname, int flags, mode_t mode) {
    int fd = openat(dirfd, pathname, flags, mode);
    if (fd < 0) PLOGE("openat %s", pathname ? pathname : "(null)");
    return fd;
}

ssize_t xwrite(int fd, const void *buf, size_t count) {
    const uint8_t *p = static_cast<const uint8_t *>(buf);
    size_t left = count;
    while (left > 0) {
        ssize_t r = write(fd, p, left);
        if (r < 0) {
            if (errno == EINTR) continue;
            PLOGE("write");
            return -1;
        }
        if (r == 0) break;
        p += r;
        left -= r;
    }
    return static_cast<ssize_t>(count - left);
}

ssize_t xread(int fd, void *buf, size_t count) {
    for (;;) {
        ssize_t r = read(fd, buf, count);
        if (r < 0 && errno == EINTR) continue;
        if (r < 0) PLOGE("read");
        return r;
    }
}

ssize_t xxread(int fd, void *buf, size_t count) {
    uint8_t *p = static_cast<uint8_t *>(buf);
    size_t left = count;
    while (left > 0) {
        ssize_t r = read(fd, p, left);
        if (r < 0) {
            if (errno == EINTR) continue;
            PLOGE("read");
            return -1;
        }
        if (r == 0) return -1;
        p += r;
        left -= r;
    }
    return static_cast<ssize_t>(count);
}

int xsetns(int fd, int nstype) {
    int r = setns(fd, nstype);
    if (r < 0) PLOGE("setns");
    return r;
}

int xunshare(int flags) {
    int r = unshare(flags);
    if (r < 0) PLOGE("unshare");
    return r;
}

DIR *xopendir(const char *name) {
    DIR *d = opendir(name);
    if (!d) PLOGE("opendir %s", name ? name : "(null)");
    return d;
}

DIR *xfdopendir(int fd) {
    DIR *d = fdopendir(fd);
    if (!d) PLOGE("fdopendir");
    return d;
}

dirent *xreaddir(DIR *dirp) {
    errno = 0;
    dirent *e = readdir(dirp);
    if (!e && errno) PLOGE("readdir");
    return e;
}

pid_t xsetsid() {
    pid_t r = setsid();
    if (r < 0) PLOGE("setsid");
    return r;
}

int xfstat(int fd, struct stat *buf) {
    int r = fstat(fd, buf);
    if (r < 0) PLOGE("fstat");
    return r;
}

int xdup2(int oldfd, int newfd) {
    int r = dup2(oldfd, newfd);
    if (r < 0) PLOGE("dup2");
    return r;
}

ssize_t xreadlinkat(int dirfd, const char *__restrict__ pathname, char *__restrict__ buf, size_t bufsiz) {
    ssize_t r = readlinkat(dirfd, pathname, buf, bufsiz);
    if (r < 0) PLOGE("readlinkat %s", pathname ? pathname : "(null)");
    return r;
}

int xsymlink(const char *target, const char *linkpath) {
    int r = symlink(target, linkpath);
    if (r < 0) PLOGE("symlink %s -> %s", target ? target : "(null)", linkpath ? linkpath : "(null)");
    return r;
}

int xmount(const char *source, const char *target, const char *filesystemtype,
           unsigned long mountflags, const void *data) {
    int r = mount(source, target, filesystemtype, mountflags, data);
    if (r < 0) PLOGE("mount %s -> %s", source ? source : "(null)", target ? target : "(null)");
    return r;
}

int xumount2(const char *target, int flags) {
    int r = umount2(target, flags);
    if (r < 0) PLOGE("umount2 %s", target ? target : "(null)");
    return r;
}

int xrename(const char *oldpath, const char *newpath) {
    int r = rename(oldpath, newpath);
    if (r < 0) PLOGE("rename %s -> %s", oldpath ? oldpath : "(null)", newpath ? newpath : "(null)");
    return r;
}

int xmkdir(const char *pathname, mode_t mode) {
    int r = mkdir(pathname, mode);
    if (r < 0 && errno != EEXIST) PLOGE("mkdir %s", pathname ? pathname : "(null)");
    return r;
}

int xmkdirs(const char *pathname, mode_t mode) {
    return mkdirs(pathname, mode);
}

ssize_t xsendfile(int out_fd, int in_fd, off_t *offset, size_t count) {
    ssize_t r = sendfile(out_fd, in_fd, offset, count);
    if (r < 0) PLOGE("sendfile");
    return r;
}

pid_t xfork() {
    pid_t r = fork();
    if (r < 0) PLOGE("fork");
    return r;
}

ssize_t xrealpath(const char *__restrict__ path, char *__restrict__ buf, size_t bufsiz) {
    if (!path || !buf || bufsiz == 0) return -1;
    char *rp = realpath(path, buf);
    if (!rp) {
        PLOGE("realpath %s", path);
        return -1;
    }
    size_t len = strnlen(buf, bufsiz - 1);
    return static_cast<ssize_t>(len);
}

int xmknod(const char *pathname, mode_t mode, dev_t dev) {
    int r = mknod(pathname, mode, dev);
    if (r < 0) PLOGE("mknod %s", pathname ? pathname : "(null)");
    return r;
}

int xpipe2(int fds[2], int flags) {
    int r = pipe2(fds, flags);
    if (r < 0) PLOGE("pipe2");
    return r;
}

int mkdirs(const char *path, mode_t mode) {
    if (!path || *path == '\0') return -1;
    char tmp[PATH_MAX];
    size_t len = strlcpy(tmp, path, sizeof(tmp));
    if (len == 0 || len >= sizeof(tmp)) return -1;

    for (char *p = tmp + 1; *p; ++p) {
        if (*p == '/') {
            *p = '\0';
            (void) mkdir(tmp, mode);
            *p = '/';
        }
    }
    if (mkdir(tmp, mode) < 0 && errno != EEXIST) return -1;
    return 0;
}

ssize_t canonical_path(const char *__restrict__ path, char *__restrict__ buf, size_t bufsiz) {
    return xrealpath(path, buf, bufsiz);
}

} // extern "C"

int vssprintf(char *dest, size_t size, const char *fmt, va_list ap) {
    if (!dest || size == 0) return -1;
    dest[0] = '\0';
    int r = ::vsnprintf(dest, size, fmt, ap);
    if (r < 0) return -1;
    // Return written bytes (clamped)
    size_t n = strnlen(dest, size - 1);
    return static_cast<int>(n);
}

int ssprintf(char *dest, size_t size, const char *fmt, ...) {
    va_list va;
    va_start(va, fmt);
    int r = vssprintf(dest, size, fmt, va);
    va_end(va);
    return r;
}

size_t strscpy(char *dest, const char *src, size_t size) {
    if (!dest || size == 0) return 0;
    if (!src) {
        dest[0] = '\0';
        return 0;
    }
    size_t n = strlcpy(dest, src, size);
    return std::min(n, size - 1);
}

uint32_t parse_uint32_hex(std::string_view s) {
    uint32_t out = 0;
    for (char c : s) {
        out <<= 4u;
        if (c >= '0' && c <= '9') out |= static_cast<uint32_t>(c - '0');
        else if (c >= 'a' && c <= 'f') out |= static_cast<uint32_t>(c - 'a' + 10);
        else if (c >= 'A' && c <= 'F') out |= static_cast<uint32_t>(c - 'A' + 10);
        else break;
    }
    return out;
}

int parse_int(std::string_view s) {
    int sign = 1;
    long out = 0;
    size_t i = 0;
    if (!s.empty() && s[0] == '-') { sign = -1; i = 1; }
    for (; i < s.size(); ++i) {
        char c = s[i];
        if (c < '0' || c > '9') break;
        out = out * 10 + (c - '0');
    }
    return static_cast<int>(out * sign);
}

extern "C" int new_daemon_thread(thread_entry entry, void *arg) {
    pthread_t t;
    pthread_attr_t attr;
    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
    int r = pthread_create(&t, &attr, entry, arg);
    pthread_attr_destroy(&attr);
    return r == 0 ? 0 : -1;
}

int fork_dont_care() {
    pid_t pid = xfork();
    if (pid != 0) return pid < 0 ? -1 : 1;
    // child
    if (xfork() != 0) _exit(0);
    // grandchild
    return 0;
}

int fork_no_orphan() {
    pid_t pid = xfork();
    if (pid < 0) return -1;
    if (pid == 0) return 0;
    int status;
    waitpid(pid, &status, 0);
    return 1;
}

void init_argv0(int /*argc*/, char ** /*argv*/) {
    // Upstream sets process title; we keep no-op for now.
}

void set_nice_name(Utf8CStr name) {
    // Best effort: set thread name (limited to 15 chars + NUL on Linux)
    prctl(PR_SET_NAME, name.c_str(), 0, 0, 0);
}

int switch_mnt_ns(int pid) {
    char mnt[64];
    ssprintf(mnt, sizeof(mnt), "/proc/%d/ns/mnt", pid);
    int fd = xopen(mnt, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return -1;
    int r = xsetns(fd, 0);
    close(fd);
    return r;
}

static sDIR make_dir_impl(DIR *dp) { return sDIR(dp, [](DIR *d){ return d ? closedir(d) : 0; }); }
static sFILE make_file_impl(FILE *fp) { return sFILE(fp, [](FILE *f){ return f ? fclose(f) : 0; }); }

sDIR make_dir(DIR *dp) { return make_dir_impl(dp); }
sFILE make_file(FILE *fp) { return make_file_impl(fp); }

std::string full_read(int fd) {
    std::string out;
    char buf[4096];
    for (;;) {
        ssize_t r = xread(fd, buf, sizeof(buf));
        if (r <= 0) break;
        out.append(buf, buf + r);
    }
    return out;
}

std::string full_read(const char *filename) {
    std::string out;
    if (!filename) return out;
    int fd = xopen(filename, O_RDONLY | O_CLOEXEC);
    if (fd >= 0) {
        out = full_read(fd);
        close(fd);
    }
    return out;
}

int exec_command(exec_t &exec) {
    if (!exec.argv || !exec.argv[0]) return -1;

    int pipefd[2] = {-1, -1};
    if (exec.fd != -2) {
        if (xpipe2(pipefd, O_CLOEXEC) < 0) return -1;
    }

    pid_t pid = exec.fork ? exec.fork() : xfork();
    if (pid < 0) {
        if (pipefd[0] >= 0) close(pipefd[0]);
        if (pipefd[1] >= 0) close(pipefd[1]);
        return -1;
    }
    if (pid == 0) {
        if (exec.pre_exec) exec.pre_exec();
        if (exec.fd != -2) {
            close(pipefd[0]);
            if (exec.fd < 0) {
                // Capture stdout+stderr to pipe
                xdup2(pipefd[1], STDOUT_FILENO);
                xdup2(pipefd[1], STDERR_FILENO);
            } else {
                xdup2(exec.fd, STDOUT_FILENO);
                xdup2(exec.fd, STDERR_FILENO);
            }
            close(pipefd[1]);
        }
        execvp(exec.argv[0], const_cast<char *const *>(exec.argv));
        _exit(127);
    }

    // parent
    if (exec.fd != -2) {
        close(pipefd[1]);
        exec.fd = pipefd[0];
    }
    return static_cast<int>(pid);
}

int exec_command_sync(exec_t &exec) {
    pid_t pid = exec_command(exec);
    if (pid <= 0) return -1;
    int status = 0;
    waitpid(pid, &status, 0);
    if (WIFEXITED(status)) return WEXITSTATUS(status);
    if (WIFSIGNALED(status)) return 128 + WTERMSIG(status);
    return -1;
}

