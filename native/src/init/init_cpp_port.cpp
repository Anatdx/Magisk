#include <sys/mount.h>
#include <unistd.h>

#include <cerrno>

#include <base.hpp>
#include <consts.hpp>

#include "init.hpp"

extern "C" {
extern char **environ;
}

void MagiskInit::prepare_data_cpp() const noexcept {
    LOGD("init-cpp: prepare_data_cpp\n");

    // Equivalent of Rust `prepare_data()`:
    // - mount tmpfs at /data
    // - copy /init, /.backup, /overlay.d into /data for later stages
    xmkdir("/data", 0755);
    // Ignore failure here; Rust side also logs and continues.
    mount("magisk", "/data", "tmpfs", 0, "mode=755");

    (void)cp_afc("/init", "/data/magiskinit");
    (void)cp_afc("/.backup", "/data/.backup");
    (void)cp_afc("/overlay.d", "/data/overlay.d");
}

void MagiskInit::exec_init_cpp() noexcept {
    LOGD("init-cpp: exec_init_cpp\n");

    // Unmount in reverse order
    for (size_t i = mount_list.size(); i > 0; --i) {
        auto &p = mount_list[i - 1];
        // best-effort
        if (umount2(p.c_str(), 0) == 0) {
            LOGD("init-cpp: unmount [%s]\n", p.c_str());
        }
    }

    execve("/init", argv, environ);
    PLOGE("execve /init");
    _exit(1);
}

