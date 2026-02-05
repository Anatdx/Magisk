#include <core.hpp>

#include <cstdio>

// CMake core-only build stub.
// The production ndk-build path still builds the full zygisk implementation.

int zygisk_main(int /*argc*/, char * /*argv*/[]) {
    std::fputs("zygisk: disabled in core-only CMake build\n", stderr);
    return 1;
}

