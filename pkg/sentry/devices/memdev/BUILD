load("//tools/go_stateify:defs.bzl", "go_library")

package(licenses = ["notice"])

go_library(
    name = "memdev",
    srcs = [
        "full.go",
        "memdev.go",
        "null.go",
        "random.go",
        "zero.go",
    ],
    importpath = "gvisor.dev/gvisor/pkg/sentry/devices/memdev",
    visibility = ["//pkg/sentry:internal"],
    deps = [
        "//pkg/abi/linux",
        "//pkg/rand",
        "//pkg/sentry/context",
        "//pkg/sentry/fsimpl/devtmpfs",
        "//pkg/sentry/memmap",
        "//pkg/sentry/mm",
        "//pkg/sentry/pgalloc",
        "//pkg/sentry/safemem",
        "//pkg/sentry/usermem",
        "//pkg/sentry/vfs",
        "//pkg/syserror",
    ],
)
