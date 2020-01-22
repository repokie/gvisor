load("//tools/go_stateify:defs.bzl", "go_library")

package(licenses = ["notice"])

go_library(
    name = "vfs2",
    srcs = [
        "linux64_override_amd64.go",
        "sys_read.go",
    ],
    importpath = "gvisor.dev/gvisor/pkg/sentry/syscalls/linux/vfs2",
    visibility = ["//:sandbox"],
    deps = [
        "//pkg/sentry/arch",
        "//pkg/sentry/kernel",
        "//pkg/sentry/syscalls",
        "//pkg/sentry/syscalls/linux",
        "//pkg/sentry/usermem",
        "//pkg/sentry/vfs",
        "//pkg/syserror",
        "//pkg/waiter",
    ],
)
