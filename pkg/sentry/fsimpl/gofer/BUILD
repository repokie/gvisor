load("//tools/go_stateify:defs.bzl", "go_library")
load("//tools/go_generics:defs.bzl", "go_template_instance")

package(licenses = ["notice"])

go_template_instance(
    name = "dentry_list",
    out = "dentry_list.go",
    package = "gofer",
    prefix = "dentry",
    template = "//pkg/ilist:generic_list",
    types = {
        "Element": "*dentry",
        "Linker": "*dentry",
    },
)

go_library(
    name = "gofer",
    srcs = [
        "dentry_list.go",
        "directory.go",
        "filesystem.go",
        "gofer.go",
        "handle.go",
        "handle_unsafe.go",
        "pagemath.go",
        "regular_file.go",
        "special_file.go",
        "symlink.go",
        "time.go",
    ],
    importpath = "gvisor.dev/gvisor/pkg/sentry/fsimpl/gofer",
    visibility = ["//pkg/sentry:internal"],
    deps = [
        "//pkg/abi/linux",
        "//pkg/log",
        "//pkg/p9",
        "//pkg/sentry/context",
        "//pkg/sentry/fs/fsutil",
        "//pkg/sentry/kernel/auth",
        "//pkg/sentry/kernel/time",
        "//pkg/sentry/memmap",
        "//pkg/sentry/pgalloc",
        "//pkg/sentry/platform",
        "//pkg/sentry/safemem",
        "//pkg/sentry/usage",
        "//pkg/sentry/usermem",
        "//pkg/sentry/vfs",
        "//pkg/syserror",
        "//pkg/unet",
    ],
)
