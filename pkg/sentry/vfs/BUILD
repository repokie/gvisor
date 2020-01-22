load("//tools/go_stateify:defs.bzl", "go_library")
load("@io_bazel_rules_go//go:def.bzl", "go_test")
load("//tools/go_generics:defs.bzl", "go_template_instance")

package(licenses = ["notice"])

go_template_instance(
    name = "epoll_interest_list",
    out = "epoll_interest_list.go",
    package = "vfs",
    prefix = "epollInterest",
    template = "//pkg/ilist:generic_list",
    types = {
        "Element": "*epollInterest",
        "Linker": "*epollInterest",
    },
)

go_library(
    name = "vfs",
    srcs = [
        "anonfs.go",
        "context.go",
        "debug.go",
        "dentry.go",
        "device.go",
        "epoll.go",
        "epoll_interest_list.go",
        "file_description.go",
        "file_description_impl_util.go",
        "filesystem.go",
        "filesystem_impl_util.go",
        "filesystem_type.go",
        "mount.go",
        "mount_unsafe.go",
        "options.go",
        "pathname.go",
        "permissions.go",
        "resolving_path.go",
        "vfs.go",
    ],
    importpath = "gvisor.dev/gvisor/pkg/sentry/vfs",
    visibility = ["//pkg/sentry:internal"],
    deps = [
        "//pkg/abi/linux",
        "//pkg/fspath",
        "//pkg/sentry/arch",
        "//pkg/sentry/context",
        "//pkg/sentry/kernel/auth",
        "//pkg/sentry/memmap",
        "//pkg/sentry/usermem",
        "//pkg/sync",
        "//pkg/syserror",
        "//pkg/waiter",
    ],
)

go_test(
    name = "vfs_test",
    size = "small",
    srcs = [
        "file_description_impl_util_test.go",
        "mount_test.go",
    ],
    embed = [":vfs"],
    deps = [
        "//pkg/abi/linux",
        "//pkg/sentry/context",
        "//pkg/sentry/context/contexttest",
        "//pkg/sentry/usermem",
        "//pkg/sync",
        "//pkg/syserror",
    ],
)
