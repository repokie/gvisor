load("@io_bazel_rules_go//go:def.bzl", "go_test")
load("//tools/go_generics:defs.bzl", "go_template_instance")
load("//tools/go_stateify:defs.bzl", "go_library")

package(licenses = ["notice"])

go_template_instance(
    name = "waiter_list",
    out = "waiter_list.go",
    package = "waiter",
    prefix = "waiter",
    template = "//pkg/ilist:generic_list",
    types = {
        "Element": "*Entry",
        "Linker": "*Entry",
    },
)

go_library(
    name = "waiter",
    srcs = [
        "waiter.go",
        "waiter_list.go",
    ],
    importpath = "gvisor.dev/gvisor/pkg/waiter",
    visibility = ["//visibility:public"],
    deps = ["//pkg/sync"],
)

go_test(
    name = "waiter_test",
    size = "small",
    srcs = [
        "waiter_test.go",
    ],
    embed = [":waiter"],
)
