load("//tools/go_stateify:defs.bzl", "go_library")
load("@io_bazel_rules_go//go:def.bzl", "go_test")

package(
    default_visibility = ["//visibility:public"],
    licenses = ["notice"],
)

go_library(
    name = "pool",
    srcs = [
        "pool.go",
    ],
    importpath = "gvisor.dev/gvisor/pkg/pool",
)

go_test(
    name = "pool_test",
    size = "small",
    srcs = [
        "pool_test.go",
    ],
    embed = [":pool"],
)
