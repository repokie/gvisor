load("//tools/go_stateify:defs.bzl", "go_library")

package(licenses = ["notice"])

go_library(
    name = "tun",
    srcs = [
        "protocol.go",
        "tun_unsafe.go",
    ],
    importpath = "gvisor.dev/gvisor/pkg/tcpip/link/tun",
    visibility = ["//visibility:public"],
    deps = [
        "//pkg/tcpip",
    ],
)
