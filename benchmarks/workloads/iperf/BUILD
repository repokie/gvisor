load("//benchmarks:defs.bzl", "py_library", "py_test", "requirement")
load("@rules_pkg//:pkg.bzl", "pkg_tar")

package(
    default_visibility = ["//benchmarks:__subpackages__"],
    licenses = ["notice"],
)

py_library(
    name = "iperf",
    srcs = ["__init__.py"],
)

py_test(
    name = "iperf_test",
    srcs = ["iperf_test.py"],
    python_version = "PY3",
    deps = [
        ":iperf",
        requirement("attrs", False),
        requirement("atomicwrites", False),
        requirement("more-itertools", False),
        requirement("pathlib2", False),
        requirement("pluggy", False),
        requirement("py", False),
        requirement("pytest", True),
        requirement("six", False),
    ],
)

pkg_tar(
    name = "tar",
    srcs = [
        "Dockerfile",
    ],
)
