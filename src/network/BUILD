cc_library(
    name ="network",
    srcs = glob(["*.cpp"]),
    visibility = ["//visibility:public"],
    deps = [
        "//include/network:network_headers",
        "//src/core:core",
        "@boost.asio//:boost.asio",
        "//src/crypto:crypto",
        "@openssl//:crypto",
        "@openssl//:ssl",
    ],
)
