cc_binary(
    name = "vpn_client",
    srcs = ["src/vpn_client.cpp"],
    deps = [

        "//src/core:core",
        "//src/network:network",
        "//src/crypto:crypto",

        "@boost.asio//:boost.asio",
        "@boost.system//:boost.system",

        "@openssl//:crypto",
        "@openssl//:ssl",

    ],
    copts = [
        # Turn Asio into header-only
        "-DBOOST_ASIO_HEADER_ONLY",
    ],

)

cc_binary(
    name = "vpn_server",
    srcs = ["src/vpn_server.cpp"],
    deps = [

        "//src/core:core",
        "//src/network:network",
        "//src/crypto:crypto",

        "@boost.asio//:boost.asio",
        "@boost.system//:boost.system",

        "@openssl//:crypto",
        "@openssl//:ssl",

    ],
    copts = [
        # Turn Asio into header-only
        "-DBOOST_ASIO_HEADER_ONLY",
    ],

)



load("@hedron_compile_commands//:refresh_compile_commands.bzl", "refresh_compile_commands")

refresh_compile_commands(
    name = "refresh_compile_commands",
    targets = [
        "//:vpn_client",
        "//:test_client",
    ],
    exclude_headers = "external",
    exclude_external_sources = True,
)
