cc_binary(
    name = "vpn_app",
    srcs = ["src/main.cpp"],
    deps = [
        "//src/core:core",
        "//src/network:network",
        "@boost.asio//:boost.asio",
        "@openssl//:crypto",
        "//src/crypto:crypto",

    ],
)

cc_binary(
    name = "test_client",
    srcs = ["test/test_client_spammer.cpp"],
    deps = ["@boost.asio//:boost.asio",
            "//src/protocol:protocol",
            "//src/core:core",

    ]
)

load("@hedron_compile_commands//:refresh_compile_commands.bzl", "refresh_compile_commands")

refresh_compile_commands(
    name = "refresh_compile_commands",
    targets = [
        "//:vpn_app",
        "//:test_client",
    ],
    exclude_headers = "external",
    exclude_external_sources = True,
)
