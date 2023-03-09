# Net

A small network library written for use in C++ applications.

## Features

- SslStream: An OpenSSL wrapper for TCP/UDP sockets.
- HttpConnection/HttpServer: HTTP(s) client/server.
- WebSocketClient: WebSocket client.

## Getting Started

### Prerequisites

- [CMake](https://cmake.org/download/) (version >= 3.15)
- Compiler with C++20 support, i.e. MSVC, GCC, Clang

### Installing

This library uses [CPM.cmake](https://github.com/cpm-cmake/CPM.cmake) to manage dependencies. It is an amazing package manager for CMake projects and allows us to install the entire library using the following commands:

```bash
  git clone https://www.github.com/xminent/net
  cd net
  cmake -S . -B build
  cmake --build build --target install
```

From there you can simply integrate it into your CMake project like so:

```cmake
    find_package(net REQUIRED)
    target_link_libraries(${PROJECT_NAME} PRIVATE net::net)
```

## Usage/Examples

See [examples](https://github.com/Xminent/net/tree/main/examples).

## Dependencies

### Third party Dependencies

- [expected](https://github.com/TartanLlama/expected) (comes bundled with project)
- [OpenSSL](https://openssl.org/) (comes bundled with project, unless you have it installed)

## License

[MIT](https://choosealicense.com/licenses/mit/)
