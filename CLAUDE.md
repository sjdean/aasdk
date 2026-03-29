# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project

A C++ library implementing the Android Auto Protocol (AAP) v1.6, providing USB/TCP transport, SSL encryption, AOAP device management, and all service channel implementations needed by a headunit. It is a fork of the original f1x/aasdk → Crankshaft-NG lineage, substantially reworked by CubeOne (Simon Dean).

## Build

Dependencies: `cmake`, `protobuf-compiler`, `libprotobuf-dev`, `libusb-1.0.0-dev`, `libssl-dev`, `libboost-dev`, `libboost-system-dev`, `libboost-log-dev`

```bash
# Standard release build (out-of-source recommended)
cmake -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j$(nproc)
cmake --install build

# With unit tests
cmake -B build -DCMAKE_BUILD_TYPE=Debug -DAASDK_TEST=ON
cmake --build build --target aasdk_ut
./build/aasdk_ut

# Run a single test filter
./build/aasdk_ut --gtest_filter=MessengerUT.*

# With code coverage
cmake -B build -DCMAKE_BUILD_TYPE=Debug -DAASDK_TEST=ON -DAASDK_CODE_COVERAGE=ON

# Raspberry Pi cross-compile
cmake -B build -DCMAKE_TOOLCHAIN_FILE=rpi-toolchain.cmake -DCMAKE_BUILD_TYPE=Release
```

The build defaults to Release mode. Unit tests use the `*.ut.cpp` file suffix and are excluded from the main library sources automatically.

## Versioning — two separate version numbers

There are **two independent version numbers** and it is important not to confuse them:

| Version | Location | Meaning |
|---|---|---|
| **Library version** (4.1.x) | `CMakeLists.txt` `LIBRARY_BUILD_*` variables | The CMake/pkg-config/SOVERSION of the built `.so`. Used for packaging. |
| **Protocol version** (1.6) | `include/aasdk/Version.hpp` `AASDK_MAJOR/MINOR` | The AAP protocol version negotiated on the wire with the Android device. |

When bumping a release: update `LIBRARY_BUILD_MAJOR_RELEASE`, `MINOR_RELEASE`, `INCREMENTAL`, and `LIBRARY_BUILD_DATE` in `CMakeLists.txt`. Do **not** change `Version.hpp` unless the AAP wire protocol itself changes.

## CI/CD

The GitHub Actions workflow (`.github/workflows/build_compile.yml`) triggers on **any pushed tag**. It builds Docker-based Debian packages for `armhf` and `amd64`, then creates a draft GitHub release. Push a tag to trigger a release build.

## Architecture

The library is layered; each layer depends only on the one below it.

```
Service Channels  (src/Channel/*)       — one class per AAP service
      ↓
Messenger         (src/Messenger/*)     — framing, encryption, channel mux
      ↓
Transport         (src/Transport/*)     — ITransport interface
      ↓
USB / TCP         (src/USB/*, src/TCP/*)— hardware I/O via libusb / Boost.ASIO
```

**Async model:** All I/O is async via `io::Promise<T>` (a bespoke deferred-result type, not `std::promise`). Operations are strand-serialised through `IOContextWrapper` (Boost.ASIO). Never block on a Promise inside a strand callback.

**Interface/implementation split:** Every significant class has an `I*.hpp` pure-virtual interface in `include/aasdk/` and a concrete implementation in `src/`. Event callbacks are separate `I*EventHandler` interfaces. This pattern is used throughout and must be maintained for new channels.

**Channel implementation pattern:**
- `include/aasdk/Channel/<Service>/I<Service>.hpp` — public interface
- `include/aasdk/Channel/<Service>/I<Service>EventHandler.hpp` — callback interface
- `src/Channel/<Service>/<Service>.cpp` — implementation
- Messages arrive via `enqueueReceive`, are dispatched to the EventHandler; outgoing messages go via `enqueueSend` on the Messenger.

## Protobuf

254 `.proto` files live under `protobuf/aap_protobuf/`. They are compiled by the separate `aap_protobuf` CMake package (found via `find_package(aap_protobuf CONFIG REQUIRED)`), not built inside this repo. The directory structure mirrors the AAP service hierarchy:

```
aap_protobuf/
  channel/control/     — handshake, version, service discovery
  service/<name>/message/  — per-service request/response messages
  shared/              — PhoneInfo, MessageStatus (used across services)
```

Message IDs are defined as constants alongside each service's channel implementation, not in the proto files themselves.

## Key files

| File | Purpose |
|---|---|
| `CMakeLists.txt` | Single source of truth for library version and all build config |
| `include/aasdk/Version.hpp` | AAP wire protocol version constants |
| `include/aasdk/IO/Promise.hpp` | The async primitive used everywhere |
| `include/aasdk/Messenger/IMessenger.hpp` | Top-level protocol interface |
| `include/aasdk/Transport/ITransport.hpp` | Transport abstraction |
| `include/aasdk/USB/IUSBHub.hpp` | USB device detection entry point |
| `src/Messenger/Messenger.cpp` | Frame parsing, encryption dispatch, channel mux |
| `src/Transport/USBTransport.cpp` | USB bulk-transfer implementation |

## Branching strategy

| Branch | Purpose |
|---|---|
| `main` | Stable releases — merge here and tag for a release |
| `develop` | Active development |
| `feature/<name>` | Feature branches off `develop` |
| `release/<major.minor>` | Optional stabilisation branch before merging to `main` |

Tags use `v<LIBRARY_BUILD_VERSION>` format (e.g. `v4.1.4`). Historical upstream tags `v1.0`–`v2.1` on `origin/master` reflect the pre-fork lineage and should not be moved.