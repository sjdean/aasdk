# Release Notes

---

## v4.1.4 — 2026-03-10

### Bug fixes

- **MediaSourceService**: corrected wrong message ID being used for media data payloads (`MEDIA_MESSAGE_CODEC_CONFIG` was incorrectly sent in place of `MEDIA_MESSAGE_DATA`).
- **Version request**: protocol major/minor version is now sourced from `GalConstants` in `aap_protobuf` rather than the local `Version.hpp` header; fixed the `boost::endian` cast to operate on `uint16_t` to avoid byte-swapping a 32-bit enum value.

### Build system

- **Yocto / cross-compilation**: fixed a critical failure where absolute sysroot paths were being baked into exported CMake targets, breaking any consumer building against a different sysroot. Protobuf is now linked via the `Protobuf::libprotobuf` imported target throughout.
- **Proto header install**: replaced `protobuf_generate_cpp()` with `protobuf_generate()` to preserve the source directory structure in generated headers. Fixed a double-nesting issue that caused headers to install at the wrong path. `#include <aap_protobuf/service/...>` now resolves correctly in both the build tree and installed sysroot.
- **macOS**: added a `FindProtobuf` shim so `protobuf_generate_cpp` is always available regardless of config vs module discovery mode; fixed compiler flag separator (spaces silently failed with Xcode generators; semicolons used throughout).
- **Library versioning**: `SOVERSION` now correctly tracks the major release number only; was previously set to the git commit count, which changed every commit and broke ABI tracking. `.so` filename no longer contains the `+` display suffix.
- **CMake package config**: added `find_dependency()` for `aap_protobuf`, `Boost`, and `OpenSSL` so downstream consumers get transitive dependencies resolved against their own sysroot.
- **CPack / Debian packaging**: fixed `.deb` corruption caused by a non-ASCII character in the maintainer field.
- **libusb discovery**: unified to config mode first, pkg-config fallback, result exposed as a single `LIBUSB_TARGET` for consistent cross-platform linking.
- **Git metadata**: gracefully degrades when `.git` is absent (Yocto work directories, CI tarballs); falls back to `unknown` rather than failing.
- Replaced bare `include_directories()` with target-scoped `target_include_directories()` throughout both `aasdk` and `aap_protobuf`.

---

## v2.0.1 — 2024-11-21

Initial release of the AAP 1.6 rework.

### New features

- **Android Auto Protocol 1.6 protobuf definitions**: restructured and expanded all proto files based on the reverse-engineering research by [milek7](https://milek7.pl/.stuff/galdocs/readme.md). Enums and message types now carry their full AAP 1.6 naming conventions for correctness and readability.
- **New service channels**: added initial implementations for `GenericNotification`, `MediaBrowser`, `MediaPlaybackStatus`, `PhoneStatus`, `Radio`, `VendorExtension`, and `WifiProjection`.
- **Media service hierarchy**: refactored `AudioService`/`VideoService`/`AVInput` into a cleaner `MediaSinkService` hierarchy — `AudioMediaSinkService` and `VideoMediaSinkService` now extend a common base, with individual channel types extending those.

### Improvements

- Logging (`AASDK_LOG`) entries updated for consistency across all services.
- CMake simplified: defaults to Release mode; unnecessary parameters removed.