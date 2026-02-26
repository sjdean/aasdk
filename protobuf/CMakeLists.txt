cmake_minimum_required(VERSION 3.16)

# ─── Version (single source of truth) ────────────────────────────────────────
# Numeric triplet only — used for library VERSION/SOVERSION and CMake package.
# Display string (with date) is separate and never used for file naming.
set(LIBRARY_BUILD_DATE          "20260225")
set(LIBRARY_BUILD_MAJOR_RELEASE 4)
set(LIBRARY_BUILD_MINOR_RELEASE 1)
set(LIBRARY_BUILD_INCREMENTAL   3)
set(AAP_PROTO_VERSION           1.6)

set(LIBRARY_BUILD_VERSION_STRING
        "${LIBRARY_BUILD_MAJOR_RELEASE}.${LIBRARY_BUILD_MINOR_RELEASE}.${LIBRARY_BUILD_INCREMENTAL}+${LIBRARY_BUILD_DATE}")

# Pass the numeric triplet into CMake's project() so it flows into
# write_basic_package_version_file automatically.
# Never use LIBRARY_BUILD_VERSION_STRING here — the '+' breaks file naming.
project(aap_protobuf
        VERSION "${LIBRARY_BUILD_MAJOR_RELEASE}.${LIBRARY_BUILD_MINOR_RELEASE}.${LIBRARY_BUILD_INCREMENTAL}"
        DESCRIPTION "Android Auto Projection Protocol Library (AAP proto ${AAP_PROTO_VERSION})"
        LANGUAGES CXX
)

message(STATUS "aap_protobuf version : ${LIBRARY_BUILD_VERSION_STRING}")
message(STATUS "AAP protocol version : ${AAP_PROTO_VERSION}")
message(STATUS "Build type           : ${CMAKE_BUILD_TYPE}")
if(CMAKE_CROSSCOMPILING)
    message(STATUS "Cross-compiling for  : ${CMAKE_SYSTEM_NAME} / ${CMAKE_SYSTEM_PROCESSOR}")
endif()

# ─── Language standard ───────────────────────────────────────────────────────
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

# ─── Default build type ──────────────────────────────────────────────────────
if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
    message(STATUS "Defaulting to Release build")
    set(CMAKE_BUILD_TYPE Release CACHE STRING "Build type" FORCE)
    set_property(CACHE CMAKE_BUILD_TYPE PROPERTY STRINGS
            "Debug" "Release" "MinSizeRel" "RelWithDebInfo")
endif()

# ─── GNU install dirs (required for correct Yocto/sysroot paths) ─────────────
include(GNUInstallDirs)

# ─── Protobuf discovery (cross-platform, single path) ────────────────────────
#
# Strategy:
#   1. Try config mode first — works on Mac (Homebrew), vcpkg, Conan, Yocto SDK.
#   2. Fall back to module mode — works on plain Linux distros.
#
# After this block the following are always defined:
#   PROTOBUF_TARGET   — an imported (relocatable) target to link against.
#                       This is critical for Yocto: an imported target does NOT
#                       bake an absolute sysroot path into the exported targets
#                       file, so consumers resolve it against their own sysroot.
#   protobuf_generate_cpp is guaranteed to exist (see shim below).
#
find_package(protobuf CONFIG QUIET)
if(protobuf_FOUND)
    message(STATUS "Protobuf found via config mode (${protobuf_VERSION})")
    set(PROTOBUF_TARGET protobuf::libprotobuf)
else()
    find_package(Protobuf REQUIRED)
    message(STATUS "Protobuf found via module mode (${Protobuf_VERSION})")
    # Use the imported target (available since CMake 3.10), NOT ${Protobuf_LIBRARIES}.
    # ${Protobuf_LIBRARIES} is an absolute path which gets baked into the exported
    # TargetsFile and will break any consumer building against a different sysroot.
    set(PROTOBUF_TARGET Protobuf::libprotobuf)
endif()

# protobuf_generate_cpp lives in FindProtobuf.cmake (module mode).
# Config mode exposes protobuf_generate() but NOT protobuf_generate_cpp.
# Load the module manually so the macro is always available.
if(NOT COMMAND protobuf_generate_cpp)
    include(FindProtobuf)
endif()

# ─── Proto sources ───────────────────────────────────────────────────────────
# Generated headers go into their own subdirectory, preserving source structure.
# e.g. ${SOURCE}/service/bluetooth/X.proto → ${PROTO_BINARY_DIR}/service/bluetooth/X.pb.h
# Install: ${PROTO_BINARY_DIR}/ → include/aap_protobuf/
# Result:  usr/include/aap_protobuf/service/bluetooth/X.pb.h  ✓
# Include: -Iusr/include → #include <aap_protobuf/service/bluetooth/X.pb.h> resolves ✓
set(PROTO_BINARY_DIR "${CMAKE_CURRENT_BINARY_DIR}/proto_gen")

file(GLOB_RECURSE source_proto_files
        CONFIGURE_DEPENDS
        "${CMAKE_CURRENT_SOURCE_DIR}/*.proto"
)

if(NOT source_proto_files)
    message(FATAL_ERROR "No .proto files found under ${CMAKE_CURRENT_SOURCE_DIR}")
endif()

# protobuf_generate() preserves directory structure via IMPORT_DIRS.
# protobuf_generate_cpp() always flattens — do not use it here.
protobuf_generate(
        LANGUAGE       cpp
        OUT_VAR        PROTO_SRCS
        PROTOS         ${source_proto_files}
        IMPORT_DIRS    "${CMAKE_CURRENT_SOURCE_DIR}"
        PROTOC_OUT_DIR "${PROTO_BINARY_DIR}"
)

# ─── Library target ──────────────────────────────────────────────────────────
option(BUILD_SHARED_LIBS "Build shared libraries" ON)

# add_library() respects BUILD_SHARED_LIBS automatically when no STATIC/SHARED
# keyword is given — no if/else needed.
add_library(aap_protobuf ${PROTO_SRCS} ${PROTO_HDRS})

if(BUILD_SHARED_LIBS)
    message(STATUS "Library type         : SHARED")
else()
    message(STATUS "Library type         : STATIC")
endif()

# All include paths go through the target — no bare include_directories()
# BUILD_INTERFACE: -I<binary_dir> so #include <aap_protobuf/service/...> resolves
#                  from the proto_gen/ subdir during the build itself
# INSTALL_INTERFACE: -I<prefix>/include so consumers resolve the same path post-install
target_include_directories(aap_protobuf
        PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_BINARY_DIR}>
        $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
)
# Link using the imported target — relocatable and sysroot-safe.
target_link_libraries(aap_protobuf
        PUBLIC ${PROTOBUF_TARGET}
)

# ─── Version properties ──────────────────────────────────────────────────────
# VERSION  : numeric triplet — names the .so file (e.g. libaap_protobuf.so.4.1.3)
# SOVERSION: ABI major only — bump only on breaking ABI changes
# Do NOT use LIBRARY_BUILD_VERSION_STRING here — the '+' breaks the linker.
set_target_properties(aap_protobuf PROPERTIES
        VERSION   "${LIBRARY_BUILD_MAJOR_RELEASE}.${LIBRARY_BUILD_MINOR_RELEASE}.${LIBRARY_BUILD_INCREMENTAL}"
        SOVERSION "${LIBRARY_BUILD_MAJOR_RELEASE}"
)

# ─── Install rules ───────────────────────────────────────────────────────────
install(TARGETS aap_protobuf
        EXPORT   aap_protobufTargets
        LIBRARY  DESTINATION "${CMAKE_INSTALL_LIBDIR}"
        ARCHIVE  DESTINATION "${CMAKE_INSTALL_LIBDIR}"
        RUNTIME  DESTINATION "${CMAKE_INSTALL_BINDIR}"
        INCLUDES DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}"
)

# Install only the generated headers, preserving structure, no CMakeFiles junk.
# proto_gen/service/bluetooth/X.pb.h → include/aap_protobuf/service/bluetooth/X.pb.h
install(DIRECTORY "${PROTO_BINARY_DIR}/"
        DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}/aap_protobuf"
        FILES_MATCHING PATTERN "*.pb.h"
)

# ─── CMake package config ────────────────────────────────────────────────────
include(CMakePackageConfigHelpers)

# PROJECT_VERSION is purely numeric — CMake can compare it correctly.
# LIBRARY_BUILD_VERSION_STRING contains '+' and must never be used here.
write_basic_package_version_file(
        "${CMAKE_CURRENT_BINARY_DIR}/aap_protobufConfigVersion.cmake"
        VERSION       "${PROJECT_VERSION}"
        COMPATIBILITY AnyNewerVersion
)

configure_package_config_file(Config.cmake.in
        "${CMAKE_CURRENT_BINARY_DIR}/aap_protobufConfig.cmake"
        INSTALL_DESTINATION "${CMAKE_INSTALL_LIBDIR}/cmake/aap_protobuf"
)

install(EXPORT aap_protobufTargets
        FILE        aap_protobufTargets.cmake
        NAMESPACE   AAPProto::
        DESTINATION "${CMAKE_INSTALL_LIBDIR}/cmake/aap_protobuf"
)

install(FILES
        "${CMAKE_CURRENT_BINARY_DIR}/aap_protobufConfig.cmake"
        "${CMAKE_CURRENT_BINARY_DIR}/aap_protobufConfigVersion.cmake"
        DESTINATION "${CMAKE_INSTALL_LIBDIR}/cmake/aap_protobuf"
)