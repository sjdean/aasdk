cmake_minimum_required(VERSION 3.16)

# ─── Version (single source of truth) ────────────────────────────────────────
# Numeric triplet only — used for library VERSION/SOVERSION and CMake package.
# Display string (with date/git) is separate and never used for file naming.
set(LIBRARY_BUILD_DATE          "20260310")
set(LIBRARY_BUILD_MAJOR_RELEASE 4)
set(LIBRARY_BUILD_MINOR_RELEASE 1)
set(LIBRARY_BUILD_INCREMENTAL   4)

set(LIBRARY_BUILD_VERSION_STRING
        "${LIBRARY_BUILD_MAJOR_RELEASE}.${LIBRARY_BUILD_MINOR_RELEASE}.${LIBRARY_BUILD_INCREMENTAL}+${LIBRARY_BUILD_DATE}")

# Pass the numeric triplet into CMake's project() so it flows into
# write_basic_package_version_file automatically.
# Never use LIBRARY_BUILD_VERSION_STRING here — the '+' breaks file naming.
project(aasdk
        VERSION "${LIBRARY_BUILD_MAJOR_RELEASE}.${LIBRARY_BUILD_MINOR_RELEASE}.${LIBRARY_BUILD_INCREMENTAL}"
        DESCRIPTION "Android Auto SDK Library"
        LANGUAGES CXX
)

# ─── Language standard ────────────────────────────────────────────────────────
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

# ─── Module path ─────────────────────────────────────────────────────────────
list(APPEND CMAKE_MODULE_PATH "${PROJECT_SOURCE_DIR}/cmake_modules/")

# ─── GNU install dirs (required for Yocto sysroot correctness) ───────────────
include(GNUInstallDirs)

# ─── Default build type ───────────────────────────────────────────────────────
if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
    message(STATUS "Defaulting to Release build")
    set(CMAKE_BUILD_TYPE Release CACHE STRING "Build type" FORCE)
    set_property(CACHE CMAKE_BUILD_TYPE PROPERTY STRINGS
            "Debug" "Release" "MinSizeRel" "RelWithDebInfo")
endif()

message(STATUS "Build type      : ${CMAKE_BUILD_TYPE}")
message(STATUS "System          : ${CMAKE_SYSTEM_NAME} / ${CMAKE_SYSTEM_PROCESSOR}")
if(CMAKE_CROSSCOMPILING)
    message(STATUS "Cross-compiling : YES (target: ${CMAKE_SYSTEM_PROCESSOR})")
endif()

# ─── Git metadata (display only — never used in file/library names) ───────────
# Gracefully degrade when .git is absent (Yocto work dir, CI tarballs, etc.)
find_package(Git QUIET)
if(Git_FOUND)
    execute_process(
            COMMAND "${GIT_EXECUTABLE}" rev-parse --short HEAD
            WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}"
            OUTPUT_VARIABLE   _git_short_hash
            ERROR_QUIET OUTPUT_STRIP_TRAILING_WHITESPACE
    )
endif()
if(NOT _git_short_hash OR _git_short_hash STREQUAL "")
    set(_git_short_hash "unknown")
endif()

# Append git hash to the display string if available.
# LIBRARY_BUILD_VERSION_STRING is used only in message() and generated headers.
if(NOT _git_short_hash STREQUAL "unknown")
    set(LIBRARY_BUILD_VERSION_STRING
            "${LIBRARY_BUILD_MAJOR_RELEASE}.${LIBRARY_BUILD_MINOR_RELEASE}.${LIBRARY_BUILD_INCREMENTAL}+${LIBRARY_BUILD_DATE}.g${_git_short_hash}")
endif()
message(STATUS "aasdk version   : ${LIBRARY_BUILD_VERSION_STRING}")

# ─── ccache ───────────────────────────────────────────────────────────────────
find_program(CCACHE_PROGRAM ccache)
if(CCACHE_PROGRAM)
    message(STATUS "ccache          : ${CCACHE_PROGRAM}")
    set_property(GLOBAL PROPERTY RULE_LAUNCH_COMPILE "${CCACHE_PROGRAM}")
endif()

# ─── Dependencies ─────────────────────────────────────────────────────────────

# aap_protobuf — provides AAPProto::aap_protobuf
# Its Config.cmake.in handles finding protobuf transitively and correctly
# per-sysroot. Do NOT separately find or link Protobuf here — doing so with
# ${PROTOBUF_LIBRARIES} is what caused the original Yocto path bake-in error.
find_package(aap_protobuf REQUIRED CONFIG)

# Qt6
find_package(Qt6 REQUIRED COMPONENTS Core Network)

# Boost (system only — log removed in Stage 1.1)
find_package(Boost REQUIRED COMPONENTS system)

# OpenSSL
find_package(OpenSSL REQUIRED)

# ─── libusb discovery (three-tier: config → pkg-config → manual) ─────────────
# Yocto's libusb1 recipe does not install CMake config files, and pkg-config
# is a native tool unavailable in the cross sysroot. The manual fallback using
# find_library/find_path always works because Yocto stages headers and libs
# into the recipe sysroot at known FHS paths.
find_package(libusb-1.0 QUIET CONFIG)
if(libusb-1.0_FOUND OR TARGET libusb-1.0::libusb-1.0)
    set(LIBUSB_TARGET libusb-1.0::libusb-1.0)
    message(STATUS "libusb-1.0      : found via config mode")
else()
    # Try pkg-config (works on desktop Linux/Mac, not in Yocto cross sysroot)
    find_package(PkgConfig QUIET)
    if(PKG_CONFIG_FOUND)
        pkg_check_modules(libusb QUIET IMPORTED_TARGET libusb-1.0)
    endif()

    if(TARGET PkgConfig::libusb)
        set(LIBUSB_TARGET PkgConfig::libusb)
        message(STATUS "libusb-1.0      : found via pkg-config")
    else()
        # Manual fallback — safe for Yocto cross sysroot, Windows (vcpkg), Mac
        find_path(LIBUSB_INCLUDE_DIR
                NAMES libusb.h
                PATH_SUFFIXES libusb-1.0
        )
        find_library(LIBUSB_LIBRARY
                NAMES usb-1.0 usb
        )

        if(NOT LIBUSB_INCLUDE_DIR OR NOT LIBUSB_LIBRARY)
            message(FATAL_ERROR
                    "libusb-1.0 not found. Tried config mode, pkg-config, and "
                    "find_library. Ensure libusb1 is in DEPENDS in your .bb recipe.")
        endif()

        # Wrap in an imported target so the rest of the file stays clean
        add_library(libusb-1.0::libusb-1.0 UNKNOWN IMPORTED)
        set_target_properties(libusb-1.0::libusb-1.0 PROPERTIES
                IMPORTED_LOCATION             "${LIBUSB_LIBRARY}"
                INTERFACE_INCLUDE_DIRECTORIES "${LIBUSB_INCLUDE_DIR}"
        )
        set(LIBUSB_TARGET libusb-1.0::libusb-1.0)
        message(STATUS "libusb-1.0      : found via find_library (${LIBUSB_LIBRARY})")
    endif()
endif()

# Winsock (Windows only)
if(WIN32)
    set(PLATFORM_LINK_LIBS ws2_32)
endif()

# ─── Source files ─────────────────────────────────────────────────────────────
# CONFIGURE_DEPENDS causes CMake to re-glob when files are added/removed.
# Yocto's do_configure re-runs cmake before do_compile so this is safe here.
file(GLOB_RECURSE _all_sources  CONFIGURE_DEPENDS "${CMAKE_CURRENT_SOURCE_DIR}/src/*.cpp")
file(GLOB_RECURSE _test_sources CONFIGURE_DEPENDS "${CMAKE_CURRENT_SOURCE_DIR}/src/*.ut.cpp")
list(REMOVE_ITEM _all_sources ${_test_sources})

if(NOT _all_sources)
    message(FATAL_ERROR "No source files found under ${CMAKE_CURRENT_SOURCE_DIR}/src/")
endif()

# ─── Library target ───────────────────────────────────────────────────────────
option(BUILD_SHARED_LIBS "Build shared libraries" ON)

# add_library() respects BUILD_SHARED_LIBS automatically when no STATIC/SHARED
# keyword is given — no if/else needed.
add_library(aasdk ${_all_sources})

if(BUILD_SHARED_LIBS)
    message(STATUS "Library type    : SHARED")
else()
    message(STATUS "Library type    : STATIC")
endif()

# ─── Compiler options (cross-platform) ───────────────────────────────────────
target_compile_features(aasdk PRIVATE cxx_std_17)

# Semicolons required as separators inside generator expressions — spaces work
# in Makefiles/Ninja but silently fail with Xcode and Visual Studio generators.
target_compile_options(aasdk PRIVATE
        $<$<CXX_COMPILER_ID:GNU,Clang,AppleClang>:-Wall;-Wextra;-pedantic>
        $<$<CXX_COMPILER_ID:MSVC>:/W4>
)

target_compile_definitions(aasdk PRIVATE
        $<$<CONFIG:Release>:NDEBUG>
)

# ─── Include directories (target-scoped only) ─────────────────────────────────
target_include_directories(aasdk
        PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
        $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}/aap_protobuf>  # ← ADD THIS
        PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/include_ut
)

# ─── Link libraries ───────────────────────────────────────────────────────────
# AAPProto::aap_protobuf brings in protobuf transitively via its Config.cmake.in
# using find_dependency(), which resolves against the consumer's own sysroot.
# Do NOT also link ${PROTOBUF_LIBRARIES} — that raw path variable is what caused
# the 'missing libprotobuf.so' Yocto error.
target_link_libraries(aasdk
        PUBLIC
        AAPProto::aap_protobuf
        PRIVATE
        ${LIBUSB_TARGET}
        Boost::system
        Qt6::Core
        Qt6::Network
        OpenSSL::SSL
        OpenSSL::Crypto
        ${PLATFORM_LINK_LIBS}
)

# ─── Version properties ───────────────────────────────────────────────────────
# VERSION  : numeric triplet — names the .so file (e.g. libaasdk.so.4.1.1)
# SOVERSION: ABI major only — bump only on breaking ABI changes
# Do NOT use LIBRARY_BUILD_VERSION_STRING here — the '+' breaks the linker.
set_target_properties(aasdk PROPERTIES
        VERSION   "${LIBRARY_BUILD_MAJOR_RELEASE}.${LIBRARY_BUILD_MINOR_RELEASE}.${LIBRARY_BUILD_INCREMENTAL}"
        SOVERSION "${LIBRARY_BUILD_MAJOR_RELEASE}"
)

# ─── Install rules ────────────────────────────────────────────────────────────
install(TARGETS aasdk
        EXPORT   aasdkTargets
        ARCHIVE  DESTINATION "${CMAKE_INSTALL_LIBDIR}"   COMPONENT libraries
        LIBRARY  DESTINATION "${CMAKE_INSTALL_LIBDIR}"   COMPONENT libraries
        RUNTIME  DESTINATION "${CMAKE_INSTALL_BINDIR}"   COMPONENT libraries
)

install(DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/include/aasdk"
        DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}"
        COMPONENT   headers
)

install(EXPORT aasdkTargets
        FILE        aasdkTargets.cmake
        NAMESPACE   AASDK::
        DESTINATION "${CMAKE_INSTALL_LIBDIR}/cmake/aasdk"
        COMPONENT   libraries
)

# ─── CMake package config ─────────────────────────────────────────────────────
include(CMakePackageConfigHelpers)

# PROJECT_VERSION is purely numeric — CMake can compare it correctly.
# LIBRARY_BUILD_VERSION_STRING contains '+' and must never be used here.
write_basic_package_version_file(
        "${CMAKE_CURRENT_BINARY_DIR}/aasdkConfigVersion.cmake"
        VERSION       "${PROJECT_VERSION}"
        COMPATIBILITY AnyNewerVersion
)

configure_package_config_file(
        "${CMAKE_CURRENT_SOURCE_DIR}/Config.cmake.in"
        "${CMAKE_CURRENT_BINARY_DIR}/aasdkConfig.cmake"
        INSTALL_DESTINATION "${CMAKE_INSTALL_LIBDIR}/cmake/aasdk"
)

install(FILES
        "${CMAKE_CURRENT_BINARY_DIR}/aasdkConfig.cmake"
        "${CMAKE_CURRENT_BINARY_DIR}/aasdkConfigVersion.cmake"
        DESTINATION "${CMAKE_INSTALL_LIBDIR}/cmake/aasdk"
        COMPONENT   libraries
)

# ─── Unit tests ───────────────────────────────────────────────────────────────
if(AASDK_TEST)
    message(STATUS "Configuring unit tests")

    if(_test_sources)
        include(ExternalGtest)

        add_executable(aasdk_ut ${_test_sources})
        target_include_directories(aasdk_ut PRIVATE
                ${GTEST_INCLUDE_DIRS}
                ${GMOCK_INCLUDE_DIRS}
        )
        target_link_libraries(aasdk_ut PRIVATE aasdk gmock gtest)

        include(CTest)
        add_test(NAME aasdk_unit_test COMMAND aasdk_ut)

        if(AASDK_CODE_COVERAGE)
            include(CodeCoverage)
            append_coverage_compiler_flags()
            setup_target_for_coverage(
                    NAME         aasdk_coverage
                    EXECUTABLE   aasdk_ut
                    DEPENDENCIES aasdk_ut
            )
        endif()
    else()
        message(WARNING "AASDK_TEST is ON but no *.ut.cpp files were found")
    endif()
endif()

# ─── CPack ────────────────────────────────────────────────────────────────────
set(CPACK_GENERATOR                         "DEB")
set(CPACK_PACKAGE_VENDOR                    "AASDK")
# ASCII 'I' only — the original had a Turkish 'İ' which corrupts the .deb manifest
set(CPACK_DEBIAN_PACKAGE_MAINTAINER         "AASDK")
# Use numeric PROJECT_VERSION — not the display string with '+'
set(CPACK_PACKAGE_VERSION                   "${PROJECT_VERSION}")
set(CPACK_DEBIAN_FILE_NAME                  DEB-DEFAULT)
set(CPACK_DEBIAN_PACKAGE_DEPENDS
        "libusb-1.0-0, libboost-system-dev, libssl-dev, libprotobuf-dev")
set(CPACK_COMPONENTS_ALL                    libraries headers)
set(CPACK_COMPONENT_LIBRARIES_DISPLAY_NAME  "Libraries")
set(CPACK_COMPONENT_HEADERS_DISPLAY_NAME    "C++ Headers")
set(CPACK_COMPONENT_LIBRARIES_DESCRIPTION   "AASDK shared/static libraries")
set(CPACK_COMPONENT_HEADERS_DESCRIPTION     "C/C++ header files for AASDK")
set(CPACK_COMPONENT_HEADERS_DEPENDS         libraries)
include(CPack)