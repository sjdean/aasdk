cmake_minimum_required(VERSION 3.15) # Bumped to 3.15 for modern practices

project(aasdk)
message(STATUS "AASDK Library")

# --- Global Configuration ---
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_POSITION_INDEPENDENT_CODE ON) # Ensures -fPIC for all targets

set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${PROJECT_SOURCE_DIR}/cmake_modules/")

# Use GNUInstallDirs for standard FHS-compliant paths (e.g., lib, lib64)
include(GNUInstallDirs)

# --- Automatic Versioning (Best Practice) ---
include(gitversion)

set(LIBRARY_BUILD_MAJOR_RELEASE 4)
set(LIBRARY_BUILD_MINOR_RELEASE 0)
set(LIBRARY_VERSION_STRING "${LIBRARY_BUILD_MAJOR_RELEASE}.${LIBRARY_BUILD_MINOR_RELEASE}.${_git_commit_count}+${_build_version}")
message(STATUS "Project Version: ${LIBRARY_VERSION_STRING}")


# --- Build Type (Your logic is fine) ---
if(NOT CMAKE_BUILD_TYPE)
    message(STATUS "Forcing Release build type")
    set(CMAKE_BUILD_TYPE Release CACHE STRING "Choose the type of build." FORCE)
    set_property(CACHE CMAKE_BUILD_TYPE PROPERTY STRINGS "Debug" "Release" "MinSizeRel" "RelWithDebInfo")
endif()

# --- CCACHE (Your logic is fine) ---
find_program(CCACHE_PROGRAM ccache)
if(CCACHE_PROGRAM)
    set_property(GLOBAL PROPERTY RULE_LAUNCH_COMPILE "${CCACHE_PROGRAM}")
endif()

# --- Find Dependencies (Modernized) ---
# Using CONFIG mode and modern targets
find_package(aap_protobuf REQUIRED CONFIG) # Finds config, provides AAPProto::aap_protobuf
find_package(Boost REQUIRED COMPONENTS system log)
find_package(libusb-1.0 REQUIRED) # Provides libusb-1.0::libusb
find_package(OpenSSL REQUIRED) # Provides OpenSSL::SSL and OpenSSL::Crypto

# Protobuf finding logic
if(CMAKE_SYSTEM_NAME STREQUAL "Darwin")  # macOS
    message(STATUS "MacOS System Detected")
    find_package(protobuf REQUIRED CONFIG)
    find_package(absl REQUIRED)
else ()
    find_package(Protobuf REQUIRED) # Provides Protobuf::protobuf
endif ()

if(WIN32)
    set(WINSOCK2_LIBRARIES "ws2_32") # This one doesn't have a modern target
endif()

if(AASDK_TEST)
    include(ExternalGtest)
endif()

# --- Define Source Files (Best Practice) ---
# Explicitly listing files is safer than GLOB.
# GLOB means CMake won't see new files until you manually re-run it.
# Please replace this block with your actual source files.
message(WARNING "Using file(GLOB) is not recommended. Please list source files explicitly.")
file(GLOB_RECURSE source_files ${CMAKE_CURRENT_SOURCE_DIR}/src/*.cpp)
file(GLOB_RECURSE tests_source_files ${CMAKE_CURRENT_SOURCE_DIR}/src/*.ut.cpp)

list(REMOVE_ITEM source_files ${tests_source_files})

# --- Main Library Target (FIXED) ---
option(BUILD_SHARED_LIBS "Build shared libraries" ON)

#
# *** THIS LOGIC WAS INVERTED IN YOUR FILE ***
#
if(BUILD_SHARED_LIBS)
    message(NOTICE "Configuring SHARED Library")
    add_library(aasdk SHARED ${source_files})
else()
    message(NOTICE "Configuring STATIC Library")
    add_library(aasdk STATIC ${source_files})
endif()

# --- Target Properties (FIXED) ---

# Set compiler flags and definitions *per target*
target_compile_features(aasdk PRIVATE cxx_std_17)
target_compile_options(aasdk PRIVATE -Wall -pedantic)
target_compile_definitions(aasdk PRIVATE BOOST_ALL_DYN_LINK)

if(CMAKE_BUILD_TYPE STREQUAL "Release")
    message(STATUS "Disabling Boost DEBUG logs")
    target_compile_definitions(aasdk PRIVATE NDEBUG)
endif()

# This block fixes the "INTERFACE_INCLUDE_DIRECTORIES" error
target_include_directories(aasdk
        PUBLIC
        # For consumers: path in build tree, path in install tree
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
        PRIVATE
        # Internal-only headers
        ${CMAKE_CURRENT_SOURCE_DIR}/include_ut
)

# NEW (with correct target names from your modules)
target_link_libraries(aasdk
        PUBLIC
        AAPProto::aap_protobuf    # Target from Findaap_protobuf.cmake
        PRIVATE
        libusb          # Target from Findlibusb-1.0.cmake
        Boost::system
        Boost::log
        OpenSSL::SSL
        OpenSSL::Crypto
        ${PROTOBUF_LIBRARIES}   # Use variable for Protobuf
        ${WINSOCK2_LIBRARIES}
)

set_target_properties(aasdk
        PROPERTIES VERSION ${LIBRARY_VERSION_STRING} SOVERSION ${_git_commit_count})

#ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}/${CMAKE_INSTALL_LIBDIR}"
#LIBRARY_OUTPUT_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}/${CMAKE_INSTALL_LIBDIR}"
#RUNTIME_OUTPUT_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}/${CMAKE_INSTALL_BINDIR}"

# --- Install Rules (FIXED) ---
# This is now much simpler

# 1. Install the library, runtime, and archive files
install(TARGETS aasdk
        EXPORT aasdkTargets # This name is used in the next step
        ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR} COMPONENT libraries
        LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR} COMPONENT libraries
        RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR} COMPONENT libraries
)

# 2. Install the public headers
install(DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/include/aasdk
        DESTINATION ${CMAKE_INSTALL_INCLUDEDIR} # Uses 'include'
        COMPONENT headers
)

# 3. Install the exported target file (aasdkTargets.cmake)
install(EXPORT aasdkTargets
        FILE aasdkTargets.cmake
        NAMESPACE AASDK::
        DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/aasdk
        COMPONENT libraries
)

# 4. Install the Config and Version files
include(CMakePackageConfigHelpers)
write_basic_package_version_file(
        "${CMAKE_CURRENT_BINARY_DIR}/aasdkConfigVersion.cmake"
        VERSION ${LIBRARY_VERSION_STRING}
        COMPATIBILITY AnyNewerVersion
)

# You still need to provide this file
configure_package_config_file(${CMAKE_CURRENT_SOURCE_DIR}/Config.cmake.in
        "${CMAKE_CURRENT_BINARY_DIR}/aasdkConfig.cmake"
        INSTALL_DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/aasdk
)

install(FILES
        "${CMAKE_CURRENT_BINARY_DIR}/aasdkConfigVersion.cmake"
        "${CMAKE_CURRENT_BINARY_DIR}/aasdkConfig.cmake"
        DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/aasdk
        COMPONENT libraries
)


# --- Unit Testing (Modernized) ---
if(AASDK_TEST)
    message(STATUS "Configuring Unit Tests")

    add_executable(aasdk_ut ${tests_source_files})

    # Add the include paths from ExternalGtest.cmake
    target_include_directories(aasdk_ut PRIVATE
            ${GTEST_INCLUDE_DIRS}
            ${GMOCK_INCLUDE_DIRS}
    )

    # Link libraries to the test executable
    target_link_libraries(aasdk_ut PRIVATE
            aasdk
            gmock   # Target from ExternalGtest.cmake
            gtest   # Target from ExternalGtest.cmake
    )

    # Add test to CTest
    include(CTest)
    add_test(NAME aasdk_unit_test COMMAND aasdk_ut)

    if(AASDK_CODE_COVERAGE)
        include(CodeCoverage)
        append_coverage_compiler_flags()
        # This function is from your CodeCoverage.cmake module [cite: 30]
        setup_target_for_coverage(
                NAME aasdk_coverage
                EXECUTABLE aasdk_ut
                DEPENDENCIES aasdk_ut
        )
    endif()
endif(AASDK_TEST)


# --- CPack (Updated for Components) ---
set(CPACK_GENERATOR "DEB")
set(CPACK_DEBIAN_PACKAGE_MAINTAİNER "AASDK")
set(CPACK_PACKAGE_VENDOR "AASDK")
set(CPACK_PACKAGE_VERSION ${LIBRARY_VERSION_STRING})
set(CPACK_DEBIAN_FILE_NAME DEB-DEFAULT)
set(CPACK_DEBIAN_PACKAGE_DEPENDS "libusb-1.0-0, libboost-system-dev, libboost-log-dev, libssl-dev, libprotobuf-dev")

# Use the component names defined in install()
set(CPACK_COMPONENTS_ALL libraries headers)

set(CPACK_COMPONENT_LIBRARIES_DISPLAY_NAME "Libraries")
set(CPACK_COMPONENT_HEADERS_DISPLAY_NAME "C++ Headers")
set(CPACK_COMPONENT_LIBRARIES_DESCRIPTION "AASDK shared/static libraries")
set(CPACK_COMPONENT_HEADERS_DESCRIPTION "C/C++ header files for AASDK")
set(CPACK_COMPONENT_HEADERS_DEPENDS libraries)

include(CPack)