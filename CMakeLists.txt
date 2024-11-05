cmake_minimum_required(VERSION 3.5.1)

project(aasdk)

# Cross Compiling Architecture
if( TARGET_ARCH STREQUAL "amd64" )
    message("Building for amd64")
    set(CPACK_DEBIAN_PACKAGE_ARCHITECTURE "amd64")
elseif( TARGET_ARCH STREQUAL "armhf" )
    message("Building for armhf")
    set(CMAKE_C_COMPILER /usr/bin/arm-linux-gnueabihf-gcc-8)
    set(CMAKE_CXX_COMPILER /usr/bin/arm-linux-gnueabihf-g++-8)
    set(CPACK_DEBIAN_PACKAGE_ARCHITECTURE "armhf")
else()
    if(CMAKE_SYSTEM_NAME STREQUAL "Darwin")  # macOS
        # macOS specific command
        #set(CMAKE_OSX_ARCHITECTURES "x86_64")
        #set(CMAKE_OSX_DEPLOYMENT_TARGET "10.12")
    endif()
    message("Target Architecture not specified, not cross compiling")
endif()

# Set Compile Versions
set(LIBRARY_BUILD_DATE "20241028")    # Binary Release Build Date
set(LIBRARY_BUILD_MAJOR_RELEASE 1)        # Binary Release Build Number (increment if released on same day)
set(LIBRARY_BUILD_MINOR_RELEASE 1)        # Binary Release Build Number (increment if released on same day)
set(LIBRARY_BUILD_INCREMENTAL 1)    # Binary Build Version - Increment for Each Build

# Cache
find_program(CCACHE_PROGRAM ccache)
if(CCACHE_PROGRAM)
    set_property(GLOBAL PROPERTY RULE_LAUNCH_COMPILE "${CCACHE_PROGRAM}")
endif()

# Configure CMAKE
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${PROJECT_SOURCE_DIR}/cmake_modules/")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS_INIT} -fPIC -Wall -pedantic")
set(CMAKE_CXX_FLAGS_DEBUG "-g -O0")
set(CMAKE_CXX_FLAGS_RELEASE "-g -O3")

# Paths
set(sources_directory ${CMAKE_CURRENT_SOURCE_DIR}/src)
set(include_directory ${CMAKE_CURRENT_SOURCE_DIR}/include)
set(include_ut_directory ${CMAKE_CURRENT_SOURCE_DIR}/include_ut)

set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/lib)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/lib)

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/bin)
set(EXECUTABLE_OUTPUT_PATH ${CMAKE_CURRENT_SOURCE_DIR}/bin)

#This line Errors - TODO
#include(${CMAKE_CURRENT_SOURCE_DIR}/cmake_modules/gitversion.cmake)
set (CMAKE_PROJECT_VERSION_PATCH ${_commit_timestamp})

# Configure Boost
set(Boost_USE_STATIC_LIBS OFF)
set(Boost_USE_MULTITHREADED ON)
set(Boost_USE_STATIC_RUNTIME OFF)

add_definitions(-DBOOST_ALL_DYN_LINK)

if(WIN32)
    set(WINSOCK2_LIBRARIES "ws2_32")
endif(WIN32)

if(AASDK_TEST)
    include(ExternalGtest)
endif(AASDK_TEST)

find_package(aap_protobuf REQUIRED)

# Building on a Mac requires Abseil
if(CMAKE_SYSTEM_NAME STREQUAL "Darwin")  # macOS
    find_package(protobuf REQUIRED CONFIG)
    find_package(absl REQUIRED)
else ()
    find_package(Protobuf REQUIRED)
endif ()

include(FindProtobuf)

find_package(Boost REQUIRED COMPONENTS system log OPTIONAL_COMPONENTS unit_test_framework)
find_package(libusb-1.0 REQUIRED)

find_package(OpenSSL REQUIRED)

include_directories(
        ${Boost_INCLUDE_DIRS}
        ${LIBUSB_1_INCLUDE_DIRS}
        ${LIBUSB_INCLUDE_DIR}
        ${PROTOBUF_INCLUDE_DIR}
        ${AAP_PROTOBUF_INCLUDE_DIR}
        ${OPENSSL_INCLUDE_DIR}
        ${GTEST_INCLUDE_DIRS}
        ${GMOCK_INCLUDE_DIRS}
        ${include_directory}
        ${include_ut_directory})

file(GLOB_RECURSE source_files ${sources_directory}/*.cpp)
file(GLOB_RECURSE include_files ${include_directory}/*.hpp)
file(GLOB_RECURSE tests_source_files ${sources_directory}/*.ut.cpp)
file(GLOB_RECURSE tests_include_files ${include_ut_directory}/*.hpp)

list(REMOVE_ITEM source_files ${tests_source_files})

add_library(aasdk SHARED
        ${source_files}
        ${include_files})

target_include_directories(aasdk PUBLIC ${AAP_PROTOBUF_INCLUDE_DIR})

target_link_libraries(aasdk PUBLIC
        libusb
        ${Boost_LIBRARIES}
        ${AAP_PROTOBUF_LIB_DIR}
        ${LIBUSB_1_LIBRARIES}
        ${PROTOBUF_LIBRARIES}
        ${OPENSSL_LIBRARIES}
        ${WINSOCK2_LIBRARIES})


set(LIBRARY_VERSION_STRING "${LIBRARY_BUILD_MAJOR_RELEASE}.${LIBRARY_BUILD_MINOR_RELEASE}.${LIBRARY_BUILD_INCREMENTAL}+${LIBRARY_BUILD_DATE}")
message(INFO " Project Version: ${LIBRARY_VERSION_STRING}")
set_target_properties(aasdk
        PROPERTIES VERSION ${LIBRARY_VERSION_STRING} SOVERSION ${LIBRARY_BUILD_INCREMENTAL})

# Install rules
install(TARGETS aasdk libusb
        EXPORT aasdkTargets
        LIBRARY DESTINATION lib
        ARCHIVE DESTINATION lib
        RUNTIME DESTINATION bin
        INCLUDES DESTINATION include
)

#target_include_directories(aasdk
#        PUBLIC
#        $<BUILD_INTERFACE:${PROTOBUF_SOURCES}>
#        $<INSTALL_INTERFACE:include/aap_protobuf>
#)

# Install headers explicitly
install(DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/include/aasdk
        DESTINATION include
)

# Export the targets to a script
install(EXPORT aasdkTargets
        FILE aasdkTargets.cmake
        NAMESPACE AASDK::
        DESTINATION lib/cmake/aasdk
)

# Create a Config file for FindPackage
include(CMakePackageConfigHelpers)
write_basic_package_version_file(
        "${CMAKE_CURRENT_BINARY_DIR}/aasdkConfigVersion.cmake"
        VERSION 1.0
        COMPATIBILITY AnyNewerVersion
)

configure_package_config_file(${CMAKE_CURRENT_SOURCE_DIR}/Config.cmake.in
        "${CMAKE_CURRENT_BINARY_DIR}/aasdkConfig.cmake"
        INSTALL_DESTINATION lib/cmake/aasdk
)

# Install the config files
install(FILES "${CMAKE_CURRENT_BINARY_DIR}/aasdkConfigVersion.cmake"
        "${CMAKE_CURRENT_BINARY_DIR}/aasdkConfig.cmake"
        DESTINATION lib/cmake/aasdk)

if(AASDK_TEST)
    add_executable(aasdk_ut
            ${tests_source_files}
            ${tests_include_files})

    add_dependencies(aasdk_ut aasdk)
    target_link_libraries(aasdk_ut
            aasdk
            ${GMOCK_LIBRARY_PATH}
            ${GTEST_LIBRARY_PATH})

    if(AASDK_CODE_COVERAGE)
        include(CodeCoverage)
        append_coverage_compiler_flags()
        setup_target_for_coverage(NAME aasdk_coverage EXECUTABLE aasdk_ut DEPENDENCIES aasdk_ut)
    endif(AASDK_CODE_COVERAGE)
endif(AASDK_TEST)


set(CPACK_GENERATOR "DEB")
set(CPACK_DEBIAN_PACKAGE_MAINTAINER "AASDK") #required
set(CPACK_PACKAGE_VENDOR "AASDK")
set(CPACK_PACKAGE_VERSION ${LIBRARY_VERSION_STRING})
set(CPACK_DEBIAN_FILE_NAME DEB-DEFAULT)
set(CPACK_DEBIAN_PACKAGE_DEPENDS "libusb-1.0-0,libboost-all-dev,libssl-dev,libprotobuf-dev")
set(CPACK_COMPONENTS_ALL libraries headers Unspecified)
set(CPACK_COMPONENT_LIBRARIES_DISPLAY_NAME "Libraries")
set(CPACK_COMPONENT_HEADERS_DISPLAY_NAME "C++ Headers")
set(CPACK_COMPONENT_LIBRARIES_DESCRIPTION
        "Static libraries used to build programs with AASDK")
set(CPACK_COMPONENT_HEADERS_DESCRIPTION
        "C/C++ header files for use with AASDK")
set(CPACK_COMPONENT_LIBRARIES_GROUP "Development")
set(CPACK_COMPONENT_HEADERS_GROUP "Development")
set(CPACK_COMPONENT_GROUP_DEVELOPMENT_EXPANDED ON)
set(CPACK_COMPONENT_GROUP_DEVELOPMENT_DESCRIPTION
        "All of the tools you'll ever need to develop software")
set(CPACK_COMPONENT_HEADERS_DEPENDS libraries)
set(CPACK_ALL_INSTALL_TYPES Full Developer)
set(CPACK_INSTALL_TYPE_FULL_DISPLAY_NAME "Everything")
set(CPACK_COMPONENT_LIBRARIES_INSTALL_TYPES Developer Full)
set(CPACK_COMPONENT_HEADERS_INSTALL_TYPES Developer Full)
include(CPack)
