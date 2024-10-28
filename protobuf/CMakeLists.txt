cmake_minimum_required(VERSION 3.5)

#Android Auto Projection Protocol Library
project(aap_protobuf)

# Set Compile Versions
set(AAP_PROTO_VERSION 1.6)          # Underlying AAP (Android Auto Projection Library Protocol)
set(LIBRARY_BUILD_DATE 20241028)    # Binary Release Build Date
set(LIBRARY_BUILD_RELEASE 1)        # Binary Release Build Number (increment if released on same day)
set(LIBRARY_BUILD_INCREMENTAL 1)    # Binary Build Version - Increment for Each Build

set(CMAKE_CXX_STANDARD 14)

set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Require ProtoBuf library
find_package(Protobuf CONFIG REQUIRED)
include(FindProtobuf)


# Turn off Path Appending
set(PROTOBUF_GENERATE_CPP_APPEND_PATH OFF)

# Locate all proto files
file(GLOB_RECURSE source_proto_files ${CMAKE_CURRENT_SOURCE_DIR}/*.proto)

# Compile ProtoBuf files
protobuf_generate_cpp(PROTO_SRCS PROTO_HDRS ${source_proto_files})

# Generate Library
add_library(aap_protobuf SHARED ${PROTO_SRCS} ${PROTO_HDRS})
target_link_libraries(aap_protobuf PUBLIC ${PROTOBUF_LIBRARIES})


include_directories(
        ${CMAKE_CURRENT_BINARY_DIR}
        ${CMAKE_CURRENT_BINARY_DIR}/proto
        ${PROTOBUF_INCLUDE_DIR}
)

set(LIBRARY_BUILD_VERSION_STRING ${AAP_PROTO_VERSION}.${LIBRARY_BUILD_DATE}.${LIBRARY_BUILD_RELEASE})

set_target_properties(aap_protobuf
        PROPERTIES
        VERSION ${LIBRARY_BUILD_VERSION_STRING}
        SOVERSION ${LIBRARY_BUILD_INCREMENTAL})

# Install rules
install(TARGETS aap_protobuf
        EXPORT aap_protobuf_targets
        LIBRARY DESTINATION lib
        ARCHIVE DESTINATION lib
        RUNTIME DESTINATION bin
        INCLUDES DESTINATION include
)

# Install headers explicitly
install(DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
        DESTINATION include/aap_protobuf
        FILES_MATCHING PATTERN "*.h")

# Export the targets to a script
install(EXPORT aap_protobufTargets
        FILE aap_protobufTargets.cmake
        NAMESPACE AAPProto::
        DESTINATION lib/cmake/aap_protobuf
)

# Create a Config file for FindPackage
include(CMakePackageConfigHelpers)
write_basic_package_version_file(
        "${CMAKE_CURRENT_BINARY_DIR}/aap_protobufConfigVersion.cmake"
        VERSION 1.0
        COMPATIBILITY AnyNewerVersion
)

configure_package_config_file(${CMAKE_CURRENT_SOURCE_DIR}/Config.cmake.in
        "${CMAKE_CURRENT_BINARY_DIR}/aap_protobufConfig.cmake"
        INSTALL_DESTINATION lib/cmake/aap_protobuf
)

# Install the config files
install(FILES "${CMAKE_CURRENT_BINARY_DIR}/aap_protobufConfigVersion.cmake"
        "${CMAKE_CURRENT_BINARY_DIR}/aap_protobufConfig.cmake"
        DESTINATION lib/cmake/aap_protobuf)


