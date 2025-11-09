if (AAP_PROTOBUF_LIB_DIRS AND AAP_PROTOBUF_INCLUDE_DIRS)
    # in cache already
    message(STATUS "aap_protobuf is cached")
    set(AAP_PROTOBUF_FOUND TRUE)
else (AAP_PROTOBUF_LIB_DIRS AND AAP_PROTOBUF_INCLUDE_DIRS)
    find_path(AAP_PROTOBUF_INCLUDE_DIR
            NAMES
            channel/control/GalConstants.pb.h
            PATHS
            /usr/include
            /usr/local/include
            /opt/local/include
            /sw/include
            PATH_SUFFIXES
            aap_protobuf
    )

    find_library(AAP_PROTOBUF_LIB_DIR
            NAMES
            aap_protobuf libaap_protobuf
            PATHS
            /usr/lib
            /usr/local/lib
            /opt/local/lib
            /sw/lib
    )

    set(AAP_PROTOBUF_INCLUDE_DIRS
            ${AAP_PROTOBUF_INCLUDE_DIR}
    )
    set(AAP_PROTOBUF_LIB_DIRS
            ${AAP_PROTOBUF_LIB_DIR}
    )

    if (AAP_PROTOBUF_INCLUDE_DIRS AND AAP_PROTOBUF_LIB_DIRS)
        set(AAP_PROTOBUF_FOUND TRUE)
    endif (AAP_PROTOBUF_INCLUDE_DIRS AND AAP_PROTOBUF_LIB_DIRS)

    if (AAP_PROTOBUF_FOUND)
        message(STATUS "SUCCESS. Found: aap_protobuf:")
        message(STATUS " - Includes: ${AAP_PROTOBUF_INCLUDE_DIRS}")
        message(STATUS " - Libraries: ${AAP_PROTOBUF_LIB_DIRS}")

        # Get the directory *containing* the library
        get_filename_component(AAP_PROTOBUF_LIBRARY_DIR ${AAP_PROTOBUF_LIB_DIR} DIRECTORY)
        message(STATUS " - Lib Dir:  ${AAP_PROTOBUF_LIBRARY_DIR}")

        # Create the INTERFACE target (if it doesn't exist)
        if(NOT TARGET aap_protobuf)
            add_library(aap_protobuf INTERFACE)
        endif()

        # Tell the target where the include files are
        target_include_directories(aap_protobuf SYSTEM INTERFACE ${AAP_PROTOBUF_INCLUDE_DIR})

        # Tell the target to add the library's *directory* to the linker search path
        # This adds "-L/usr/local/lib" and is the main fix.
        target_link_directories(aap_protobuf INTERFACE ${AAP_PROTOBUF_LIBRARY_DIR})

        # Tell the target the name of the library file
        target_link_libraries(aap_protobuf INTERFACE ${AAP_PROTOBUF_LIB_DIR})

    else (AAP_PROTOBUF_FOUND)
        message(STATUS " - Includes: ${AAP_PROTOBUF_INCLUDE_DIRS}")
        message(STATUS " - Libraries: ${AAP_PROTOBUF_LIB_DIRS}")
        message(FATAL_ERROR "Could not locate aap_protobuf")
    endif (AAP_PROTOBUF_FOUND)

    # show the AAP_PROTOBUF_INCLUDE_DIRS and AAP_PROTOBUF_LIB_DIRS variables only in the advanced view
    mark_as_advanced(AAP_PROTOBUF_INCLUDE_DIRS AAP_PROTOBUF_LIB_DIRS)

endif (AAP_PROTOBUF_LIB_DIRS AND AAP_PROTOBUF_INCLUDE_DIRS)
