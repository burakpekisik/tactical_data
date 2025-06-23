cmake_minimum_required(VERSION 3.16)
project(TacticalMapClient VERSION 1.0 LANGUAGES CXX C)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_AUTOMOC ON)

# Set Qt6 installation path
set(Qt6_DIR "/home/aliburakpekisik/Qt/6.9.1/gcc_64/lib/cmake/Qt6")
set(CMAKE_PREFIX_PATH "/home/aliburakpekisik/Qt/6.9.1/gcc_64")

find_package(Qt6 REQUIRED COMPONENTS Core Widgets Quick QuickControls2 QuickWidgets Location Positioning Network)

# Include directories
include_directories(${CMAKE_SOURCE_DIR}/../include)
include_directories(${CMAKE_SOURCE_DIR}/../cjson)

# C source files from the main project
set(C_SOURCES
    ../src/common/crypto_utils.c
    ../src/crypto/aes.c
    ../src/dynamic_key/ecdh.c
    ../src/common/logger.c
    ../src/client/protocol_manager.c
    ../src/client/fallback_manager.c
    ../cjson/cJSON.c
    ../cjson/cJSON_Utils.c
)

set(SOURCES
    main.cpp
    mainwindow.cpp
    mapwidget.cpp
    client_wrapper.cpp
    ${C_SOURCES}
)

set(HEADERS
    mainwindow.h
    mapwidget.h
    client_wrapper.h
)

add_executable(TacticalMapClient
    ${SOURCES}
    ${HEADERS}
)

target_link_libraries(TacticalMapClient 
    PUBLIC
    Qt6::Core
    Qt6::Widgets
    Qt6::Quick
    Qt6::QuickControls2
    Qt6::QuickWidgets
    Qt6::Location
    Qt6::Positioning
    Qt6::Network
    m  # Math library for crypto operations
)
