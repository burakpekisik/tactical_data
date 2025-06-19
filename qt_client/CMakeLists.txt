cmake_minimum_required(VERSION 3.16)
project(TacticalMapClient VERSION 1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_AUTOMOC ON)

# Set Qt6 installation path
set(Qt6_DIR "/home/aliburakpekisik/Qt/6.9.1/gcc_64/lib/cmake/Qt6")
set(CMAKE_PREFIX_PATH "/home/aliburakpekisik/Qt/6.9.1/gcc_64")

find_package(Qt6 REQUIRED COMPONENTS Core Widgets Quick QuickControls2 QuickWidgets Location Positioning)

set(SOURCES
    main.cpp
    mainwindow.cpp
    mapwidget.cpp
)

set(HEADERS
    mainwindow.h
    mapwidget.h
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
)
