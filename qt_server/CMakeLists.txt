cmake_minimum_required(VERSION 3.16)

project(TacticalMapServer VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Set Qt6 installation path
set(Qt6_DIR "/home/aliburakpekisik/Qt/6.9.1/gcc_64/lib/cmake/Qt6")
set(CMAKE_PREFIX_PATH "/home/aliburakpekisik/Qt/6.9.1/gcc_64")

find_package(Qt6 REQUIRED COMPONENTS Core Widgets Quick QuickWidgets Location Positioning Network)

qt_standard_project_setup()

set(SOURCES
    main.cpp
    serverwindow.cpp
    servermapwidget.cpp
)

set(HEADERS
    serverwindow.h
    servermapwidget.h
)

qt_add_executable(TacticalMapServerApp ${SOURCES} ${HEADERS})

qt_add_qml_module(TacticalMapServer
    URI TacticalMapServer
    VERSION 1.0
    QML_FILES
        servermap.qml
)

target_link_libraries(TacticalMapServerApp PRIVATE
    Qt6::Core
    Qt6::Widgets
    Qt6::Quick
    Qt6::QuickWidgets
    Qt6::Location
    Qt6::Positioning
    Qt6::Network
)

# Copy QML file to build directory
configure_file(${CMAKE_CURRENT_SOURCE_DIR}/servermap.qml 
               ${CMAKE_CURRENT_BINARY_DIR}/servermap.qml COPYONLY)
