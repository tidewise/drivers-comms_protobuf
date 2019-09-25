rock_library(comms_protobuf
    SOURCES Dummy.cpp
    HEADERS Dummy.hpp)

rock_executable(comms_protobuf_bin Main.cpp
    DEPS comms_protobuf)

