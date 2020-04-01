rock_library(comms_protobuf
    SOURCES Protocol.cpp
    HEADERS Protocol.hpp Channel.hpp
    DEPS_PKGCONFIG iodrivers_base libcrypto)

