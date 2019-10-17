find_package(Protobuf REQUIRED)
include_directories(${CMAKE_CURRENT_BINARY_DIR})
protobuf_generate_cpp(PROTO_SRCS PROTO_HDRS test.proto)

rock_gtest(test_suite suite.cpp
   test_Protocol.cpp
   test_Channel.cpp ${PROTO_SRCS}
   DEPS comms_protobuf
   DEPS_PLAIN Protobuf)
