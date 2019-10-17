# comms_protobuf

Base code to create communication channels using protocol buffers and iodrivers_base

## Usage

This package makes it somewhat simple to create communication classes where the
data samples are made of protobuf-serialized data. To use it, you have to

- design a 'local' protobuf message that will be **sent** from the class you are
  creating
- design a 'remote' protobuf message that will be **received** by the class you
  are creating

To keep with the spirit of the Rock conventions, we recommend that both
messages should be saved in the packages `src/${LIBRARY_NAMESPACE}.proto`
file. This proto file should be declared within the library's namespace
package for consistency. Use protobuf's `oneof` mechanism if you need to send
different messages at different points in time.

For instance, let's assume we want to create a `drivers/comms_base_station`
package for a communication between a device and its base station, with a
`Telemetry` message sent by the device and a `Configuration` message sent by the
base station.

We would create `src/comms_base_station.proto` with

~~~
syntax = 'proto3';

package comms_base_station;

message Telemetry {
}

message Configuration {
}
~~~

and then `src/Device.hpp` with

~~~ cpp
#ifndef COMMS_BASE_STATION_DEVICE_HPP
#define COMMS_BASE_STATION_DEVICE_HPP

#include <comms_protobuf/Channel.hpp>
#include <comms_base_station/comms_base_station.pb.h>

namespace comms_base_station {
    class Device : public comms_protobuf::Channel<Telemetry, Configuration> {
        static const int MAX_MESSAGE_SIZE = ...
    public:
        Device()
            : comms_protobuf::Channel<Telemetry, Configuration>(MAX_MESSAGE_SIZE) {
        }
    }
}

#endif
~~~

the other direction, `src/BaseStation.hpp` is left to the reader.

**Note** that the implementation requires to have a reasonable guess of the
*maximum message size. In practice, accounting for the max size of each field
(ignoring protobufs own overhead) should be fine.

Finally, you need to update `CMakeLists.txt` to run the protobuf generator and
compile all of this:

~~~ cmake
find_package(Protobuf REQUIRED)
protobuf_generate_cpp(PROTO_SRCS PROTO_HDRS comms_base_station.proto)

rock_library(comms_base_station
    USE_BINARY_DIR
    HEADERS Device.hpp BaseStation.hpp ${PROTO_HDRS}
    SOURCE ${PROTO_SRCS}
    DEPS_PKGCONFIG comms_protobuf
    DEPS_PLAIN Protobuf
)
~~~

Finally, within Rock, you have to add protobuf as dependency in `manifest.xml`:

~~~ xml
<depend package="protobuf-compiler" />
<depend package="protobuf-cxx" />
~~~


## License

BSD 3-clause
