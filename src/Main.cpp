#include <iostream>
#include <comms_protobuf/Dummy.hpp>

int main(int argc, char** argv)
{
    comms_protobuf::DummyClass dummyClass;
    dummyClass.welcome();

    return 0;
}
