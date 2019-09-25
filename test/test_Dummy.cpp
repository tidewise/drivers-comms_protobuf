#include <boost/test/unit_test.hpp>
#include <comms_protobuf/Dummy.hpp>

using namespace comms_protobuf;

BOOST_AUTO_TEST_CASE(it_should_not_crash_when_welcome_is_called)
{
    comms_protobuf::DummyClass dummy;
    dummy.welcome();
}
