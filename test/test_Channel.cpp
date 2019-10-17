#include <gtest/gtest.h>
#include "test.pb.h"
#include <comms_protobuf/Channel.hpp>
#include <iodrivers_base/FixtureGTest.hpp>

using namespace std;
using namespace comms_protobuf;

struct TestChannel : public Channel<test_channel::Local, test_channel::Remote> {
    typedef test_channel::Local Local;
    typedef test_channel::Remote Remote;

    TestChannel()
        : Channel<Local, Remote>(100) {
    }
};

struct ChannelTest : public ::testing::Test, iodrivers_base::Fixture<TestChannel> {
    template<typename Msg>
    void pushMessageToDriver(Msg const& msg) {
        vector<uint8_t> marshalled(256);
        msg.SerializeToArray(&marshalled[0], marshalled.size());

        uint8_t buffer[1024];
        uint8_t* end = protocol::encodeFrame(
            buffer, buffer + 1024, &marshalled[0], &marshalled[0] + msg.ByteSizeLong()
        );
        this->pushDataToDriver(buffer, end);
    }
};

TEST_F(ChannelTest, it_can_send_a_message) {
    driver.openURI("test://");

    test_channel::Local local;
    local.set_something(10);
    driver.write(local);

    auto buffer = readDataFromDriver();
    ASSERT_GT(protocol::extractPacket(&buffer[0], buffer.size(), 100), 0);
    auto payload_range = protocol::getPayload(&buffer[0], &buffer[0] + buffer.size());
    std::string marshalled(payload_range.first, payload_range.second);

    test_channel::Local received;
    received.ParseFromString(marshalled);
    ASSERT_EQ(10, local.something());
}

TEST_F(ChannelTest, it_can_receive_a_message) {
    test_channel::Remote remote;
    remote.set_something_else(10);
    ASSERT_EQ(10, remote.something_else());
    pushMessageToDriver(remote);

    test_channel::Remote received = driver.read();
    ASSERT_EQ(10, received.something_else());
}

TEST_F(ChannelTest, it_throws_if_receiving_a_message_that_is_valid_for_extractPacket_but_invalid_for_protobuf) {
    uint8_t buffer[10] = { 0xB5, 0x62, 0x05, 1, 2, 3, 4, 5, 0x37, 0xF0 };
    pushDataToDriver(buffer, buffer + 10);

    ASSERT_THROW(driver.read(), InvalidProtobufMessage);
}