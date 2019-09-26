#include <gtest/gtest.h>
#include <comms_protobuf/Protocol.hpp>

// All CRCs computed with https://www.lammertbies.nl/comm/info/crc-calculation.html
// Mode: CRC-CCIT(0x1D0F)

using namespace std;
using namespace comms_protobuf;

struct ProtocolTest : public ::testing::Test {
};

TEST_F(ProtocolTest, it_decodes_a_single_byte_vla) {
    uint8_t buffer[1] = { 0x10 };
    auto parsed = protocol::parseLength(buffer);
    ASSERT_EQ(0x10, parsed.first);
    ASSERT_EQ(buffer + 1, parsed.second);
}

TEST_F(ProtocolTest, it_decodes_a_two_byte_vla) {
    uint8_t buffer[2] = { 0x85, 0x10 };
    auto parsed = protocol::parseLength(buffer);
    ASSERT_EQ(0x805, parsed.first);
    ASSERT_EQ(buffer + 2, parsed.second);
}

TEST_F(ProtocolTest, it_decodes_a_three_byte_vla) {
    uint8_t buffer[3] = { 0x85, 0x90, 0x40 };
    auto parsed = protocol::parseLength(buffer);
    ASSERT_EQ(0x100805, parsed.first);
    ASSERT_EQ(buffer + 3, parsed.second);
}

TEST_F(ProtocolTest, it_refuses_decoding_of_a_four_byte_vla) {
    uint8_t buffer[4] = { 0x85, 0x90, 0x80, 1 };
    auto parsed = protocol::parseLength(buffer);
    ASSERT_EQ(0, parsed.first);
    ASSERT_EQ(nullptr, parsed.second);
}

TEST_F(ProtocolTest, it_computes_the_CRC) {
    uint8_t buffer[3] = { 0x85, 0x90, 0x40 };
    uint16_t crc = protocol::crc(buffer, buffer + 3);
    ASSERT_EQ(0x9189, crc);
}

TEST_F(ProtocolTest, it_recognizes_a_well_formed_packet) {
    uint8_t buffer[10] = { 0xB5, 0x62, 0x05, 1, 2, 3, 4, 5, 0x37, 0xF0 };
    ASSERT_EQ(10, protocol::extractPacket(buffer, 10, 100));
}

TEST_F(ProtocolTest, it_handles_a_well_formed_packet_that_arrives_progressively) {
    uint8_t buffer[10] = { 0xB5, 0x62, 0x05, 1, 2, 3, 4, 5, 0x37, 0xF0 };
    for (int i = 0; i < 9; ++i) {
        ASSERT_EQ(0, protocol::extractPacket(buffer, i, 100));
    }
}

TEST_F(ProtocolTest, it_jumps_to_the_first_SYNC_0_byte) {
    uint8_t buffer[6] = { 1, 2, 3, 4, 5, 0xB5 };
    ASSERT_EQ(-5, protocol::extractPacket(buffer, 6, 100));
}

TEST_F(ProtocolTest, it_rejects_the_whole_buffer_if_there_is_no_SYNC_0) {
    uint8_t buffer[5] = { 1, 2, 3, 4, 5 };
    ASSERT_EQ(-5, protocol::extractPacket(buffer, 5, 100));
}

TEST_F(ProtocolTest, it_rejects_a_packet_whose_length_is_above_the_max_length) {
    uint8_t buffer[5] = { 0xB5, 0x62, 0x81, 0x1, 0x2 };
    ASSERT_EQ(-1, protocol::extractPacket(buffer, 5, 0x80));
}

TEST_F(ProtocolTest, it_rejects_a_packet_whose_field_length_is_above_the_max_field_length) {
    uint8_t buffer[5] = { 0xB5, 0x62, 0x80, 0x80, 0x80 };
    ASSERT_EQ(-1, protocol::extractPacket(buffer, 5, 100));
}

TEST_F(ProtocolTest, it_rejects_a_packet_whose_CRC_MSB_does_not_match) {
    uint8_t buffer[10] = { 0xB5, 0x62, 0x05, 1, 2, 3, 4, 5, 0x37, 0xF1 };
    ASSERT_EQ(-1, protocol::extractPacket(buffer, 10, 100));
}

TEST_F(ProtocolTest, it_rejects_a_packet_whose_CRC_LSB_does_not_match) {
    uint8_t buffer[10] = { 0xB5, 0x62, 0x05, 1, 2, 3, 4, 5, 0x38, 0xF0 };
    ASSERT_EQ(-1, protocol::extractPacket(buffer, 10, 100));
}
