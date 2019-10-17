#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include <comms_protobuf/Protocol.hpp>

// All CRCs computed with https://www.lammertbies.nl/comm/info/crc-calculation.html
// Mode: CRC-CCIT(0x1D0F)

using namespace std;
using namespace comms_protobuf;
using ::testing::ElementsAreArray;

struct ProtocolTest : public ::testing::Test {
};

TEST_F(ProtocolTest, it_computes_the_encoded_size_of_various_length) {
    size_t size = 1;
    for (int i = 0; i < 7; ++i) {
        ASSERT_EQ(i + 1, protocol::getLengthEncodedSize(size));
        size = (size << 8) | 0x80;
    }
}

TEST_F(ProtocolTest, it_throws_for_more_than_8_bytes) {
    ASSERT_THROW(protocol::getLengthEncodedSize(0x8080808080808080),
                 invalid_argument);
}

TEST_F(ProtocolTest, it_validates_that_a_buffer_is_big_enough_to_contain_a_full_message) {
    ASSERT_EQ(6 + 0x100, protocol::validateEncodingBufferSize(6 + 0x100, 0x100));
}

TEST_F(ProtocolTest, validation_throws_if_the_buffer_is_too_small) {
    ASSERT_THROW(protocol::validateEncodingBufferSize(5 + 0x100, 0x100),
                 std::invalid_argument);
}

TEST_F(ProtocolTest, it_validates_a_buffer_size_that_is_too_big) {
    ASSERT_EQ(6 + 0x100, protocol::validateEncodingBufferSize(50 + 0x100, 0x100));
}

TEST_F(ProtocolTest, it_decodes_a_single_byte_vla) {
    uint8_t buffer[1] = { 0x10 };
    auto parsed = protocol::parseLength(buffer, buffer + 1);
    ASSERT_EQ(0x10, parsed.first);
    ASSERT_EQ(buffer + 1, parsed.second);
}

TEST_F(ProtocolTest, it_decodes_a_two_byte_vla) {
    uint8_t buffer[2] = { 0x85, 0x10 };
    auto parsed = protocol::parseLength(buffer, buffer + 2);
    ASSERT_EQ(0x805, parsed.first);
    ASSERT_EQ(buffer + 2, parsed.second);
}

TEST_F(ProtocolTest, it_returns_invalid_if_a_two_byte_vla_is_found_in_a_one_byte_buffer) {
    uint8_t buffer[2] = { 0x85, 0x10 };
    auto parsed = protocol::parseLength(buffer, buffer + 1);
    ASSERT_EQ(0, parsed.first);
    ASSERT_EQ(nullptr, parsed.second);
}

TEST_F(ProtocolTest, it_decodes_a_three_byte_vla) {
    uint8_t buffer[3] = { 0x85, 0x90, 0x40 };
    auto parsed = protocol::parseLength(buffer, buffer + 3);
    ASSERT_EQ(0x100805, parsed.first);
    ASSERT_EQ(buffer + 3, parsed.second);
}

TEST_F(ProtocolTest, it_returns_invalid_if_a_three_byte_vla_is_found_in_a_two_byte_buffer) {
    uint8_t buffer[3] = { 0x85, 0x90, 0x40 };
    auto parsed = protocol::parseLength(buffer, buffer + 2);
    ASSERT_EQ(0, parsed.first);
    ASSERT_EQ(nullptr, parsed.second);
}

TEST_F(ProtocolTest, it_encodes_a_single_byte_vla) {
    uint8_t buffer[1] = { 0x10 };
    uint8_t const* end = protocol::encodeLength(buffer, buffer + 1, 0x10);
    ASSERT_EQ(0x10, buffer[0]);
    ASSERT_EQ(buffer + 1, end);
}

TEST_F(ProtocolTest, it_throws_if_encoding_a_single_byte_vla_in_a_zero_byte_buffer) {
    ASSERT_THROW(protocol::encodeLength(nullptr, nullptr, 0x10), std::invalid_argument);
}

TEST_F(ProtocolTest, it_encodes_a_two_byte_vla) {
    uint8_t buffer[2];
    uint8_t const* end = protocol::encodeLength(buffer, buffer + 2, 0x805);
    ASSERT_EQ(0x85, buffer[0]);
    ASSERT_EQ(0x10, buffer[1]);
    ASSERT_EQ(buffer + 2, end);
}

TEST_F(ProtocolTest, it_throws_if_encoding_a_two_byte_vla_in_a_one_byte_buffer) {
    uint8_t buffer[1];
    ASSERT_THROW(protocol::encodeLength(buffer, buffer + 1, 0x805),
                 std::invalid_argument);
}

TEST_F(ProtocolTest, it_encodes_a_three_byte_vla) {
    uint8_t buffer[3];
    uint8_t const* end = protocol::encodeLength(buffer, buffer + 3, 0x100805);
    ASSERT_EQ(0x85, buffer[0]);
    ASSERT_EQ(0x90, buffer[1]);
    ASSERT_EQ(0x40, buffer[2]);
    ASSERT_EQ(buffer + 3, end);
}

TEST_F(ProtocolTest, it_throws_if_encoding_a_three_byte_vla_in_a_two_byte_buffer) {
    uint8_t buffer[2];
    ASSERT_THROW(protocol::encodeLength(buffer, buffer + 2, 0x100805),
                 std::invalid_argument);
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

TEST_F(ProtocolTest, it_recognizes_partial_packets) {
    vector<uint8_t> buffer = { 0xB5, 0x62, 0x85, 0x10 };
    buffer.resize(4 + 0x805);
    uint16_t crc = protocol::crc(&buffer[2], &buffer[buffer.size()]);
    buffer.push_back(crc & 0xFF);
    buffer.push_back((crc >> 8) & 0xFF);

    for (size_t i = 0; i < buffer.size(); ++i) {
        vector<uint8_t> current_buffer(buffer.begin(), buffer.begin() + i);
        ASSERT_EQ(0, protocol::extractPacket(&current_buffer[0],
                                             current_buffer.size(), 0x1000));
    }
}

TEST_F(ProtocolTest, it_returns_the_payload_range_of_a_well_formed_packet) {
    uint8_t buffer[10] = { 0xB5, 0x62, 0x05, 1, 2, 3, 4, 5, 0x37, 0xF0 };
    auto payload = protocol::getPayload(buffer, buffer + 10);
    ASSERT_EQ(buffer + 3, payload.first);
    ASSERT_EQ(buffer + 8, payload.second);
}

TEST_F(ProtocolTest, it_throws_if_the_payload_size_and_buffer_size_are_incompatible) {
    uint8_t buffer[10] = { 0xB5, 0x62, 0x05, 1, 2, 3, 4, 5, 0x37, 0xF0 };
    ASSERT_THROW(protocol::getPayload(buffer, buffer + 7),
                 std::invalid_argument);
}

TEST_F(ProtocolTest, it_handles_a_well_formed_packet_that_arrives_progressively) {
    uint8_t buffer[10] = { 0xB5, 0x62, 0x05, 1, 2, 3, 4, 5, 0x37, 0xF0 };
    for (int i = 0; i < 9; ++i) {
        ASSERT_EQ(0, protocol::extractPacket(buffer, i, 100));
    }
}

TEST_F(ProtocolTest, it_creates_a_well_formed_packet) {
    uint8_t buffer[10];
    uint8_t payload[5] = { 1, 2, 3, 4, 5 };

    uint8_t* end = protocol::encodeFrame(buffer, buffer + 10, payload, payload + 5);
    ASSERT_EQ(end, buffer + 10);

    uint8_t expected[] = { 0xB5, 0x62, 0x05, 1, 2, 3, 4, 5, 0x37, 0xF0 };
    ASSERT_THAT(buffer, ElementsAreArray(expected));
}

TEST_F(ProtocolTest, it_throws_if_trying_to_encode_a_packet_in_a_buffer_too_small) {
    uint8_t buffer[10];
    uint8_t payload[5] = { 1, 2, 3, 4, 5 };

    ASSERT_THROW(protocol::encodeFrame(buffer, buffer + 9, payload, payload + 5),
                 std::invalid_argument);
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
