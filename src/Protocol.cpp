#include <comms_protobuf/Protocol.hpp>

using namespace std;
using namespace comms_protobuf;

int protocol::extractPacket(uint8_t const* buffer, size_t size,
                            size_t max_payload_size) {
    if (max_payload_size > PACKET_MAX_PAYLOAD_SIZE) {
        throw std::invalid_argument("extractPacket: max_payload_size argument bigger "
                                    "than hardcoded PACKET_MAX_PAYLOAD_SIZE");
    }
    size_t start = 0;
    for (start = 0; start < size; ++start) {
        if (buffer[start] == SYNC_0) {
            break;
        }
    }

    if (start != 0) {
        return -start;
    }
    else if (size < PACKET_MIN_SIZE) {
        return 0;
    }

    auto parsed_length = parseLength(buffer + 2);
    auto payload_length = parsed_length.first;
    auto length_field_end = parsed_length.second;
    if (!length_field_end) {
        return -1;
    }
    if (payload_length > max_payload_size) {
        return -1;
    }
    if (size < payload_length + PACKET_OVERHEAD) {
        return 0;
    }

    auto payload_end = length_field_end + payload_length;
    auto expected_crc = crc(buffer + 2, payload_end);
    uint16_t actual_crc = payload_end[0] |
                          static_cast<uint16_t>(payload_end[1]) << 8;

    if (expected_crc != actual_crc) {
        return -1;
    }
    return 2 + payload_end - buffer;
}

pair<uint32_t, uint8_t const*> protocol::parseLength(uint8_t const* begin) {
    uint32_t length = 0;
    for (size_t i = 0; i < PACKET_MAX_PAYLOAD_SIZE_FIELD_LENGTH; ++i) {
        uint32_t b = begin[i];
        length |= (b & 0x7F) << (i * 7);
        if ((b & 0x80) == 0) {
            return make_pair(length, begin + i + 1);
        }
    }
    return make_pair(0, nullptr);
}

uint16_t protocol::crc(uint8_t const* begin, uint8_t const* end) {
    uint32_t crc = 0x1D0F;
    for (auto it = begin; it != end; ++it) {
        crc = crc ^ (static_cast<uint16_t>(*it) << 8);
        for (int i = 0; i < 8; ++i) {
            if (crc & 0x8000) {
                crc = (crc << 1) ^ 0x1021;
            }
            else {
                crc = (crc << 1);
            }
        }
        crc = crc & 0xffff;
    }

    return crc;
}
