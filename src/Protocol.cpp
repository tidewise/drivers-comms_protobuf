#include <cstring>
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
    if (size < payload_length + PACKET_MIN_OVERHEAD) {
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

std::pair<uint8_t const*, uint8_t const*> protocol::getPayload(uint8_t const* buffer) {
    auto parsed_length = parseLength(buffer + 2);
    return make_pair(parsed_length.second, parsed_length.first + parsed_length.second);
}

uint8_t* protocol::encodeFrame(uint8_t* buffer,
                               uint8_t const* payload_begin,
                               uint8_t const* payload_end) {
    buffer[0] = SYNC_0;
    buffer[1] = SYNC_1;

    size_t payload_length = payload_end - payload_begin;
    uint8_t* length_end = encodeLength(buffer + 2, payload_length);
    std::memcpy(length_end, payload_begin, payload_length);

    uint8_t* buffer_end = length_end + payload_length + 2;
    uint16_t calculated_crc = crc(buffer + 2, buffer_end - 2);
    buffer_end[-2] = calculated_crc & 0xFF;
    buffer_end[-1] = (calculated_crc >> 8) & 0xFF;
    return buffer_end;
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

uint8_t* protocol::encodeLength(uint8_t* begin, size_t length) {
    uint8_t* ptr = begin;
    for (size_t i = 0; i < PACKET_MAX_PAYLOAD_SIZE_FIELD_LENGTH; ++i) {
        *ptr = length & 0x7F;
        length >>= 7;
        if (!length) {
            return ptr + 1;
        }

        *(ptr++) |= 0x80;
    }
    return nullptr;
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
