#ifndef COMMS_PROTOBUF_PROTOCOL_HPP
#define COMMS_PROTOBUF_PROTOCOL_HPP

#include <array>

namespace comms_protobuf {
    /** Implementation of the framing protocol
     */
    namespace protocol {
        static const uint8_t PACKET_MIN_SIZE = 5;
        static const uint8_t PACKET_OVERHEAD = 4;

        /** Max 3 bytes in the size field
         *
         * This packet extraction simpler as we must have at least 3 valid
         * bytes after the prologue (one size, two CRC)
         */
        static const uint32_t PACKET_MAX_PAYLOAD_SIZE_FIELD_LENGTH = 3;

        /** Max 3 bytes in the size field
         */
        static const uint32_t PACKET_MAX_PAYLOAD_SIZE = 7*7*7;

        static const uint8_t SYNC_0 = 0xB5;
        static const uint8_t SYNC_1 = 0x62;

        /** Extracts packet from the buffer
         *
         * @arg max_payload_length the maximum payload length expected by
         *   the underlying protocol
         * @return value expected by iodrivers_base::Driver::extractPacket
         */
        int extractPacket(uint8_t const* buffer, size_t size,
                          size_t max_payload_size);

        /** Extract variable-length integer field
         *
         * @arg buffer pointer on the length field. It is must have at
         *   least PAXKET_MAX_PAYLOAD_SIZE_FIELD_LENGTH bytes.
         */
        std::pair<uint32_t, uint8_t const*> parseLength(uint8_t const* begin);

        /** Computes the 2-byte checksum over the given buffer
         */
        uint16_t crc(uint8_t const* begin, uint8_t const* end);
    }
}

#endif