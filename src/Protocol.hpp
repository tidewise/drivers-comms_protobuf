#ifndef COMMS_PROTOBUF_PROTOCOL_HPP
#define COMMS_PROTOBUF_PROTOCOL_HPP

#include <array>

namespace comms_protobuf {
    /** Implementation of the framing protocol
     */
    namespace protocol {
        static const uint8_t PACKET_MIN_SIZE = 5;

        /** Two bytes start, one byte for size and two bytes for CRC */
        static const uint8_t PACKET_MIN_OVERHEAD = 5;

        /** Two bytes start, three bytes for size and two bytes for CRC */
        static const uint8_t PACKET_MAX_OVERHEAD = 7;

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

        /** Get the payload range
         *
         * The provided buffer is expected to have been validated with
         * extractPacket
         */
        std::pair<uint8_t const*, uint8_t const*> getPayload(uint8_t const* buffer);

        /** Extract variable-length integer field
         *
         * @arg buffer pointer on the length field. It is must have at
         *   least PAXKET_MAX_PAYLOAD_SIZE_FIELD_LENGTH bytes.
         * @return the decoded size, and the past-the-end pointer after the
         *   length field
         */
        std::pair<uint32_t, uint8_t const*> parseLength(uint8_t const* begin);

        /** Write variable-length integer field
         *
         * @arg buffer pointer on the length field. It is must have at
         *   least PAXKET_MAX_PAYLOAD_SIZE_FIELD_LENGTH bytes.
         * @return the decoded size, and the past-the-end pointer after the
         *   length field
         */
        uint8_t* encodeLength(uint8_t* buffer, size_t length);

        /** Encode a frame containing the given bytes
         *
         * @arg buffer target buffer
         * @arg payload the payload. This is a string as it is what Google's
         *    protocol buffer C++ API uses
         * @return the past-the-end pointer after the encoded frame
         */
        uint8_t* encodeFrame(uint8_t* buffer,
                             uint8_t const* payload_begin,
                             uint8_t const* payload_end);

        /** Computes the 2-byte checksum over the given buffer
         */
        uint16_t crc(uint8_t const* begin, uint8_t const* end);

        /** Encode a frame containing the given protobuf message */
        template<typename Message>
        uint8_t* encodeFrame(uint8_t* buffer, Message const& message) {
            size_t payload_length = message.ByteSizeLong();

            buffer[0] = SYNC_0;
            buffer[1] = SYNC_1;

            uint8_t* length_end = encodeLength(buffer + 2, payload_length);
            message.SerializeWithCachedSizesToArray(length_end);

            uint8_t* payload_end = length_end + payload_length;
            uint16_t calculated_crc = crc(buffer + 2, payload_end);
            payload_end[0] = calculated_crc & 0xFF;
            payload_end[1] = (calculated_crc >> 8) & 0xFF;
            return payload_end + 2;
        }
    }
}

#endif