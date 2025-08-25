#ifndef COMMS_PROTOBUF_PROTOCOL_HPP
#define COMMS_PROTOBUF_PROTOCOL_HPP

#include <cstdint>
#include <array>
#include <stdexcept>

namespace comms_protobuf {
    struct DecryptionFailed : std::runtime_error {
        using std::runtime_error::runtime_error;
    };
    struct EncryptionFailed : std::runtime_error {
        using std::runtime_error::runtime_error;
    };

    /** Implementation of the framing protocol
     */
    namespace protocol {
        struct InternalError : std::runtime_error {
            using std::runtime_error::runtime_error;
        };

        using size_t = std::size_t;
        using uint8_t = std::uint8_t;

        static const uint8_t PACKET_MIN_SIZE = 5;

        /** Two bytes start, one byte for size and two bytes for CRC */
        static const uint8_t PACKET_MIN_OVERHEAD = 5;

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
        std::pair<uint8_t const*, uint8_t const*> getPayload(
            uint8_t const* buffer, uint8_t const* buffer_end
        );

        /** Extract variable-length integer field
         *
         * @arg buffer pointer on the length field. It is must have at
         *   least PAXKET_MAX_PAYLOAD_SIZE_FIELD_LENGTH bytes.
         * @return the decoded size, and the past-the-end pointer after the
         *   length field
         */
        std::pair<size_t, uint8_t const*> parseLength(
            uint8_t const* begin, uint8_t const* end
        );

        /**
         * Validate that a buffer with the given length would be big enough to
         * contain a message with the provided payload length
         *
         * @return the actual encoded message length
         */
        size_t validateEncodingBufferSize(size_t buffer_length, size_t length);

        /** Compute the size in bytes of the encoded version of the given length
         */
        size_t getLengthEncodedSize(size_t length);

        /** Write variable-length integer field
         *
         * @arg buffer pointer on the length field
         * @arg buffer_end pointer on the end of the available byte range.
         *    The method throws std::invalid_argument if the encoded length
         *    does not fit in the available buffer range.
         * @arg length the length to be encoded
         * @return past-the-end pointer after the encoded length field
         */
        uint8_t* encodeLength(uint8_t* buffer, uint8_t* buffer_end, size_t length);

        /** Encode a frame containing the given bytes
         *
         * @arg buffer target buffer
         * @arg payload the payload. This is a string as it is what Google's
         *    protocol buffer C++ API uses
         * @return the past-the-end pointer after the encoded frame
         */
        uint8_t* encodeFrame(uint8_t* buffer, uint8_t* buffer_end,
                             uint8_t const* payload_begin,
                             uint8_t const* payload_end);

        /** Computes the 2-byte checksum over the given buffer
         */
        uint16_t crc(uint8_t const* begin, uint8_t const* end);

        typedef std::array<uint8_t, 16> aes_tag;

        struct CipherContext {
            static const int KEY_SIZE = 32;
            static const int MAX_BLOCK_LENGTH = 32;

            uint8_t key[KEY_SIZE];
            uint8_t iv[KEY_SIZE];

            CipherContext(std::string const& psk);

            static constexpr int getMaxCiphertextLength(size_t size) {
                return size + MAX_BLOCK_LENGTH - 1 + sizeof(aes_tag);
            }
        };

        size_t encrypt(CipherContext& ctx,
                       uint8_t* ciphertext, aes_tag& tag,
                       uint8_t const* plaintext, size_t plaintext_length);
        size_t decrypt(CipherContext& ctx,
                       uint8_t* plaintext,
                       uint8_t const* ciphertext, size_t ciphertext_length,
                       aes_tag& tag);

        /** Encode a frame containing the given protobuf message
         *
         * @return the past-the-end pointer after the encoded frame
        */
        template<typename Message>
        uint8_t* encodeFrame(uint8_t* buffer, uint8_t* buffer_end,
                             Message const& message) {
#if GOOGLE_PROTOBUF_VERSION >= 3006001
            size_t payload_length = message.ByteSizeLong();
#else
            size_t payload_length = message.ByteSize();
#endif
            auto message_end = buffer + validateEncodingBufferSize(
                buffer_end - buffer, payload_length
            );

            buffer[0] = SYNC_0;
            buffer[1] = SYNC_1;

            uint8_t* length_end = encodeLength(
                buffer + 2, buffer_end, payload_length
            );
            message.SerializeWithCachedSizesToArray(length_end);

            uint8_t* payload_end = length_end + payload_length;
            if (payload_end + 2 != message_end) {
                throw InternalError("message boundary calculations do not match");
            }
            uint16_t calculated_crc = crc(buffer + 2, payload_end);
            payload_end[0] = calculated_crc & 0xFF;
            payload_end[1] = (calculated_crc >> 8) & 0xFF;
            return payload_end + 2;
        }
    }
}

#endif
