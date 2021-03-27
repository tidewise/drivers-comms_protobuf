#ifndef COMMS_PROTOBUF_CHANNEL_HPP
#define COMMS_PROTOBUF_CHANNEL_HPP

#include <iodrivers_base/Driver.hpp>
#include <comms_protobuf/Protocol.hpp>

namespace comms_protobuf {
    /** Exception thrown in read() when a packet was valid for the underlying protocol,
     * but could not be unmarshalled by the protocol buffers
     */
    struct InvalidProtobufMessage : public std::runtime_error {
        using std::runtime_error::runtime_error;
    };

    /**
     * A communication channel using protocol buffer messages
     *
     * The Local type is the type used for messages created locally for the remote
     * side. The Remote type is the type expected from the remote side
     */
    template<typename Local, typename Remote>
    class Channel : public iodrivers_base::Driver {
    protected:
        const size_t m_max_message_size;
        /** Define a plain type for the benefit of subclasses */
        typedef Channel<Local, Remote> ChannelType;

    private:
        protocol::CipherContext* m_cipher = nullptr;
        bool m_encrypted = false;

        /** Send/receive buffer used internally
         */
        std::vector<uint8_t> m_io_buffer;

        /** Buffer used as target when decrypting the payload from m_io_buffer
         */
        std::vector<uint8_t> m_plaintext_buffer;

        /**
         * Buffer used as target when encrypting the serialized version of the
         * protobuf message
         */
        std::vector<uint8_t> m_ciphertext_buffer;

        int extractPacket(uint8_t const* buffer, size_t size) const {
            return protocol::extractPacket(buffer, size, m_max_message_size);
        }

    public:
        static size_t getBufferSizeFromMessageSize(size_t message_size) {
            return (protocol::PACKET_MIN_OVERHEAD +
                    protocol::getLengthEncodedSize(message_size) +
                    message_size) * 10;
        }

        /** @arg max_message_size the maximum marshalled size of a Remote message
         *      You can estimate this by taking the nominal size of each field
         *      and adding two bytes per field. It does not need to be precise,
         *      the values used internally will be 10x this
         */
        Channel(size_t max_message_size)
            : iodrivers_base::Driver(getBufferSizeFromMessageSize(max_message_size))
            , m_max_message_size(max_message_size)
            , m_io_buffer(getBufferSizeFromMessageSize(max_message_size)) {
        }

        ~Channel() {
            delete m_cipher;
        }

        void setEncryptionKey(std::string key) {
            delete m_cipher;
            m_cipher = new protocol::CipherContext(key);
            m_encrypted = true;

            size_t encryptedPayloadSize =
                protocol::CipherContext::getMaxCiphertextLength(m_max_message_size);

            m_ciphertext_buffer.resize(encryptedPayloadSize);
            m_io_buffer.resize(getBufferSizeFromMessageSize(encryptedPayloadSize));
            m_plaintext_buffer.resize(
                getBufferSizeFromMessageSize(m_max_message_size)
            );
        }

        Remote read() {
            return read(getReadTimeout(), getReadTimeout());
        }

        Remote read(base::Time const& timeout) {
            return read(timeout, timeout);
        }

        Remote read(base::Time const& timeout, base::Time const& first_byte_timeout) {
            size_t size = readPacket(&m_io_buffer[0], m_io_buffer.size(),
                                     timeout, first_byte_timeout);
            auto payload_range = protocol::getPayload(
                &m_io_buffer[0],
                &m_io_buffer[0] + size
            );

            if (m_encrypted) {
                // Payload starts with the AES tag
                protocol::aes_tag tag;
                uint8_t const* ciphertext_start = payload_range.first + tag.size();
                std::copy(payload_range.first, ciphertext_start, tag.begin());

                size_t ciphertext_length = payload_range.second - ciphertext_start;
                size_t size = protocol::decrypt(
                    *m_cipher, &m_plaintext_buffer[0],
                    payload_range.first + tag.size(), ciphertext_length, tag
                );
                payload_range.first = &m_plaintext_buffer[0];
                payload_range.second = &m_plaintext_buffer[size];
            }

            Remote result;
            bool success = result.ParseFromString(
                std::string(reinterpret_cast<char const*>(payload_range.first),
                            reinterpret_cast<char const*>(payload_range.second))
            );
            if (!success) {
                throw InvalidProtobufMessage(
                    "a valid packet was received, but it could not be successfully "\
                    "unmarshalled by the protocol buffer implementation"
                );
            }
            return result;
        }

        void write(Local const& message) {
            uint8_t* end;
            if (m_encrypted) {
#if GOOGLE_PROTOBUF_VERSION >= 3006001
                size_t serialized_length = message.ByteSizeLong();
#else
                size_t serialized_length = message.ByteSize();
#endif
                message.SerializeWithCachedSizesToArray(&m_plaintext_buffer[0]);

                protocol::aes_tag tag;
                size_t ciphertext_length = protocol::encrypt(
                    *m_cipher, &m_ciphertext_buffer[sizeof(tag)], tag,
                    &m_plaintext_buffer[0], serialized_length
                );

                std::copy(tag.begin(), tag.end(), m_ciphertext_buffer.begin());

                end = protocol::encodeFrame(
                    m_io_buffer.data(),
                    m_io_buffer.data() + m_io_buffer.size(),
                    m_ciphertext_buffer.data(),
                    m_ciphertext_buffer.data() + ciphertext_length + sizeof(tag)
                );
            }
            else {
                end = protocol::encodeFrame(
                    &m_io_buffer[0], &m_io_buffer[0] + m_io_buffer.size(),
                    message
                );
            }
            writePacket(&m_io_buffer[0], end - &m_io_buffer[0]);
        }
    };
}

#endif