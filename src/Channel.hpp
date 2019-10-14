#ifndef COMMS_PROTOBUF_CHANNEL_HPP
#define COMMS_PROTOBUF_CHANNEL_HPP

#include <iodrivers_base/Driver.hpp>
#include <comms_protobuf/Protocol.hpp>

namespace comms_protobuf {
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
        /** Send buffer used internally
         */
        std::vector<uint8_t> m_send_buffer;

        /** Receive buffer used internally
         */
        std::vector<uint8_t> m_receive_buffer;

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
            , m_send_buffer(getBufferSizeFromMessageSize(max_message_size))
            , m_receive_buffer(getBufferSizeFromMessageSize(max_message_size)) {
        }

        Remote read() {
            return read(getReadTimeout(), getReadTimeout());
        }

        Remote read(base::Time const& timeout) {
            return read(timeout, timeout);
        }

        Remote read(base::Time const& timeout, base::Time const& first_byte_timeout) {
            base::Time deadline = base::Time::now() + timeout;
            Remote result;
            while (true) {
                size_t size = readPacket(&m_receive_buffer[0], m_receive_buffer.size(),
                                         timeout, first_byte_timeout);
                auto payload_range = protocol::getPayload(
                    &m_receive_buffer[0],
                    &m_receive_buffer[0] + size
                );

                bool success = result.ParseFromString(
                    std::string(reinterpret_cast<char const*>(payload_range.first),
                                reinterpret_cast<char const*>(payload_range.second))
                );
                if (success) {
                    return result;
                }
                else if (deadline < base::Time::now()) {
                    throw iodrivers_base::TimeoutError(
                        iodrivers_base::TimeoutError::PACKET,
                        "packets were received, but none was successfully unmarshalled "\
                        "by the protocol buffer implementation"
                    );
                }
            }
        }

        void write(Local const& message) {
            uint8_t* end = protocol::encodeFrame(
                &m_send_buffer[0], &m_send_buffer[0] + m_send_buffer.size(), message);
            writePacket(&m_send_buffer[0], end - &m_send_buffer[0]);
        }
    };
}

#endif