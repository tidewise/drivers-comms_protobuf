#include <comms_protobuf/Protocol.hpp>

#include <cstring>
#include <openssl/rand.h>
#include <openssl/evp.h>

using namespace std;
using namespace comms_protobuf;

static_assert(protocol::CipherContext::MAX_BLOCK_LENGTH == EVP_MAX_BLOCK_LENGTH,
              "max block length differ between EVP (OpenSSL) and our internal value");

int protocol::extractPacket(uint8_t const* buffer, size_t size,
                            size_t max_payload_size) {
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

    auto parsed_length = parseLength(buffer + 2, buffer + size);
    auto payload_length = parsed_length.first;
    auto length_field_end = parsed_length.second;
    if (!length_field_end) {
        return -1;
    }
    if (payload_length > max_payload_size) {
        return -1;
    }

    uint8_t const* message_end = length_field_end + payload_length + 2;
    if (buffer + size < message_end) {
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

std::pair<uint8_t const*, uint8_t const*> protocol::getPayload(
    uint8_t const* buffer, uint8_t const* buffer_end
) {
    auto parsed_length = parseLength(buffer + 2, buffer_end);
    auto payload_end = parsed_length.first + parsed_length.second;
    if (payload_end > buffer_end) {
        throw std::invalid_argument(
            "getPayload: provided buffer is not big enough to contain payload "
            "of the encoded length (" + to_string(parsed_length.first) + ") bytes. "
            "Would have expected a buffer of size " + to_string(payload_end - buffer) +
            ", but got " + to_string(buffer_end - buffer)
        );
    }
    return make_pair(parsed_length.second, payload_end);
}

uint8_t* protocol::encodeFrame(uint8_t* buffer, uint8_t* buffer_end,
                               uint8_t const* payload_begin,
                               uint8_t const* payload_end) {
    validateEncodingBufferSize(buffer_end - buffer, payload_end - payload_begin);

    buffer[0] = SYNC_0;
    buffer[1] = SYNC_1;

    size_t payload_length = payload_end - payload_begin;
    uint8_t* length_end = encodeLength(buffer + 2, buffer_end, payload_length);
    std::memcpy(length_end, payload_begin, payload_length);

    uint8_t* message_end = length_end + payload_length + 2;
    uint16_t calculated_crc = crc(buffer + 2, message_end - 2);
    message_end[-2] = calculated_crc & 0xFF;
    message_end[-1] = (calculated_crc >> 8) & 0xFF;
    return message_end;
}

pair<size_t, uint8_t const*> protocol::parseLength(
    uint8_t const* begin, uint8_t const* end
) {
    size_t length = 0;
    uint8_t const* max_end = std::min(begin + sizeof(size_t), end);

    int shift = 0;
    for (auto ptr = begin; ptr < max_end; ++ptr, shift += 7) {
        size_t b = *ptr;
        length |= (b & 0x7F) << shift;
        if ((b & 0x80) == 0) {
            return make_pair(length, ptr + 1);
        }
    }
    return make_pair(0, nullptr);
}

size_t protocol::getLengthEncodedSize(size_t length) {
    int size = 0;
    while (length) {
        size += 1;
        length >>= 7;
    }
    if (size > 8) {
        throw std::invalid_argument("given length cannot be encoded on 8 bytes");
    }
    return size;
}

uint8_t* protocol::encodeLength(uint8_t* begin, uint8_t* end, size_t length) {
    size_t remaining_length = length;
    for (uint8_t* ptr = begin; ptr < end; ++ptr) {
        *ptr = remaining_length & 0x7F;
        remaining_length >>= 7;
        if (!remaining_length) {
            return ptr + 1;
        }

        *ptr |= 0x80;
    }
    throw std::invalid_argument(
        "encodeLength: provided buffer too small to contain the given length: " +
        to_string(end - begin) + " bytes available, needed " +
        to_string(getLengthEncodedSize(length)) + " bytes to encode " +
        to_string(length)
    );
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

size_t protocol::validateEncodingBufferSize(
    size_t buffer_length, size_t payload_length
) {
    size_t length_encoded_size = getLengthEncodedSize(payload_length);
    // NOTE: MIN_OVERHEAD accounts for one byte of length, thus the -1
    size_t expected_buffer_length = PACKET_MIN_OVERHEAD +
                                    payload_length + length_encoded_size - 1;
    if (expected_buffer_length > buffer_length) {
        throw std::invalid_argument(
            "encodeFrame: provided buffer is too small. It needed to be " +
            std::to_string(expected_buffer_length) +
            " bytes for this particular message, but was only " +
            to_string(buffer_length) + " bytes long"
        );
    }
    return expected_buffer_length;
}

protocol::CipherContext::CipherContext(string const& psk) {
    static const int NROUNDS = 1000000;
    int i = EVP_BytesToKey(
        EVP_aes_256_gcm(), EVP_sha256(),
        nullptr, // salt
        reinterpret_cast<uint8_t const*>(&psk[0]), psk.length(), NROUNDS, key, iv
    );
    if (i != KEY_SIZE) {
        throw std::runtime_error("failed key derivation");
    }
}

struct ContextGuard {
    EVP_CIPHER_CTX*& ctx;
    ContextGuard(EVP_CIPHER_CTX*& ctx)
        : ctx(ctx) {
        ctx = EVP_CIPHER_CTX_new();
    }
    ContextGuard(ContextGuard&) = delete;
    ~ContextGuard() {
        EVP_CIPHER_CTX_free(ctx);
    }
};

size_t protocol::encrypt(CipherContext& ctx_,
                         uint8_t* ciphertext, aes_tag& tag,
                         uint8_t const* plaintext, size_t plaintext_length) {

    EVP_CIPHER_CTX* ctx;
    ContextGuard guard(ctx);

    /* Initialise the encryption operation. */
    if (!EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, ctx_.key, ctx_.iv)) {
        throw EncryptionFailed("encrypt: failed to initialize the AES 256 GCM cypher");
    }

    int encrypted_length = 0;
    int operation_length = 0;
    if (1 != EVP_EncryptUpdate(ctx, ciphertext, &operation_length,
                              plaintext, plaintext_length)) {
        throw EncryptionFailed("encrypt: encryption failed");
    }
    encrypted_length += operation_length;

    if (1 != EVP_EncryptFinal_ex(ctx, ciphertext + encrypted_length, &operation_length)) {
        throw EncryptionFailed("encrypt: finalization failed");
    }
    encrypted_length += operation_length;

    if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, &tag[0])) {
        throw EncryptionFailed("encrypt: failed to get the AES tag");
    }

    return encrypted_length;
}

size_t protocol::decrypt(CipherContext& ctx_,
                         uint8_t* plaintext,
                         uint8_t const* ciphertext, size_t ciphertext_length,
                         aes_tag& tag) {

    EVP_CIPHER_CTX* ctx;
    ContextGuard guard(ctx);

    if (!EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, ctx_.key, ctx_.iv)) {
        throw DecryptionFailed("encrypt: failed to initialize the AES 256 GCM cipher");
    }

    int decrypted_length = 0;
    int operation_length = 0;
    if (1 != EVP_DecryptUpdate(ctx, plaintext, &operation_length,
                               ciphertext, ciphertext_length)) {
        throw DecryptionFailed("encrypt: decryption failed");
    }
    decrypted_length += operation_length;

    if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG,
                                 16, const_cast<uint8_t*>(&tag[0]))) {
        throw DecryptionFailed("encrypt: failed to set the AES tag");
    }

    if (1 != EVP_DecryptFinal_ex(ctx, plaintext + decrypted_length, &operation_length)) {
        throw DecryptionFailed("encrypt: message validation failed");
    }
    decrypted_length += operation_length;

    return decrypted_length;
}