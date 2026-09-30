// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Stripped-down version of the P2P transport implementations in Bitcoin
// Core's net.cpp.

#include <net.h>

#include <random.h>
#include <span.h>

#include <algorithm>
#include <cassert>
#include <cstring>
#include <iterator>
#include <unordered_map>

namespace {

/** Clear a vector (or std::deque) and release its allocated memory. */
template<typename V>
inline void ClearShrink(V& v) noexcept
{
    // There are various ways to clear a vector and release its memory:
    //
    // 1. V{}.swap(v)
    // 2. v = V{}
    // 3. v = {}; v.shrink_to_fit();
    // 4. v.clear(); v.shrink_to_fit();
    //
    // (2) does not appear to release memory in glibc debug mode, even if v.shrink_to_fit()
    // follows. (3) and (4) rely on std::vector::shrink_to_fit, which is only a non-binding
    // request. Therefore, we use method (1).

    V{}.swap(v);
}

} // namespace

V1Transport::V1Transport() noexcept
{
    Reset();
}

Transport::Info V1Transport::GetInfo() const noexcept
{
    return {.transport_type = TransportProtocolType::V1, .session_id = {}};
}

int V1Transport::readHeader(std::span<const uint8_t> msg_bytes)
{
    // copy data to temporary parsing buffer
    unsigned int nRemaining = CMessageHeader::HEADER_SIZE - nHdrPos;
    unsigned int nCopy = std::min<unsigned int>(nRemaining, msg_bytes.size());

    memcpy(&hdrbuf[nHdrPos], msg_bytes.data(), nCopy);
    nHdrPos += nCopy;

    // if header incomplete, exit
    if (nHdrPos < CMessageHeader::HEADER_SIZE)
        return nCopy;

    // deserialize to CMessageHeader
    try {
        hdrbuf >> hdr;
    }
    catch (const std::exception&) {
        return -1;
    }

    // Check start string, network magic
    if (memcmp(hdr.pchMessageStart, pchMessageStart, sizeof(pchMessageStart)) != 0) {
        return -1;
    }

    // reject messages larger than MAX_SIZE or MAX_PROTOCOL_MESSAGE_LENGTH
    if (hdr.nMessageSize > MAX_SIZE || hdr.nMessageSize > MAX_PROTOCOL_MESSAGE_LENGTH) {
        return -1;
    }

    // switch state to reading message data
    in_data = true;

    return nCopy;
}

int V1Transport::readData(std::span<const uint8_t> msg_bytes)
{
    unsigned int nRemaining = hdr.nMessageSize - nDataPos;
    unsigned int nCopy = std::min<unsigned int>(nRemaining, msg_bytes.size());

    if (vRecv.size() < nDataPos + nCopy) {
        // Allocate up to 256 KiB ahead, but never more than the total message size.
        vRecv.resize(std::min(hdr.nMessageSize, nDataPos + nCopy + 256 * 1024));
    }

    hasher.Write(msg_bytes.first(nCopy));
    memcpy(&vRecv[nDataPos], msg_bytes.data(), nCopy);
    nDataPos += nCopy;

    return nCopy;
}

const uint256& V1Transport::GetMessageHash() const
{
    assert(CompleteInternal());
    if (data_hash.IsNull())
        hasher.Finalize(data_hash);
    return data_hash;
}

CNetMessage V1Transport::GetReceivedMessage(bool& reject_message)
{
    // Initialize out parameter
    reject_message = false;
    // decompose a single CNetMessage from the TransportDeserializer
    CNetMessage msg(std::move(vRecv));

    // store message type string, and sizes
    msg.m_type = hdr.GetCommand();
    msg.m_message_size = hdr.nMessageSize;
    msg.m_raw_message_size = hdr.nMessageSize + CMessageHeader::HEADER_SIZE;

    uint256 hash = GetMessageHash();

    // Check checksum and header message type string
    if (memcmp(hash.begin(), hdr.pchChecksum, CMessageHeader::CHECKSUM_SIZE) != 0) {
        reject_message = true;
    } else if (!hdr.IsValid()) {
        reject_message = true;
    }

    // Always reset the network deserializer (prepare for the next message)
    Reset();
    return msg;
}

bool V1Transport::SetMessageToSend(CSerializedNetMsg& msg) noexcept
{
    // Determine whether a new message can be set.
    if (m_sending_header || m_bytes_sent < m_message_to_send.data.size()) return false;

    // create dbl-sha256 checksum
    uint256 hash = Hash(msg.data);

    // create header
    CMessageHeader hdr(msg.m_type.c_str(), msg.data.size());
    memcpy(hdr.pchChecksum, hash.begin(), CMessageHeader::CHECKSUM_SIZE);

    // serialize header
    m_header_to_send.clear();
    VectorWriter{m_header_to_send, 0, hdr};

    // update state
    m_message_to_send = std::move(msg);
    m_sending_header = true;
    m_bytes_sent = 0;
    return true;
}

Transport::BytesToSend V1Transport::GetBytesToSend(bool have_next_message) const noexcept
{
    if (m_sending_header) {
        return {std::span{m_header_to_send}.subspan(m_bytes_sent),
                // We have more to send after the header if the message has payload, or if there
                // is a next message after that.
                have_next_message || !m_message_to_send.data.empty(),
                m_message_to_send.m_type
               };
    } else {
        return {std::span{m_message_to_send.data}.subspan(m_bytes_sent),
                // We only have more to send after this message's payload if there is another
                // message.
                have_next_message,
                m_message_to_send.m_type
               };
    }
}

void V1Transport::MarkBytesSent(size_t bytes_sent) noexcept
{
    m_bytes_sent += bytes_sent;
    if (m_sending_header && m_bytes_sent == m_header_to_send.size()) {
        // We're done sending a message's header. Switch to sending its data bytes.
        m_sending_header = false;
        m_bytes_sent = 0;
    } else if (!m_sending_header && m_bytes_sent == m_message_to_send.data.size()) {
        // We're done sending a message's data. Wipe the data vector to reduce memory consumption.
        ClearShrink(m_message_to_send.data);
        m_bytes_sent = 0;
    }
}

namespace {

/** List of short messages as defined in BIP324, in order.
 *
 * Only message types that are actually implemented in Bitcoin Core need to be listed, as other
 * messages get ignored anyway - whether we know how to decode them or not.
 */
const std::array<std::string, BIP324_SHORTIDS_IMPLEMENTED> V2_MESSAGE_IDS = {
    "", // 12 bytes follow encoding the message type like in V1
    "addr",
    "block",
    "blocktxn",
    "cmpctblock",
    "feefilter",
    "filteradd",
    "filterclear",
    "filterload",
    "getblocks",
    "getblocktxn",
    "getdata",
    "getheaders",
    "headers",
    "inv",
    "mempool",
    "merkleblock",
    "notfound",
    "ping",
    "pong",
    "sendcmpct",
    "tx",
    "getcfilters",
    "cfilter",
    "getcfheaders",
    "cfheaders",
    "getcfcheckpt",
    "cfcheckpt",
    "addrv2",
    "", "", "", // Unimplemented message types 29-31
    "", "", "", "", // Unimplemented message types 32-35
    "",  // Unimplemented message type 36
    "feature",
};

class V2MessageMap
{
    std::unordered_map<std::string, uint8_t> m_map;

public:
    V2MessageMap() noexcept
    {
        for (size_t i = 1; i < std::size(V2_MESSAGE_IDS); ++i) {
            m_map.emplace(V2_MESSAGE_IDS[i], i);
        }
    }

    std::optional<uint8_t> operator()(const std::string& message_name) const noexcept
    {
        auto it = m_map.find(message_name);
        if (it == m_map.end()) return std::nullopt;
        return it->second;
    }
};

const V2MessageMap V2_MESSAGE_MAP;

std::vector<uint8_t> GenerateRandomGarbage() noexcept
{
    std::vector<uint8_t> ret;
    ret.resize(GetRandRange(V2Transport::MAX_GARBAGE_LEN + 1));
    GetRandBytes(ret);
    return ret;
}

} // namespace

void V2Transport::StartSendingHandshake() noexcept
{
    assert(m_send_state == SendState::AWAITING_KEY);
    assert(m_send_buffer.empty());
    // Initialize the send buffer with ellswift pubkey + provided garbage.
    m_send_buffer.resize(EllSwiftPubKey::size() + m_send_garbage.size());
    std::copy(std::begin(m_cipher.GetOurPubKey()), std::end(m_cipher.GetOurPubKey()), MakeWritableByteSpan(m_send_buffer).begin());
    std::copy(m_send_garbage.begin(), m_send_garbage.end(), m_send_buffer.begin() + EllSwiftPubKey::size());
    // We cannot wipe m_send_garbage as it will still be used as AAD later in the handshake.
}

V2Transport::V2Transport(const CKey& key, std::span<const std::byte> ent32, std::vector<uint8_t> garbage) noexcept
    : m_cipher{key, ent32},
      m_recv_state{RecvState::KEY},
      m_send_garbage{std::move(garbage)},
      m_send_state{SendState::AWAITING_KEY}
{
    assert(m_send_garbage.size() <= MAX_GARBAGE_LEN);
    // Start sending immediately, as we're the initiator of the connection.
    StartSendingHandshake();
}

V2Transport::V2Transport() noexcept
    : V2Transport{GenerateRandomKey(), MakeByteSpan(GetRandHash()), GenerateRandomGarbage()} {}

void V2Transport::SetReceiveState(RecvState recv_state) noexcept
{
    // Enforce allowed state transitions.
    switch (m_recv_state) {
    case RecvState::KEY:
        assert(recv_state == RecvState::GARB_GARBTERM);
        break;
    case RecvState::GARB_GARBTERM:
        assert(recv_state == RecvState::VERSION);
        break;
    case RecvState::VERSION:
        assert(recv_state == RecvState::APP);
        break;
    case RecvState::APP:
        assert(recv_state == RecvState::APP_READY);
        break;
    case RecvState::APP_READY:
        assert(recv_state == RecvState::APP);
        break;
    }
    // Change state.
    m_recv_state = recv_state;
}

void V2Transport::SetSendState(SendState send_state) noexcept
{
    // Enforce allowed state transitions.
    switch (m_send_state) {
    case SendState::AWAITING_KEY:
        assert(send_state == SendState::READY);
        break;
    case SendState::READY:
        assert(false); // Final state
        break;
    }
    // Change state.
    m_send_state = send_state;
}

bool V2Transport::ReceivedMessageComplete() const noexcept
{
    return m_recv_state == RecvState::APP_READY;
}

bool V2Transport::ProcessReceivedKeyBytes() noexcept
{
    assert(m_recv_state == RecvState::KEY);
    assert(m_recv_buffer.size() <= EllSwiftPubKey::size());

    if (m_recv_buffer.size() == EllSwiftPubKey::size()) {
        // Other side's key has been fully received, and can now be Diffie-Hellman combined with
        // our key to initialize the encryption ciphers.

        // Initialize the ciphers.
        EllSwiftPubKey ellswift(MakeByteSpan(m_recv_buffer));
        m_cipher.Initialize(ellswift, /*initiator=*/true);

        // Switch receiver state to GARB_GARBTERM.
        SetReceiveState(RecvState::GARB_GARBTERM);
        m_recv_buffer.clear();

        // Switch sender state to READY.
        SetSendState(SendState::READY);

        // Append the garbage terminator to the send buffer.
        m_send_buffer.resize(m_send_buffer.size() + BIP324Cipher::GARBAGE_TERMINATOR_LEN);
        std::copy(m_cipher.GetSendGarbageTerminator().begin(),
                  m_cipher.GetSendGarbageTerminator().end(),
                  MakeWritableByteSpan(m_send_buffer).last(BIP324Cipher::GARBAGE_TERMINATOR_LEN).begin());

        // Construct version packet in the send buffer, with the sent garbage data as AAD.
        m_send_buffer.resize(m_send_buffer.size() + BIP324Cipher::EXPANSION + VERSION_CONTENTS.size());
        m_cipher.Encrypt(
            /*contents=*/VERSION_CONTENTS,
            /*aad=*/MakeByteSpan(m_send_garbage),
            /*ignore=*/false,
            /*output=*/MakeWritableByteSpan(m_send_buffer).last(BIP324Cipher::EXPANSION + VERSION_CONTENTS.size()));
        // We no longer need the garbage.
        ClearShrink(m_send_garbage);
    } else {
        // We still have to receive more key bytes.
    }
    return true;
}

bool V2Transport::ProcessReceivedGarbageBytes() noexcept
{
    assert(m_recv_state == RecvState::GARB_GARBTERM);
    assert(m_recv_buffer.size() <= MAX_GARBAGE_LEN + BIP324Cipher::GARBAGE_TERMINATOR_LEN);
    if (m_recv_buffer.size() >= BIP324Cipher::GARBAGE_TERMINATOR_LEN) {
        if (std::ranges::equal(MakeByteSpan(m_recv_buffer).last(BIP324Cipher::GARBAGE_TERMINATOR_LEN), m_cipher.GetReceiveGarbageTerminator())) {
            // Garbage terminator received. Store garbage to authenticate it as AAD later.
            m_recv_aad = std::move(m_recv_buffer);
            m_recv_aad.resize(m_recv_aad.size() - BIP324Cipher::GARBAGE_TERMINATOR_LEN);
            m_recv_buffer.clear();
            SetReceiveState(RecvState::VERSION);
        } else if (m_recv_buffer.size() == MAX_GARBAGE_LEN + BIP324Cipher::GARBAGE_TERMINATOR_LEN) {
            // We've reached the maximum length for garbage + garbage terminator, and the
            // terminator still does not match. Abort.
            return false;
        } else {
            // We still need to receive more garbage and/or garbage terminator bytes.
        }
    } else {
        // We have less than GARBAGE_TERMINATOR_LEN (16) bytes, so we certainly need to receive
        // more first.
    }
    return true;
}

bool V2Transport::ProcessReceivedPacketBytes() noexcept
{
    assert(m_recv_state == RecvState::VERSION || m_recv_state == RecvState::APP);

    // The maximum permitted contents length for a packet, consisting of:
    // - 0x00 byte: indicating long message type encoding
    // - 12 bytes of message type
    // - payload
    static constexpr size_t MAX_CONTENTS_LEN =
        1 + CMessageHeader::COMMAND_SIZE +
        std::min<size_t>(MAX_SIZE, MAX_PROTOCOL_MESSAGE_LENGTH);

    if (m_recv_buffer.size() == BIP324Cipher::LENGTH_LEN) {
        // Length descriptor received.
        m_recv_len = m_cipher.DecryptLength(MakeByteSpan(m_recv_buffer));
        if (m_recv_len > MAX_CONTENTS_LEN) {
            return false;
        }
    } else if (m_recv_buffer.size() > BIP324Cipher::LENGTH_LEN && m_recv_buffer.size() == m_recv_len + BIP324Cipher::EXPANSION) {
        // Ciphertext received, decrypt it into m_recv_decode_buffer.
        // Note that it is impossible to reach this branch without hitting the branch above first,
        // as GetMaxBytesToProcess only allows up to LENGTH_LEN into the buffer before that point.
        m_recv_decode_buffer.resize(m_recv_len);
        bool ignore{false};
        bool ret = m_cipher.Decrypt(
            /*input=*/MakeByteSpan(m_recv_buffer).subspan(BIP324Cipher::LENGTH_LEN),
            /*aad=*/MakeByteSpan(m_recv_aad),
            /*ignore=*/ignore,
            /*contents=*/MakeWritableByteSpan(m_recv_decode_buffer));
        if (!ret) {
            return false;
        }
        // We have decrypted a valid packet with the AAD we expected, so clear the expected AAD.
        ClearShrink(m_recv_aad);

        // At this point we have a valid packet decrypted into m_recv_decode_buffer. If it's not a
        // decoy, which we simply ignore, use the current state to decide what to do with it.
        if (!ignore) {
            switch (m_recv_state) {
            case RecvState::VERSION:
                // Version message received; transition to application phase. The contents is
                // ignored, but can be used for future extensions.
                SetReceiveState(RecvState::APP);
                break;
            case RecvState::APP:
                // Application message decrypted correctly. It can be extracted using GetMessage().
                SetReceiveState(RecvState::APP_READY);
                break;
            default:
                // Any other state is invalid (this function should not have been called).
                assert(false);
            }
        }
        // Wipe the receive buffer where the next packet will be received into.
        ClearShrink(m_recv_buffer);
        // In all but APP_READY state, we can wipe the decoded contents.
        if (m_recv_state != RecvState::APP_READY) ClearShrink(m_recv_decode_buffer);
    } else {
        // We either have less than 3 bytes, so we don't know the packet's length yet, or more
        // than 3 bytes but less than the packet's full ciphertext. Wait until those arrive.
    }
    return true;
}

size_t V2Transport::GetMaxBytesToProcess() noexcept
{
    switch (m_recv_state) {
    case RecvState::KEY:
        // During the KEY state, we only allow the 64-byte key into the receive buffer.
        assert(m_recv_buffer.size() <= EllSwiftPubKey::size());
        // As long as we have not received the other side's public key, don't receive more than
        // that (64 bytes), as garbage follows, and locating the garbage terminator requires the
        // key exchange first.
        return EllSwiftPubKey::size() - m_recv_buffer.size();
    case RecvState::GARB_GARBTERM:
        // Process garbage bytes one by one (because terminator may appear anywhere).
        return 1;
    case RecvState::VERSION:
    case RecvState::APP:
        // These three states all involve decoding a packet. Process the length descriptor first,
        // so that we know where the current packet ends (and we don't process bytes from the next
        // packet or decoy yet). Then, process the ciphertext bytes of the current packet.
        if (m_recv_buffer.size() < BIP324Cipher::LENGTH_LEN) {
            return BIP324Cipher::LENGTH_LEN - m_recv_buffer.size();
        } else {
            // Note that BIP324Cipher::EXPANSION is the total difference between contents size
            // and encoded packet size, which includes the 3 bytes due to the packet length.
            // When transitioning from receiving the packet length to receiving its ciphertext,
            // the encrypted packet length is left in the receive buffer.
            return BIP324Cipher::EXPANSION + m_recv_len - m_recv_buffer.size();
        }
    case RecvState::APP_READY:
        // No bytes can be processed until GetMessage() is called.
        return 0;
    }
    assert(false); // unreachable
    return 0;
}

bool V2Transport::ReceivedBytes(std::span<const uint8_t>& msg_bytes) noexcept
{
    /** How many bytes to allocate in the receive buffer at most above what is received so far. */
    static constexpr size_t MAX_RESERVE_AHEAD = 256 * 1024;

    // Process the provided bytes in msg_bytes in a loop. In each iteration a nonzero number of
    // bytes (decided by GetMaxBytesToProcess) are taken from the beginning om msg_bytes, and
    // appended to m_recv_buffer. Then, depending on the receiver state, one of the
    // ProcessReceived*Bytes functions is called to process the bytes in that buffer.
    while (!msg_bytes.empty()) {
        // Decide how many bytes to copy from msg_bytes to m_recv_buffer.
        size_t max_read = GetMaxBytesToProcess();

        // Reserve space in the buffer if there is not enough.
        if (m_recv_buffer.size() + std::min(msg_bytes.size(), max_read) > m_recv_buffer.capacity()) {
            switch (m_recv_state) {
            case RecvState::KEY:
            case RecvState::GARB_GARBTERM:
                // During the initial states (key/garbage), allocate once to fit the maximum (4111
                // bytes).
                m_recv_buffer.reserve(MAX_GARBAGE_LEN + BIP324Cipher::GARBAGE_TERMINATOR_LEN);
                break;
            case RecvState::VERSION:
            case RecvState::APP: {
                // During states where a packet is being received, as much as is expected but never
                // more than MAX_RESERVE_AHEAD bytes in addition to what is received so far.
                // This means attackers that want to cause us to waste allocated memory are limited
                // to MAX_RESERVE_AHEAD above the largest allowed message contents size, and to
                // MAX_RESERVE_AHEAD more than they've actually sent us.
                size_t alloc_add = std::min(max_read, msg_bytes.size() + MAX_RESERVE_AHEAD);
                m_recv_buffer.reserve(m_recv_buffer.size() + alloc_add);
                break;
            }
            case RecvState::APP_READY:
                // The buffer is empty in this state.
                assert(m_recv_buffer.empty());
                break;
            }
        }

        // Can't read more than provided input.
        max_read = std::min(msg_bytes.size(), max_read);
        // Copy data to buffer.
        m_recv_buffer.insert(m_recv_buffer.end(), UCharCast(msg_bytes.data()), UCharCast(msg_bytes.data() + max_read));
        msg_bytes = msg_bytes.subspan(max_read);

        // Process data in the buffer.
        switch (m_recv_state) {
        case RecvState::KEY:
            if (!ProcessReceivedKeyBytes()) return false;
            break;

        case RecvState::GARB_GARBTERM:
            if (!ProcessReceivedGarbageBytes()) return false;
            break;

        case RecvState::VERSION:
        case RecvState::APP:
            if (!ProcessReceivedPacketBytes()) return false;
            break;

        case RecvState::APP_READY:
            return true;
        }
        // Make sure we have made progress before continuing.
        assert(max_read > 0);
    }

    return true;
}

std::optional<std::string> V2Transport::GetMessageType(std::span<const uint8_t>& contents) noexcept
{
    if (contents.size() == 0) return std::nullopt; // Empty contents
    uint8_t first_byte = contents[0];
    contents = contents.subspan(1); // Strip first byte.

    if (first_byte != 0) {
        // Short (1 byte) encoding.
        if (first_byte < std::size(V2_MESSAGE_IDS)) {
            // Valid short message id.
            return V2_MESSAGE_IDS[first_byte];
        } else {
            // Unknown short message id.
            return std::nullopt;
        }
    }

    if (contents.size() < CMessageHeader::COMMAND_SIZE) {
        return std::nullopt; // Long encoding needs 12 message type bytes.
    }

    size_t msg_type_len{0};
    while (msg_type_len < CMessageHeader::COMMAND_SIZE && contents[msg_type_len] != 0) {
        // Verify that message type bytes before the first 0x00 are in range. BIP324 specifies the
        // long message type encoding as "an ASCII message type (as in the v1 P2P protocol)".
        if (contents[msg_type_len] < ' ' || contents[msg_type_len] > 0x7E) {
            return {};
        }
        ++msg_type_len;
    }
    std::string ret{reinterpret_cast<const char*>(contents.data()), msg_type_len};
    while (msg_type_len < CMessageHeader::COMMAND_SIZE) {
        // Verify that message type bytes after the first 0x00 are also 0x00.
        if (contents[msg_type_len] != 0) return {};
        ++msg_type_len;
    }
    // Strip message type bytes of contents.
    contents = contents.subspan(CMessageHeader::COMMAND_SIZE);
    return ret;
}

CNetMessage V2Transport::GetReceivedMessage(bool& reject_message) noexcept
{
    assert(m_recv_state == RecvState::APP_READY);
    std::span<const uint8_t> contents{m_recv_decode_buffer};
    auto msg_type = GetMessageType(contents);
    CNetMessage msg{DataStream{}};
    // Note that BIP324Cipher::EXPANSION also includes the length descriptor size.
    msg.m_raw_message_size = m_recv_decode_buffer.size() + BIP324Cipher::EXPANSION;
    if (msg_type) {
        reject_message = false;
        msg.m_type = std::move(*msg_type);
        msg.m_message_size = contents.size();
        msg.m_recv.resize(contents.size());
        std::copy(contents.begin(), contents.end(), UCharCast(msg.m_recv.data()));
    } else {
        reject_message = true;
    }
    ClearShrink(m_recv_decode_buffer);
    SetReceiveState(RecvState::APP);

    return msg;
}

bool V2Transport::SetMessageToSend(CSerializedNetMsg& msg) noexcept
{
    // We only allow adding a new message to be sent when in the READY state (so the packet cipher
    // is available) and the send buffer is empty. This limits the number of messages in the send
    // buffer to just one, and leaves the responsibility for queueing them up to the caller.
    if (!(m_send_state == SendState::READY && m_send_buffer.empty())) return false;
    // Construct contents (encoding message type + payload).
    std::vector<uint8_t> contents;
    auto short_message_id = V2_MESSAGE_MAP(msg.m_type);
    if (short_message_id) {
        contents.resize(1 + msg.data.size());
        contents[0] = *short_message_id;
        std::copy(msg.data.begin(), msg.data.end(), contents.begin() + 1);
    } else {
        // Initialize with zeroes, and then write the message type string starting at offset 1.
        // This means contents[0] and the unused positions in contents[1..13] remain 0x00.
        contents.resize(1 + CMessageHeader::COMMAND_SIZE + msg.data.size(), 0);
        std::copy(msg.m_type.begin(), msg.m_type.end(), contents.data() + 1);
        std::copy(msg.data.begin(), msg.data.end(), contents.begin() + 1 + CMessageHeader::COMMAND_SIZE);
    }
    // Construct ciphertext in send buffer.
    m_send_buffer.resize(contents.size() + BIP324Cipher::EXPANSION);
    m_cipher.Encrypt(MakeByteSpan(contents), {}, false, MakeWritableByteSpan(m_send_buffer));
    m_send_type = msg.m_type;
    // Release memory
    ClearShrink(msg.data);
    return true;
}

Transport::BytesToSend V2Transport::GetBytesToSend(bool have_next_message) const noexcept
{
    assert(m_send_pos <= m_send_buffer.size());
    return {
        std::span{m_send_buffer}.subspan(m_send_pos),
        // We only have more to send after the current m_send_buffer if there is a (next)
        // message to be sent, and we're capable of sending packets. */
        have_next_message && m_send_state == SendState::READY,
        m_send_type
    };
}

void V2Transport::MarkBytesSent(size_t bytes_sent) noexcept
{
    m_send_pos += bytes_sent;
    assert(m_send_pos <= m_send_buffer.size());
    if (m_send_pos >= CMessageHeader::HEADER_SIZE) {
        m_sent_v1_header_worth = true;
    }
    // Wipe the buffer when everything is sent.
    if (m_send_pos == m_send_buffer.size()) {
        m_send_pos = 0;
        ClearShrink(m_send_buffer);
    }
}

bool V2Transport::ShouldReconnectV1() const noexcept
{
    // We only reconnect in the very first state and when the receive buffer is empty. Together
    // these conditions imply nothing has been received so far.
    if (m_recv_state != RecvState::KEY) return false;
    if (!m_recv_buffer.empty()) return false;
    // Check if we've sent enough for the other side to disconnect us (if it was V1).
    return m_sent_v1_header_worth;
}

Transport::Info V2Transport::GetInfo() const noexcept
{
    Transport::Info info;

    // Do not report v2 and session ID until the version packet has been received
    // and verified (confirming that the other side very likely has the same keys as us).
    if (m_recv_state != RecvState::KEY && m_recv_state != RecvState::GARB_GARBTERM &&
        m_recv_state != RecvState::VERSION) {
        info.transport_type = TransportProtocolType::V2;
        info.session_id = uint256(MakeUCharSpan(m_cipher.GetSessionID()));
    } else {
        info.transport_type = TransportProtocolType::DETECTING;
    }

    return info;
}
