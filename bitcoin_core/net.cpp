// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Stripped-down version of the P2P transport implementations in Bitcoin
// Core's net.cpp.

#include <net.h>

#include <algorithm>
#include <cstring>

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
