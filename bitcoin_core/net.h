// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Stripped-down version of the P2P transport abstraction in Bitcoin Core's
// net.h, without locking (a transport is only used by a single thread here).

#ifndef BITCOIN_NET_H
#define BITCOIN_NET_H

#include <bip324.h>
#include <hash.h>
#include <key.h>
#include <protocol.h>
#include <streams.h>
#include <uint256.h>

#include <cstddef>
#include <cstdint>
#include <array>
#include <optional>
#include <span>
#include <string>
#include <tuple>
#include <vector>

/** Maximum length of incoming protocol messages. Bitcoin Core uses 4 MB; dnsseed limits received
 *  messages to 256 KiB, as the messages it processes are much smaller. */
inline constexpr unsigned int MAX_PROTOCOL_MESSAGE_LENGTH = 256 * 1024;

enum class TransportProtocolType : uint8_t {
    DETECTING, //!< Peer could be v1 or v2
    V1, //!< Unencrypted, plaintext protocol
    V2, //!< BIP324 protocol
};

struct CSerializedNetMsg {
    CSerializedNetMsg() = default;
    CSerializedNetMsg(CSerializedNetMsg&&) = default;
    CSerializedNetMsg& operator=(CSerializedNetMsg&&) = default;
    // No implicit copying, only moves.
    CSerializedNetMsg(const CSerializedNetMsg& msg) = delete;
    CSerializedNetMsg& operator=(const CSerializedNetMsg&) = delete;

    std::vector<unsigned char> data;
    std::string m_type;
};

/** Transport protocol agnostic message container.
 * Ideally it should only contain receive time, payload,
 * type and size.
 */
class CNetMessage
{
public:
    DataStream m_recv;                   //!< received message data
    uint32_t m_message_size{0};          //!< size of the payload
    uint32_t m_raw_message_size{0};      //!< used wire size of the message (including header/checksum)
    std::string m_type;

    explicit CNetMessage(DataStream&& recv_in) : m_recv(std::move(recv_in)) {}
    // Only one CNetMessage object will exist for the same message on either
    // the receive or processing queue. For performance reasons we therefore
    // delete the copy constructor and assignment operator to avoid the
    // possibility of copying CNetMessage objects.
    CNetMessage(CNetMessage&&) = default;
    CNetMessage(const CNetMessage&) = delete;
    CNetMessage& operator=(CNetMessage&&) = default;
    CNetMessage& operator=(const CNetMessage&) = delete;
};

/** The Transport converts one connection's sent messages to wire bytes, and received bytes back. */
class Transport {
public:
    virtual ~Transport() = default;

    struct Info
    {
        TransportProtocolType transport_type;
        std::optional<uint256> session_id;
    };

    /** Retrieve information about this transport. */
    virtual Info GetInfo() const noexcept = 0;

    // 1. Receiver side functions, for decoding bytes received on the wire into transport protocol
    // agnostic CNetMessage (message type & payload) objects.

    /** Returns true if the current message is complete (so GetReceivedMessage can be called). */
    virtual bool ReceivedMessageComplete() const = 0;

    /** Feed wire bytes to the transport.
     *
     * @return false if some bytes were invalid, in which case the transport can't be used anymore.
     *
     * Consumed bytes are chopped off the front of msg_bytes.
     */
    virtual bool ReceivedBytes(std::span<const uint8_t>& msg_bytes) = 0;

    /** Retrieve a completed message from transport.
     *
     * This can only be called when ReceivedMessageComplete() is true.
     *
     * If reject_message=true is returned the message itself is invalid, but (other than false
     * returned by ReceivedBytes) the transport is not in an inconsistent state.
     */
    virtual CNetMessage GetReceivedMessage(bool& reject_message) = 0;

    // 2. Sending side functions, for converting messages into bytes to be sent over the wire.

    /** Set the next message to send.
     *
     * If no message can currently be set (perhaps because the previous one is not yet done being
     * sent), returns false, and msg will be unmodified. Otherwise msg is enqueued (and
     * possibly moved-from) and true is returned.
     */
    virtual bool SetMessageToSend(CSerializedNetMsg& msg) noexcept = 0;

    /** Return type for GetBytesToSend, consisting of:
     *  - std::span<const uint8_t> to_send: span of bytes to be sent over the wire (possibly empty).
     *  - bool more: whether there will be more bytes to be sent after the ones in to_send are
     *    all sent (as signaled by MarkBytesSent()).
     *  - const std::string& m_type: message type on behalf of which this is being sent
     *    ("" for bytes that are not on behalf of any message).
     */
    using BytesToSend = std::tuple<
        std::span<const uint8_t> /*to_send*/,
        bool /*more*/,
        const std::string& /*m_type*/
    >;

    /** Get bytes to send on the wire, if any, along with other information about it.
     *
     * As a const function, it does not modify the transport's observable state, and is thus safe
     * to be called multiple times.
     *
     * @param[in] have_next_message If true, the "more" return value reports whether more will
     *            be sendable after a SetMessageToSend call. It is set by the caller when they know
     *            they have another message ready to send, and only care about what happens
     *            after that. The have_next_message argument only affects this "more" return value
     *            and nothing else.
     *
     *            Effectively, there are three possible outcomes about whether there are more bytes
     *            to send:
     *            - Yes:     the transport itself has more bytes to send later. For example, for
     *                       V1Transport this happens during the sending of the header of a
     *                       message, when there is a non-empty payload that follows.
     *            - No:      the transport itself has no more bytes to send, but will have bytes to
     *                       send if handed a message through SetMessageToSend. In V1Transport this
     *                       happens when sending the payload of a message.
     *            - Blocked: the transport itself has no more bytes to send, and is also incapable
     *                       of sending anything more at all now, if it were handed another
     *                       message to send. This occurs in V2Transport before the handshake is
     *                       complete, as the encryption ciphers are not set up for sending
     *                       messages before that point.
     *
     *            The boolean 'more' is true for Yes, false for Blocked, and have_next_message
     *            controls what is returned for No.
     *
     * @return a BytesToSend object. The to_send member returned acts as a stream which is only
     *         ever appended to. This means that with the exception of MarkBytesSent (which pops
     *         bytes off the front of later to_sends), operations on the transport can only append
     *         to what is being returned. Also note that m_type and to_send refer to data that is
     *         internal to the transport, and calling any non-const function on this object may
     *         invalidate them.
     */
    virtual BytesToSend GetBytesToSend(bool have_next_message) const noexcept = 0;

    /** Report how many bytes returned by the last GetBytesToSend() have been sent.
     *
     * bytes_sent cannot exceed to_send.size() of the last GetBytesToSend() result.
     *
     * If bytes_sent=0, this call has no effect.
     */
    virtual void MarkBytesSent(size_t bytes_sent) noexcept = 0;

    // 3. Miscellaneous functions.

    /** Whether upon disconnections, a reconnect with V1 is warranted. */
    virtual bool ShouldReconnectV1() const noexcept = 0;
};

class V1Transport final : public Transport
{
private:
    mutable CHash256 hasher;
    mutable uint256 data_hash;
    bool in_data; // parsing header (false) or data (true)
    DataStream hdrbuf{}; // partially received header
    CMessageHeader hdr; // complete header
    DataStream vRecv{}; // received message data
    unsigned int nHdrPos;
    unsigned int nDataPos;

    const uint256& GetMessageHash() const;
    int readHeader(std::span<const uint8_t> msg_bytes);
    int readData(std::span<const uint8_t> msg_bytes);

    void Reset() {
        vRecv.clear();
        hdrbuf.clear();
        hdrbuf.resize(24);
        in_data = false;
        nHdrPos = 0;
        nDataPos = 0;
        data_hash.SetNull();
        hasher.Reset();
    }

    bool CompleteInternal() const noexcept
    {
        if (!in_data) return false;
        return hdr.nMessageSize == nDataPos;
    }

    /** The header of the message currently being sent. */
    std::vector<uint8_t> m_header_to_send;
    /** The data of the message currently being sent. */
    CSerializedNetMsg m_message_to_send;
    /** Whether we're currently sending header bytes or message bytes. */
    bool m_sending_header {false};
    /** How many bytes have been sent so far (from m_header_to_send, or from m_message_to_send.data). */
    size_t m_bytes_sent {0};

public:
    explicit V1Transport() noexcept;

    bool ReceivedMessageComplete() const override
    {
        return CompleteInternal();
    }

    Info GetInfo() const noexcept override;

    bool ReceivedBytes(std::span<const uint8_t>& msg_bytes) override
    {
        int ret = in_data ? readData(msg_bytes) : readHeader(msg_bytes);
        if (ret < 0) {
            Reset();
        } else {
            msg_bytes = msg_bytes.subspan(ret);
        }
        return ret >= 0;
    }

    CNetMessage GetReceivedMessage(bool& reject_message) override;

    bool SetMessageToSend(CSerializedNetMsg& msg) noexcept override;
    BytesToSend GetBytesToSend(bool have_next_message) const noexcept override;
    void MarkBytesSent(size_t bytes_sent) noexcept override;
    bool ShouldReconnectV1() const noexcept override { return false; }
};

/** V2 (BIP324) transport, for the initiator side of connections only. */
class V2Transport final : public Transport
{
private:
    /** Contents of the version packet to send. BIP324 stipulates that senders should leave this
     *  empty, and receivers should ignore it. Future extensions can change what is sent as long as
     *  an empty version packet contents is interpreted as no extensions supported. */
    static constexpr std::array<std::byte, 0> VERSION_CONTENTS = {};

    // The sender side and receiver side of V2Transport are state machines that are transitioned
    // through, based on what has been received. The receive state corresponds to the contents of,
    // and bytes received to, the receive buffer. The send state controls what can be appended to
    // the send buffer and what can be sent from it.

    /** State type that defines the current contents of the receive buffer and/or how the next
     *  received bytes added to it will be interpreted.
     *
     * Diagram:
     *
     *                                             /---------\
     *                                             |         |
     *                                             v         |
     *  start -> KEY -> GARB_GARBTERM -> VERSION -> APP -> APP_READY
     */
    enum class RecvState : uint8_t {
        /** Public key.
         *
         * This is the initial state, during which the other side's public key is
         * received. When that information arrives, the ciphers get initialized and the state
         * becomes GARB_GARBTERM. */
        KEY,

        /** Garbage and garbage terminator.
         *
         * Whenever a byte is received, the last 16 bytes are compared with the expected garbage
         * terminator. When that happens, the state becomes VERSION. If no matching terminator is
         * received in 4111 bytes (4095 for the maximum garbage length, and 16 bytes for the
         * terminator), the connection aborts. */
        GARB_GARBTERM,

        /** Version packet.
         *
         * A packet is received, and decrypted/verified. If that fails, the connection aborts. The
         * first received packet in this state (whether it's a decoy or not) is expected to
         * authenticate the garbage received during the GARB_GARBTERM state as associated
         * authenticated data (AAD). The first non-decoy packet in this state is interpreted as
         * version negotiation (currently, that means ignoring the contents, but it can be used for
         * negotiating future extensions), and afterwards the state becomes APP. */
        VERSION,

        /** Application packet.
         *
         * A packet is received, and decrypted/verified. If that succeeds, the state becomes
         * APP_READY and the decrypted contents is kept in m_recv_decode_buffer until it is
         * retrieved as a message by GetMessage(). */
        APP,

        /** Nothing (an application packet is available for GetMessage()).
         *
         * Nothing can be received in this state. When the message is retrieved by GetMessage,
         * the state becomes APP again. */
        APP_READY,
    };

    /** State type that controls the sender side.
     *
     * Diagram:
     *
     *  start -> AWAITING_KEY -> READY
     */
    enum class SendState : uint8_t {
        /** Waiting for the other side's public key.
         *
         * This is the initial state. The public key and garbage is sent out. When
         * the receiver receives the other side's public key and transitions to GARB_GARBTERM, the
         * sender state becomes READY. */
        AWAITING_KEY,

        /** Normal sending state.
         *
         * In this state, the ciphers are initialized, so packets can be sent. When this state is
         * entered, the garbage terminator and version packet are appended to the send buffer (in
         * addition to the key and garbage which may still be there). In this state a message can be
         * provided if the send buffer is empty. */
        READY,
    };

    /** Cipher state. */
    BIP324Cipher m_cipher;

    /** In {VERSION, APP}, the decrypted packet length, if m_recv_buffer.size() >=
     *  BIP324Cipher::LENGTH_LEN. Unspecified otherwise. */
    uint32_t m_recv_len {0};
    /** Receive buffer; meaning is determined by m_recv_state. */
    std::vector<uint8_t> m_recv_buffer;
    /** AAD expected in next received packet (currently used only for garbage). */
    std::vector<uint8_t> m_recv_aad;
    /** Buffer to put decrypted contents in, for converting to CNetMessage. */
    std::vector<uint8_t> m_recv_decode_buffer;
    /** Current receiver state. */
    RecvState m_recv_state;

    /** The send buffer; meaning is determined by m_send_state. */
    std::vector<uint8_t> m_send_buffer;
    /** How many bytes from the send buffer have been sent so far. */
    uint32_t m_send_pos {0};
    /** The garbage sent, or to be sent (AWAITING_KEY state only). */
    std::vector<uint8_t> m_send_garbage;
    /** Type of the message being sent. */
    std::string m_send_type;
    /** Current sender state. */
    SendState m_send_state;
    /** Whether we've sent at least 24 bytes (which would trigger disconnect for V1 peers). */
    bool m_sent_v1_header_worth {false};

    /** Change the receive state. */
    void SetReceiveState(RecvState recv_state) noexcept;
    /** Change the send state. */
    void SetSendState(SendState send_state) noexcept;
    /** Given a packet's contents, find the message type (if valid), and strip it from contents. */
    static std::optional<std::string> GetMessageType(std::span<const uint8_t>& contents) noexcept;
    /** Determine how many received bytes can be processed in one go. */
    size_t GetMaxBytesToProcess() noexcept;
    /** Put our public key + garbage in the send buffer. */
    void StartSendingHandshake() noexcept;
    /** Process bytes in m_recv_buffer, while in KEY state. */
    bool ProcessReceivedKeyBytes() noexcept;
    /** Process bytes in m_recv_buffer, while in GARB_GARBTERM state. */
    bool ProcessReceivedGarbageBytes() noexcept;
    /** Process bytes in m_recv_buffer, while in VERSION/APP state. */
    bool ProcessReceivedPacketBytes() noexcept;

public:
    static constexpr uint32_t MAX_GARBAGE_LEN = 4095;

    /** Construct a V2 transport with securely generated random keys. */
    V2Transport() noexcept;

    /** Construct a V2 transport with specified keys and garbage (test use only). */
    V2Transport(const CKey& key, std::span<const std::byte> ent32, std::vector<uint8_t> garbage) noexcept;

    // Receive side functions.
    bool ReceivedMessageComplete() const noexcept override;
    bool ReceivedBytes(std::span<const uint8_t>& msg_bytes) noexcept override;
    CNetMessage GetReceivedMessage(bool& reject_message) noexcept override;

    // Send side functions.
    bool SetMessageToSend(CSerializedNetMsg& msg) noexcept override;
    BytesToSend GetBytesToSend(bool have_next_message) const noexcept override;
    void MarkBytesSent(size_t bytes_sent) noexcept override;

    // Miscellaneous functions.
    bool ShouldReconnectV1() const noexcept override;
    Info GetInfo() const noexcept override;
};

#endif // BITCOIN_NET_H
