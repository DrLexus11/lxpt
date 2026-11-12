// SPDX-License-Identifier: Apache-2.0
package io.github.drlexus11.lxpt

/**
 * lxpt wire v1 and NOTICE v1: structural encode and decode, no keys needed.
 *
 * The layouts, limits and the order of errors are `spec/wire-v1.md`'s. The
 * Python reference (`python/lxpt/wire.py`) and the C++ headers give the same
 * bytes and the same errors, held by `fixtures/lxpt_wire_v1.json`.
 *
 * Unsigned 32-bit fields are [Long], 16- and 8-bit fields [Int]; encoders
 * check every range. Nothing here checks a MAC or a signature: see [Channel].
 */

/** A refused message; [code] is one of [WireException.CODES]. */
class WireException(val code: String) : IllegalArgumentException(code) {
    companion object {
        val CODES = setOf("truncated", "oversize", "version", "type", "field", "mac", "signature", "identity")
    }
}

enum class Tier(val code: Int, val wireName: String) {
    COMMANDER(1, "commander"), DEPUTY(2, "deputy"), LEADER(3, "leader"), MEMBER(4, "member"), OBSERVER(5, "observer");

    companion object {
        fun of(code: Int) = entries.firstOrNull { it.code == code }
    }
}

/**
 * LXST's profile ids; v1 carries the five that talk uses. For Codec2 (spec "Codec payloads"):
 * the Codec2 frame time, the Codec2 frames one FRAME carries, and libcodec2's bytes per Codec2
 * frame (700C's 28 bits byte-aligned to 4). No mode byte: the profile names the mode. Opus
 * profiles carry one Opus packet and have none of these (0).
 */
enum class Profile(
    val code: Int,
    val wireName: String,
    val codec2FrameMs: Int = 0,
    val codec2Frames: Int = 0,
    val codec2FrameBytes: Int = 0,
) {
    ULBW(0x10, "ulbw", 40, 10, 4), VLBW(0x20, "vlbw", 40, 8, 8), LBW(0x30, "lbw", 20, 10, 8), MQ(0x40, "mq"), HQ(0x50, "hq");

    /** The exact payload length of one FRAME on a Codec2 profile; null on Opus. */
    val codec2PayloadLen: Int? get() = if (codec2Frames == 0) null else codec2Frames * codec2FrameBytes

    companion object {
        fun of(code: Int) = entries.firstOrNull { it.code == code }
    }
}

enum class Carrier(val code: Int, val wireName: String) {
    IP(1, "ip"), BLE(2, "ble"), GFSK(3, "gfsk"), HALOW(4, "halow");

    companion object {
        fun of(code: Int) = entries.firstOrNull { it.code == code }
    }
}

enum class SubMode(val code: Int, val wireName: String) {
    VOICE(1, "voice"), WATCH(2, "watch");

    companion object {
        fun of(code: Int) = entries.firstOrNull { it.code == code }
    }
}

enum class BusyReason(val code: Int, val wireName: String) {
    BUSY(1, "busy"), RATE_LIMITED(2, "rate_limited");

    companion object {
        fun of(code: Int) = entries.firstOrNull { it.code == code }
    }
}

enum class YieldReason(val code: Int, val wireName: String) {
    COLLISION(1, "collision"), PREEMPTED(2, "preempted");

    companion object {
        fun of(code: Int) = entries.firstOrNull { it.code == code }
    }
}

enum class NoticeKind(val code: Int, val wireName: String) {
    START(1, "start"), PREEMPT(2, "preempt"), EMERGENCY(3, "emergency");

    companion object {
        fun of(code: Int) = entries.firstOrNull { it.code == code }
    }
}

/** A holder or a winner: who holds which spurt, at which tier. */
class SpurtRef(val talkerTag: ByteArray, val spurt: Long, val tier: Tier, val emergency: Boolean)

sealed class Message

class Frame(
    val channelTag: ByteArray, val talkerTag: ByteArray, val spurt: Long, val seq: Int,
    /** Ciphertext, 1..197 bytes. */
    val payload: ByteArray, val mac: ByteArray,
) : Message()

class Claim(
    val channelTag: ByteArray, val talkerTag: ByteArray, val spurt: Long, val epoch: Long, val nonce: ByteArray,
    val tier: Tier, val emergency: Boolean, val clockVerified: Boolean, val clock: Long,
    /** Reticulum layout: X25519 then Ed25519, 64 bytes. */
    val publicKey: ByteArray, val signature: ByteArray,
) : Message()

class Grant(
    val channelTag: ByteArray, val talkerTag: ByteArray, val spurt: Long, val profile: Profile, val talkLimitS: Int,
    val reached: List<ByteArray>,
) : Message()

class Busy(
    val channelTag: ByteArray, val talkerTag: ByteArray, val spurt: Long, val reason: BusyReason,
    /** Required for [BusyReason.BUSY], optional for [BusyReason.RATE_LIMITED]. */
    val holder: SpurtRef?,
) : Message()

class Yield(
    val channelTag: ByteArray, val talkerTag: ByteArray, val spurt: Long, val reason: YieldReason,
    /** Required; nullable only so a missing one is refused as the other implementations refuse it. */
    val winner: SpurtRef?,
) : Message()

class Release(
    val channelTag: ByteArray, val talkerTag: ByteArray, val spurt: Long, val frameCount: Int,
    val publicKey: ByteArray, val signature: ByteArray,
) : Message()

class Talking(val channelTag: ByteArray, val holder: SpurtRef?, val profile: Profile, val talkLimitS: Int) : Message()

class SubEntry(val channelTag: ByteArray, val memberTag: ByteArray, val mode: SubMode)

class Sub(val carrier: Carrier, val entries: List<SubEntry>) : Message()

class PeerChannel(val channelTag: ByteArray, val narrow: Boolean, val members: List<ByteArray>)

class Peer(val relayHash: ByteArray, val stallP99Ms: Int, val channels: List<PeerChannel>) : Message()

class HeardEntry(val memberTag: ByteArray, val frames: Int)

class Heard(val channelTag: ByteArray, val talkerTag: ByteArray, val spurt: Long, val heard: List<HeardEntry>) :
    Message()

class Notice(
    val kind: NoticeKind, val hopLimit: Int, val channelTag: ByteArray,
    /** As it travels: encrypted ([Channel.openNotice] decrypts it). */
    val talker: ByteArray, val spurt16: Int, val talkLimitS: Int, val mac: ByteArray,
)

object Wire {
    const val VERSION = 0x01
    const val NOTICE_VERSION = 0x01
    const val MAX_MESSAGE_LEN = 431

    const val TAG_LEN = 4
    const val HASH_LEN = 16
    const val NONCE_LEN = 16
    const val PUBLIC_KEY_LEN = 64
    const val SIGNATURE_LEN = 64
    const val MAC_LEN = 8

    const val FRAME_HEADER_LEN = 16
    /** 19 B PLAIN header + 221 B frame + IFAC 16 = the relay's 256-byte slot. */
    const val FRAME_MAX_PAYLOAD = 197
    const val FRAME_MIN_LEN = FRAME_HEADER_LEN + 1 + MAC_LEN
    const val FRAME_MAX_LEN = FRAME_HEADER_LEN + FRAME_MAX_PAYLOAD + MAC_LEN
    const val CLAIM_LEN = 168
    const val CLAIM_SIGNED_LEN = CLAIM_LEN - SIGNATURE_LEN
    const val GRANT_MIN_LEN = 17
    const val GRANT_MAX_REACHED = 64
    const val BUSY_LEN = 25
    const val YIELD_LEN = 25
    const val RELEASE_LEN = 144
    const val RELEASE_SIGNED_LEN = RELEASE_LEN - SIGNATURE_LEN
    const val TALKING_LEN = 18
    const val SUB_MIN_LEN = 4
    const val SUB_ENTRY_LEN = 9
    const val SUB_MAX_ENTRIES = 32
    const val PEER_MIN_LEN = 21
    const val PEER_CHANNEL_MIN_LEN = 6
    const val PEER_MAX_CHANNELS = 32
    const val PEER_MAX_MEMBERS = 64
    const val HEARD_MIN_LEN = 15
    const val HEARD_ENTRY_LEN = 6
    const val HEARD_MAX_ENTRIES = 64
    const val SPURT_REF_LEN = 10
    const val NOTICE_LEN = 21
    const val NOTICE_MAX_HOP_LIMIT = 15

    val CLAIM_DOMAIN = "lxpt/v1/claim".toByteArray(Charsets.US_ASCII)
    val RELEASE_DOMAIN = "lxpt/v1/release".toByteArray(Charsets.US_ASCII)

    const val FRAME = 1
    const val CLAIM = 2
    const val GRANT = 3
    const val BUSY = 4
    const val YIELD = 5
    const val RELEASE = 6
    const val TALKING = 7
    const val SUB = 8
    const val PEER = 9
    const val HEARD = 10

    // --- encode -------------------------------------------------------------------------

    private class Out(capacity: Int) {
        var b = ByteArray(capacity)
        var n = 0
        fun u8(v: Int) {
            if (n == b.size) b = b.copyOf(b.size * 2)
            b[n++] = v.toByte()
        }
        fun u16(v: Int) { u8(v ushr 8); u8(v) }
        fun u32(v: Long) { u8((v ushr 24).toInt()); u8((v ushr 16).toInt()); u8((v ushr 8).toInt()); u8(v.toInt()) }
        fun bytes(v: ByteArray) { for (x in v) u8(x.toInt()) }
        fun done() = b.copyOf(n)
    }

    private fun field(ok: Boolean) { if (!ok) throw WireException("field") }
    private fun size(v: ByteArray, n: Int) = field(v.size == n)
    private fun u32(v: Long, min: Long = 0) = field(v in min..0xFFFFFFFFL)
    private fun u16(v: Int) = field(v in 0..0xFFFF)
    private fun u8(v: Int, min: Int = 0) = field(v in min..0xFF)

    private fun head(o: Out, type: Int, channelTag: ByteArray) {
        size(channelTag, TAG_LEN)
        o.u8(VERSION); o.u8(type); o.bytes(channelTag)
    }

    private fun talker(o: Out, tag: ByteArray, spurt: Long) {
        size(tag, TAG_LEN); u32(spurt, 1)
        o.bytes(tag); o.u32(spurt)
    }

    private fun ref(o: Out, r: SpurtRef?) {
        if (r == null) { repeat(SPURT_REF_LEN) { o.u8(0) }; return }
        size(r.talkerTag, TAG_LEN); u32(r.spurt, 1)
        o.bytes(r.talkerTag); o.u32(r.spurt); o.u8(r.tier.code); o.u8(if (r.emergency) 1 else 0)
    }

    private fun tagList(o: Out, tags: List<ByteArray>, max: Int) {
        field(tags.size <= max)
        o.u8(tags.size)
        for (t in tags) { size(t, TAG_LEN); o.bytes(t) }
    }

    /** A message to its bytes; throws [WireException] ("field" or "oversize"). */
    fun encode(m: Message): ByteArray {
        val o = Out(MAX_MESSAGE_LEN)
        when (m) {
            is Frame -> {
                field(m.payload.isNotEmpty())
                if (m.payload.size > FRAME_MAX_PAYLOAD) throw WireException("oversize")
                head(o, FRAME, m.channelTag); talker(o, m.talkerTag, m.spurt); u16(m.seq); o.u16(m.seq)
                o.bytes(m.payload); size(m.mac, MAC_LEN); o.bytes(m.mac)
            }
            is Claim -> {
                claimBody(o, m); size(m.signature, SIGNATURE_LEN); o.bytes(m.signature)
            }
            is Grant -> {
                head(o, GRANT, m.channelTag); talker(o, m.talkerTag, m.spurt)
                u8(m.talkLimitS, 1); o.u8(m.profile.code); o.u8(m.talkLimitS); tagList(o, m.reached, GRANT_MAX_REACHED)
            }
            is Busy -> {
                field(!(m.holder == null && m.reason == BusyReason.BUSY))
                head(o, BUSY, m.channelTag); talker(o, m.talkerTag, m.spurt); o.u8(m.reason.code); ref(o, m.holder)
            }
            is Yield -> {
                field(m.winner != null)
                head(o, YIELD, m.channelTag); talker(o, m.talkerTag, m.spurt); o.u8(m.reason.code); ref(o, m.winner)
            }
            is Release -> {
                releaseBody(o, m); size(m.signature, SIGNATURE_LEN); o.bytes(m.signature)
            }
            is Talking -> {
                field(m.holder != null); u8(m.talkLimitS, 1)
                head(o, TALKING, m.channelTag); ref(o, m.holder); o.u8(m.profile.code); o.u8(m.talkLimitS)
            }
            is Sub -> {
                field(m.entries.size <= SUB_MAX_ENTRIES)
                o.u8(VERSION); o.u8(SUB); o.u8(m.carrier.code); o.u8(m.entries.size)
                for (e in m.entries) {
                    size(e.channelTag, TAG_LEN); size(e.memberTag, TAG_LEN)
                    o.bytes(e.channelTag); o.bytes(e.memberTag); o.u8(e.mode.code)
                }
            }
            is Peer -> {
                field(m.channels.size <= PEER_MAX_CHANNELS)
                size(m.relayHash, HASH_LEN); u16(m.stallP99Ms)
                o.u8(VERSION); o.u8(PEER); o.bytes(m.relayHash); o.u16(m.stallP99Ms); o.u8(m.channels.size)
                for (c in m.channels) {
                    field(c.members.size <= PEER_MAX_MEMBERS)
                    size(c.channelTag, TAG_LEN)
                    o.bytes(c.channelTag); o.u8(if (c.narrow) 1 else 0); tagList(o, c.members, PEER_MAX_MEMBERS)
                }
            }
            is Heard -> {
                field(m.heard.size <= HEARD_MAX_ENTRIES)
                head(o, HEARD, m.channelTag); talker(o, m.talkerTag, m.spurt); o.u8(m.heard.size)
                for (h in m.heard) { size(h.memberTag, TAG_LEN); u16(h.frames); o.bytes(h.memberTag); o.u16(h.frames) }
            }
        }
        if (o.n > MAX_MESSAGE_LEN) throw WireException("oversize")
        return o.done()
    }

    private fun claimBody(o: Out, m: Claim) {
        head(o, CLAIM, m.channelTag); talker(o, m.talkerTag, m.spurt); u32(m.epoch); o.u32(m.epoch)
        size(m.nonce, NONCE_LEN); o.bytes(m.nonce); o.u8(m.tier.code)
        o.u8((if (m.emergency) 1 else 0) or (if (m.clockVerified) 2 else 0))
        u32(m.clock); o.u32(m.clock); size(m.publicKey, PUBLIC_KEY_LEN); o.bytes(m.publicKey)
    }

    private fun releaseBody(o: Out, m: Release) {
        head(o, RELEASE, m.channelTag); talker(o, m.talkerTag, m.spurt); u16(m.frameCount); o.u16(m.frameCount)
        size(m.publicKey, PUBLIC_KEY_LEN); o.bytes(m.publicKey)
    }

    // --- decode -------------------------------------------------------------------------

    private fun ByteArray.u8(at: Int) = this[at].toInt() and 0xFF
    private fun ByteArray.u16(at: Int) = (u8(at) shl 8) or u8(at + 1)
    private fun ByteArray.u32(at: Int) = (u16(at).toLong() shl 16) or u16(at + 2).toLong()
    private fun ByteArray.slice(at: Int, n: Int) = copyOfRange(at, at + n)

    private fun exact(b: ByteArray, n: Int) {
        if (b.size < n) throw WireException("truncated")
        if (b.size > n) throw WireException("oversize")
    }

    private fun spurtAt(b: ByteArray): Long = b.u32(10).also { field(it != 0L) }

    private fun refAt(b: ByteArray, at: Int): SpurtRef? {
        if ((0 until SPURT_REF_LEN).all { b[at + it].toInt() == 0 }) return null
        val spurt = b.u32(at + 4)
        val tier = Tier.of(b.u8(at + 8))
        val flags = b.u8(at + 9)
        if (spurt == 0L || tier == null || (flags and 0x01.inv()) != 0) throw WireException("field")
        return SpurtRef(b.slice(at, 4), spurt, tier, (flags and 1) != 0)
    }

    private fun <T> known(v: T?): T = v ?: throw WireException("field")

    /**
     * Refuses a FRAME payload [profile] cannot carry: a Codec2 payload of another length (an
     * LXST mode byte left in, or bit-packed 700C) with "field", an empty Opus one with "field",
     * and one past [FRAME_MAX_PAYLOAD] with "oversize".
     */
    fun checkPayload(profile: Profile, payload: ByteArray) {
        val want = profile.codec2PayloadLen
        when {
            want != null -> if (payload.size != want) throw WireException("field")
            payload.isEmpty() -> throw WireException("field")
            payload.size > FRAME_MAX_PAYLOAD -> throw WireException("oversize")
        }
    }

    /** The message type code, after the version and type checks. */
    fun peekType(b: ByteArray): Int {
        if (b.isEmpty()) throw WireException("truncated")
        if (b.u8(0) != VERSION) throw WireException("version")
        if (b.size < 2) throw WireException("truncated")
        val t = b.u8(1)
        if (t < FRAME || t > HEARD) throw WireException("type")
        return t
    }

    /** Bytes to a message, or [WireException]. */
    fun decode(b: ByteArray): Message {
        val type = peekType(b)
        if (b.size > MAX_MESSAGE_LEN) throw WireException("oversize")
        return when (type) {
            FRAME -> {
                if (b.size < FRAME_MIN_LEN) throw WireException("truncated")
                if (b.size > FRAME_MAX_LEN) throw WireException("oversize")
                Frame(b.slice(2, 4), b.slice(6, 4), spurtAt(b), b.u16(14), b.copyOfRange(FRAME_HEADER_LEN, b.size - MAC_LEN),
                    b.copyOfRange(b.size - MAC_LEN, b.size))
            }
            CLAIM -> {
                exact(b, CLAIM_LEN)
                val spurt = spurtAt(b)
                val tier = known(Tier.of(b.u8(34)))
                val flags = b.u8(35)
                field((flags and 0x03.inv()) == 0)
                Claim(b.slice(2, 4), b.slice(6, 4), spurt, b.u32(14), b.slice(18, 16), tier, (flags and 1) != 0,
                    (flags and 2) != 0, b.u32(36), b.slice(40, 64), b.slice(104, 64))
            }
            GRANT -> {
                if (b.size < GRANT_MIN_LEN) throw WireException("truncated")
                val count = b.u8(16)
                field(count <= GRANT_MAX_REACHED)
                exact(b, GRANT_MIN_LEN + TAG_LEN * count)
                val spurt = spurtAt(b)
                val profile = known(Profile.of(b.u8(14)))
                val limit = b.u8(15)
                field(limit != 0)
                Grant(b.slice(2, 4), b.slice(6, 4), spurt, profile, limit, List(count) { b.slice(17 + 4 * it, 4) })
            }
            BUSY -> {
                exact(b, BUSY_LEN)
                val spurt = spurtAt(b)
                val reason = known(BusyReason.of(b.u8(14)))
                val holder = refAt(b, 15)
                field(!(holder == null && reason == BusyReason.BUSY))
                Busy(b.slice(2, 4), b.slice(6, 4), spurt, reason, holder)
            }
            YIELD -> {
                exact(b, YIELD_LEN)
                val spurt = spurtAt(b)
                val reason = known(YieldReason.of(b.u8(14)))
                val winner = known(refAt(b, 15))
                Yield(b.slice(2, 4), b.slice(6, 4), spurt, reason, winner)
            }
            RELEASE -> {
                exact(b, RELEASE_LEN)
                Release(b.slice(2, 4), b.slice(6, 4), spurtAt(b), b.u16(14), b.slice(16, 64), b.slice(80, 64))
            }
            TALKING -> {
                exact(b, TALKING_LEN)
                val holder = known(refAt(b, 6))
                val profile = known(Profile.of(b.u8(16)))
                val limit = b.u8(17)
                field(limit != 0)
                Talking(b.slice(2, 4), holder, profile, limit)
            }
            SUB -> {
                if (b.size < SUB_MIN_LEN) throw WireException("truncated")
                val count = b.u8(3)
                field(count <= SUB_MAX_ENTRIES)
                exact(b, SUB_MIN_LEN + SUB_ENTRY_LEN * count)
                val carrier = known(Carrier.of(b.u8(2)))
                Sub(carrier, List(count) {
                    val at = SUB_MIN_LEN + SUB_ENTRY_LEN * it
                    SubEntry(b.slice(at, 4), b.slice(at + 4, 4), known(SubMode.of(b.u8(at + 8))))
                })
            }
            PEER -> {
                if (b.size < PEER_MIN_LEN) throw WireException("truncated")
                val count = b.u8(20)
                field(count <= PEER_MAX_CHANNELS)
                var at = PEER_MIN_LEN
                val channels = ArrayList<PeerChannel>(count)
                repeat(count) {
                    if (b.size < at + PEER_CHANNEL_MIN_LEN) throw WireException("truncated")
                    val flags = b.u8(at + 4)
                    val members = b.u8(at + 5)
                    field((flags and 0x01.inv()) == 0 && members <= PEER_MAX_MEMBERS)
                    val end = at + PEER_CHANNEL_MIN_LEN + TAG_LEN * members
                    if (b.size < end) throw WireException("truncated")
                    val start = at
                    channels.add(PeerChannel(b.slice(start, 4), (flags and 1) != 0,
                        List(members) { b.slice(start + 6 + 4 * it, 4) }))
                    at = end
                }
                if (b.size > at) throw WireException("oversize")
                Peer(b.slice(2, 16), b.u16(18), channels)
            }
            else -> {
                if (b.size < HEARD_MIN_LEN) throw WireException("truncated")
                val count = b.u8(14)
                field(count <= HEARD_MAX_ENTRIES)
                exact(b, HEARD_MIN_LEN + HEARD_ENTRY_LEN * count)
                val spurt = spurtAt(b)
                Heard(b.slice(2, 4), b.slice(6, 4), spurt, List(count) {
                    val at = HEARD_MIN_LEN + HEARD_ENTRY_LEN * it
                    HeardEntry(b.slice(at, 4), b.u16(at + 4))
                })
            }
        }
    }

    // --- signed spans -------------------------------------------------------------------

    /** What a CLAIM's signature covers: [CLAIM_DOMAIN], then every byte before it. */
    fun claimSignedBytes(b: ByteArray): ByteArray {
        if (decode(b) !is Claim) throw WireException("type")
        return CLAIM_DOMAIN + b.copyOf(CLAIM_SIGNED_LEN)
    }

    /** What a RELEASE's signature covers: [RELEASE_DOMAIN], then every byte before it. */
    fun releaseSignedBytes(b: ByteArray): ByteArray {
        if (decode(b) !is Release) throw WireException("type")
        return RELEASE_DOMAIN + b.copyOf(RELEASE_SIGNED_LEN)
    }

    internal fun claimUnsigned(m: Claim): ByteArray = Out(CLAIM_LEN).also { claimBody(it, m) }.done()
    internal fun releaseUnsigned(m: Release): ByteArray = Out(RELEASE_LEN).also { releaseBody(it, m) }.done()

    // --- NOTICE v1 ----------------------------------------------------------------------

    fun encodeNotice(n: Notice): ByteArray {
        field(n.hopLimit in 0..NOTICE_MAX_HOP_LIMIT)
        size(n.channelTag, TAG_LEN); size(n.talker, TAG_LEN); u16(n.spurt16); u8(n.talkLimitS, 1); size(n.mac, MAC_LEN)
        val o = Out(NOTICE_LEN)
        o.u8(NOTICE_VERSION); o.u8((n.kind.code shl 4) or n.hopLimit); o.bytes(n.channelTag); o.bytes(n.talker)
        o.u16(n.spurt16); o.u8(n.talkLimitS); o.bytes(n.mac)
        return o.done()
    }

    fun decodeNotice(b: ByteArray): Notice {
        if (b.isEmpty()) throw WireException("truncated")
        if (b.u8(0) != NOTICE_VERSION) throw WireException("version")
        exact(b, NOTICE_LEN)
        val kind = known(NoticeKind.of(b.u8(1) shr 4))
        val limit = b.u8(12)
        field(limit != 0)
        return Notice(kind, b.u8(1) and 0x0F, b.slice(2, 4), b.slice(6, 4), b.u16(10), limit, b.slice(13, 8))
    }
}
