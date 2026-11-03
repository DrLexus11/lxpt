// SPDX-License-Identifier: Apache-2.0
package io.github.drlexus11.lxpt

/**
 * Signs with a Reticulum identity's Ed25519 key. On a phone this is the host's
 * identity stack (Columba's `RnsCore.signWithIdentity`), so lxpt never holds
 * the private key. [sign] returns the 64-byte signature of exactly the bytes given.
 */
interface Signer {
    /** The identity's 64-byte public key: X25519, then Ed25519. */
    val publicKey: ByteArray
    fun sign(message: ByteArray): ByteArray
}

/** A [Signer] from a raw Ed25519 seed, for tools and tests. */
class SeedSigner(private val seed: ByteArray, publicKey: ByteArray) : Signer {
    override val publicKey: ByteArray = publicKey.copyOf()

    init {
        require(seed.size == 32 && publicKey.size == Wire.PUBLIC_KEY_LEN &&
            Ed25519.publicKey(seed).contentEquals(publicKey.copyOfRange(32, 64))) {
            "the seed does not belong to the public key's signing half"
        }
    }

    override fun sign(message: ByteArray): ByteArray = Ed25519.sign(seed, message)
}

/** The AES-256 key and the HMAC key of one spurt. */
class SpurtKeys(val encKey: ByteArray, val macKey: ByteArray)

/** Everything derived from one channel key epoch for one channel (spec/wire-v1.md section 3). */
class ChannelKeys(kEpoch: ByteArray, channelId: ByteArray) {
    val kEpoch: ByteArray = kEpoch.copyOf()
    val channelId: ByteArray = channelId.copyOf()
    val channelTag: ByteArray
    val noticeKey: ByteArray

    init {
        if (kEpoch.size != Channel.KEY_LEN || channelId.size != Channel.CHANNEL_ID_LEN) throw WireException("field")
        channelTag = Crypto.hmacSha256(this.kEpoch, Channel.TAG_LABEL, this.channelId).copyOf(Wire.TAG_LEN)
        noticeKey = Crypto.hmacSha256(this.kEpoch, Channel.NOTICE_KEY_LABEL, this.channelId)
    }

    fun memberTag(identityHash: ByteArray): ByteArray {
        if (identityHash.size != Wire.HASH_LEN) throw WireException("field")
        return Crypto.hmacSha256(kEpoch, Channel.MEMBER_LABEL, channelId, identityHash).copyOf(Wire.TAG_LEN)
    }

    /** HKDF-SHA256(ikm = k_epoch, salt = nonce, info = label || channel id || talker || spurt). */
    fun spurtKeys(talkerHash: ByteArray, spurt: Long, nonce: ByteArray): SpurtKeys {
        if (talkerHash.size != Wire.HASH_LEN || nonce.size != Wire.NONCE_LEN || spurt !in 1..0xFFFFFFFFL)
            throw WireException("field")
        val info = Channel.SPURT_LABEL + channelId + talkerHash + Channel.be32(spurt)
        val okm = Crypto.hkdfSha256(kEpoch, nonce, info, 64)
        return SpurtKeys(okm.copyOf(32), okm.copyOfRange(32, 64))
    }
}

/**
 * What needs the channel key or an identity: channel ids, sealing and opening
 * FRAMEs and NOTICEs, CLAIM and RELEASE signatures. A relay needs only
 * [verifyClaim] and [verifyRelease]: it holds no channel keys.
 */
object Channel {
    const val KEY_LEN = 32
    const val CHANNEL_ID_LEN = 8
    const val ROOM_MAX_LEN = 255

    private fun ascii(s: String) = s.toByteArray(Charsets.US_ASCII)
    internal val CHANNEL_ID_LABEL = ascii("lxpt/ch/v1")
    internal val HUBLESS_ID_LABEL = ascii("lxpt/hubless/v1")
    internal val TAG_LABEL = ascii("lxpt/v1/tag")
    internal val MEMBER_LABEL = ascii("lxpt/v1/member")
    internal val NOTICE_KEY_LABEL = ascii("lxpt/v1/notice-key")
    internal val NOTICE_MAC_LABEL = ascii("lxpt/v1/notice-mac")
    internal val NOTICE_TALKER_LABEL = ascii("lxpt/v1/notice-talker")
    internal val SPURT_LABEL = ascii("lxpt/v1/spurt")

    internal fun be32(v: Long) = byteArrayOf((v ushr 24).toByte(), (v ushr 16).toByte(), (v ushr 8).toByte(), v.toByte())

    /** Strict UTF-8: no overlong forms, no surrogates, nothing past U+10FFFF. */
    internal fun utf8Valid(b: ByteArray): Boolean {
        var i = 0
        while (i < b.size) {
            val c = b[i].toInt() and 0xff
            if (c < 0x80) { i++; continue }
            var lo = 0x80
            var hi = 0xbf
            val need = when {
                c in 0xc2..0xdf -> 1
                c == 0xe0 -> { lo = 0xa0; 2 }
                c in 0xe1..0xec || c == 0xee || c == 0xef -> 2
                c == 0xed -> { hi = 0x9f; 2 }
                c == 0xf0 -> { lo = 0x90; 3 }
                c in 0xf1..0xf3 -> 3
                c == 0xf4 -> { hi = 0x8f; 3 }
                else -> return false
            }
            if (i + need >= b.size) return false
            if ((b[i + 1].toInt() and 0xff) !in lo..hi) return false
            for (k in 2..need) if ((b[i + k].toInt() and 0xff) !in 0x80..0xbf) return false
            i += need + 1
        }
        return true
    }

    /**
     * A room name exactly as its hub returns it: lxpt never re-normalises (hubs
     * and clients disagree on case folding, whitespace and '#'). It must be 1
     * to 255 bytes of strict UTF-8, else [WireException] "field".
     */
    fun canonicalRoom(name: ByteArray): ByteArray {
        if (name.size !in 1..ROOM_MAX_LEN || !utf8Valid(name)) throw WireException("field")
        return name.copyOf()
    }

    fun canonicalRoom(name: String) = canonicalRoom(name.toByteArray(Charsets.UTF_8))

    private fun hash16(h: ByteArray) = h.also { if (it.size != Wire.HASH_LEN) throw WireException("field") }

    /** SHA-256("lxpt/ch/v1" || hub hash || the hub's canonical room name)[:8]. */
    fun channelId(hubHash: ByteArray, room: ByteArray): ByteArray =
        Crypto.sha256(CHANNEL_ID_LABEL + hash16(hubHash) + canonicalRoom(room)).copyOf(CHANNEL_ID_LEN)

    /** A phone-only channel: SHA-256("lxpt/hubless/v1" || creator || the name as created)[:8]. */
    fun hublessChannelId(creatorHash: ByteArray, name: ByteArray): ByteArray =
        Crypto.sha256(HUBLESS_ID_LABEL + hash16(creatorHash) + canonicalRoom(name)).copyOf(CHANNEL_ID_LEN)

    /** A Reticulum identity hash: SHA-256 of the 64-byte public key, first 16 bytes. */
    fun identityHash(publicKey: ByteArray): ByteArray {
        if (publicKey.size != Wire.PUBLIC_KEY_LEN) throw WireException("field")
        return Crypto.sha256(publicKey).copyOf(Wire.HASH_LEN)
    }

    private fun frameIv(seq: Int) = ByteArray(16).also { it[0] = (seq ushr 8).toByte(); it[1] = seq.toByte() }

    /** Encrypts a codec frame (AES-256-CTR from seq || 14 zero bytes) and MACs header and ciphertext. */
    fun sealFrame(keys: SpurtKeys, channelTag: ByteArray, talkerTag: ByteArray, spurt: Long, seq: Int,
                  plaintext: ByteArray): ByteArray {
        // Every field checked before any crypto.
        Wire.encode(Frame(channelTag, talkerTag, spurt, seq, plaintext, ByteArray(Wire.MAC_LEN)))
        val cipher = Crypto.aes256Ctr(keys.encKey, frameIv(seq), plaintext)
        val body = Wire.encode(Frame(channelTag, talkerTag, spurt, seq, cipher, ByteArray(Wire.MAC_LEN)))
            .copyOf(Wire.FRAME_HEADER_LEN + cipher.size)
        return body + Crypto.hmacSha256(keys.macKey, body).copyOf(Wire.MAC_LEN)
    }

    /** The frame and its plaintext if the MAC holds, else [WireException] "mac". */
    fun openFrame(keys: SpurtKeys, data: ByteArray): Pair<Frame, ByteArray> {
        val m = Wire.decode(data) as? Frame ?: throw WireException("type")
        val expect = Crypto.hmacSha256(keys.macKey, data.copyOf(data.size - Wire.MAC_LEN)).copyOf(Wire.MAC_LEN)
        if (!Crypto.equal(expect, m.mac)) throw WireException("mac")
        return m to Crypto.aes256Ctr(keys.encKey, frameIv(m.seq), m.payload)
    }

    // The hop limit (low nibble of byte 1) is left out, so a later hop can lower it.
    private fun noticeMac(key: ByteArray, plain: ByteArray): ByteArray {
        val covered = plain.copyOf(13)
        covered[1] = (covered[1].toInt() and 0xF0).toByte()
        return Crypto.hmacSha256(key, NOTICE_MAC_LABEL, covered).copyOf(Wire.MAC_LEN)
    }

    private fun talkerPad(key: ByteArray, mac: ByteArray) =
        Crypto.hmacSha256(key, NOTICE_TALKER_LABEL, mac).copyOf(Wire.TAG_LEN)

    private fun xor(a: ByteArray, b: ByteArray) = ByteArray(a.size) { (a[it].toInt() xor b[it].toInt()).toByte() }

    /** A NOTICE with its MAC, the talker prefix (first four bytes of the identity hash) encrypted. */
    fun sealNotice(noticeKey: ByteArray, kind: NoticeKind, hopLimit: Int, channelTag: ByteArray,
                   talkerPrefix: ByteArray, spurt16: Int, talkLimitS: Int): ByteArray {
        val plain = Wire.encodeNotice(Notice(kind, hopLimit, channelTag, talkerPrefix, spurt16, talkLimitS,
            ByteArray(Wire.MAC_LEN)))
        val mac = noticeMac(noticeKey, plain)
        val talker = xor(talkerPrefix, talkerPad(noticeKey, mac))
        return Wire.encodeNotice(Notice(kind, hopLimit, channelTag, talker, spurt16, talkLimitS, mac))
    }

    /** The notice and its decrypted talker prefix, or [WireException] "mac". */
    fun openNotice(noticeKey: ByteArray, data: ByteArray): Pair<Notice, ByteArray> {
        val n = Wire.decodeNotice(data)
        val prefix = xor(n.talker, talkerPad(noticeKey, n.mac))
        val plain = data.copyOf()
        prefix.copyInto(plain, 6)
        if (!Crypto.equal(noticeMac(noticeKey, plain), n.mac)) throw WireException("mac")
        return n to prefix
    }

    private fun signed(signer: Signer, publicKey: ByteArray, span: ByteArray): ByteArray {
        require(signer.publicKey.contentEquals(publicKey)) { "the signer's public key is not the message's" }
        val sig = signer.sign(span)
        check(sig.size == Wire.SIGNATURE_LEN && Ed25519.verify(publicKey.copyOfRange(32, 64), span, sig)) {
            "the signer's signature does not verify under the message's public key"
        }
        return sig
    }

    /**
     * A CLAIM's bytes, signed by [signer] (the host's identity stack); its
     * signature field is ignored. The signature is verified before it is returned.
     */
    fun signClaim(m: Claim, signer: Signer): ByteArray {
        val unsigned = Wire.claimUnsigned(m)
        return unsigned + signed(signer, m.publicKey, Wire.CLAIM_DOMAIN + unsigned)
    }

    /** The decoded CLAIM if its signature holds, else [WireException] "signature". */
    fun verifyClaim(data: ByteArray): Claim {
        val m = Wire.decode(data) as? Claim ?: throw WireException("type")
        if (!Ed25519.verify(m.publicKey.copyOfRange(32, 64), Wire.claimSignedBytes(data), m.signature))
            throw WireException("signature")
        return m
    }

    fun signRelease(m: Release, signer: Signer): ByteArray {
        val unsigned = Wire.releaseUnsigned(m)
        return unsigned + signed(signer, m.publicKey, Wire.RELEASE_DOMAIN + unsigned)
    }

    fun verifyRelease(data: ByteArray): Release {
        val m = Wire.decode(data) as? Release ?: throw WireException("type")
        if (!Ed25519.verify(m.publicKey.copyOfRange(32, 64), Wire.releaseSignedBytes(data), m.signature))
            throw WireException("signature")
        return m
    }

    const val RELAY_KEY_LEN = Wire.TAG_LEN + Wire.HASH_LEN + 4

    /**
     * What a relay keys every per-talker state on, for a verified CLAIM or
     * RELEASE: channel tag || identity hash of the signing key || spurt. Never
     * the talker tag alone: a relay cannot tie a tag to a key.
     */
    fun relayKey(data: ByteArray): ByteArray = when (Wire.peekType(data)) {
        Wire.CLAIM -> verifyClaim(data).let { it.channelTag + identityHash(it.publicKey) + be32(it.spurt) }
        Wire.RELEASE -> verifyRelease(data).let { it.channelTag + identityHash(it.publicKey) + be32(it.spurt) }
        else -> throw WireException("type")
    }

    /**
     * Returns if the RELEASE ends this CLAIM's spurt: both verify and share the
     * channel tag, talker tag, spurt and signing key. Else [WireException]
     * "signature" or "identity".
     */
    fun releaseMatchesClaim(claim: ByteArray, release: ByteArray) {
        val c = verifyClaim(claim)
        val r = verifyRelease(release)
        if (!c.channelTag.contentEquals(r.channelTag) || !c.talkerTag.contentEquals(r.talkerTag) || c.spurt != r.spurt ||
            !c.publicKey.contentEquals(r.publicKey)) throw WireException("identity")
    }

    /** Whether a talker tag is the member tag of the identity whose public key is given. */
    fun memberOk(keys: ChannelKeys, publicKey: ByteArray, talkerTag: ByteArray): Boolean =
        Crypto.equal(keys.memberTag(identityHash(publicKey)), talkerTag)
}
