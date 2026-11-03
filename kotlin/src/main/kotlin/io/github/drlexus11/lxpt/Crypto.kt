// SPDX-License-Identifier: Apache-2.0
package io.github.drlexus11.lxpt

import java.security.MessageDigest
import javax.crypto.Cipher
import javax.crypto.Mac
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * The primitives wire v1 uses. SHA-256/512, HMAC-SHA256 and AES-256-CTR come
 * from the platform's JCA provider (present on the JVM and on every Android
 * level); HKDF is RFC 5869 over that HMAC; Ed25519 is [Ed25519], pure Kotlin.
 */
object Crypto {
    fun sha256(data: ByteArray): ByteArray = MessageDigest.getInstance("SHA-256").digest(data)

    fun sha512(data: ByteArray): ByteArray = MessageDigest.getInstance("SHA-512").digest(data)

    fun hmacSha256(key: ByteArray, vararg parts: ByteArray): ByteArray {
        // An empty key is HMAC's all-zero padded key; the JCA refuses an empty spec.
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(if (key.isEmpty()) ByteArray(1) else key, "HmacSHA256"))
        for (p in parts) mac.update(p)
        return mac.doFinal()
    }

    /** RFC 5869. An empty salt means 32 zero bytes. */
    fun hkdfSha256(ikm: ByteArray, salt: ByteArray, info: ByteArray, length: Int): ByteArray {
        require(length in 1..255 * 32) { "HKDF length out of range" }
        val prk = hmacSha256(if (salt.isEmpty()) ByteArray(32) else salt, ikm)
        val out = ByteArray(length)
        var block = ByteArray(0)
        var done = 0
        var counter = 1
        while (done < length) {
            block = hmacSha256(prk, block, info, byteArrayOf(counter.toByte()))
            val take = minOf(32, length - done)
            block.copyInto(out, done, 0, take)
            done += take
            counter++
        }
        return out
    }

    /** AES-256-CTR, the whole 16-byte counter block incremented big-endian (SP 800-38A). */
    fun aes256Ctr(key: ByteArray, iv: ByteArray, data: ByteArray): ByteArray {
        require(key.size == 32 && iv.size == 16)
        if (data.isEmpty()) return ByteArray(0)
        val c = Cipher.getInstance("AES/CTR/NoPadding")
        c.init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "AES"), IvParameterSpec(iv))
        return c.doFinal(data)
    }

    /** Constant-time comparison. */
    fun equal(a: ByteArray, b: ByteArray): Boolean = MessageDigest.isEqual(a, b)
}
