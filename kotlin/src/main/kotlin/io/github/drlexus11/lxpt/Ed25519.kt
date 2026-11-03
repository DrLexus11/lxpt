// SPDX-License-Identifier: Apache-2.0
package io.github.drlexus11.lxpt

/**
 * Ed25519 (RFC 8032) in pure Kotlin, so it runs on any Android level: a
 * transcription of TweetNaCl's crypto_sign (public domain; Bernstein, van
 * Gastel, Janssen, Lange, Schwabe, Smetsers), the same code as the C++
 * `crypto.hpp`, with spec/wire-v1.md's verification rules: S below the group
 * order, the public key a canonical encoding and not of small order, R compared as bytes with the
 * canonical encoding of [S]B - [k]A.
 *
 * A phone that holds its key elsewhere signs through its own stack and passes
 * the signature in; [verify] is what lxpt itself needs.
 */
object Ed25519 {
    private fun gf(vararg v: Long) = LongArray(16).also { v.copyInto(it) }

    private val GF0 = LongArray(16)
    private val GF1 = gf(1)
    private val D = gf(0x78a3, 0x1359, 0x4dca, 0x75eb, 0xd8ab, 0x4141, 0x0a4d, 0x0070,
        0xe898, 0x7779, 0x4079, 0x8cc7, 0xfe73, 0x2b6f, 0x6cee, 0x5203)
    private val D2 = gf(0xf159, 0x26b2, 0x9b94, 0xebd6, 0xb156, 0x8283, 0x149a, 0x00e0,
        0xd130, 0xeef3, 0x80f2, 0x198e, 0xfce7, 0x56df, 0xd9dc, 0x2406)
    private val BX = gf(0xd51a, 0x8f25, 0x2d60, 0xc956, 0xa7b2, 0x9525, 0xc760, 0x692c,
        0xdc5c, 0xfdd6, 0xe231, 0xc0a4, 0x53fe, 0xcd6e, 0x36d3, 0x2169)
    private val BY = gf(0x6658, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666,
        0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666)
    private val SQRTM1 = gf(0xa0b0, 0x4a0e, 0x1b27, 0xc4ee, 0xe478, 0xad2f, 0x1806, 0x2f43,
        0xd7a7, 0x3dfb, 0x0099, 0x2b4d, 0xdf0b, 0x4fc1, 0x2480, 0x2b83)
    private val L = longArrayOf(0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9,
        0xde, 0x14, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10)
    private val L_BYTES = ByteArray(32) { L[it].toByte() }
    private val P_BYTES = ByteArray(32) { if (it == 0) 0xed.toByte() else if (it == 31) 0x7f.toByte() else 0xff.toByte() }

    private fun set(r: LongArray, a: LongArray) = a.copyInto(r)

    private fun car(o: LongArray) {
        for (i in 0 until 16) {
            o[i] += 65536
            val c = o[i] shr 16
            if (i < 15) o[i + 1] += c - 1 else o[0] += 38 * (c - 1)
            o[i] -= c * 65536
        }
    }

    private fun sel(p: LongArray, q: LongArray, b: Int) {
        val c = (b.toLong() - 1).inv()
        for (i in 0 until 16) {
            val t = c and (p[i] xor q[i])
            p[i] = p[i] xor t
            q[i] = q[i] xor t
        }
    }

    private fun pack25519(o: ByteArray, off: Int, n: LongArray) {
        val m = LongArray(16)
        val t = n.copyOf()
        car(t); car(t); car(t)
        for (j in 0 until 2) {
            m[0] = t[0] - 0xffed
            for (i in 1 until 15) {
                m[i] = t[i] - 0xffff - ((m[i - 1] shr 16) and 1)
                m[i - 1] = m[i - 1] and 0xffff
            }
            m[15] = t[15] - 0x7fff - ((m[14] shr 16) and 1)
            val b = ((m[15] shr 16) and 1).toInt()
            m[14] = m[14] and 0xffff
            sel(t, m, 1 - b)
        }
        for (i in 0 until 16) {
            o[off + 2 * i] = (t[i] and 0xff).toByte()
            o[off + 2 * i + 1] = ((t[i] shr 8) and 0xff).toByte()
        }
    }

    private fun packed(a: LongArray) = ByteArray(32).also { pack25519(it, 0, a) }

    private fun neq(a: LongArray, b: LongArray) = !packed(a).contentEquals(packed(b))

    private fun par(a: LongArray) = packed(a)[0].toInt() and 1

    private fun unpack25519(o: LongArray, n: ByteArray) {
        for (i in 0 until 16) o[i] = (n[2 * i].toLong() and 0xff) + ((n[2 * i + 1].toLong() and 0xff) shl 8)
        o[15] = o[15] and 0x7fff
    }

    private fun A(o: LongArray, a: LongArray, b: LongArray) { for (i in 0 until 16) o[i] = a[i] + b[i] }

    private fun Z(o: LongArray, a: LongArray, b: LongArray) { for (i in 0 until 16) o[i] = a[i] - b[i] }

    private fun M(o: LongArray, a: LongArray, b: LongArray) {
        val t = LongArray(31)
        for (i in 0 until 16) for (j in 0 until 16) t[i + j] += a[i] * b[j]
        for (i in 0 until 15) t[i] += 38 * t[i + 16]
        for (i in 0 until 16) o[i] = t[i]
        car(o); car(o)
    }

    private fun S(o: LongArray, a: LongArray) = M(o, a, a)

    private fun inv25519(o: LongArray, i: LongArray) {
        val c = i.copyOf()
        for (a in 253 downTo 0) {
            S(c, c)
            if (a != 2 && a != 4) M(c, c, i)
        }
        set(o, c)
    }

    private fun pow2523(o: LongArray, i: LongArray) {
        val c = i.copyOf()
        for (a in 250 downTo 0) {
            S(c, c)
            if (a != 1) M(c, c, i)
        }
        set(o, c)
    }

    private fun point() = Array(4) { LongArray(16) }

    private fun add(p: Array<LongArray>, q: Array<LongArray>) {
        val a = LongArray(16); val b = LongArray(16); val c = LongArray(16); val d = LongArray(16)
        val t = LongArray(16); val e = LongArray(16); val f = LongArray(16); val g = LongArray(16)
        val h = LongArray(16)
        Z(a, p[1], p[0]); Z(t, q[1], q[0]); M(a, a, t)
        A(b, p[0], p[1]); A(t, q[0], q[1]); M(b, b, t)
        M(c, p[3], q[3]); M(c, c, D2)
        M(d, p[2], q[2]); A(d, d, d)
        Z(e, b, a); Z(f, d, c); A(g, d, c); A(h, b, a)
        M(p[0], e, f); M(p[1], h, g); M(p[2], g, f); M(p[3], e, h)
    }

    private fun cswap(p: Array<LongArray>, q: Array<LongArray>, b: Int) { for (i in 0 until 4) sel(p[i], q[i], b) }

    private fun pack(r: ByteArray, off: Int, p: Array<LongArray>) {
        val tx = LongArray(16); val ty = LongArray(16); val zi = LongArray(16)
        inv25519(zi, p[2]); M(tx, p[0], zi); M(ty, p[1], zi)
        pack25519(r, off, ty)
        r[off + 31] = (r[off + 31].toInt() xor (par(tx) shl 7)).toByte()
    }

    private fun scalarmult(p: Array<LongArray>, q: Array<LongArray>, s: ByteArray, off: Int) {
        set(p[0], GF0); set(p[1], GF1); set(p[2], GF1); set(p[3], GF0)
        for (i in 255 downTo 0) {
            val b = ((s[off + i / 8].toInt() and 0xff) shr (i and 7)) and 1
            cswap(p, q, b); add(q, p); add(p, p); cswap(p, q, b)
        }
    }

    private fun scalarbase(p: Array<LongArray>, s: ByteArray, off: Int) {
        val q = point()
        set(q[0], BX); set(q[1], BY); set(q[2], GF1); M(q[3], BX, BY)
        scalarmult(p, q, s, off)
    }

    private fun modL(r: ByteArray, off: Int, x: LongArray) {
        var carry: Long
        for (i in 63 downTo 32) {
            carry = 0
            var j = i - 32
            while (j < i - 12) {
                x[j] += carry - 16 * x[i] * L[j - (i - 32)]
                carry = (x[j] + 128) shr 8
                x[j] -= carry * 256
                j++
            }
            x[j] += carry
            x[i] = 0
        }
        carry = 0
        for (j in 0 until 32) {
            x[j] += carry - (x[31] shr 4) * L[j]
            carry = x[j] shr 8
            x[j] = x[j] and 255
        }
        for (j in 0 until 32) x[j] -= carry * L[j]
        for (i in 0 until 32) {
            x[i + 1] += x[i] shr 8
            r[off + i] = (x[i] and 255).toByte()
        }
    }

    private fun reduce(r: ByteArray) {
        val x = LongArray(64) { r[it].toLong() and 0xff }
        r.fill(0)
        modL(r, 0, x)
    }

    private fun below(v: ByteArray, off: Int, bound: ByteArray): Boolean {
        for (i in 31 downTo 0) {
            val a = v[off + i].toInt() and 0xff
            val b = bound[i].toInt() and 0xff
            if (a < b) return true
            if (a > b) return false
        }
        return false
    }

    private fun unpackneg(r: Array<LongArray>, p: ByteArray): Boolean {
        val y = p.copyOf()
        y[31] = (y[31].toInt() and 0x7f).toByte()
        if (!below(y, 0, P_BYTES)) return false
        val t = LongArray(16); val chk = LongArray(16); val num = LongArray(16); val den = LongArray(16)
        val den2 = LongArray(16); val den4 = LongArray(16); val den6 = LongArray(16)
        set(r[2], GF1)
        unpack25519(r[1], p)
        S(num, r[1]); M(den, num, D); Z(num, num, r[2]); A(den, r[2], den)
        S(den2, den); S(den4, den2); M(den6, den4, den2)
        M(t, den6, num); M(t, t, den)
        pow2523(t, t)
        M(t, t, num); M(t, t, den); M(t, t, den); M(r[0], t, den)
        S(chk, r[0]); M(chk, chk, den)
        if (neq(chk, num)) M(r[0], r[0], SQRTM1)
        S(chk, r[0]); M(chk, chk, den)
        if (neq(chk, num)) return false
        val sign = (p[31].toInt() and 0xff) shr 7
        if (packed(r[0]).all { it.toInt() == 0 } && sign == 1) return false
        if (par(r[0]) == sign) Z(r[0], GF0, r[0])
        M(r[3], r[0], r[1])
        return true
    }

    private val IDENTITY = ByteArray(32).also { it[0] = 1 }

    /** [8]P is the identity: P is in the torsion subgroup (order 1, 2, 4 or 8). */
    private fun smallOrder(p: Array<LongArray>): Boolean {
        val t = Array(4) { p[it].copyOf() }
        add(t, t); add(t, t); add(t, t)
        return ByteArray(32).also { pack(it, 0, t) }.contentEquals(IDENTITY)
    }

    private fun expand(seed: ByteArray): ByteArray {
        require(seed.size == 32) { "an Ed25519 seed is 32 bytes" }
        val d = Crypto.sha512(seed)
        d[0] = (d[0].toInt() and 248).toByte()
        d[31] = (d[31].toInt() and 127).toByte()
        d[31] = (d[31].toInt() or 64).toByte()
        return d
    }

    fun publicKey(seed: ByteArray): ByteArray {
        val d = expand(seed)
        val p = point()
        scalarbase(p, d, 0)
        return ByteArray(32).also { pack(it, 0, p) }
    }

    fun sign(seed: ByteArray, message: ByteArray): ByteArray {
        val d = expand(seed)
        val p = point()
        scalarbase(p, d, 0)
        val pk = ByteArray(32).also { pack(it, 0, p) }
        val r = Crypto.sha512(d.copyOfRange(32, 64) + message)
        reduce(r)
        val sig = ByteArray(64)
        scalarbase(p, r, 0)
        pack(sig, 0, p)
        val h = Crypto.sha512(sig.copyOf(32) + pk + message)
        reduce(h)
        val x = LongArray(64)
        for (i in 0 until 32) x[i] = r[i].toLong() and 0xff
        for (i in 0 until 32) for (j in 0 until 32) x[i + j] += (h[i].toLong() and 0xff) * (d[j].toLong() and 0xff)
        modL(sig, 32, x)
        return sig
    }

    fun verify(publicKey: ByteArray, message: ByteArray, signature: ByteArray): Boolean {
        if (publicKey.size != 32 || signature.size != 64) return false
        if (!below(signature, 32, L_BYTES)) return false
        val q = point()
        if (!unpackneg(q, publicKey) || smallOrder(q)) return false
        val h = Crypto.sha512(signature.copyOf(32) + publicKey + message)
        reduce(h)
        val p = point()
        scalarmult(p, q, h, 0)
        scalarbase(q, signature, 32)
        add(p, q)
        val t = ByteArray(32).also { pack(it, 0, p) }
        return t.contentEquals(signature.copyOf(32))
    }
}
