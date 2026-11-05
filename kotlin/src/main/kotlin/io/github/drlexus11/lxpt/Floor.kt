// SPDX-License-Identifier: Apache-2.0
package io.github.drlexus11.lxpt

/**
 * The lxpt floor core v1: one channel's floor as one node sees it.
 *
 * Pure: events in, actions out, the clock passed in as milliseconds, no I/O.
 * `spec/floor-v1.md` is the contract; the Python reference
 * (`python/lxpt/floor.py`) and the C++ core (`cpp/include/lxpt/floor.hpp`)
 * give the same actions, held by `fixtures/lxpt_floor_v1.json`.
 *
 * The host verifies every CLAIM and RELEASE signature before it calls the core.
 */
enum class FloorRole { RELAY, PHONE }

enum class SpurtState(val rank: Int) { LIVE(0), LOST(1), YIELDED(2), PENDING(3), KNOWN(4), ENDED(5) }

/** What the core needs from a verified CLAIM. */
class FloorClaim(
    val who: ByteArray, val tag: ByteArray, val spurt: Long, val nonce: ByteArray, val tier: Int = 4,
    val emergency: Boolean = false, val verified: Boolean = false, val local: Boolean = false, val src: Int = -1,
    val stallMs: Long = 0, val blob: ByteArray = ByteArray(0),
)

/** One spurt as this node knows it. */
class SpurtRec internal constructor(c: FloorClaim, now: Long, val own: Boolean) {
    val who: ByteArray = c.who.copyOf()
    val tag: ByteArray = c.tag.copyOf()
    val spurt: Long = c.spurt
    val nonce: ByteArray = c.nonce.copyOf()
    val tier: Int = c.tier
    val emergency: Boolean = c.emergency
    val verified: Boolean = c.verified
    val local: Boolean = c.local
    val src: Int = c.src
    val blob: ByteArray = c.blob.copyOf()
    val order: ByteArray = Floor.orderKey(c.who, c.spurt, c.nonce, c.tier, c.emergency, c.verified)
    var state = SpurtState.KNOWN
    var seenAt = now
    var holdUntil = now
    var liveSince = Floor.NEVER
    var lastHeard = Floor.NEVER
    var lastSeq = -1
    var quiet = false
    var lostAt = Floor.NEVER
    /** A yielded spurt that was lost keeps the lost spurt's window. */
    var lostWindow = false
    var endedAt = Floor.NEVER
    val lostMs: Long = Floor.lostMsFor(c.stallMs)
    var limitS = Floor.TALK_LIMIT_S
    var profile = 0
    var sends = 0
    var retryAt = Floor.NEVER
    // media time (v1.2, Floor.keepSchedule): the best offset and whether it is set
    // yet, the last live frame's arrival, late frames in a row at real-time pace,
    // and whether the last frame the floor forwarded was late
    var bestOffset = 0L
    var timed = false
    var lastArrival = Floor.NEVER
    var lateRun = 0
    var lastLate = false
    // relay bookkeeping, unused by the floor's own rules
    var reached: List<ByteArray> = emptyList()
    var hbNext = Floor.NEVER
    var nudgeAt = Floor.NEVER
    var announce = false
    var told = false

    fun ref(): String = Floor.hex(who) + "/" + spurt
}

/** A floor decision: kind, the spurt, BUSY's holder or YIELD's winner, a reason. */
class FloorAction(val kind: String, val rec: SpurtRec, val other: SpurtRec?, val reason: String) {
    /** The fixture's line for this action. */
    fun line(): String {
        val sb = StringBuilder(kind).append(' ').append(rec.ref())
        if (kind == "busy" || kind == "yield") sb.append(' ').append(other?.ref() ?: "-")
        if (reason.isNotEmpty()) sb.append(' ').append(reason)
        return sb.toString()
    }
}

/** Bytes with content equality and unsigned order, for map keys and sorting. */
internal class Bk(val b: ByteArray) : Comparable<Bk> {
    override fun equals(other: Any?) = other is Bk && b.contentEquals(other.b)
    override fun hashCode() = b.contentHashCode()
    override fun compareTo(other: Bk) = Floor.compareBytes(b, other.b)
}

/**
 * The last spurt per (channel tag, identity hash) and the time of its last
 * Emergency claim: replay protection that outlives the floor's records. When
 * full, the least recently advanced goes (ties to the lower tag || hash).
 */
class Counters(val capacity: Int = 64) {
    private class E(var last: Long, var emergencyAt: Long, var usedAt: Long)

    private val e = HashMap<Bk, E>()

    private fun key(tag: ByteArray, who: ByteArray) = Bk(tag + who)

    fun last(tag: ByteArray, who: ByteArray): Long? = e[key(tag, who)]?.last

    fun emergencyAt(tag: ByteArray, who: ByteArray): Long = e[key(tag, who)]?.emergencyAt ?: Floor.NEVER

    fun setEmergency(tag: ByteArray, who: ByteArray, now: Long) {
        e[key(tag, who)]?.emergencyAt = now
    }

    fun advance(now: Long, tag: ByteArray, who: ByteArray, spurt: Long) {
        val k = key(tag, who)
        val x = e[k]
        if (x != null) {
            x.last = maxOf(x.last, spurt)
            x.usedAt = now
            return
        }
        if (e.size >= capacity) {
            val victim = e.entries.minWithOrNull(compareBy<Map.Entry<Bk, E>> { it.value.usedAt }.thenBy { it.key })
            if (victim != null) e.remove(victim.key)
        }
        e[k] = E(spurt, Floor.NEVER, now)
    }
}

class Floor(
    val role: FloorRole, channelTag: ByteArray, val counters: Counters, val capacity: Int = 4,
    val talkLimitS: Int = TALK_LIMIT_S,
) {
    companion object {
        const val SETTLE_CAP_MS = 300L
        const val REMOTE_HOLD_MS = 600L
        const val QUIET_MS = 1200L
        const val LOST_MIN_MS = 5000L
        const val LOST_MAX_MS = 15000L
        /** A yielded spurt can come back within this. */
        const val RESUME_MS = 20000L
        /** A lost spurt can come back only within this (v1.1). */
        const val RESUME_WINDOW_MS = 2000L
        /** A frame this far behind its spurt's schedule is a backlog (v1.2). */
        const val LATE_MS = 800L
        /** This many late frames in a row at real-time pace re-anchor the schedule (v1.2). */
        const val REANCHOR_AFTER = 5
        const val TOMBSTONE_MS = 30000L
        const val LIMIT_GRACE_MS = 1000L
        const val CLAIM_RETRY_MS = 600L
        const val CLAIM_SENDS = 3
        const val TALK_LIMIT_S = 30
        const val NEVER = -1000000000L
        private const val TIER_MEMBER = 4

        fun hex(b: ByteArray): String = b.joinToString("") { "%02x".format(it.toInt() and 0xff) }

        fun compareBytes(a: ByteArray, b: ByteArray): Int {
            for (i in 0 until minOf(a.size, b.size)) {
                val d = (a[i].toInt() and 0xff) - (b[i].toInt() and 0xff)
                if (d != 0) return d
            }
            return a.size - b.size
        }

        /** A tier counts only from a verified membership. */
        fun effTier(tier: Int, verified: Boolean) = if (verified) tier else maxOf(tier, TIER_MEMBER)

        /** Emergency first, then the higher effective tier, then the lower SHA-256(who || u32 spurt || nonce). */
        fun orderKey(who: ByteArray, spurt: Long, nonce: ByteArray, tier: Int, emergency: Boolean, verified: Boolean):
            ByteArray {
            val d = Crypto.sha256(who + Channel.be32(spurt) + nonce)
            return byteArrayOf((if (emergency) 0 else 1).toByte(), effTier(tier, verified).toByte()) + d
        }

        private fun cuts(c: Int, s: Int) = (c == 1 && s >= 2) || (c == 2 && s >= 3) || (c == 3 && s == 4)

        fun canPreempt(c: SpurtRec, s: SpurtRec): Boolean {
            if (!c.verified || s.emergency) return false
            return c.emergency || cuts(effTier(c.tier, true), effTier(s.tier, s.verified))
        }

        fun lostMsFor(stallMs: Long) = minOf(LOST_MAX_MS, maxOf(LOST_MIN_MS, stallMs * 3 / 2))

        /** A profile's frame time in ms (LXST's); 0 for an unknown profile. */
        fun frameMs(profile: Int): Long = when (profile) {
            0x10 -> 400L
            0x20 -> 320L
            0x30 -> 200L
            0x40, 0x50 -> 60L
            else -> 0L
        }

        /**
         * Whether frame [seq] of [rec], received at [rx], is more than LATE_MS behind the spurt's schedule
         * (v1.2). False with no schedule yet (profile unknown, or no frame timed).
         */
        fun behind(rec: SpurtRec, seq: Int, rx: Long): Boolean {
            val fm = frameMs(rec.profile)
            if (fm == 0L || !rec.timed) return false
            return rx - seq.toLong() * fm - rec.bestOffset > LATE_MS
        }

        /**
         * A live spurt's frame [seq], received at [rx]: whether it is late (more than LATE_MS behind the
         * schedule), keeping the schedule (v1.2). The first timed frame sets the best offset, an earlier one
         * lowers it; a late frame arriving at least half a frame time after the previous one adds to a run,
         * any other frame ends it, and REANCHOR_AFTER of them re-anchor the schedule on this frame, which is
         * then not late. Without a profile there is nothing to judge by.
         */
        fun keepSchedule(rec: SpurtRec, seq: Int, rx: Long): Boolean {
            val fm = frameMs(rec.profile)
            if (fm == 0L) return false
            val offset = rx - seq.toLong() * fm
            if (!rec.timed) {
                rec.timed = true
                rec.bestOffset = offset
                rec.lastArrival = rx - fm
            }
            if (offset < rec.bestOffset) rec.bestOffset = offset
            var isLate = offset - rec.bestOffset > LATE_MS
            rec.lateRun = if (isLate && rx - rec.lastArrival >= fm / 2) rec.lateRun + 1 else 0
            if (rec.lateRun >= REANCHOR_AFTER) {
                rec.bestOffset = offset
                rec.lateRun = 0
                isLate = false
            }
            rec.lastArrival = rx
            return isLate
        }
    }

    val channelTag: ByteArray = channelTag.copyOf()
    val recs = ArrayList<SpurtRec>()
    private var lastTick: Long? = null
    private var settleMs = 0L
    private val out = ArrayList<FloorAction>()

    private val byOrder = Comparator<SpurtRec> { a, b -> compareBytes(a.order, b.order) }

    // --- lookups -------------------------------------------------------------------------

    fun sorted(state: SpurtState? = null): List<SpurtRec> =
        recs.filter { state == null || it.state == state }.sortedWith(byOrder)

    fun find(who: ByteArray, spurt: Long): SpurtRec? = recs.firstOrNull { it.spurt == spurt && it.who.contentEquals(who) }

    /** The record a clear header names: live, lost, yielded, pending, known (then ended, if asked); ties by order. */
    fun findTag(tag: ByteArray, spurt: Long, ended: Boolean = false): SpurtRec? =
        recs.filter { it.spurt == spurt && it.tag.contentEquals(tag) && (ended || it.state != SpurtState.ENDED) }
            .minWithOrNull(compareBy<SpurtRec> { it.state.rank }.then(byOrder))

    fun lives(): List<SpurtRec> = sorted(SpurtState.LIVE)

    fun holder(): SpurtRec? = lives().firstOrNull()

    fun own(): SpurtRec? = sorted().firstOrNull { it.own && it.state != SpurtState.ENDED }

    fun empty(): Boolean = recs.all { it.state == SpurtState.ENDED }

    // --- internals -----------------------------------------------------------------------

    private fun emit(kind: String, rec: SpurtRec, other: SpurtRec? = null, reason: String = "") {
        out.add(FloorAction(kind, rec, other, reason))
    }

    private fun take(): List<FloorAction> {
        val r = ArrayList(out)
        out.clear()
        return r
    }

    private fun insert(rec: SpurtRec, tombstone: Boolean = false): Boolean {
        if (recs.size < capacity) {
            recs.add(rec)
            return true
        }
        val classes = if (tombstone) listOf(SpurtState.ENDED)
        else listOf(SpurtState.ENDED, SpurtState.KNOWN, SpurtState.YIELDED, SpurtState.LOST)
        for (st in classes) {
            val victim = recs.filter { it.state == st && (st == SpurtState.ENDED || !it.own) }
                .minWithOrNull(compareBy<SpurtRec> { evictionTime(it, st) }.then(byOrder))
            if (victim != null) {
                recs.remove(victim)
                recs.add(rec)
                return true
            }
        }
        return false
    }

    private fun evictionTime(r: SpurtRec, st: SpurtState): Long = when (st) {
        SpurtState.ENDED -> r.endedAt
        SpurtState.KNOWN -> r.seenAt
        else -> r.lostAt
    }

    private fun end(now: Long, rec: SpurtRec, reason: String) {
        rec.state = SpurtState.ENDED
        rec.endedAt = now
        emit("ended", rec, null, reason)
    }

    private fun makeLive(now: Long, rec: SpurtRec) {
        rec.state = SpurtState.LIVE
        rec.liveSince = now
        rec.lastHeard = now
        rec.quiet = false
        emit("live", rec)
        yieldRule(now)
    }

    private fun yieldOne(now: Long, loser: SpurtRec, w: SpurtRec, reason: String) {
        if (loser.own) {
            loser.state = SpurtState.ENDED
            loser.endedAt = now
        } else {
            loser.state = SpurtState.YIELDED
            loser.lostAt = now
            loser.lostWindow = false
        }
        emit("yield", loser, w, reason)
    }

    private fun yieldRule(now: Long) {
        val rs = lives()
        if (rs.size < 2) return
        val w = rs[0]
        for (loser in rs.drop(1)) yieldOne(now, loser, w, if (canPreempt(w, loser)) "preempted" else "collision")
    }

    private fun blocks(c: SpurtRec): SpurtRec? {
        val rs = lives()
        return if (rs.any { !canPreempt(c, it) }) rs[0] else null
    }

    private fun setSettle(ms: Long) {
        settleMs = minOf(SETTLE_CAP_MS, maxOf(0L, ms))
    }

    // --- events ----------------------------------------------------------------------------

    /** A verified CLAIM, from this relay's client ([FloorClaim.local]) or from elsewhere. */
    fun claim(now: Long, c: FloorClaim, settleMs: Long = 0): List<FloorAction> {
        setSettle(settleMs)
        val last = counters.last(channelTag, c.who)
        val existing = find(c.who, c.spurt)
        if (existing != null || (last != null && c.spurt <= last)) {
            if (existing != null && role == FloorRole.RELAY && existing.local && c.local) retry(now, existing)
            return take()
        }
        for (r in sorted()) if (r.who.contentEquals(c.who) && r.state != SpurtState.ENDED && !r.own) end(now, r, "superseded")
        val rec = SpurtRec(c, now, false)
        rec.limitS = talkLimitS
        if (!insert(rec)) return take()
        counters.advance(now, channelTag, c.who, c.spurt)
        val blocker = blocks(rec)
        if (role == FloorRole.RELAY && rec.local) {
            if (blocker != null) {
                rec.state = SpurtState.KNOWN
                emit("busy", rec, blocker)
            } else {
                rec.state = SpurtState.PENDING
                rec.holdUntil = now + this.settleMs
                emit("pending", rec)
            }
        } else if (role == FloorRole.RELAY && blocker == null) {
            rec.state = SpurtState.PENDING
            rec.holdUntil = now + REMOTE_HOLD_MS
            emit("pending", rec)
        } else {
            rec.state = SpurtState.KNOWN
            emit("known", rec)
        }
        return take()
    }

    private fun retry(now: Long, rec: SpurtRec) {
        if (rec.state == SpurtState.LIVE) {
            emit("regrant", rec)
        } else if (rec.state == SpurtState.KNOWN) {
            val blocker = blocks(rec)
            if (blocker != null) {
                emit("busy", rec, blocker)
            } else {
                rec.state = SpurtState.PENDING
                rec.holdUntil = now + settleMs
                emit("pending", rec)
            }
        }
    }

    /** A TALKING: evidence the spurt was granted somewhere. Returns (actions, its record). */
    fun talking(now: Long, tag: ByteArray, spurt: Long, profile: Int, limitS: Int): Pair<List<FloorAction>, SpurtRec?> {
        val rec = findTag(tag, spurt)
        if (rec == null || rec.own || (role == FloorRole.RELAY && rec.local)) return Pair(take(), rec)
        rec.profile = profile
        rec.limitS = limitS
        if (role == FloorRole.PHONE) {
            // The phone's relay holds nothing live that orders before this one.
            for (r in lives()) {
                if (r !== rec && !r.own && compareBytes(r.order, rec.order) < 0) {
                    r.state = SpurtState.LOST
                    r.lostAt = now
                    emit("lost", r)
                }
            }
            if (rec.state == SpurtState.LOST || rec.state == SpurtState.YIELDED) {
                rec.state = SpurtState.LIVE
                rec.lastHeard = now
                rec.quiet = false
                emit("resumed", rec)
                yieldRule(now)
            }
        }
        if (rec.state == SpurtState.PENDING || rec.state == SpurtState.KNOWN) makeLive(now, rec)
        return Pair(take(), rec)
    }

    /** A FRAME's clear header. Returns (actions, its record, whether it goes on). */
    fun frame(now: Long, rx: Long, tag: ByteArray, spurt: Long, seq: Int): Triple<List<FloorAction>, SpurtRec?, Boolean> {
        val rec = findTag(tag, spurt)
        if (rec == null || rec.own) return Triple(take(), rec, false)
        if (rec.state == SpurtState.PENDING || rec.state == SpurtState.KNOWN) {
            if (role == FloorRole.RELAY && rec.local) return Triple(take(), rec, false)
            rec.lastSeq = maxOf(rec.lastSeq, seq)
            makeLive(now, rec)
        } else if (rec.state == SpurtState.LOST || rec.state == SpurtState.YIELDED) {
            // A lost spurt comes back only on a frame received within the resume
            // window: later ones are a backlog. A yielded one's talker was still sending.
            // Only a frame on its spurt's schedule brings either back (v1.2): a backlog
            // never does, however soon it arrives.
            val windowed = rec.state == SpurtState.LOST || rec.lostWindow
            val late = if (windowed) rx - rec.lostAt >= RESUME_WINDOW_MS else now - rec.lostAt >= RESUME_MS
            if (seq <= rec.lastSeq || late || behind(rec, seq, rx)) return Triple(take(), rec, false)
            rec.lastSeq = seq
            val w = holder()
            if (w != null && compareBytes(w.order, rec.order) < 0) {
                if (rec.state == SpurtState.LOST) {
                    // Yielded now, but still a lost spurt: its window runs from the loss.
                    val lostAt = rec.lostAt
                    yieldOne(now, rec, w, if (canPreempt(w, rec)) "preempted" else "collision")
                    rec.lostAt = lostAt
                    rec.lostWindow = true
                }
                return Triple(take(), rec, false)
            }
            rec.state = SpurtState.LIVE
            rec.lastHeard = now
            rec.quiet = false
            emit("resumed", rec)
            yieldRule(now)
        }
        if (rec.state != SpurtState.LIVE) return Triple(take(), rec, false)
        rec.lastHeard = maxOf(rec.lastHeard, rx)
        rec.lastSeq = maxOf(rec.lastSeq, seq)
        rec.lastLate = keepSchedule(rec, seq, rx)
        if (rec.quiet) {
            rec.quiet = false
            emit("unquiet", rec)
        }
        return Triple(take(), rec, true)
    }

    /**
     * A verified RELEASE, keyed on its signing key. Returns (actions, whether it ended a spurt). One that
     * matches no record leaves a tombstone only in free or ended room, advances no counter, and is not new.
     */
    fun release(now: Long, who: ByteArray, spurt: Long, tag: ByteArray): Pair<List<FloorAction>, Boolean> {
        val rec = find(who, spurt)
        if (rec != null) {
            if (rec.state == SpurtState.ENDED) return Pair(take(), false)
            end(now, rec, "released")
            return Pair(take(), true)
        }
        val last = counters.last(channelTag, who)
        if (last != null && spurt < last) return Pair(take(), false)
        val t = SpurtRec(FloorClaim(who, tag, spurt, ByteArray(16)), now, false)
        if (insert(t, tombstone = true)) end(now, t, "released")
        return Pair(take(), false)
    }

    /** Judge every timer, after the host has drained its ingress. */
    fun tick(now: Long, settleMs: Long = 0): List<FloorAction> {
        setSettle(settleMs)
        val previous = lastTick
        val gap = if (previous == null) 0L else now - previous
        lastTick = now
        if (gap > QUIET_MS) {
            // A pass longer than the quiet timer is not silence.
            for (r in recs) if (r.state == SpurtState.LIVE) r.lastHeard = minOf(now, r.lastHeard + gap)
        }
        for (r in sorted()) {
            if (r.state == SpurtState.LIVE && r.own) {
                if (now - r.liveSince >= r.limitS * 1000L) end(now, r, "limit")
            } else if (r.state == SpurtState.LIVE) {
                if (now - r.liveSince >= r.limitS * 1000L + LIMIT_GRACE_MS) {
                    end(now, r, "limit")
                    continue
                }
                val silence = now - r.lastHeard
                if (silence >= r.lostMs) {
                    r.state = SpurtState.LOST
                    r.lostAt = now
                    emit("lost", r)
                } else if (silence >= QUIET_MS && !r.quiet) {
                    r.quiet = true
                    emit("quiet", r)
                }
            } else if (r.state == SpurtState.LOST) {
                if (now - r.lostAt >= RESUME_WINDOW_MS) end(now, r, "lost") // dead: late frames never move it
            } else if (r.state == SpurtState.YIELDED) {
                if (now - r.lostAt >= (if (r.lostWindow) RESUME_WINDOW_MS else RESUME_MS)) end(now, r, "yielded")
            } else if (r.state == SpurtState.PENDING && r.own) {
                if (now >= r.retryAt) {
                    if (r.sends < CLAIM_SENDS) {
                        r.sends++
                        r.retryAt = now + CLAIM_RETRY_MS
                        emit("retry", r)
                    } else {
                        end(now, r, "gave_up")
                    }
                }
            } else if (r.state == SpurtState.PENDING && !r.local) {
                if (now >= r.holdUntil) r.state = SpurtState.KNOWN
            }
        }
        if (role == FloorRole.RELAY) {
            for (r in sorted(SpurtState.PENDING)) {
                if (!r.local || r.state != SpurtState.PENDING || now < r.holdUntil) continue
                if (recs.any { it.state == SpurtState.PENDING && compareBytes(it.order, r.order) < 0 }) continue
                val blocker = blocks(r)
                if (blocker != null) {
                    r.state = SpurtState.KNOWN
                    emit("busy", r, blocker)
                    continue
                }
                for (l in lives()) yieldOne(now, l, r, "preempted")
                r.state = SpurtState.LIVE
                r.liveSince = now
                r.lastHeard = now
                emit("grant", r)
            }
        }
        recs.removeAll { it.state == SpurtState.ENDED && now - it.endedAt >= TOMBSTONE_MS }
        return take()
    }

    // --- the phone's own claim ---------------------------------------------------------------

    /** The phone keys up: its own signed CLAIM, which the host sends now. */
    fun key(now: Long, c: FloorClaim): List<FloorAction> {
        val last = counters.last(channelTag, c.who)
        if (last != null && c.spurt <= last) return take()  // a spurt id is never reused
        for (r in sorted()) if (r.who.contentEquals(c.who) && r.state != SpurtState.ENDED) end(now, r, "superseded")
        val rec = SpurtRec(c, now, true)
        rec.limitS = talkLimitS
        if (!insert(rec)) return take()
        counters.advance(now, channelTag, c.who, c.spurt)
        rec.state = SpurtState.PENDING
        rec.sends = 1
        rec.retryAt = now + CLAIM_RETRY_MS
        emit("pending", rec)
        return take()
    }

    private fun ownPending(tag: ByteArray, spurt: Long, liveToo: Boolean): SpurtRec? {
        val r = own() ?: return null
        if (!r.tag.contentEquals(tag) || r.spurt != spurt) return null
        return if (r.state == SpurtState.PENDING || (liveToo && r.state == SpurtState.LIVE)) r else null
    }

    private fun named(tag: ByteArray, spurt: Long): SpurtRec? = findTag(tag, spurt)?.takeIf { !it.own }

    /** A GRANT: taken only for the phone's own outstanding claim. */
    fun granted(now: Long, tag: ByteArray, spurt: Long, profile: Int, limitS: Int): List<FloorAction> {
        val r = ownPending(tag, spurt, false)
        if (r != null) {
            r.state = SpurtState.LIVE
            r.liveSince = now
            r.profile = profile
            r.limitS = limitS
            emit("grant", r)
            yieldRule(now)
        }
        return take()
    }

    /** A BUSY for the phone's own outstanding claim; [holder] is (talker tag, spurt) or null. */
    fun busy(now: Long, tag: ByteArray, spurt: Long, holder: Pair<ByteArray, Long>?, rateLimited: Boolean):
        List<FloorAction> {
        val r = ownPending(tag, spurt, false) ?: return take()
        val h = holder?.let { named(it.first, it.second) }
        if (h == null && !(rateLimited && holder == null)) return take()
        r.state = SpurtState.ENDED
        r.endedAt = now
        emit("busy", r, h)
        return take()
    }

    /** A YIELD for the phone's own claim or spurt, naming a claim it holds. */
    fun yielded(now: Long, tag: ByteArray, spurt: Long, winner: Pair<ByteArray, Long>, preempted: Boolean):
        List<FloorAction> {
        val r = ownPending(tag, spurt, true)
        val w = named(winner.first, winner.second)
        if (r == null || w == null) return take()
        r.state = SpurtState.ENDED
        r.endedAt = now
        emit("yield", r, w, if (preempted) "preempted" else "collision")
        return take()
    }

    /** The user released the key (after the release tail). */
    fun end(now: Long): List<FloorAction> {
        val r = own()
        if (r != null) end(now, r, "released")
        return take()
    }
}
