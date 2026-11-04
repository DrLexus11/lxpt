// SPDX-License-Identifier: Apache-2.0
package io.github.drlexus11.lxpt

/**
 * The lxpt relay core v1: subscriptions, peers, dedup and forwarding choices
 * around one [Floor] per channel, for a phone that hosts a talk channel.
 *
 * Pure: the host hands it wire bytes received on a client leg or from a peer
 * relay and ticks it; it answers with [RelayAction]s, sends (bytes to one
 * client leg or one peer) and notes (floor decisions). `spec/floor-v1.md`
 * section 5 is the contract; the Python reference (`python/lxpt/relay.py`)
 * and the C++ core (`cpp/include/lxpt/relay.hpp`) give the same lines, held by
 * `fixtures/lxpt_relay_v1.json`.
 *
 * The host calls [admitClaim] on a CLAIM's bytes before verifying its
 * signature, and passes to [client] and [peer] only CLAIMs and RELEASEs whose
 * signature verified.
 */
sealed class RelayAction {
    abstract fun line(): String

    /** Bytes for client leg [index] (`kind` 'c') or peer relay [index] (`kind` 'p'). */
    class Send(val kind: Char, val index: Int, val data: ByteArray) : RelayAction() {
        override fun line() = "send $kind$index ${Floor.hex(data)}"
    }

    class Note(val channelTag: ByteArray, val action: FloorAction) : RelayAction() {
        override fun line() = "note ${Floor.hex(channelTag)} ${action.line()}"
    }
}

class RelayLimits(
    val channels: Int = 32, val legs: Int = 8, val peers: Int = 4, val spurts: Int = 4, val dedup: Int = 128,
    val talkers: Int = 64,
)

class Relay(relayHash: ByteArray, val limits: RelayLimits = RelayLimits(), val talkLimitS: Int = Floor.TALK_LIMIT_S) {
    companion object {
        const val SUB_LEASE_MS = 60000L
        const val PEER_EVERY_MS = 5000L
        const val PEER_LOST_MS = 15000L
        const val TALKING_EVERY_MS = 2000L
        const val TALKING_FORWARD_MS = 1000L
        const val FRAME_MAX_AGE_MS = 500L
        const val EMERGENCY_EVERY_MS = 10000L

        private fun who(publicKey: ByteArray) = Crypto.sha256(publicKey).copyOf(16)

        private fun codec2(profile: Int) = profile == 0x10 || profile == 0x20 || profile == 0x30
    }

    private class Leg(val carrier: Carrier, val leaseUntil: Long) {
        val entries = ArrayList<SubEntry>()
        fun narrow() = carrier == Carrier.BLE || carrier == Carrier.GFSK
    }

    private class PeerSlot {
        var up = false
        var rttMs = 0L
        var nextAt = Floor.NEVER
        var heard = false
        var stallMs = 0L
        var lastSeen = Floor.NEVER
        val channels = LinkedHashMap<Bk, Pair<Boolean, List<ByteArray>>>()
    }

    private class Chan(val tag: ByteArray, counters: Counters, limits: RelayLimits, talkLimitS: Int) {
        val floor = Floor(FloorRole.RELAY, tag, counters, limits.spurts, talkLimitS)
        var admitted0 = Floor.NEVER
        var admitted1 = Floor.NEVER
    }

    private class LegOn(val index: Int, val leg: Leg, val entry: SubEntry)

    private val relayHash = relayHash.copyOf()
    private val legs = arrayOfNulls<Leg>(limits.legs)
    private val peers = Array(limits.peers) { PeerSlot() }
    private val channels = HashMap<Bk, Chan>()
    private val counters = Counters(limits.talkers)
    private val dedup = HashSet<Bk>()
    private val dedupRing = ArrayList<Bk>()
    private var dedupAt = 0
    private var stallMs = 0L
    private val out = ArrayList<RelayAction>()

    private fun take(): List<RelayAction> {
        val r = ArrayList(out)
        out.clear()
        return r
    }

    private fun send(kind: Char, index: Int, data: ByteArray) {
        out.add(RelayAction.Send(kind, index, data.copyOf()))
    }

    // --- tables -----------------------------------------------------------------------------

    private fun channel(tag: ByteArray, create: Boolean): Chan? {
        val k = Bk(tag)
        val ch = channels[k]
        if (ch == null && create && channels.size < limits.channels) {
            val c = Chan(tag.copyOf(), counters, limits, talkLimitS)
            channels[k] = c
            return c
        }
        return ch
    }

    private fun sortedChannels(): List<Chan> = channels.entries.sortedBy { it.key }.map { it.value }

    private fun legsOn(tag: ByteArray, voiceOnly: Boolean): List<LegOn> {
        val r = ArrayList<LegOn>()
        for (i in legs.indices) {
            val leg = legs[i] ?: continue
            val e = leg.entries.firstOrNull { it.channelTag.contentEquals(tag) } ?: continue
            if (e.mode == SubMode.VOICE || !voiceOnly) r.add(LegOn(i, leg, e))
        }
        return r
    }

    private fun peersOn(tag: ByteArray, membersOnly: Boolean): List<Int> {
        val k = Bk(tag)
        return peers.indices.filter { j ->
            val p = peers[j]
            val c = p.channels[k]
            p.up && p.heard && c != null && (!membersOnly || c.second.isNotEmpty())
        }
    }

    private fun peerChannel(j: Int, tag: ByteArray) = peers[j].channels[Bk(tag)]!!

    private fun settle(tag: ByteArray): Long = peersOn(tag, false).maxOfOrNull { peers[it].rttMs }?.let { maxOf(0L, it) } ?: 0L

    private fun dedupSeen(key: ByteArray): Boolean {
        val k = Bk(key)
        if (k in dedup) return true
        if (dedupRing.size < limits.dedup) {
            dedupRing.add(k)
        } else {
            dedup.remove(dedupRing[dedupAt])
            dedupRing[dedupAt] = k
            dedupAt = (dedupAt + 1) % limits.dedup
        }
        dedup.add(k)
        return false
    }

    // --- messages the relay builds ------------------------------------------------------------

    private fun ref(r: SpurtRec) = SpurtRef(r.tag, r.spurt, Tier.of(r.tier)!!, r.emergency)

    private fun talking(ch: Chan, r: SpurtRec) = Wire.encode(Talking(ch.tag, ref(r), Profile.of(r.profile)!!, r.limitS))

    private fun grantFields(ch: Chan, rec: SpurtRec, profileToo: Boolean) {
        val talkerLeg = if (rec.src in legs.indices) legs[rec.src] else null
        var narrow = talkerLeg != null && talkerLeg.narrow()
        val reached = HashSet<Bk>()
        for (l in legsOn(ch.tag, true)) {
            if (l.index == rec.src) continue
            reached.add(Bk(l.entry.memberTag))
            narrow = narrow || l.leg.narrow()
        }
        for (j in peersOn(ch.tag, false)) {
            val (pn, members) = peerChannel(j, ch.tag)
            narrow = narrow || pn
            for (m in members) reached.add(Bk(m))
        }
        reached.remove(Bk(rec.tag))
        rec.reached = reached.sorted().take(Wire.GRANT_MAX_REACHED).map { it.b }
        if (profileToo) {
            rec.profile = if (narrow) Profile.LBW.code else Profile.HQ.code
            rec.limitS = talkLimitS
        }
    }

    private fun grant(ch: Chan, r: SpurtRec) =
        Wire.encode(Grant(ch.tag, r.tag, r.spurt, Profile.of(r.profile)!!, r.limitS, r.reached))

    private fun busy(ch: Chan, tag: ByteArray, spurt: Long, holder: SpurtRec?, reason: BusyReason) =
        Wire.encode(Busy(ch.tag, tag, spurt, reason, holder?.let { ref(it) }))

    private fun peerSummary(q: Int): ByteArray {
        val entries = ArrayList<PeerChannel>()
        var size = Wire.PEER_MIN_LEN
        for (ch in sortedChannels()) {
            var listed = false
            var narrow = false
            val members = HashSet<Bk>()
            for (l in legsOn(ch.tag, false)) {
                listed = true
                if (l.entry.mode == SubMode.VOICE) {
                    members.add(Bk(l.entry.memberTag))
                    narrow = narrow || l.leg.narrow()
                }
            }
            for (j in peersOn(ch.tag, false)) {
                if (j == q) continue
                listed = true
                val (pn, pm) = peerChannel(j, ch.tag)
                narrow = narrow || pn
                for (m in pm) members.add(Bk(m))
            }
            if (!listed) continue
            val ms = members.sorted().take(Wire.PEER_MAX_MEMBERS).map { it.b }
            val need = Wire.PEER_CHANNEL_MIN_LEN + 4 * ms.size
            if (size + need > Wire.MAX_MESSAGE_LEN || entries.size == Wire.PEER_MAX_CHANNELS) break
            size += need
            entries.add(PeerChannel(ch.tag, narrow, ms))
        }
        return Wire.encode(Peer(relayHash, minOf(0xFFFFL, stallMs).toInt(), entries))
    }

    // --- fan-out ------------------------------------------------------------------------------

    private fun toClients(ch: Chan, data: ByteArray, voiceOnly: Boolean, skip: Int = -1, rec: SpurtRec? = null) {
        for (l in legsOn(ch.tag, voiceOnly)) {
            if (l.index == skip) continue
            if (rec != null && l.leg.narrow() && (rec.profile == 0 || !codec2(rec.profile))) continue
            send('c', l.index, data)
        }
    }

    private fun toPeers(ch: Chan, data: ByteArray, membersOnly: Boolean, skip: Int = -1) {
        for (j in peersOn(ch.tag, membersOnly)) if (j != skip) send('p', j, data)
    }

    private fun pairToClients(ch: Chan, rec: SpurtRec) {
        if (rec.profile == 0) return
        val skip = if (rec.local) rec.src else -1
        val t = talking(ch, rec)
        for (l in legsOn(ch.tag, false)) {
            if (l.index == skip) continue
            send('c', l.index, rec.blob)
            send('c', l.index, t)
        }
        rec.told = true
    }

    private fun pairToPeers(ch: Chan, rec: SpurtRec, skip: Int, talkingBytes: ByteArray? = null) {
        if (rec.profile == 0) return
        val t = talkingBytes ?: talking(ch, rec)
        for (j in peersOn(ch.tag, false)) {
            if (j == skip) continue
            send('p', j, rec.blob)
            send('p', j, t)
        }
    }

    private fun apply(now: Long, ch: Chan, actions: List<FloorAction>) {
        for (a in actions) {
            out.add(RelayAction.Note(ch.tag, a))
            val rec = a.rec
            val srcLeg = if (rec.local) rec.src else -1
            val srcPeer = if (rec.local) -1 else rec.src
            when (a.kind) {
                "pending", "known" -> {
                    toClients(ch, rec.blob, false, srcLeg)
                    toPeers(ch, rec.blob, false, srcPeer)
                }
                "grant" -> {
                    grantFields(ch, rec, true)
                    send('c', rec.src, grant(ch, rec))
                    pairToClients(ch, rec)
                    pairToPeers(ch, rec, -1)
                    rec.hbNext = now + TALKING_EVERY_MS
                }
                "regrant" -> {
                    grantFields(ch, rec, false)
                    send('c', rec.src, grant(ch, rec))
                }
                "busy" -> {
                    val h = a.other!!
                    send('c', rec.src, h.blob)
                    send('c', rec.src, busy(ch, rec.tag, rec.spurt, h, BusyReason.BUSY))
                }
                "live" -> {
                    rec.hbNext = now + TALKING_EVERY_MS
                    pairToClients(ch, rec)
                }
                "yield" -> if (rec.local) {
                    val w = a.other!!
                    send('c', rec.src, w.blob)
                    val reason = if (a.reason == "preempted") YieldReason.PREEMPTED else YieldReason.COLLISION
                    send('c', rec.src, Wire.encode(Yield(ch.tag, rec.tag, rec.spurt, reason, ref(w))))
                }
            }
        }
    }

    // --- events -------------------------------------------------------------------------------

    /**
     * The cheap check on a client's CLAIM, before its signature is verified:
     * a stale spurt is dropped silently, a retry passes, and at most two new
     * claims per channel per second are admitted (else BUSY rate_limited).
     * Returns (whether the host should verify it and pass it on, actions).
     */
    fun admitClaim(now: Long, leg: Int, data: ByteArray): Pair<Boolean, List<RelayAction>> {
        val ok = admit(now, leg, data)
        return Pair(ok, take())
    }

    private fun admit(now: Long, leg: Int, data: ByteArray): Boolean {
        val m = try { Wire.decode(data) } catch (_: WireException) { return false }
        if (m !is Claim) return false
        val ch = channels[Bk(m.channelTag)] ?: return false
        val last = counters.last(ch.tag, who(m.publicKey))
        if (last != null && m.spurt < last) return false
        if (last != null && m.spurt == last) return true
        if (now - ch.admitted0 < 1000) {
            val holder = ch.floor.holder()
            if (holder != null) send('c', leg, holder.blob)
            send('c', leg, busy(ch, m.talkerTag, m.spurt, holder, BusyReason.RATE_LIMITED))
            return false
        }
        ch.admitted0 = ch.admitted1
        ch.admitted1 = now
        return true
    }

    /** Bytes received on client leg [leg]; [verified]: the CLAIM's membership verified (false in v1). */
    fun client(now: Long, leg: Int, data: ByteArray, rx: Long = now, verified: Boolean = false): List<RelayAction> {
        receive(now, 'c', leg, data, rx, verified)
        return take()
    }

    /** Bytes received from peer relay [index] (PLAIN one hop or a link). */
    fun peer(now: Long, index: Int, data: ByteArray, rx: Long = now, verified: Boolean = false): List<RelayAction> {
        receive(now, 'p', index, data, rx, verified)
        return take()
    }

    /** The TCP slot or BLE peer was released: its subscription goes at once. */
    @Suppress("UNUSED_PARAMETER")
    fun legDown(now: Long, leg: Int): List<RelayAction> {
        legs[leg] = null
        return take()
    }

    fun peerUp(now: Long, index: Int, rttMs: Long = 0): List<RelayAction> {
        val p = peers[index]
        p.up = true
        p.rttMs = rttMs
        p.nextAt = now
        return take()
    }

    @Suppress("UNUSED_PARAMETER")
    fun peerRtt(now: Long, index: Int, rttMs: Long): List<RelayAction> {
        peers[index].rttMs = rttMs
        return take()
    }

    @Suppress("UNUSED_PARAMETER")
    fun peerDown(now: Long, index: Int): List<RelayAction> {
        peers[index] = PeerSlot()
        return take()
    }

    private fun receive(now: Long, kind: Char, idx: Int, data: ByteArray, rx: Long, verified: Boolean) {
        val m = try { Wire.decode(data) } catch (_: WireException) { return }
        val fromPeer = kind == 'p'
        if (fromPeer && !peers[idx].up) return
        if (fromPeer && peers[idx].heard) peers[idx].lastSeen = now  // any message: the peer is not silent
        when (m) {
            is Sub -> if (!fromPeer) onSub(now, idx, m)
            is Peer -> if (fromPeer) onPeer(now, idx, m)
            is Claim -> onClaim(now, kind, idx, m, data, verified)
            is Frame -> onFrame(now, kind, idx, m, data, rx)
            is Release -> onRelease(now, kind, idx, m, data)
            is Talking -> if (fromPeer) onTalking(now, idx, m, data)
            is Heard -> onHeard(kind, idx, m, data)
            else -> {}
        }
    }

    private fun onSub(now: Long, i: Int, m: Sub) {
        val old = legs[i]
        val before = old?.entries?.map { Bk(it.channelTag) }?.toSet() ?: emptySet()
        val leg = Leg(m.carrier, now + SUB_LEASE_MS)
        val seen = LinkedHashSet<Bk>()
        for (e in m.entries) {
            val k = Bk(e.channelTag)
            if (k in seen || channel(e.channelTag, true) == null) continue
            seen.add(k)
            leg.entries.add(e)
        }
        legs[i] = leg
        for (k in (seen - before).sorted()) {
            val ch = channels[k]!!
            for (rec in ch.floor.lives()) {
                if (rec.profile == 0 || (rec.local && rec.src == i)) continue
                send('c', i, rec.blob)
                send('c', i, talking(ch, rec))
            }
        }
    }

    private fun onPeer(now: Long, j: Int, m: Peer) {
        val p = peers[j]
        val before = if (p.heard) p.channels.keys.toSet() else emptySet()
        p.heard = true
        p.stallMs = m.stallP99Ms.toLong()
        p.lastSeen = now
        p.channels.clear()
        for (c in m.channels) {
            val k = Bk(c.channelTag)
            if (k !in p.channels && channel(c.channelTag, true) != null) {
                p.channels[k] = Pair(c.narrow, c.members.map { Bk(it) }.toSet().sorted().map { it.b })
            }
        }
        for (k in (p.channels.keys - before).sorted()) {
            val ch = channels[k]!!
            for (rec in ch.floor.lives()) {
                if (rec.profile == 0 || (!rec.local && rec.src == j)) continue
                send('p', j, rec.blob)
                send('p', j, talking(ch, rec))
            }
        }
    }

    private fun onClaim(now: Long, kind: Char, idx: Int, m: Claim, data: ByteArray, verified: Boolean) {
        val ch = channels[Bk(m.channelTag)] ?: return
        val w = who(m.publicKey)
        val local = kind == 'c'
        val last = counters.last(ch.tag, w)
        val fresh = last == null || m.spurt > last
        if (local && m.emergency && fresh && now - counters.emergencyAt(ch.tag, w) < EMERGENCY_EVERY_MS) {
            val holder = ch.floor.holder()
            if (holder != null) send('c', idx, holder.blob)
            send('c', idx, busy(ch, m.talkerTag, m.spurt, holder, BusyReason.RATE_LIMITED))
            return
        }
        val stall = if (local) stallMs else maxOf(stallMs, peers[idx].stallMs)
        val c = FloorClaim(w, m.talkerTag, m.spurt, m.nonce, m.tier.code, m.emergency, verified, local, idx, stall, data)
        val actions = ch.floor.claim(now, c, settle(ch.tag))
        if (local && m.emergency && fresh) counters.setEmergency(ch.tag, w, now)
        apply(now, ch, actions)
    }

    private fun onFrame(now: Long, kind: Char, idx: Int, m: Frame, data: ByteArray, rx: Long) {
        val ch = channels[Bk(m.channelTag)] ?: return
        val key = m.channelTag + m.talkerTag + Channel.be32(m.spurt) +
            byteArrayOf((m.seq ushr 8).toByte(), m.seq.toByte()) + m.mac.copyOf(4)
        if (dedupSeen(key)) return
        val (actions, rec, forward) = ch.floor.frame(now, rx, m.talkerTag, m.spurt, m.seq)
        apply(now, ch, actions)
        if (!forward || rec == null || now - rx > FRAME_MAX_AGE_MS) return
        toClients(ch, data, true, if (kind == 'c') idx else -1, rec)
        for (j in peersOn(ch.tag, true)) {
            if ((kind == 'p' && j == idx) || (!rec.local && j == rec.src)) continue
            send('p', j, data)
        }
    }

    private fun onRelease(now: Long, kind: Char, idx: Int, m: Release, data: ByteArray) {
        val ch = channels[Bk(m.channelTag)] ?: return
        val (actions, fresh) = ch.floor.release(now, who(m.publicKey), m.spurt, m.talkerTag)
        apply(now, ch, actions)
        if (fresh) {
            toClients(ch, data, false, if (kind == 'c') idx else -1)
            toPeers(ch, data, false, if (kind == 'p') idx else -1)
        }
    }

    private fun onTalking(now: Long, j: Int, m: Talking, data: ByteArray) {
        val ch = channels[Bk(m.channelTag)] ?: return
        val h = m.holder ?: return
        val (actions, rec) = ch.floor.talking(now, h.talkerTag, h.spurt, m.profile.code, m.talkLimitS)
        apply(now, ch, actions)
        if (rec == null || rec.local || rec.state != SpurtState.LIVE) return
        if (!rec.told) pairToClients(ch, rec)
        if (now - rec.fwdAt >= TALKING_FORWARD_MS) {
            rec.fwdAt = now
            pairToPeers(ch, rec, j, data)
        }
    }

    private fun onHeard(kind: Char, idx: Int, m: Heard, data: ByteArray) {
        val ch = channels[Bk(m.channelTag)] ?: return
        val rec = ch.floor.findTag(m.talkerTag, m.spurt, ended = true) ?: return
        if (rec.local && !(kind == 'c' && idx == rec.src)) {
            send('c', rec.src, data)
        } else if (!rec.local && !(kind == 'p' && idx == rec.src)) {
            send('p', rec.src, data)
        }
    }

    /** Judge every timer and send what is due: once per pass, after draining ingress. */
    fun tick(now: Long, stallP99Ms: Long = 0): List<RelayAction> {
        stallMs = maxOf(0L, stallP99Ms)
        for (i in legs.indices) {
            val leg = legs[i]
            if (leg != null && now >= leg.leaseUntil) legs[i] = null
        }
        for (p in peers) {
            if (p.up && p.heard && now - p.lastSeen >= PEER_LOST_MS) {
                p.heard = false
                p.channels.clear()
            }
        }
        for (ch in sortedChannels()) {
            apply(now, ch, ch.floor.tick(now, settle(ch.tag)))
            for (rec in ch.floor.lives()) {
                if (now < rec.hbNext) continue
                rec.hbNext = now + TALKING_EVERY_MS
                pairToClients(ch, rec)
                if (rec.local) pairToPeers(ch, rec, -1)
            }
        }
        for (j in peers.indices) {
            val p = peers[j]
            if (p.up && now >= p.nextAt) {
                p.nextAt = now + PEER_EVERY_MS
                send('p', j, peerSummary(j))
            }
        }
        for (ch in sortedChannels()) {
            if (legsOn(ch.tag, false).isEmpty() && peersOn(ch.tag, false).isEmpty() && ch.floor.empty()) {
                channels.remove(Bk(ch.tag))
            }
        }
        return take()
    }
}
