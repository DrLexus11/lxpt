package io.github.drlexus11.lxpt

import java.io.File

/**
 * fixtures/lxpt_floor_v1.json and fixtures/lxpt_relay_v1.json against the
 * Kotlin floor and relay cores. Every step's lines must equal the fixture's;
 * each scenario is recorded as one "floor/<name>" or "relay/<name>" line, the
 * SHA-256 of every line it produced (tools/crosscheck.py compares them).
 */
class CoresRunner(private val floorFixture: File, private val relayFixture: File) {
    val failures = ArrayList<String>()
    val lines = ArrayList<String>()
    var checks = 0

    @Suppress("UNCHECKED_CAST")
    private fun Any?.obj() = this as Map<String, Any?>
    @Suppress("UNCHECKED_CAST")
    private fun Any?.arr() = this as List<Any?>
    private fun Any?.str() = this as String
    private fun Any?.long() = this as Long
    private fun Any?.int() = (this as Long).toInt()
    private fun Any?.bool() = this as Boolean
    private fun Any?.hex(): ByteArray =
        (this as String).let { s -> ByteArray(s.length / 2) { s.substring(2 * it, 2 * it + 2).toInt(16).toByte() } }
    private operator fun Any?.get(k: String) = obj()[k]
    private fun Any?.has(k: String) = obj().containsKey(k)

    private fun digest(all: List<String>) = Floor.hex(Crypto.sha256(all.joinToString("\n").toByteArray(Charsets.UTF_8)))

    private fun compare(where: String, got: List<String>, want: List<String>) {
        checks++
        if (got == want) return
        val i = (0 until maxOf(got.size, want.size)).first { got.getOrNull(it) != want.getOrNull(it) }
        failures.add("$where: got ${got.size} lines, want ${want.size}; first difference at $i:\n" +
            "      got  ${got.getOrNull(i)?.take(160)}\n      want ${want.getOrNull(i)?.take(160)}")
    }

    private fun claimOf(e: Any?) = FloorClaim(e["who"].hex(), e["tag"].hex(), e["spurt"].long(), e["nonce"].hex(),
        e["tier"].int(), e["emergency"].bool(), e["verified"].bool(), e["local"].bool(), e["src"].int(),
        e["stall_ms"].long())

    private fun floorStep(f: Floor, at: Long, e: Any?): List<String> {
        val extra = ArrayList<String>()
        val acts: List<FloorAction> = when (val d = e["do"].str()) {
            "claim" -> f.claim(at, claimOf(e))
            "key" -> f.key(at, claimOf(e))
            "talking" -> f.talking(at, e["tag"].hex(), e["spurt"].long(), e["profile"].int(), e["limit_s"].int()).first
            "frame" -> {
                val rx = if (e.has("rx")) e["rx"].long() else at
                val (a, _, fwd) = f.frame(at, rx, e["tag"].hex(), e["spurt"].long(), e["seq"].int())
                extra.add(if (fwd) "forward" else "drop")
                a
            }
            "release" -> {
                val (a, fresh) = f.release(at, e["who"].hex(), e["spurt"].long(), e["tag"].hex())
                extra.add(if (fresh) "new" else "seen")
                a
            }
            "tick" -> f.tick(at, e["settle_ms"].long())
            "ticks" -> (0 until e["count"].long()).flatMap { f.tick(at + it * e["every"].long(), e["settle_ms"].long()) }
            "granted" -> f.granted(at, e["tag"].hex(), e["spurt"].long(), e["profile"].int(), e["limit_s"].int())
            "busy" -> {
                val h = e["holder"]?.arr()?.let { Pair(it[0].hex(), it[1].long()) }
                f.busy(at, e["tag"].hex(), e["spurt"].long(), h, e["rate_limited"].bool())
            }
            "yielded" -> {
                val w = e["winner"].arr()
                f.yielded(at, e["tag"].hex(), e["spurt"].long(), Pair(w[0].hex(), w[1].long()), e["preempted"].bool())
            }
            "end" -> f.end(at)
            else -> throw IllegalArgumentException("unknown step $d")
        }
        val h = f.holder()
        return acts.map { it.line() } + extra + listOf("holder " + (h?.ref() ?: "-"))
    }

    private fun relayStep(r: Relay, at: Long, e: Any?): List<String> {
        val rx = if (e.has("rx")) e["rx"].long() else at
        val verified = e.has("verified") && e["verified"].bool()
        val acts: List<RelayAction> = when (val d = e["do"].str()) {
            "admit" -> {
                val (ok, a) = r.admitClaim(at, e["leg"].int(), e["hex"].hex())
                return listOf(if (ok) "admit ok" else "admit no") + a.map { it.line() }
            }
            "client" -> r.client(at, e["leg"].int(), e["hex"].hex(), rx, verified)
            "peer" -> r.peer(at, e["index"].int(), e["hex"].hex(), rx, verified)
            "tick" -> r.tick(at, e["stall_ms"].long())
            "ticks" -> (0 until e["count"].long()).flatMap { r.tick(at + it * e["every"].long(), e["stall_ms"].long()) }
            "leg_down" -> r.legDown(at, e["leg"].int())
            "peer_up" -> r.peerUp(at, e["index"].int(), if (e.has("rtt_ms")) e["rtt_ms"].long() else 0)
            "peer_rtt" -> r.peerRtt(at, e["index"].int(), e["rtt_ms"].long())
            "peer_down" -> r.peerDown(at, e["index"].int())
            else -> throw IllegalArgumentException("unknown step $d")
        }
        return acts.map { it.line() }
    }

    fun run(): CoresRunner {
        @Suppress("UNCHECKED_CAST")
        val floor = Json.parse(floorFixture.readText()) as Map<String, Any?>
        @Suppress("UNCHECKED_CAST")
        val relay = Json.parse(relayFixture.readText()) as Map<String, Any?>
        val c = floor["constants"]
        checks++
        if (c["settle_cap_ms"].long() != Floor.SETTLE_CAP_MS || c["quiet_ms"].long() != Floor.QUIET_MS ||
            c["sub_lease_ms"].long() != Relay.SUB_LEASE_MS || c["remote_hold_ms"].long() != Floor.REMOTE_HOLD_MS) {
            failures.add("constants")
        }
        for (s in floor["scenarios"].arr()) {
            val name = s["name"].str()
            val role = if (s["role"].str() == "phone") FloorRole.PHONE else FloorRole.RELAY
            val f = Floor(role, s["channel_tag"].hex(), Counters(s["talkers"].int()), s["capacity"].int(),
                s["talk_limit_s"].int())
            val all = ArrayList<String>()
            s["steps"].arr().forEachIndexed { k, e ->
                val got = floorStep(f, e["at"].long(), e)
                compare("floor/$name step $k (${e["do"].str()} at ${e["at"].long()})", got, e["expect"].arr().map { it.str() })
                all.addAll(got)
            }
            lines.add("floor/$name ${digest(all)}")
        }
        for (s in relay["scenarios"].arr()) {
            val name = s["name"].str()
            val l = s["limits"]
            val r = Relay(s["relay_hash"].hex(), RelayLimits(l["channels"].int(), l["legs"].int(), l["peers"].int(),
                l["spurts"].int(), l["dedup"].int(), l["talkers"].int()), s["talk_limit_s"].int())
            val all = ArrayList<String>()
            s["steps"].arr().forEachIndexed { k, e ->
                val got = relayStep(r, e["at"].long(), e)
                compare("relay/$name step $k (${e["do"].str()} at ${e["at"].long()})", got, e["expect"].arr().map { it.str() })
                all.addAll(got)
            }
            lines.add("relay/$name ${digest(all)}")
        }
        return this
    }
}
