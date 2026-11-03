package io.github.drlexus11.lxpt

import java.io.File
import java.security.KeyFactory
import java.security.Signature
import java.security.spec.EdECPrivateKeySpec
import java.security.spec.NamedParameterSpec
import kotlin.random.Random

/**
 * Every vector of fixtures/lxpt_wire_v1.json against the Kotlin implementation,
 * with no test framework, so it also runs from a bare kotlinc build. Each result
 * is recorded as one "key value" line, the same lines the Python and C++
 * suites record (tools/crosscheck.py compares them).
 */
class FixtureRunner(fixture: File) {
    @Suppress("UNCHECKED_CAST")
    private val f = Json.parse(fixture.readText()) as Map<String, Any?>
    val failures = ArrayList<String>()
    val lines = ArrayList<String>()
    var checks = 0

    private fun check(ok: Boolean, what: String) {
        checks++
        if (!ok) failures.add(what)
    }

    private fun record(key: String, value: String) { lines.add("$key $value") }

    // --- JSON helpers --------------------------------------------------------------------

    @Suppress("UNCHECKED_CAST")
    private fun Any?.obj() = this as Map<String, Any?>
    @Suppress("UNCHECKED_CAST")
    private fun Any?.arr() = this as List<Any?>
    private fun Any?.str() = this as String
    private fun Any?.long() = this as Long
    private fun Any?.int() = (this as Long).toInt()
    private fun Any?.bool() = this as Boolean
    private fun Any?.hex(): ByteArray = (this as String).let { s -> ByteArray(s.length / 2) { s.substring(2 * it, 2 * it + 2).toInt(16).toByte() } }
    private fun ByteArray.hex() = joinToString("") { "%02x".format(it.toInt() and 0xff) }
    private operator fun Any?.get(k: String) = obj()[k]
    private fun err(block: () -> Unit): String = try { block(); "ok" } catch (e: WireException) { e.code }

    private fun <T> name(v: Any?, all: Array<T>, nameOf: (T) -> String): T =
        all.firstOrNull { nameOf(it) == v } ?: throw WireException("field")

    private fun tier(v: Any?) = name(v, Tier.entries.toTypedArray()) { it.wireName }
    private fun profile(v: Any?) = name(v, Profile.entries.toTypedArray()) { it.wireName }

    private fun ref(v: Any?): SpurtRef? = v?.let {
        SpurtRef(it["talker_tag"].hex(), it["spurt"].long(), tier(it["tier"]), it["emergency"].bool())
    }

    private fun message(v: Any?): Message {
        val sig = { if (v.obj().containsKey("signature")) v["signature"].hex() else ByteArray(64) }
        return when (v["type"]) {
            "frame" -> Frame(v["channel_tag"].hex(), v["talker_tag"].hex(), v["spurt"].long(), v["seq"].int(),
                v["payload"].hex(), v["mac"].hex())
            "claim" -> Claim(v["channel_tag"].hex(), v["talker_tag"].hex(), v["spurt"].long(), v["epoch"].long(),
                v["nonce"].hex(), tier(v["tier"]), v["emergency"].bool(), v["clock_verified"].bool(), v["clock"].long(),
                v["public_key"].hex(), sig())
            "grant" -> Grant(v["channel_tag"].hex(), v["talker_tag"].hex(), v["spurt"].long(), profile(v["profile"]),
                v["talk_limit_s"].int(), v["reached"].arr().map { it.hex() })
            "busy" -> Busy(v["channel_tag"].hex(), v["talker_tag"].hex(), v["spurt"].long(),
                name(v["reason"], BusyReason.entries.toTypedArray()) { it.wireName }, ref(v["holder"]))
            "yield" -> Yield(v["channel_tag"].hex(), v["talker_tag"].hex(), v["spurt"].long(),
                name(v["reason"], YieldReason.entries.toTypedArray()) { it.wireName }, ref(v["winner"]))
            "release" -> Release(v["channel_tag"].hex(), v["talker_tag"].hex(), v["spurt"].long(),
                v["frame_count"].int(), v["public_key"].hex(), sig())
            "talking" -> Talking(v["channel_tag"].hex(), ref(v["holder"]), profile(v["profile"]), v["talk_limit_s"].int())
            "sub" -> Sub(name(v["carrier"], Carrier.entries.toTypedArray()) { it.wireName }, v["entries"].arr().map {
                SubEntry(it["channel_tag"].hex(), it["member_tag"].hex(),
                    name(it["mode"], SubMode.entries.toTypedArray()) { m -> m.wireName })
            })
            "peer" -> Peer(v["relay_hash"].hex(), v["stall_p99_ms"].int(), v["channels"].arr().map {
                PeerChannel(it["channel_tag"].hex(), it["narrow"].bool(), it["members"].arr().map { m -> m.hex() })
            })
            "heard" -> Heard(v["channel_tag"].hex(), v["talker_tag"].hex(), v["spurt"].long(),
                v["heard"].arr().map { HeardEntry(it["member_tag"].hex(), it["frames"].int()) })
            else -> throw WireException("type")
        }
    }

    private fun refJson(r: SpurtRef?): Any? = r?.let {
        mapOf("talker_tag" to it.talkerTag.hex(), "spurt" to it.spurt, "tier" to it.tier.wireName,
            "emergency" to it.emergency)
    }

    private fun json(m: Message): Map<String, Any?> = when (m) {
        is Frame -> mapOf("type" to "frame", "channel_tag" to m.channelTag.hex(), "talker_tag" to m.talkerTag.hex(),
            "spurt" to m.spurt, "seq" to m.seq.toLong(), "payload" to m.payload.hex(), "mac" to m.mac.hex())
        is Claim -> mapOf("type" to "claim", "channel_tag" to m.channelTag.hex(), "talker_tag" to m.talkerTag.hex(),
            "spurt" to m.spurt, "epoch" to m.epoch, "nonce" to m.nonce.hex(), "tier" to m.tier.wireName,
            "emergency" to m.emergency, "clock_verified" to m.clockVerified, "clock" to m.clock,
            "public_key" to m.publicKey.hex(), "signature" to m.signature.hex())
        is Grant -> mapOf("type" to "grant", "channel_tag" to m.channelTag.hex(), "talker_tag" to m.talkerTag.hex(),
            "spurt" to m.spurt, "profile" to m.profile.wireName, "talk_limit_s" to m.talkLimitS.toLong(),
            "reached" to m.reached.map { it.hex() })
        is Busy -> mapOf("type" to "busy", "channel_tag" to m.channelTag.hex(), "talker_tag" to m.talkerTag.hex(),
            "spurt" to m.spurt, "reason" to m.reason.wireName, "holder" to refJson(m.holder))
        is Yield -> mapOf("type" to "yield", "channel_tag" to m.channelTag.hex(), "talker_tag" to m.talkerTag.hex(),
            "spurt" to m.spurt, "reason" to m.reason.wireName, "winner" to refJson(m.winner))
        is Release -> mapOf("type" to "release", "channel_tag" to m.channelTag.hex(), "talker_tag" to m.talkerTag.hex(),
            "spurt" to m.spurt, "frame_count" to m.frameCount.toLong(), "public_key" to m.publicKey.hex(),
            "signature" to m.signature.hex())
        is Talking -> mapOf("type" to "talking", "channel_tag" to m.channelTag.hex(), "holder" to refJson(m.holder),
            "profile" to m.profile.wireName, "talk_limit_s" to m.talkLimitS.toLong())
        is Sub -> mapOf("type" to "sub", "carrier" to m.carrier.wireName, "entries" to m.entries.map {
            mapOf("channel_tag" to it.channelTag.hex(), "member_tag" to it.memberTag.hex(), "mode" to it.mode.wireName)
        })
        is Peer -> mapOf("type" to "peer", "relay_hash" to m.relayHash.hex(), "stall_p99_ms" to m.stallP99Ms.toLong(),
            "channels" to m.channels.map {
                mapOf("channel_tag" to it.channelTag.hex(), "narrow" to it.narrow, "members" to it.members.map { t -> t.hex() })
            })
        is Heard -> mapOf("type" to "heard", "channel_tag" to m.channelTag.hex(), "talker_tag" to m.talkerTag.hex(),
            "spurt" to m.spurt, "heard" to m.heard.map {
                mapOf("member_tag" to it.memberTag.hex(), "frames" to it.frames.toLong())
            })
    }

    private fun noticeJson(n: Notice) = mapOf("kind" to n.kind.wireName, "hop_limit" to n.hopLimit.toLong(),
        "channel_tag" to n.channelTag.hex(), "talker" to n.talker.hex(), "spurt16" to n.spurt16.toLong(),
        "talk_limit_s" to n.talkLimitS.toLong(), "mac" to n.mac.hex())

    private fun keys(v: Any?) = ChannelKeys(v["k_epoch"].hex(), v["channel_id"].hex())

    // --- sections ------------------------------------------------------------------------

    private fun crypto() {
        val c = f["crypto"]
        c["sha256"].arr().forEachIndexed { i, v ->
            val got = Crypto.sha256(v["message"].hex()).hex()
            check(got == v["digest"], "sha256 $i"); record("crypto/sha256/$i", got)
        }
        c["hmac_sha256"].arr().forEachIndexed { i, v ->
            val got = Crypto.hmacSha256(v["key"].hex(), v["message"].hex()).hex()
            check(got == v["mac"], "hmac $i"); record("crypto/hmac_sha256/$i", got)
        }
        c["hkdf_sha256"].arr().forEachIndexed { i, v ->
            val got = Crypto.hkdfSha256(v["ikm"].hex(), v["salt"].hex(), v["info"].hex(), v["length"].int()).hex()
            check(got == v["okm"], "hkdf $i"); record("crypto/hkdf_sha256/$i", got)
        }
        c["aes256_ctr"].arr().forEachIndexed { i, v ->
            val got = Crypto.aes256Ctr(v["key"].hex(), v["iv"].hex(), v["plaintext"].hex()).hex()
            check(got == v["ciphertext"], "aes $i"); record("crypto/aes256_ctr/$i", got)
        }
        c["ed25519"].arr().forEachIndexed { i, v ->
            val pk = Ed25519.publicKey(v["seed"].hex()).hex()
            val sig = Ed25519.sign(v["seed"].hex(), v["message"].hex()).hex()
            check(pk == v["public_key"] && sig == v["signature"], "ed25519 $i")
            check(Ed25519.verify(v["public_key"].hex(), v["message"].hex(), v["signature"].hex()), "ed25519 verify $i")
            record("crypto/ed25519/$i", pk + sig)
        }
        c["ed25519_verify"].arr().forEach { v ->
            val got = Ed25519.verify(v["public_key"].hex(), v["message"].hex(), v["signature"].hex())
            check(got == v["valid"], "ed25519_verify ${v["name"]}")
            record("crypto/ed25519_verify/${v["name"]}", if (got) "1" else "0")
        }
    }

    private fun channel() {
        val c = f["channel"]
        c["room_names_refused"].arr().forEach { v ->
            val got = err { Channel.canonicalRoom(v["input"].hex()) }
            check(got == v["error"], "room refused ${v["name"]}"); record("channel/room_names_refused/${v["name"]}", got)
        }
        c["channel_ids"].arr().forEachIndexed { i, v ->
            val got = Channel.channelId(v["hub_hash"].hex(), v["room"].hex()).hex()
            check(got == v["channel_id"], "channel id $i"); record("channel/channel_ids/$i", got)
        }
        c["hubless_ids"].arr().forEachIndexed { i, v ->
            val got = Channel.hublessChannelId(v["creator_hash"].hex(), v["name"].hex()).hex()
            check(got == v["channel_id"], "hubless id $i"); record("channel/hubless_ids/$i", got)
        }
        c["channel_keys"].arr().forEachIndexed { i, v ->
            val k = keys(v)
            check(k.channelTag.hex() == v["channel_tag"] && k.noticeKey.hex() == v["notice_key"], "channel keys $i")
            record("channel/channel_keys/$i", k.channelTag.hex() + k.noticeKey.hex())
            v["members"].arr().forEachIndexed { j, mv ->
                val got = k.memberTag(mv["identity_hash"].hex()).hex()
                check(got == mv["member_tag"], "member tag $i/$j"); record("channel/member_tags/$i/$j", got)
            }
        }
        c["spurt_keys"].arr().forEachIndexed { i, v ->
            val sk = keys(v).spurtKeys(v["talker_hash"].hex(), v["spurt"].long(), v["nonce"].hex())
            check(sk.encKey.hex() == v["enc_key"] && sk.macKey.hex() == v["mac_key"], "spurt keys $i")
            record("channel/spurt_keys/$i", sk.encKey.hex() + sk.macKey.hex())
        }
        f["identities"].obj().forEach { (name, v) ->
            val got = Channel.identityHash(v["public_key"].hex()).hex()
            check(got == v["hash"], "identity $name"); record("identities/$name", got)
        }
    }

    private fun messages() {
        f["messages"].arr().forEach { v ->
            val name = v["name"].str()
            val raw = Wire.encode(message(v["message"]))
            check(raw.hex() == v["hex"], "encode $name"); record("messages/$name", raw.hex())
            val back = Json.dump(json(Wire.decode(v["hex"].hex())))
            check(back == Json.dump(v["message"]), "decode $name: $back")
        }
        f["decode_refused"].arr().forEach { v ->
            val got = err { Wire.decode(v["hex"].hex()) }
            check(got == v["error"], "decode refused ${v["name"]}: $got"); record("decode_refused/${v["name"]}", got)
        }
        f["encode_refused"].arr().forEach { v ->
            val got = err { Wire.encode(message(v["message"])) }
            check(got == v["error"], "encode refused ${v["name"]}: $got"); record("encode_refused/${v["name"]}", got)
        }
    }

    private fun sealed() {
        f["frames"].arr().forEach { v ->
            val k = keys(v)
            val talker = v["talker_hash"].hex()
            val sk = k.spurtKeys(talker, v["spurt"].long(), v["nonce"].hex())
            val raw = Channel.sealFrame(sk, k.channelTag, k.memberTag(talker), v["spurt"].long(), v["seq"].int(),
                v["plaintext"].hex())
            check(raw.hex() == v["hex"], "seal ${v["name"]}")
            check(Channel.openFrame(sk, raw).second.hex() == v["plaintext"], "open ${v["name"]}")
            record("frames/${v["name"]}", raw.hex())
        }
        f["frames_refused"].arr().forEach { v ->
            val sk = keys(v).spurtKeys(v["talker_hash"].hex(), v["spurt"].long(), v["nonce"].hex())
            val got = err { Channel.openFrame(sk, v["hex"].hex()) }
            check(got == v["error"], "frame refused ${v["name"]}"); record("frames_refused/${v["name"]}", got)
        }
        f["notices"].arr().forEach { v ->
            val k = keys(v)
            val raw = Channel.sealNotice(k.noticeKey, name(v["kind"], NoticeKind.entries.toTypedArray()) { it.wireName },
                v["hop_limit"].int(), k.channelTag, v["talker_prefix"].hex(), v["spurt16"].int(), v["talk_limit_s"].int())
            check(raw.hex() == v["hex"], "notice ${v["name"]}")
            val (n, prefix) = Channel.openNotice(k.noticeKey, raw)
            check(prefix.hex() == v["talker_prefix"], "open notice ${v["name"]}")
            check(Json.dump(noticeJson(n)) == Json.dump(v["message"]), "notice decode ${v["name"]}")
            check(Wire.encodeNotice(n).contentEquals(raw), "notice re-encode ${v["name"]}")
            record("notices/${v["name"]}", raw.hex())
        }
        f["notices_hop_rewritten"].arr().forEach { v ->
            val (n, prefix) = Channel.openNotice(keys(v).noticeKey, v["hex"].hex())
            check(prefix.hex() == v["talker_prefix"] && n.hopLimit.toLong() == v["hop_limit"], "hop rewritten")
            record("notices_hop_rewritten/${v["name"]}", prefix.hex())
        }
        f["notices_refused"].arr().forEach { v ->
            val got = err { Channel.openNotice(keys(v).noticeKey, v["hex"].hex()) }
            check(got == v["error"], "notice refused ${v["name"]}"); record("notices_refused/${v["name"]}", got)
        }
        f["notice_decode_refused"].arr().forEach { v ->
            val got = err { Wire.decodeNotice(v["hex"].hex()) }
            check(got == v["error"], "notice decode refused ${v["name"]}")
            record("notice_decode_refused/${v["name"]}", got)
        }
        f["notice_encode_refused"].arr().forEach { v ->
            val m = v["message"]
            val got = err {
                Wire.encodeNotice(Notice(name(m["kind"], NoticeKind.entries.toTypedArray()) { it.wireName },
                    m["hop_limit"].int(), m["channel_tag"].hex(), m["talker"].hex(), m["spurt16"].int(),
                    m["talk_limit_s"].int(), m["mac"].hex()))
            }
            check(got == v["error"], "notice encode refused ${v["name"]}")
            record("notice_encode_refused/${v["name"]}", got)
        }
    }

    private fun signed() {
        f["signed"].arr().forEach { v ->
            val name = v["name"].str()
            val claim = v["kind"] == "claim"
            val raw = v["hex"].hex()
            if (v.obj().containsKey("seed")) {
                val m = message(v["message"])
                val pk = if (m is Claim) m.publicKey else (m as Release).publicKey
                val signer = SeedSigner(v["seed"].hex(), pk)
                val got = if (claim) Channel.signClaim(m as Claim, signer) else Channel.signRelease(m as Release, signer)
                check(got.hex() == v["hex"], "sign $name"); record("signed/$name", got.hex())
            }
            val span = (if (claim) Wire.claimSignedBytes(raw) else Wire.releaseSignedBytes(raw)).hex()
            check(span == v["signed_hex"], "signed span $name"); record("signed_bytes/$name", span)
            val got = err { if (claim) Channel.verifyClaim(raw) else Channel.verifyRelease(raw) }
            val m = Wire.decode(raw)
            val pk = if (m is Claim) m.publicKey else (m as Release).publicKey
            val tag = if (m is Claim) m.talkerTag else (m as Release).talkerTag
            val ok = Channel.memberOk(keys(v), pk, tag)
            check(got == v["verify"] && ok == v["member_ok"], "verify $name: $got $ok")
            record("signed_verify/$name", "$got ${if (ok) 1 else 0}")
        }
    }

    private fun relay() {
        f["relay_keys"].arr().forEach { v ->
            val got = err { Channel.relayKey(v["hex"].hex()) }
            val key = if (got == "ok") Channel.relayKey(v["hex"].hex()).hex() else got
            check(key == v["relay_key"], "relay key ${v["name"]}"); record("relay_keys/${v["name"]}", key)
        }
        f["relay_binding"].arr().forEach { v ->
            val got = err { Channel.releaseMatchesClaim(v["claim"].hex(), v["release"].hex()) }
            check(got == v["error"], "relay binding ${v["name"]}: $got"); record("relay_binding/${v["name"]}", got)
        }
    }

    /** A signer whose key is not the message's is refused before anything is returned. */
    private fun signerChecks() {
        val v = f["signed"].arr().first { it["name"] == "claim_member" }
        val m = message(v["message"]) as Claim
        val outsider = f["identities"]["outsider"]
        val wrongKey = object : Signer {
            override val publicKey = m.publicKey
            override fun sign(message: ByteArray) = Ed25519.sign(outsider["ed25519_seed"].hex(), message)
        }
        check(runCatching { Channel.signClaim(m, wrongKey) }.exceptionOrNull() is IllegalStateException,
            "a signer with the wrong private key is refused")
        check(runCatching { Channel.signClaim(m, SeedSigner(outsider["ed25519_seed"].hex(),
            outsider["public_key"].hex())) }.exceptionOrNull() is IllegalArgumentException,
            "a signer for another identity is refused")
    }

    /** The JDK's own Ed25519 (Java 15+) as an independent oracle for the pure-Kotlin one. */
    private fun jdkOracle() {
        val rng = Random(7)
        val kf = KeyFactory.getInstance("Ed25519")
        repeat(5) {
            val seed = rng.nextBytes(32)
            val msg = rng.nextBytes(it * 41)
            val jdk = Signature.getInstance("Ed25519")
            jdk.initSign(kf.generatePrivate(EdECPrivateKeySpec(NamedParameterSpec.ED25519, seed)))
            jdk.update(msg)
            check(jdk.sign().contentEquals(Ed25519.sign(seed, msg)), "JDK Ed25519 agrees $it")
        }
    }

    /** Mutated messages only ever raise WireException, and what decodes re-encodes to the same bytes. */
    private fun fuzz(iterations: Int) {
        val rng = Random(0x1A9E)
        val seeds = f["messages"].arr().map { it["hex"].hex() }
        var bad = 0
        repeat(iterations) { i ->
            var b = seeds[rng.nextInt(seeds.size)].copyOf()
            repeat(1 + rng.nextInt(4)) {
                when (rng.nextInt(3)) {
                    0 -> if (b.isNotEmpty()) b[rng.nextInt(b.size)] = rng.nextInt(256).toByte()
                    1 -> if (b.isNotEmpty()) b = b.copyOf(rng.nextInt(b.size))
                    else -> b += rng.nextBytes(1 + rng.nextInt(8))
                }
            }
            if (i % 10 == 9) b = rng.nextBytes(rng.nextInt(40))
            try {
                if (!Wire.encode(Wire.decode(b)).contentEquals(b)) bad++
            } catch (_: WireException) {
            } catch (e: Exception) {
                bad++
                failures.add("fuzz: ${e.javaClass.simpleName} on ${b.hex()}")
            }
            try {
                if (!Wire.encodeNotice(Wire.decodeNotice(b)).contentEquals(b)) bad++
            } catch (_: WireException) {
            }
        }
        check(bad == 0, "fuzz: $bad inputs failed")
    }

    fun run(fuzzIterations: Int = 20000): FixtureRunner {
        check(f["wire_version"] == Wire.VERSION.toLong() && f["notice_version"] == Wire.NOTICE_VERSION.toLong(), "versions")
        val lim = f["limits"]
        check(lim["max_message_len"] == Wire.MAX_MESSAGE_LEN.toLong() && lim["claim_len"] == Wire.CLAIM_LEN.toLong() &&
            lim["frame_max_payload"] == Wire.FRAME_MAX_PAYLOAD.toLong() && lim["notice_len"] == Wire.NOTICE_LEN.toLong(),
            "limits")
        crypto(); channel(); messages(); sealed(); signed(); relay(); signerChecks(); jdkOracle(); fuzz(fuzzIterations)
        return this
    }

    fun writeLines(out: File) = out.writeText(lines.sorted().joinToString("\n") + "\n")
}

/** For a bare kotlinc build: FixtureRunnerKt <fixture> [crosscheck-out]. */
fun main(args: Array<String>) {
    val r = FixtureRunner(File(args[0])).run()
    if (args.size > 1) r.writeLines(File(args[1]))
    r.failures.forEach { System.err.println("FAIL $it") }
    println("# ${r.checks} checks, ${r.failures.size} failures, ${r.lines.size} cross-check lines")
    if (r.failures.isNotEmpty()) kotlin.system.exitProcess(1)
}
