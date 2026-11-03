package io.github.drlexus11.lxpt

/** A small JSON reader for the tests: objects, arrays, strings, integers, booleans, null. */
object Json {
    fun parse(text: String): Any? {
        val p = P(text)
        val v = p.value()
        p.ws()
        require(p.i == text.length) { "trailing JSON" }
        return v
    }

    private class P(val t: String) {
        var i = 0
        fun ws() { while (i < t.length && t[i].isWhitespace()) i++ }
        fun peek(): Char { ws(); return t[i] }
        fun expect(c: Char) { require(peek() == c) { "expected $c at $i" }; i++ }
        fun str(): String {
            expect('"')
            val sb = StringBuilder()
            while (t[i] != '"') {
                if (t[i] == '\\') {
                    i++
                    when (val c = t[i++]) {
                        'n' -> sb.append('\n')
                        't' -> sb.append('\t')
                        'u' -> { sb.append(t.substring(i, i + 4).toInt(16).toChar()); i += 4 }
                        else -> sb.append(c)
                    }
                } else sb.append(t[i++])
            }
            i++
            return sb.toString()
        }
        fun value(): Any? = when (peek()) {
            '{' -> {
                i++
                val m = LinkedHashMap<String, Any?>()
                if (peek() == '}') i++ else while (true) {
                    val k = str(); expect(':'); m[k] = value()
                    if (peek() == ',') { i++; continue }
                    expect('}'); break
                }
                m
            }
            '[' -> {
                i++
                val l = ArrayList<Any?>()
                if (peek() == ']') i++ else while (true) {
                    l.add(value())
                    if (peek() == ',') { i++; continue }
                    expect(']'); break
                }
                l
            }
            '"' -> str()
            else -> when {
                t.startsWith("true", i) -> { i += 4; true }
                t.startsWith("false", i) -> { i += 5; false }
                t.startsWith("null", i) -> { i += 4; null }
                else -> {
                    val s = i
                    if (t[i] == '-') i++
                    while (i < t.length && t[i].isDigit()) i++
                    t.substring(s, i).toLong()
                }
            }
        }
    }

    /** Canonical form: object keys sorted, no spaces. */
    fun dump(v: Any?): String = when (v) {
        null -> "null"
        is Boolean -> v.toString()
        is Long, is Int -> v.toString()
        is String -> "\"$v\""
        is List<*> -> v.joinToString(",", "[", "]") { dump(it) }
        is Map<*, *> -> v.entries.sortedBy { it.key as String }.joinToString(",", "{", "}") {
            "\"${it.key}\":${dump(it.value)}"
        }
        else -> error("not JSON: $v")
    }
}
