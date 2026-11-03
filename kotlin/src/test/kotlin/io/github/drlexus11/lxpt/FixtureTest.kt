package io.github.drlexus11.lxpt

import java.io.File
import kotlin.test.Test
import kotlin.test.assertTrue

class FixtureTest {
    @Test
    fun everyFixtureVector() {
        val fixture = File(System.getProperty("lxpt.fixture") ?: "../fixtures/lxpt_wire_v1.json")
        val r = FixtureRunner(fixture).run()
        System.getenv("LXPT_CROSSCHECK_OUT")?.takeIf { it.isNotEmpty() }?.let { r.writeLines(File(it)) }
        println("# ${r.checks} checks, ${r.lines.size} cross-check lines")
        assertTrue(r.failures.isEmpty(), r.failures.joinToString("\n"))
    }
}
