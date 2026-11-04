package io.github.drlexus11.lxpt

import java.io.File
import kotlin.test.Test
import kotlin.test.assertTrue

class FixtureTest {
    @Test
    fun everyFixtureVector() {
        val fixture = File(System.getProperty("lxpt.fixture") ?: "../fixtures/lxpt_wire_v1.json")
        val r = FixtureRunner(fixture).run()
        val dir = fixture.absoluteFile.parentFile
        val cores = CoresRunner(File(dir, "lxpt_floor_v1.json"), File(dir, "lxpt_relay_v1.json")).run()
        System.getenv("LXPT_CROSSCHECK_OUT")?.takeIf { it.isNotEmpty() }?.let {
            File(it).writeText((r.lines + cores.lines).sorted().joinToString("\n") + "\n")
        }
        println("# wire: ${r.checks} checks, ${r.lines.size} cross-check lines")
        println("# cores: ${cores.checks} checks, ${cores.lines.size} scenarios")
        assertTrue(r.failures.isEmpty(), r.failures.joinToString("\n"))
        assertTrue(cores.failures.isEmpty(), cores.failures.take(20).joinToString("\n"))
    }
}
