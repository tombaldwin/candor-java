import java.nio.file.Files
import java.nio.file.Path
import kotlin.coroutines.Continuation
import kotlin.coroutines.EmptyCoroutineContext
import kotlin.coroutines.startCoroutine

fun sink() { try { Files.readAllBytes(Path.of("/tmp/x")) } catch (e: Exception) {} }

// 1. plain top-level chain (baseline)
fun plain() { sink() }

// 2. lambda stored + invoked (Kotlin 2.x: invokedynamic by default)
fun lambda_call() { val f = { sink() }; f() }

// 3. SUSPEND chain: CPS transform — each fn gains a Continuation param; started stdlib-only
suspend fun susp_leaf() { sink() }
suspend fun susp_mid() { susp_leaf() }
fun susp_start() {
    val block: suspend () -> Unit = { susp_mid() }
    block.startCoroutine(Continuation(EmptyCoroutineContext) {})
}

// 4. inline fn: the call inlines INTO the caller's bytecode
inline fun inlined(block: () -> Unit) { block() }
fun inline_call() { inlined { sink() } }

// 5. object singleton: effect in init -> <clinit> of the object
object Eff { init { sink() } fun touch() {} }
fun object_init() { Eff.touch() }

// 6. companion object init
class Holder { companion object { init { sink() } fun touch() {} } }
fun companion_init() { Holder.touch() }

// 7. extension function
fun String.eff_ext() { sink() }
fun ext_call() { "x".eff_ext() }

// 8. default-arg synthesized $default wrapper
fun with_default(x: Int = run { sink(); 1 }) {}
fun default_call() { with_default() }

// 9. property getter
val gprop: Int get() { sink(); return 1 }
fun getter_call() { val _u = gprop }

// 10. callable reference
fun ref_call() { val f = ::sink; f() }
