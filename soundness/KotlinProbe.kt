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

// 13-15. kotlin.io idioms — the IDIOMATIC file/entropy API (classified at the FilesKt/PathsKt/Random
// owners, verb-level; pure path manipulation must stay pure)
fun kio_read(f: java.io.File): String = f.readText()
fun kio_path(): String { kotlin.io.path.Path("/tmp/x").let { return it.toString() } } // pure: Path() + toString
fun kio_rand(): Int = kotlin.random.Random.nextInt()

// 16. NAMED class implementing a function type (NOT a lambda): compiled to a class implementing
// kotlin.jvm.functions.Function1, invoked via Function1.invoke. A bounded-CHA skip with no entry-point
// row ORPHANED its body — the /code-review hole. The caller must attribute (or the body must be a
// reachable entry point — the runner asserts on named_call, the calling function).
class NamedSender : (Int) -> Unit { override fun invoke(e: Int) { sink() } }
fun named_call() { val f: (Int) -> Unit = NamedSender(); f(1) }

// 17. `by lazy` TRUE-FORWARDING: an effectful deferred lambda stored in a field (kotlin/Lazy) and FORCED
// at a property getter must charge the FORCING site (a cross-class reader), not just the constructor.
// `lazy_force` reads ANOTHER class's lazy property — it must carry the effect (the silent-pure hole).
class LazyEff { val data: Int by lazy { sink(); 42 } }       // construction: LazyKt.lazy(λ) -> field
fun lazy_force(h: LazyEff): Int = h.data                     // force: Lazy.getValue — must be Fs/Unknown
// NEGATIVE (no-fabrication): a PURE-init lazy's reader must stay PURE — its lambda contributes nothing.
class LazyPure { val v2: Int by lazy { 1 + 1 } }
fun lazy_pure_force(h: LazyPure): Int = h.v2               // must NOT classify (the runner asserts pure)
