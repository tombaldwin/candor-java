package io.poly.candor;

import com.sun.source.tree.CompilationUnitTree;
import com.sun.source.tree.ExpressionTree;
import com.sun.source.tree.IdentifierTree;
import com.sun.source.tree.LiteralTree;
import com.sun.source.tree.MemberReferenceTree;
import com.sun.source.tree.MemberSelectTree;
import com.sun.source.tree.MethodInvocationTree;
import com.sun.source.util.JavacTask;
import com.sun.source.util.SourcePositions;
import com.sun.source.util.TreeScanner;
import com.sun.source.util.Trees;

import java.io.IOException;
import java.net.URI;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.stream.Stream;
import javax.tools.JavaFileObject;
import javax.tools.SimpleJavaFileObject;
import javax.tools.ToolProvider;

/**
 * SOURCE LINT: no environment access outside {@code Env.java} (SPEC §3.4 ⟨0.42⟩, SOUNDNESS R1634).
 *
 * <p>§3.4: "the registration is the read" — an engine that reads a result-moving variable by any route other than the
 * one class that records it has a silent switch. This lint is the gate that keeps that true, and it is an AST walk over
 * javac's own parse tree, not a grep: a regex over {@code getenv} matches the engine's own classifier table
 * ({@code method.equals("getenv")} in {@code Classifier}, which names the JDK method for the code it ANALYSES) and the
 * prose in ~200 comment lines that discuss the environment, and a check that fires on prose is a check somebody
 * learns to ignore. Calibrated by {@link EnvLintTest}, which seeds every spelling below and a real shipped file with
 * one read appended, and requires each to fail.
 *
 * <p>WHAT COUNTS — by the METHOD'S NAME, whatever its receiver, because an alias, a fully-qualified name, a static
 * import and a receiver held in a variable all spell the same call:
 * <ul>
 *   <li>a call to {@code getenv} ({@code System.getenv("X")}, {@code System.getenv(name)}, {@code System.getenv()},
 *       {@code java.lang.System.getenv(..)}, a statically imported {@code getenv(..)})</li>
 *   <li>a call to {@code environment} ({@code new ProcessBuilder(..).environment()}, {@code pb.environment()}) — the
 *       child's environment is an enumeration of this one</li>
 *   <li>a METHOD REFERENCE to either ({@code System::getenv}, {@code ProcessBuilder::environment})</li>
 *   <li>the REFLECTIVE routes: a string literal naming {@code java.lang.ProcessEnvironment}, and a string literal
 *       {@code "getenv"}/{@code "environment"} handed to {@code getMethod}/{@code getDeclaredMethod}/{@code findStatic}/
 *       {@code findVirtual}/{@code forName}</li>
 * </ul>
 * A static initialiser is scanned like any other member, so a {@code static final boolean X = System.getenv(..)} in a
 * class other than {@code Env} is a violation — which is the case that matters here, because it would consult its
 * switch at class load in a process (an evaluator verb) that never ran the logic the switch selects (§3.4 (a)).
 */
final class EnvLint {
    private EnvLint() {}

    record Hit(String file, long line, String why, String text) {
        @Override public String toString() { return file + ":" + line + ": " + why + ": " + text; }
    }

    /** The one file that may read the environment. */
    static final String ENV_FILE = "Env.java";

    private static final Set<String> ENV_METHODS = Set.of("getenv", "environment");
    /** JVM SYSTEM-PROPERTY access (SPEC §3.4 ⟨0.42⟩ "the class binds the effect, not the channel", SOUNDNESS R1645). A property is
     *  the same ambient input as a variable, delivered by the JVM's option channels. Flagged by method name wherever the name is
     *  specific to the system-property surface. */
    private static final Set<String> PROP_ANY = Set.of("getProperties", "setProperties", "setProperty", "clearProperty",
            "getInputArguments", "getRuntimeMXBean", "getSystemProperties");
    /** {@code getProperty} is also {@code java.util.Properties}' own accessor (a resource file the engine ships): flagged on a
     *  {@code System} receiver or an unqualified (statically imported) call. A {@code Properties} built from
     *  {@code System.getProperties()} is caught at the {@code getProperties} call. */
    private static final Set<String> PROP_SYSTEM_ONLY = Set.of("getProperty");
    /** {@code Boolean.getBoolean}, {@code Integer.getInteger}, {@code Long.getLong}: a property read spelled on a box class. */
    private static final Map<String, String> PROP_BOX = Map.of("getBoolean", "Boolean", "getInteger", "Integer", "getLong", "Long");
    private static final Set<String> PROP_REFLECTIVE_NAMES = Set.of("getProperty", "getProperties", "setProperty", "getBoolean",
            "getInteger", "getLong", "getInputArguments");
    private static final Set<String> REFLECTIVE = Set.of("getMethod", "getDeclaredMethod", "findStatic", "findVirtual",
            "forName", "loadClass", "getDeclaredMethods", "getMethods");

    /** Every environment access in {@code source}, however it is spelled. */
    static List<Hit> findEnvAccess(String source, String file) throws IOException {
        var jc = ToolProvider.getSystemJavaCompiler();
        JavaFileObject fo = new SimpleJavaFileObject(URI.create("string:///" + file), JavaFileObject.Kind.SOURCE) {
            @Override public CharSequence getCharContent(boolean ignore) { return source; }
        };
        JavacTask task = (JavacTask) jc.getTask(null, null, d -> { /* syntax errors surface below as a missing unit */ },
                List.of("-proc:none"), null, List.of(fo));
        Trees trees = Trees.instance(task);
        SourcePositions pos = trees.getSourcePositions();
        List<Hit> out = new ArrayList<>();
        for (CompilationUnitTree cu : task.parse()) {
            new TreeScanner<Void, Void>() {
                private void hit(com.sun.source.tree.Tree t, String why) {
                    long start = pos.getStartPosition(cu, t);
                    long line = start < 0 ? -1 : cu.getLineMap().getLineNumber(start);
                    String text = start < 0 ? t.toString() : source.substring((int) start,
                            (int) Math.min(source.length(), Math.max(start, pos.getEndPosition(cu, t))));
                    out.add(new Hit(file, line, why, text.lines().findFirst().orElse("").strip()));
                }
                private String nameOf(ExpressionTree sel) {
                    if (sel instanceof MemberSelectTree m) return m.getIdentifier().toString();
                    if (sel instanceof IdentifierTree i) return i.getName().toString();
                    return null;
                }
                /** the simple name of the receiver of {@code sel}, or null when unqualified / not a plain name */
                private String receiverOf(ExpressionTree sel) {
                    if (!(sel instanceof MemberSelectTree m)) return null;
                    return nameOf(m.getExpression());
                }
                private boolean unqualified(ExpressionTree sel) { return sel instanceof IdentifierTree; }
                private boolean propertyCall(String name, ExpressionTree sel) {
                    if (name == null) return false;
                    if (PROP_ANY.contains(name)) return true;
                    String r = receiverOf(sel);
                    if (PROP_SYSTEM_ONLY.contains(name)) return unqualified(sel) || "System".equals(r);
                    String box = PROP_BOX.get(name);
                    return box != null && (unqualified(sel) || box.equals(r));
                }
                @Override public Void visitMethodInvocation(MethodInvocationTree n, Void p) {
                    String name = nameOf(n.getMethodSelect());
                    if (name != null && ENV_METHODS.contains(name)) hit(n, "calls `" + name + "`");
                    if (propertyCall(name, n.getMethodSelect())) hit(n, "reads a JVM system property via `" + name + "`");
                    if (name != null && REFLECTIVE.contains(name))
                        for (ExpressionTree a : n.getArguments())
                            if (a instanceof LiteralTree l && l.getValue() instanceof String s && ENV_METHODS.contains(s))
                                hit(n, "reaches `" + s + "` reflectively");
                    if (name != null && REFLECTIVE.contains(name))
                        for (ExpressionTree a : n.getArguments())
                            if (a instanceof LiteralTree l && l.getValue() instanceof String s && PROP_REFLECTIVE_NAMES.contains(s))
                                hit(n, "reaches the property reader `" + s + "` reflectively");
                    // the JDK-own HOST properties are the one named exclusion: `Env.hostProperty` takes a literal that is not `candor.`
                    if ("hostProperty".equals(name)) {
                        boolean literal = n.getArguments().size() == 1 && n.getArguments().get(0) instanceof LiteralTree l
                                && l.getValue() instanceof String s && !s.regionMatches(true, 0, "candor.", 0, 7);
                        if (!literal) hit(n, "`hostProperty` takes a literal JDK-own name (a computed or candor.* name is a switch)");
                    }
                    return super.visitMethodInvocation(n, p);
                }
                @Override public Void visitMemberReference(MemberReferenceTree n, Void p) {
                    if (ENV_METHODS.contains(n.getName().toString())) hit(n, "references `" + n.getName() + "`");
                    String mn = n.getName().toString();
                    if (PROP_ANY.contains(mn) || (PROP_SYSTEM_ONLY.contains(mn) && "System".equals(nameOf(n.getQualifierExpression())))
                            || (PROP_BOX.containsKey(mn) && PROP_BOX.get(mn).equals(nameOf(n.getQualifierExpression()))))
                        hit(n, "references the property reader `" + mn + "`");
                    return super.visitMemberReference(n, p);
                }
                @Override public Void visitLiteral(LiteralTree n, Void p) {
                    if (n.getValue() instanceof String s && s.contains("ProcessEnvironment"))
                        hit(n, "names the JDK's private environment class");
                    return super.visitLiteral(n, p);
                }
            }.scan(cu, null);
        }
        return out;
    }

    /** The shipped files: every {@code .java} under {@code root} except {@link #ENV_FILE}. */
    static List<Path> shippedFiles(Path root) throws IOException {
        try (Stream<Path> s = Files.walk(root)) {
            return s.filter(f -> f.toString().endsWith(".java") && !f.getFileName().toString().equals(ENV_FILE)).sorted().toList();
        }
    }

    static List<Hit> lintTree(Path root) throws IOException {
        List<Hit> bad = new ArrayList<>();
        for (Path f : shippedFiles(root)) bad.addAll(findEnvAccess(Files.readString(f), root.relativize(f).toString()));
        return bad;
    }

    /** Every result-moving switch NAME registered in {@code root}, found the way a reader would: the string literal handed to
     *  {@code killSwitch}, {@code killSwitchOn}, {@code optIn} or {@code switchRead}. Value: the call that registered it. The
     *  engine keeps no list of its own (§3.4: the registration is the read), so this is the only enumeration there is, and a
     *  test that needs "every switch" derives it here rather than from a table that could rot. */
    static Map<String, String> registeredSwitches(Path root) throws IOException {
        Map<String, String> out = new TreeMap<>();
        for (Path f : shippedFiles(root)) {
            String source = Files.readString(f);
            var jc = ToolProvider.getSystemJavaCompiler();
            JavaFileObject fo = new SimpleJavaFileObject(URI.create("string:///" + f.getFileName()), JavaFileObject.Kind.SOURCE) {
                @Override public CharSequence getCharContent(boolean ignore) { return source; }
            };
            JavacTask task = (JavacTask) jc.getTask(null, null, d -> { }, List.of("-proc:none"), null, List.of(fo));
            SourcePositions pos = Trees.instance(task).getSourcePositions();
            for (CompilationUnitTree cu : task.parse()) {
                new TreeScanner<Void, Void>() {
                    @Override public Void visitMethodInvocation(MethodInvocationTree n, Void p) {
                        ExpressionTree sel = n.getMethodSelect();
                        String name = sel instanceof MemberSelectTree m ? m.getIdentifier().toString()
                                : sel instanceof IdentifierTree i ? i.getName().toString() : null;
                        if (name != null && Set.of("killSwitch", "killSwitchOn", "optIn", "switchRead", "propertySwitchRead", "propertyOptIn").contains(name)
                                && !n.getArguments().isEmpty()) {
                            if (n.getArguments().get(0) instanceof LiteralTree l && l.getValue() instanceof String s) out.put(s, name);
                            else out.put("<non-literal name at " + f.getFileName() + ":" + cu.getLineMap().getLineNumber(
                                    pos.getStartPosition(cu, n)) + ">", name);   // a name no enumeration can see
                        }
                        return super.visitMethodInvocation(n, p);
                    }
                }.scan(cu, null);
            }
        }
        return out;
    }
}
