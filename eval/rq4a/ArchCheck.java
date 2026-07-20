///usr/bin/env jbang "$0" "$@"
//DEPS com.tngtech.archunit:archunit:1.3.0
//JAVA 21

import com.tngtech.archunit.core.domain.JavaClasses;
import com.tngtech.archunit.core.importer.ClassFileImporter;
import com.tngtech.archunit.lang.ArchRule;
import com.tngtech.archunit.lang.EvaluationResult;

import java.nio.file.Path;

import static com.tngtech.archunit.lang.syntax.ArchRuleDefinition.noClasses;

/**
 * The architecture-conformance baseline of §2 / RQ4a: an ArchUnit import-graph gate.
 *
 * It enforces exactly the boundary the candor policy enforces ("the pricing domain performs no I/O")
 * in the way an import/package rule can express it: the domain may not DEPEND ON `java.net` or on the
 * infrastructure layer. Run it against the SAME compiled classes candor scans.
 *
 * Usage:  jbang ArchCheck.java <classes-dir>
 *
 * Expected result on the fixture: BOTH rules PASS (green). The domain reaches the network transitively
 * through the injected `RateSource` port, so its import graph names neither `java.net` nor `infra` —
 * the reach is invisible to a dependency-graph check. candor, scanning the same classes, reports it.
 */
public class ArchCheck {

    public static void main(String[] args) {
        Path classesDir = Path.of(args.length > 0 ? args[0] : "fixture/out");
        JavaClasses classes = new ClassFileImporter().importPath(classesDir);
        System.out.println("ArchUnit: imported " + classes.size() + " classes from " + classesDir);
        System.out.println("Rule set: \"the pricing domain must not perform network I/O\","
                + " expressed as an import/package-dependency gate.\n");

        ArchRule noNet = noClasses()
                .that().resideInAPackage("pricing..")
                .should().dependOnClassesThat().resideInAnyPackage("java.net..")
                .as("pricing domain must not depend on java.net");

        ArchRule noInfra = noClasses()
                .that().resideInAPackage("pricing..")
                .should().dependOnClassesThat().resideInAPackage("infra..")
                .as("pricing domain must not depend on the infrastructure layer");

        boolean allGreen = true;
        allGreen &= report(noNet, classes);
        allGreen &= report(noInfra, classes);

        System.out.println();
        if (allGreen) {
            System.out.println("ArchUnit VERDICT: GREEN — no architecture violation."
                    + " The import graph shows the pricing domain as I/O-free.");
        } else {
            System.out.println("ArchUnit VERDICT: RED — a rule was violated.");
        }
        System.exit(allGreen ? 0 : 1);
    }

    private static boolean report(ArchRule rule, JavaClasses classes) {
        EvaluationResult r = rule.evaluate(classes);
        boolean pass = !r.hasViolation();
        System.out.println((pass ? "  [PASS] " : "  [FAIL] ") + rule.getDescription());
        if (!pass) {
            r.getFailureReport().getDetails().forEach(d -> System.out.println("         · " + d));
        }
        return pass;
    }
}
