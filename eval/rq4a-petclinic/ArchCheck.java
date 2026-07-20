///usr/bin/env jbang "$0" "$@"
//DEPS com.tngtech.archunit:archunit:1.3.0
//JAVA 21

import com.tngtech.archunit.core.domain.JavaClasses;
import com.tngtech.archunit.core.importer.ClassFileImporter;
import com.tngtech.archunit.core.importer.ImportOption;
import com.tngtech.archunit.lang.ArchRule;
import com.tngtech.archunit.lang.EvaluationResult;

import java.nio.file.Path;

import static com.tngtech.archunit.lang.syntax.ArchRuleDefinition.noClasses;

/**
 * RQ4a — the DISCLOSURE half, on a real app (Spring PetClinic).
 *
 * The architecture-conformance baseline: an import/package rule that the domain and web layers must not
 * depend on the JDBC / persistence stack directly. On PetClinic this is GREEN — data access goes through
 * Spring Data repository *interfaces* (`OwnerRepository extends JpaRepository`), so no controller or
 * entity names `java.sql`/`javax.sql`. The import graph reports the layers as persistence-free.
 *
 * candor, scanning the same classes, does NOT report clean: the repository call resolves to an interface
 * with no in-project implementation (Spring generates the proxy at runtime), so candor discloses
 * `Unknown` — an honest "I cannot see through this dispatch," which a `deny Db Unknown[dispatch]` policy
 * can act on and which the import gate's silent green cannot express.
 *
 * Usage:  jbang ArchCheck.java <petclinic-target-classes-dir>
 */
public class ArchCheck {

    public static void main(String[] args) {
        Path classesDir = Path.of(args.length > 0 ? args[0] : "target/classes");
        JavaClasses classes = new ClassFileImporter()
                .withImportOption(ImportOption.Predefined.DO_NOT_INCLUDE_TESTS)
                .importPath(classesDir);
        System.out.println("ArchUnit: imported " + classes.size() + " classes from " + classesDir);
        System.out.println("Rule set: \"the application must not depend on the JDBC/persistence stack"
                + " directly\", expressed as an import/package-dependency gate.\n");

        // The web layer (controllers) must not reach the database driver directly.
        ArchRule webNoSql = noClasses()
                .that().haveSimpleNameEndingWith("Controller")
                .should().dependOnClassesThat().resideInAnyPackage("java.sql..", "javax.sql..")
                .as("controllers must not depend on java.sql / javax.sql");

        // No application class may name the JDBC driver packages directly.
        ArchRule appNoSql = noClasses()
                .that().resideInAPackage("org.springframework.samples.petclinic..")
                .should().dependOnClassesThat().resideInAnyPackage("java.sql..", "javax.sql..")
                .as("no petclinic class may depend on java.sql / javax.sql");

        boolean allGreen = true;
        allGreen &= report(webNoSql, classes);
        allGreen &= report(appNoSql, classes);

        System.out.println();
        if (allGreen) {
            System.out.println("ArchUnit VERDICT: GREEN — the import graph shows the app as"
                    + " JDBC/persistence-free. (Data access is behind Spring Data repository interfaces.)");
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
