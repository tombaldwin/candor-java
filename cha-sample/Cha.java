import java.nio.file.Files;
import java.nio.file.Path;

interface Greeter { String greet(); }

class FileGreeter implements Greeter {
    public String greet() {
        try { return Files.readString(Path.of("/etc/hostname")); } catch (Exception e) { return ""; }
    }
}
class PlainGreeter implements Greeter {
    public String greet() { return "hi"; }
}

interface Strategy { void run(); }

public class Cha {
    static String useGreeter(Greeter g) { return g.greet(); }
    static void useStrategy(Strategy s) { s.run(); }
    public static void main(String[] a) {}
}
