package corpus;

import java.io.*;

/**
 * Corpus entry (jfr_diff: Fs) — the known ABSTRACTION-BOUNDARY κ-gap, in miniature.
 *
 * A project class (Parser) holds a field of the ABSTRACT JDK supertype java.io.Reader and reads from it
 * inside a parser-like method. The concrete reader is file-backed (FileReader -> file I/O), but it is
 * created elsewhere and assigned through the abstract Reader type, so a static analysis that cannot pin
 * the concrete impl behind the abstract `Reader` field reports the parse method PURE — while at runtime
 * the read genuinely hits the file. This is the same class of gap candor's README "First real finding"
 * documents for jsoup's streaming parser (CharacterReader.bufferUp -> abstract Reader.read()).
 *
 *   Fs (real): main -> Parser.parse -> reader.read()  [abstract java.io.Reader field; concrete FileReader]
 *
 * If jfr_diff flags Parser.parse as an under-report, that is the EXPECTED, KNOWN/ACCEPTED gap — it
 * demonstrates the harness correctly surfaces the abstract-supertype boundary case. If candor fail-closes
 * to Unknown on abstract Reader.read(), it is CLEAN (Unknown is a pass).
 */
public class AbstractReaderParse {

    /** Parser-like class holding the effect leaf behind an ABSTRACT Reader field. */
    static final class Parser {
        private final Reader reader;            // abstract java.io.Reader — concrete type hidden here
        Parser(Reader reader) { this.reader = reader; }

        /** Reads the whole stream through the abstract field — the file read happens HERE at runtime. */
        String parse() throws IOException {
            StringBuilder sb = new StringBuilder();
            int c;
            while ((c = reader.read()) != -1) sb.append((char) c);   // abstract Reader.read() -> file I/O
            return sb.toString();
        }
    }

    public static void main(String[] args) throws Exception {
        File dir = new File("/tmp/dyn-corpus");
        dir.mkdirs();
        File data = new File(dir, "abstract-reader.txt");
        try (FileWriter w = new FileWriter(data)) { w.write("abstract-reader-payload"); }

        // Concrete file-backed reader assigned through the abstract Reader type.
        Reader r = new BufferedReader(new FileReader(data));         // concrete FileReader behind abstract Reader
        try (Reader auto = r) {
            String out = new Parser(r).parse();                     // parse() reads the file via the field
            System.out.println("AbstractReaderParse: parsed " + out.length() + " chars");
        }
    }
}
