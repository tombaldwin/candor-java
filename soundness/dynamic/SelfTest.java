import java.io.*; import java.net.*;
public class SelfTest {
  public static void main(String[] a) throws Exception { doFile(); doNet(); }
  static void doFile() throws Exception { writeFile(); }                       // Fs: doFile -> writeFile -> FileOutputStream.write
  static void writeFile() throws Exception {
    try (FileOutputStream f = new FileOutputStream("/tmp/dyn/out.txt")) { f.write("hi".getBytes()); }
  }
  static void doNet() throws Exception {                                       // Net: doNet -> netWrite -> Socket write
    ServerSocket ss = new ServerSocket(0);
    int port = ss.getLocalPort();
    Thread t = new Thread(() -> { try { Socket s = ss.accept(); s.getInputStream().read(); s.close(); } catch (Exception e) {} });
    t.start();
    netWrite(port);
    t.join(); ss.close();
  }
  static void netWrite(int port) throws Exception {
    try (Socket s = new Socket("127.0.0.1", port)) { s.getOutputStream().write("x".getBytes()); }
  }
}
