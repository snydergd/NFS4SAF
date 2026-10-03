package info.gdsnyder.nfs;

import java.io.IOException;

/** Wire-oriented GSS boundary; no org.ietf.jgss or sun.* dependency. */
public interface GssContext extends AutoCloseable {
    byte[] step(byte[] peerToken) throws IOException;
    boolean established();
    byte[] mic(byte[] message) throws IOException;
    void verifyMic(byte[] message, byte[] token) throws IOException;
    byte[] wrap(byte[] plaintext) throws IOException;
    /** Must reject unsealed tokens when privacy was requested. */
    byte[] unwrap(byte[] token) throws IOException;
    void close();
}
