package info.gdsnyder.nfs;

import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;
import java.io.*;
import java.util.Arrays;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import org.dcache.oncrpc4j.xdr.ByteArrayXdr;
import org.dcache.nfs.v4.xdr.*;

class ProtocolTest {
    @Test void generatedCompoundMatchesKnownWireLayout() throws Exception {
        byte[] wire=NfsCompounds.encode(NfsCompounds.rootAttributes());
        ByteArrayXdr x=new ByteArrayXdr(wire);
        assertEquals("root-probe",x.xdrDecodeString());assertEquals(0,x.xdrDecodeInt());
        assertEquals(2,x.xdrDecodeInt());assertEquals(24,x.xdrDecodeInt());assertEquals(9,x.xdrDecodeInt());
        assertEquals(1,x.xdrDecodeInt());assertEquals(18,x.xdrDecodeInt());x.requireEnd();
        COMPOUND4args decoded=new COMPOUND4args(new ByteArrayXdr(wire));assertEquals(2,decoded.argarray.length);
    }
    @Test void opaquePaddingAndUnicodeRoundtrip() throws Exception {
        ByteArrayXdr x=new ByteArrayXdr();x.xdrEncodeDynamicOpaque(new byte[]{1,2,3});x.xdrEncodeString("café");
        ByteArrayXdr d=new ByteArrayXdr(x.bytes());assertArrayEquals(new byte[]{1,2,3},d.xdrDecodeDynamicOpaque());
        assertEquals("café",d.xdrDecodeString());d.requireEnd();
    }
    @Test void malformedLengthsRejected() {
        ByteArrayXdr x=new ByteArrayXdr();x.xdrEncodeInt(Integer.MAX_VALUE);
        assertThrows(IOException.class,()->new ByteArrayXdr(x.bytes()).xdrDecodeDynamicOpaque());
        ByteArrayXdr n=new ByteArrayXdr();n.xdrEncodeInt(-1);
        assertThrows(IOException.class,()->new ByteArrayXdr(n.bytes()).xdrDecodeIntVector());
    }
    @Test void generatedArrayLengthBounded() {
        ByteArrayXdr x=new ByteArrayXdr();x.xdrEncodeString("");x.xdrEncodeInt(0);x.xdrEncodeInt(Integer.MAX_VALUE);
        assertThrows(IOException.class,()->new COMPOUND4args(new ByteArrayXdr(x.bytes())));
    }
    @Test void fragmentsReassembled() throws Exception {
        ByteArrayOutputStream out=new ByteArrayOutputStream();DataOutputStream d=new DataOutputStream(out);
        d.writeInt(2);d.write(new byte[]{1,2});d.writeInt(0x80000001);d.write(3);
        assertArrayEquals(new byte[]{1,2,3},RpcTcp.readRecord(new DataInputStream(new ByteArrayInputStream(out.toByteArray()))));
    }
    @Test void oversizedRecordRejectedBeforeAllocation() throws Exception {
        byte[] b={(byte)0xff,(byte)0xff,(byte)0xff,(byte)0xff};
        assertThrows(IOException.class,()->RpcTcp.readRecord(new DataInputStream(new ByteArrayInputStream(b))));
    }
    @Test void initRequestUsesNullProcedureAndNullVerifier() throws Exception {
        ByteArrayXdr x=new ByteArrayXdr(RpcSecGss.initCall(3,100003,4,new byte[0],new byte[]{7},false));
        assertEquals(3,x.xdrDecodeInt());assertEquals(0,x.xdrDecodeInt());assertEquals(2,x.xdrDecodeInt());
        assertEquals(100003,x.xdrDecodeInt());assertEquals(4,x.xdrDecodeInt());assertEquals(0,x.xdrDecodeInt());
        assertEquals(6,x.xdrDecodeInt());ByteArrayXdr cred=new ByteArrayXdr(x.xdrDecodeDynamicOpaque());
        assertEquals(1,cred.xdrDecodeInt());assertEquals(1,cred.xdrDecodeInt());assertEquals(0,cred.xdrDecodeInt());
        assertEquals(1,cred.xdrDecodeInt());assertEquals(0,cred.xdrDecodeDynamicOpaque().length);cred.requireEnd();
        assertEquals(0,x.xdrDecodeInt());assertEquals(0,x.xdrDecodeDynamicOpaque().length);
        assertArrayEquals(new byte[]{7},x.xdrDecodeDynamicOpaque());x.requireEnd();
    }
    @Test void integrityRequestSignsExactRpcHeaderAndPayload() throws Exception {
        TestGss g=new TestGss();RpcSecGss codec=new RpcSecGss(g,new byte[]{8},RpcSecGss.Service.INTEGRITY);
        RpcSecGss.Request req=codec.request(19,100003,4,1,new byte[]{0,0,0,7});ByteArrayXdr x=new ByteArrayXdr(req.wire);
        for(int i=0;i<6;i++)x.xdrDecodeInt();assertEquals(6,x.xdrDecodeInt());x.xdrDecodeDynamicOpaque();
        int headerLength=req.wire.length-x.remaining();assertEquals(6,x.xdrDecodeInt());
        g.verifyMic(Arrays.copyOf(req.wire,headerLength),x.xdrDecodeDynamicOpaque());
        byte[] protectedData=x.xdrDecodeDynamicOpaque();g.verifyMic(protectedData,x.xdrDecodeDynamicOpaque());
        ByteArrayXdr p=new ByteArrayXdr(protectedData);assertEquals(1,p.xdrDecodeInt());assertEquals(7,p.xdrDecodeInt());p.requireEnd();x.requireEnd();
        assertEquals(2,codec.request(20,100003,4,1,new byte[0]).sequence);
    }
    @Test void integrityReplyValidatedAndTamperingRejected() throws Exception {
        TestGss g=new TestGss();RpcSecGss codec=new RpcSecGss(g,new byte[]{8},RpcSecGss.Service.INTEGRITY);
        RpcSecGss.Request req=codec.request(19,100003,4,1,new byte[0]);byte[] reply=reply(g,19,req.sequence,req.sequence);
        assertArrayEquals(new byte[]{0,0,0,7},codec.reply(req,reply));
        reply[reply.length-1]^=1;assertThrows(IOException.class,()->codec.reply(req,reply));
    }
    @Test void replySequenceAndTransactionMismatchRejected() throws Exception {
        TestGss g=new TestGss();RpcSecGss codec=new RpcSecGss(g,new byte[]{8},RpcSecGss.Service.INTEGRITY);
        RpcSecGss.Request req=codec.request(19,100003,4,1,new byte[0]);
        assertThrows(IOException.class,()->codec.reply(req,reply(g,20,req.sequence,req.sequence)));
        assertThrows(IOException.class,()->codec.reply(req,reply(g,19,req.sequence,99)));
    }
    private byte[] reply(TestGss g,int xid,int seq,int payloadSeq) throws Exception {
        ByteArrayXdr x=new ByteArrayXdr();x.xdrEncodeInt(xid);x.xdrEncodeInt(1);x.xdrEncodeInt(0);x.xdrEncodeInt(6);
        ByteArrayXdr verifier=new ByteArrayXdr();verifier.xdrEncodeInt(seq);x.xdrEncodeDynamicOpaque(g.mic(verifier.bytes()));x.xdrEncodeInt(0);
        ByteArrayXdr body=new ByteArrayXdr();body.xdrEncodeInt(payloadSeq);body.xdrEncodeInt(7);
        x.xdrEncodeDynamicOpaque(body.bytes());x.xdrEncodeDynamicOpaque(g.mic(body.bytes()));return x.bytes();
    }
    /** Test double ONLY: exercises framing, never used as a Kerberos mechanism. */
    static class TestGss implements GssContext {
        public byte[] step(byte[] token){return new byte[0];}public boolean established(){return true;}
        public byte[] mic(byte[] bytes) throws IOException {
            try{Mac mac=Mac.getInstance("HmacSHA256");mac.init(new SecretKeySpec(new byte[32],"HmacSHA256"));return mac.doFinal(bytes);}
            catch(Exception e){throw new IOException(e);}
        }
        public void verifyMic(byte[] bytes,byte[] token) throws IOException {
            if(!java.security.MessageDigest.isEqual(mic(bytes),token))throw new IOException("Invalid MIC");
        }
        public byte[] wrap(byte[] data) throws IOException{throw new IOException("Test double has no privacy");}
        public byte[] unwrap(byte[] data) throws IOException{throw new IOException("Test double has no privacy");}
        public void close(){}
    }
}
