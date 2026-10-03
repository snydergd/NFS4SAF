package info.gdsnyder.nfs;

import java.io.IOException;
import org.dcache.oncrpc4j.xdr.ByteArrayXdr;

/** RFC 2203 message codec. GSS context establishment/crypto implementation remains separate. */
public final class RpcSecGss {
    public static final int FLAVOR = 6, DATA = 0, INIT = 1, CONTINUE_INIT = 2;
    public enum Service {
        AUTH(1), INTEGRITY(2), PRIVACY(3);
        final int wire; Service(int wire) { this.wire=wire; }
    }
    public static final class Request {
        public final int xid, sequence;
        public final byte[] wire;
        private Request(int xid,int sequence,byte[] wire) {this.xid=xid;this.sequence=sequence;this.wire=wire;}
    }
    public static final class InitReply {
        public final byte[] handle, token, verifier;
        public final int major, minor, window, verifierFlavor;
        private InitReply(byte[] handle,int major,int minor,int window,byte[] token,int vf,byte[] verifier) {
            this.handle=handle;this.major=major;this.minor=minor;this.window=window;this.token=token;
            this.verifierFlavor=vf;this.verifier=verifier;
        }
        /** Call only after the returned GSS token has been processed by the mechanism. */
        public void verifyComplete(GssContext gss) throws IOException {
            if(major != 0 || !gss.established() || verifierFlavor != FLAVOR || window <= 0)
                throw new IOException("RPCSEC_GSS context not complete");
            gss.verifyMic(u32(window),verifier);
        }
    }
    private final GssContext gss;
    private final byte[] handle;
    private final Service service;
    private int nextSequence=1;
    public RpcSecGss(GssContext gss, byte[] handle, Service service) {
        if(!gss.established() || handle.length==0 || handle.length>380)throw new IllegalArgumentException("Invalid GSS context");
        this.gss=gss;this.handle=handle.clone();this.service=service;
    }
    private static ByteArrayXdr header(int xid,int program,int version,int procedure,
                                       int control,int sequence,Service service,byte[] handle) {
        ByteArrayXdr x=new ByteArrayXdr();
        x.xdrEncodeInt(xid);x.xdrEncodeInt(0);x.xdrEncodeInt(2);
        x.xdrEncodeInt(program);x.xdrEncodeInt(version);x.xdrEncodeInt(procedure);
        ByteArrayXdr cred=new ByteArrayXdr();
        cred.xdrEncodeInt(1);cred.xdrEncodeInt(control);cred.xdrEncodeInt(sequence);
        cred.xdrEncodeInt(service.wire);cred.xdrEncodeDynamicOpaque(handle);
        x.xdrEncodeInt(FLAVOR);x.xdrEncodeDynamicOpaque(cred.bytes());return x;
    }
    public static byte[] initCall(int xid,int program,int version,byte[] handle,byte[] token,boolean continuation) {
        ByteArrayXdr x=header(xid,program,version,0,continuation?CONTINUE_INIT:INIT,0,Service.AUTH,handle);
        x.xdrEncodeInt(0);x.xdrEncodeDynamicOpaque(new byte[0]);x.xdrEncodeDynamicOpaque(token);return x.bytes();
    }
    public static InitReply initReply(int xid,byte[] reply) throws IOException {
        ByteArrayXdr x=new ByteArrayXdr(reply);checkReply(x,xid);
        int flavor=x.xdrDecodeInt();byte[] verifier=authBody(x);checkAccepted(x);
        byte[] handle=x.xdrDecodeDynamicOpaque();int major=x.xdrDecodeInt(),minor=x.xdrDecodeInt(),window=x.xdrDecodeInt();
        byte[] token=x.xdrDecodeDynamicOpaque();x.requireEnd();
        if(major!=0 && major!=1)throw new IOException("GSS setup failed: major="+major+", minor="+minor);
        if(handle.length==0 || handle.length>380)throw new IOException("Invalid GSS handle");
        if(major==1 && (flavor!=0 || verifier.length!=0))throw new IOException("Invalid continuation verifier");
        return new InitReply(handle,major,minor,window,token,flavor,verifier);
    }
    public synchronized Request request(int xid,int program,int version,int procedure,byte[] args) throws IOException {
        if(nextSequence<=0)throw new IOException("RPCSEC_GSS sequence exhausted; reestablish context");
        int seq=nextSequence++;
        ByteArrayXdr x=header(xid,program,version,procedure,DATA,seq,service,handle);
        byte[] mic=gss.mic(x.bytes());if(mic.length>400)throw new IOException("Verifier too large");
        x.xdrEncodeInt(FLAVOR);x.xdrEncodeDynamicOpaque(mic);
        byte[] payload;
        if(service==Service.AUTH) payload=args;
        else {
            ByteArrayXdr plain=new ByteArrayXdr();plain.xdrEncodeInt(seq);plain.xdrEncodeOpaque(args,args.length);
            ByteArrayXdr protectedBody=new ByteArrayXdr();
            if(service==Service.INTEGRITY) {
                protectedBody.xdrEncodeDynamicOpaque(plain.bytes());
                protectedBody.xdrEncodeDynamicOpaque(gss.mic(plain.bytes()));
            } else protectedBody.xdrEncodeDynamicOpaque(gss.wrap(plain.bytes()));
            payload=protectedBody.bytes();
        }
        x.xdrEncodeOpaque(payload,payload.length);return new Request(xid,seq,x.bytes());
    }
    public byte[] reply(Request request,byte[] reply) throws IOException {
        ByteArrayXdr x=new ByteArrayXdr(reply);checkReply(x,request.xid);
        if(x.xdrDecodeInt()!=FLAVOR)throw new IOException("Missing GSS reply verifier");
        byte[] verifier=authBody(x);gss.verifyMic(u32(request.sequence),verifier);checkAccepted(x);
        if(service==Service.AUTH)return x.xdrDecodeOpaque(x.remaining());
        byte[] plain;
        if(service==Service.INTEGRITY) {
            plain=x.xdrDecodeDynamicOpaque();gss.verifyMic(plain,x.xdrDecodeDynamicOpaque());
        } else plain=gss.unwrap(x.xdrDecodeDynamicOpaque());
        x.requireEnd();ByteArrayXdr p=new ByteArrayXdr(plain);
        if(p.xdrDecodeInt()!=request.sequence)throw new IOException("Reply sequence mismatch");
        return p.xdrDecodeOpaque(p.remaining());
    }
    private static byte[] authBody(ByteArrayXdr x) throws IOException {
        byte[] b=x.xdrDecodeDynamicOpaque();if(b.length>400)throw new IOException("RPC verifier too large");return b;
    }
    private static void checkReply(ByteArrayXdr x,int xid) throws IOException {
        if(x.xdrDecodeInt()!=xid || x.xdrDecodeInt()!=1)throw new IOException("RPC transaction mismatch");
        if(x.xdrDecodeInt()!=0)throw new IOException("RPC request denied");
    }
    private static void checkAccepted(ByteArrayXdr x) throws IOException {
        int status=x.xdrDecodeInt();if(status!=0)throw new IOException("RPC accept status "+status);
    }
    private static byte[] u32(int n) {ByteArrayXdr x=new ByteArrayXdr();x.xdrEncodeInt(n);return x.bytes();}
}
