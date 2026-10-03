package info.gdsnyder.nfs;

import java.io.*;
import java.nio.*;
import java.security.*;
import java.util.*;
import org.apache.kerby.kerberos.kerb.KrbException;
import org.apache.kerby.kerberos.kerb.common.EncryptionUtil;
import org.apache.kerby.kerberos.kerb.crypto.*;
import org.apache.kerby.kerberos.kerb.type.KerberosTime;
import org.apache.kerby.kerberos.kerb.type.ap.*;
import org.apache.kerby.kerberos.kerb.type.base.*;
import org.apache.kerby.kerberos.kerb.type.ticket.SgtTicket;

/** RFC 4121 initiator, AES128/AES256 CTS-HMAC-SHA1-96. No desktop GSS APIs. */
public final class KerberosGss implements GssContext {
    private static final byte[] OID={6,9,42,(byte)134,72,(byte)134,(byte)247,18,1,2,2};
    private final SgtTicket ticket;
    private final String principal;
    private EncryptionKey session, key;
    private Authenticator authenticator;
    private boolean started, ready, closed, acceptorSubkey;
    private long sendSeq, receiveSeq;
    private long expiry;
    public KerberosGss(SgtTicket ticket,String principal) throws IOException {
        this.ticket=ticket;this.principal=principal;
        this.session=copy(ticket.getSessionKey());this.key=copy(session);checkType(key);
        expiry=ticket.getEncKdcRepPart().getEndTime().getTime();
    }
    private static EncryptionKey copy(EncryptionKey k){return new EncryptionKey(k.getKeyType(),k.getKeyData().clone());}
    private static void checkType(EncryptionKey k) throws IOException {
        if(k.getKeyType()!=EncryptionType.AES128_CTS_HMAC_SHA1_96 && k.getKeyType()!=EncryptionType.AES256_CTS_HMAC_SHA1_96)
            throw new IOException("Unsupported Kerberos enctype: "+k.getKeyType()+"; use AES128/AES256 CTS-HMAC-SHA1-96");
    }
    public synchronized byte[] step(byte[] peer) throws IOException {
        if(closed)throw new IOException("GSS context closed");
        try {
            if(!started) {
                if(peer.length!=0)throw new IOException("Unexpected initial GSS token");
                if(System.currentTimeMillis()>=expiry)throw new IOException("Service ticket expired; sign in again");
                int at=principal.lastIndexOf('@');if(at<=0)throw new IOException("User principal must include @REALM");
                authenticator=new Authenticator();authenticator.setAuthenticatorVno(5);
                authenticator.setCname(new PrincipalName(principal));authenticator.setCrealm(principal.substring(at+1));
                long now=System.currentTimeMillis();authenticator.setCtime(new KerberosTime(now-now%1000));
                authenticator.setCusec((int)(now%1000)*1000);
                // Mutual authentication, replay detection, sequencing, confidentiality and integrity. No delegation/bindings.
                byte[] checksum=ByteBuffer.allocate(24).order(ByteOrder.LITTLE_ENDIAN).putInt(16).put(new byte[16]).putInt(62).array();
                authenticator.setCksum(new GssChecksum(checksum));
                sendSeq=new SecureRandom().nextInt()&0xffffffffL;authenticator.setSeqNumber((int)sendSeq);
                // Deliberately omit initiator subkey. AP-REP is encrypted with the service session key.
                ApReq req=new ApReq();ApOptions options=new ApOptions();options.setFlag(ApOption.MUTUAL_REQUIRED);req.setApOptions(options);
                req.setTicket(ticket.getTicket());req.setEncryptedAuthenticator(EncryptionUtil.seal(authenticator,session,KeyUsage.AP_REQ_AUTH));
                byte[] encoded=req.encode();started=true;return initialToken(1,encoded);
            }
            if(ready)throw new IOException("GSS context already established");
            byte[] token=stripInitial(peer);
            if(token.length<2 || token[1]!=0)throw new IOException("Invalid Kerberos response token");
            if(token[0]==3)throw new IOException("NFS server returned a Kerberos error during GSS authentication");
            if(token[0]!=2)throw new IOException("Expected Kerberos AP-REP");
            ApRep rep=new ApRep();rep.decode(Arrays.copyOfRange(token,2,token.length));
            EncAPRepPart part=EncryptionUtil.unseal(rep.getEncryptedEncPart(),session,KeyUsage.AP_REP_ENCPART,EncAPRepPart.class);
            if(!part.getCtime().equals(authenticator.getCtime()) || part.getCusec()!=authenticator.getCusec())
                throw new IOException("Kerberos AP-REP timestamp mismatch");
            if(part.getSubkey()!=null){Arrays.fill(key.getKeyData(),(byte)0);key=copy(part.getSubkey());checkType(key);acceptorSubkey=true;}
            int seq=part.getSeqNumber();receiveSeq=seq==-1?0:(seq&0xffffffffL);
            ready=true;return new byte[0];
        } catch(KrbException e){throw new IOException("Kerberos GSS handshake failed",e);}
    }
    private static final class GssChecksum extends CheckSum {
        GssChecksum(byte[] bytes){setFieldAsInt(CheckSumField.CKSUM_TYPE,0x8003);setChecksum(bytes);}
    }
    static byte[] initialToken(int type,byte[] encoded) throws IOException {
        ByteArrayOutputStream b=new ByteArrayOutputStream();b.write(OID);b.write(type);b.write(0);b.write(encoded);
        byte[] body=b.toByteArray();b.reset();b.write(0x60);derLength(b,body.length);b.write(body);return b.toByteArray();
    }
    private static void derLength(ByteArrayOutputStream b,int n){if(n<128)b.write(n);else{int width=0;for(int v=n;v!=0;v>>>=8)width++;b.write(0x80|width);for(int i=width-1;i>=0;i--)b.write(n>>>(i*8));}}
    static byte[] stripInitial(byte[] token) throws IOException {
        // Both complete generic GSS framing and mechanism-only AP-REP tokens are accepted.
        if(token.length==0)throw new IOException("Missing AP-REP token");
        if(token[0]!=0x60)return token;
        int i=1;if(i>=token.length)throw new IOException("Truncated GSS envelope");int n=token[i++]&255;
        if((n&128)!=0){int width=n&127;if(width<1||width>4||i+width>token.length)throw new IOException("Invalid GSS DER length");
            n=0;for(int j=0;j<width;j++)n=(n<<8)|(token[i++]&255);}
        if(n!=token.length-i || n<OID.length+2)throw new IOException("Invalid GSS envelope length");
        for(byte v:OID)if(token[i++]!=v)throw new IOException("Unexpected GSS mechanism OID");
        return Arrays.copyOfRange(token,i,token.length);
    }
    public synchronized boolean established(){return ready&&!closed;}
    synchronized void checkActive() throws IOException {active();}
    private void active() throws IOException {if(!established())throw new IOException("GSS context not established");if(System.currentTimeMillis()>=expiry)throw new IOException("Kerberos service ticket expired; sign in again");}
    private byte[] header(boolean wrap){
        byte[] h=new byte[16];h[0]=(byte)(wrap?5:4);h[1]=4;h[2]=(byte)((acceptorSubkey?4:0)|(wrap?2:0));h[3]=(byte)255;
        if(!wrap)Arrays.fill(h,4,8,(byte)255);ByteBuffer.wrap(h).putLong(8,sendSeq++);return h;
    }
    private byte[] checksum(byte[] data,byte[] h,int usage) throws IOException {
        try {CheckSumType type=key.getKeyType()==EncryptionType.AES128_CTS_HMAC_SHA1_96?CheckSumType.HMAC_SHA1_96_AES128:CheckSumType.HMAC_SHA1_96_AES256;
            return CheckSumHandler.getCheckSumHandler(type).checksumWithKey(concat(data,h),key.getKeyData(),usage);
        }catch(KrbException e){throw new IOException("GSS MIC calculation failed",e);}
    }
    public synchronized byte[] mic(byte[] message) throws IOException {active();byte[] h=header(false);return concat(h,checksum(message,h,25));}
    private byte[] peerHeader(byte[] token,boolean wrap) throws IOException {
        active();if(token.length<16 || token[0]!=(wrap?5:4)||token[1]!=4 || token[3]!=(byte)255)throw new IOException("Invalid GSS token header");
        if((token[2]&1)!=1 || ((token[2]&4)!=0)!=acceptorSubkey)throw new IOException("GSS direction/subkey mismatch");
        if(((token[2]&2)!=0)!=wrap)throw new IOException("GSS confidentiality flag mismatch");
        if(!wrap)for(int i=4;i<8;i++)if(token[i]!=(byte)255)throw new IOException("Invalid MIC filler");
        return Arrays.copyOf(token,16);
    }
    private void acceptSequence(byte[] h) throws IOException {
        long seq=ByteBuffer.wrap(h).getLong(8);
        if(Long.compareUnsigned(seq,receiveSeq)<0)throw new IOException("Replayed or out-of-order GSS token");
        if(seq==-1L)throw new IOException("GSS sequence exhausted");receiveSeq=seq+1;
    }
    public synchronized void verifyMic(byte[] message,byte[] token) throws IOException {
        byte[] h=peerHeader(token,false);if(token.length!=28 || !MessageDigest.isEqual(checksum(message,h,23),Arrays.copyOfRange(token,16,token.length)))
            throw new IOException("Invalid GSS MIC");acceptSequence(h);
    }
    public synchronized byte[] wrap(byte[] plaintext) throws IOException {
        active();byte[] h=header(true);
        try{return concat(h,EncryptionHandler.getEncHandler(key.getKeyType()).encrypt(concat(plaintext,h),key.getKeyData(),24));}
        catch(KrbException e){throw new IOException("GSS encryption failed",e);}
    }
    public synchronized byte[] unwrap(byte[] token) throws IOException {
        byte[] h=peerHeader(token,true);int ec=u16(h,4),rrc=u16(h,6);
        byte[] body=Arrays.copyOfRange(token,16,token.length);if(body.length<44)throw new IOException("Truncated encrypted GSS token");
        int rotate=rrc%body.length;byte[] rotated=new byte[body.length];
        System.arraycopy(body,rotate,rotated,0,body.length-rotate);System.arraycopy(body,0,rotated,body.length-rotate,rotate);
        try {
            byte[] plain=EncryptionHandler.getEncHandler(key.getKeyType()).decrypt(rotated,key.getKeyData(),22);
            if(plain.length<16+ec)throw new IOException("Invalid GSS filler length");h[6]=h[7]=0;
            if(!MessageDigest.isEqual(h,Arrays.copyOfRange(plain,plain.length-16,plain.length)))throw new IOException("GSS encrypted header mismatch");
            acceptSequence(h);return Arrays.copyOf(plain,plain.length-16-ec);
        }catch(KrbException e){throw new IOException("GSS decryption/integrity check failed",e);}
    }
    private static int u16(byte[] b,int i){return ((b[i]&255)<<8)|(b[i+1]&255);}
    static byte[] concat(byte[] a,byte[] b){byte[] result=Arrays.copyOf(a,a.length+b.length);System.arraycopy(b,0,result,a.length,b.length);return result;}
    public synchronized void close(){closed=true;ready=false;if(key!=null)Arrays.fill(key.getKeyData(),(byte)0);if(session!=null)Arrays.fill(session.getKeyData(),(byte)0);authenticator=null;}
}
