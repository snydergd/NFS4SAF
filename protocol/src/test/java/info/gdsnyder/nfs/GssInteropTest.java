package info.gdsnyder.nfs;

import java.net.ServerSocket;
import java.nio.file.Path;
import java.security.PrivilegedExceptionAction;
import java.util.*;
import javax.security.auth.Subject;
import javax.security.auth.login.*;
import org.ietf.jgss.*;
import org.apache.kerby.kerberos.kerb.server.SimpleKdcServer;
import org.apache.kerby.kerberos.kerb.type.ticket.SgtTicket;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.io.TempDir;
import static org.junit.jupiter.api.Assertions.*;

/** Independent JDK Kerberos acceptor verifies our Android-safe wire implementation. */
class GssInteropTest {
    @TempDir Path directory;
    SgtTicket ticket;SimpleKdcServer kdc;LoginContext login;Subject subject;KerberosGss client;org.ietf.jgss.GSSContext server;
    @BeforeEach void setUp() throws Exception {
        int port;try(ServerSocket s=new ServerSocket(0)){port=s.getLocalPort();}
        kdc=new SimpleKdcServer();kdc.setWorkDir(directory.toFile());kdc.setKdcRealm("TEST.EXAMPLE");
        kdc.setKdcHost("127.0.0.1");kdc.setAllowUdp(false);kdc.setKdcTcpPort(port);kdc.init();
        kdc.createPrincipal("user@TEST.EXAMPLE","password");kdc.createPrincipal("nfs/files.test@TEST.EXAMPLE");
        Path keytab=directory.resolve("service.keytab");kdc.exportPrincipal("nfs/files.test@TEST.EXAMPLE",keytab.toFile());kdc.start();
        ticket=KerbyTickets.acquire("TEST.EXAMPLE","127.0.0.1",port,"user@TEST.EXAMPLE","nfs/files.test@TEST.EXAMPLE","password".toCharArray());
        client=new KerberosGss(ticket,"user@TEST.EXAMPLE");
        Map<String,Object> options=new HashMap<>();options.put("useKeyTab","true");options.put("keyTab",keytab.toString());
        options.put("principal","nfs/files.test@TEST.EXAMPLE");options.put("storeKey","true");options.put("doNotPrompt","true");options.put("isInitiator","false");
        login=new LoginContext("service",null,null,new Configuration(){public AppConfigurationEntry[] getAppConfigurationEntry(String name){
            return new AppConfigurationEntry[]{new AppConfigurationEntry("com.sun.security.auth.module.Krb5LoginModule",AppConfigurationEntry.LoginModuleControlFlag.REQUIRED,options)};}});
        login.login();subject=login.getSubject();
        server=Subject.doAs(subject,(PrivilegedExceptionAction<org.ietf.jgss.GSSContext>)()->GSSManager.getInstance().createContext((GSSCredential)null));
    }
    @AfterEach void cleanUp() throws Exception {if(client!=null)client.close();if(server!=null)server.dispose();if(login!=null)login.logout();if(kdc!=null)kdc.stop();}
    void establish() throws Exception {
        byte[] initial=client.step(new byte[0]);
        byte[] reply=Subject.doAs(subject,(PrivilegedExceptionAction<byte[]>)()->server.acceptSecContext(initial,0,initial.length));
        assertTrue(server.isEstablished());assertEquals(0,client.step(reply).length);assertTrue(client.established());
    }
    @Test void mutualAuthenticationAndBidirectionalMic() throws Exception {
        establish();byte[] message="signed NFS payload".getBytes("UTF-8");byte[] mic=client.mic(message);
        server.verifyMIC(mic,0,mic.length,message,0,message.length,new MessageProp(0,false));
        byte[] replyMic=server.getMIC(message,0,message.length,new MessageProp(0,false));client.verifyMic(message,replyMic);
        if(Boolean.getBoolean("sun.security.krb5.acceptor.subkey"))assertEquals(4,replyMic[2]&4,"Acceptor subkey branch must be exercised");
        assertThrows(java.io.IOException.class,()->client.verifyMic(message,replyMic)); // replay
    }
    @Test void privacyBidirectionalAndHeaderTampering() throws Exception {
        establish();byte[] message="secret export contents".getBytes("UTF-8");byte[] wrapped=client.wrap(message);
        MessageProp prop=new MessageProp(0,false);assertArrayEquals(message,server.unwrap(wrapped,0,wrapped.length,prop));assertTrue(prop.getPrivacy());
        byte[] response=server.wrap(message,0,message.length,new MessageProp(0,true));
        byte[] tampered=response.clone();tampered[8]^=1;assertThrows(java.io.IOException.class,()->client.unwrap(tampered));
        assertArrayEquals(message,client.unwrap(response));
        assertThrows(java.io.IOException.class,()->client.unwrap(response));
    }
    @Test void alteredCiphertextAndUnsealedResponseRejected() throws Exception {
        establish();byte[] message={1,2,3,4};byte[] response=server.wrap(message,0,message.length,new MessageProp(0,true));
        byte[] tampered=response.clone();tampered[tampered.length-1]^=1;assertThrows(java.io.IOException.class,()->client.unwrap(tampered));
        byte[] unsealed=server.wrap(message,0,message.length,new MessageProp(0,false));assertThrows(java.io.IOException.class,()->client.unwrap(unsealed));
    }
    @Test void rotatedWrapTokenAccepted() throws Exception {
        establish();byte[] data=new byte[101];new Random(123).nextBytes(data);
        byte[] token=server.wrap(data,0,data.length,new MessageProp(0,true));
        // Change the RRC while preserving the underlying ciphertext's byte ordering.
        int old=((token[6]&255)<<8)|(token[7]&255),n=token.length-16,newRrc=65535;
        byte[] original=Arrays.copyOfRange(token,16,token.length),rotated=new byte[n];
        for(int i=0;i<n;i++)rotated[(i+newRrc)%n]=original[(i+old)%n];
        System.arraycopy(rotated,0,token,16,n);token[6]=(byte)(newRrc>>>8);token[7]=(byte)newRrc;
        assertArrayEquals(data,client.unwrap(token));
    }
    @Test void wrongDirectionAndInvalidMicRejected() throws Exception {
        establish();byte[] data={0,0,0,1};byte[] own=client.mic(data);assertThrows(java.io.IOException.class,()->client.verifyMic(data,own));
        byte[] mic=server.getMIC(data,0,data.length,new MessageProp(0,false));mic[mic.length-1]^=1;
        assertThrows(java.io.IOException.class,()->client.verifyMic(data,mic));
    }
    @Test void expiredServiceTicketRejected() throws Exception {
        ticket.getEncKdcRepPart().setEndTime(new org.apache.kerby.kerberos.kerb.type.KerberosTime(System.currentTimeMillis()-1000));
        try(KerberosGss expired=new KerberosGss(ticket,"user@TEST.EXAMPLE")){
            assertThrows(java.io.IOException.class,()->expired.step(new byte[0]));
        }
    }
    @Test void invalidApRepRejected() throws Exception {
        byte[] initial=client.step(new byte[0]);byte[] reply=Subject.doAs(subject,(PrivilegedExceptionAction<byte[]>)()->server.acceptSecContext(initial,0,initial.length));
        reply[reply.length-1]^=1;assertThrows(java.io.IOException.class,()->client.step(reply));assertFalse(client.established());
    }
}
