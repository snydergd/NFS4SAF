package info.gdsnyder.nfs;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import static org.junit.jupiter.api.Assertions.*;
import java.nio.file.Path;
import java.net.ServerSocket;
import org.apache.kerby.kerberos.kerb.server.SimpleKdcServer;
import org.apache.kerby.kerberos.kerb.type.ticket.SgtTicket;

class KerbyTicketsTest {
    @TempDir Path work;
    @Test void serviceTicketAndSessionKeyObtainedFromRealLocalKdc() throws Exception {
        int port;try(ServerSocket s=new ServerSocket(0)){port=s.getLocalPort();}
        SimpleKdcServer kdc=new SimpleKdcServer();
        kdc.setWorkDir(work.toFile());kdc.setKdcRealm("TEST.EXAMPLE");kdc.setKdcHost("127.0.0.1");
        kdc.setAllowUdp(false);kdc.setKdcTcpPort(port);kdc.init();
        try {
            kdc.createPrincipal("user@TEST.EXAMPLE","test-password");kdc.createPrincipal("nfs/files.test@TEST.EXAMPLE");kdc.start();
            char[] password="test-password".toCharArray();
            SgtTicket ticket=KerbyTickets.acquire("TEST.EXAMPLE","127.0.0.1",port,"user@TEST.EXAMPLE","nfs/files.test@TEST.EXAMPLE",password);
            assertNotNull(ticket.getTicket());assertNotNull(ticket.getSessionKey());
            assertTrue(ticket.getSessionKey().getKeyData().length>=16);
            for(char c:password)assertEquals('\0',c);
            char[] wrong="wrong-password".toCharArray();
            assertThrows(Exception.class,()->KerbyTickets.acquire("TEST.EXAMPLE","127.0.0.1",port,"user@TEST.EXAMPLE","nfs/files.test@TEST.EXAMPLE",wrong));
            for(char c:wrong)assertEquals('\0',c);
        }finally{kdc.stop();}
    }
}
