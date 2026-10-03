package info.gdsnyder.nfs;

import java.util.Arrays;
import org.apache.kerby.kerberos.kerb.KrbException;
import org.apache.kerby.kerberos.kerb.client.KrbClient;
import org.apache.kerby.kerberos.kerb.client.KrbConfig;
import org.apache.kerby.kerberos.kerb.type.ticket.SgtTicket;
import org.apache.kerby.kerberos.kerb.type.ticket.TgtTicket;

/** KDC-only authentication. This does NOT establish an NFS/GSS context. */
public final class KerbyTickets {
    public static SgtTicket acquire(String realm, String kdc, int port,
                                    String principal, String spn, char[] password) throws KrbException {
        try {
            // Explicit config avoids desktop /etc/krb5.conf and global system properties.
            KrbClient client = new KrbClient(new KrbConfig());
            client.setKdcRealm(realm);
            client.setKdcHost(kdc);
            client.setKdcTcpPort(port);
            client.setAllowUdp(false);
            client.setTimeout(15_000); // Kerby passes this value to Socket.setSoTimeout (milliseconds).
            client.init();
            // Kerby's API requires a String; Java cannot securely erase that internal copy.
            TgtTicket tgt = client.requestTgt(principal, new String(password));
            return client.requestSgt(tgt, spn);
        } finally { Arrays.fill(password, '\0'); }
    }
    private KerbyTickets() {}
}
