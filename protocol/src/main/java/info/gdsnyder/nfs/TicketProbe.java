package info.gdsnyder.nfs;

import java.io.Console;
import org.apache.kerby.kerberos.kerb.type.ticket.SgtTicket;

/** Desktop diagnostic; never prints ticket bytes or key material. */
public final class TicketProbe {
    public static void main(String[] args) throws Exception {
        if(args.length!=5)throw new IllegalArgumentException("realm kdc kdcPort principal servicePrincipal");
        Console console=System.console();
        if(console==null)throw new IllegalStateException("Run in a terminal so password input is hidden");
        char[] password=console.readPassword("Kerberos password: ");
        if(password==null)throw new IllegalStateException("Password input cancelled");
        SgtTicket ticket=KerbyTickets.acquire(args[0],args[1],Integer.parseInt(args[2]),args[3],args[4],password);
        System.out.println("Obtained service ticket for "+args[4]);
        System.out.println("Session-key enctype: "+ticket.getSessionKey().getKeyType());
    }
}
