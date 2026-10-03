package info.gdsnyder.nfs.android;

import java.util.*;
import java.io.IOException;
import info.gdsnyder.nfs.NfsClient;
import info.gdsnyder.nfs.CredentialSlot;
import info.gdsnyder.nfs.KerbyTickets;
import android.content.Context;
import org.apache.kerby.kerberos.kerb.type.ticket.SgtTicket;

/** Process-local credentials and connections. Saving/signing out revokes open connections. */
final class TicketVault {
    private static final Map<String,CredentialSlot<SgtTicket>> tickets=new HashMap<>();
    private static final Map<NfsClient,String> clients=new HashMap<>();
    private static synchronized CredentialSlot<SgtTicket> slot(String id){return tickets.computeIfAbsent(id,k->new CredentialSlot<>(t->t.getEncKdcRepPart().getEndTime().getTime(),t->Arrays.fill(t.getSessionKey().getKeyData(),(byte)0)));}
    static synchronized void put(String id,SgtTicket ticket){clear(id);slot(id).put(ticket);}
    private static int pending;
    static synchronized boolean signedIn(String id){
        SgtTicket ticket=slot(id).peek();
        return ticket!=null&&ticket.getEncKdcRepPart().getEndTime().getTime()>System.currentTimeMillis();
    }
    static synchronized void clear(String id){
        slot(id).clear();
        for(Map.Entry<NfsClient,String> e:clients.entrySet())if(e.getValue().equals(id))e.getKey().abort();
    }
    static NfsClient connect(Context context,ExportConfig c) throws IOException {
        CredentialSlot<SgtTicket> credentials=slot(c.id);
        SgtTicket fresh=credentials.fresh(()->{char[] pw=PasswordStore.load(context,c);try{return KerbyTickets.acquire(c.realm,c.kdc,c.kdcPort,c.principal,c.spn,pw);}finally{Arrays.fill(pw,'\0');}});
        final SgtTicket original,snapshot;
        synchronized(TicketVault.class){synchronized(credentials){
            original=credentials.peek();
            if(original!=fresh)throw new IOException("Credentials changed while connecting; retry");
            if(original==null)throw new IOException("Sign in to this export in NFS4SAF first");
            if(clients.size()+pending>=32)throw new IOException("Too many open NFS connections");
            org.apache.kerby.kerberos.kerb.type.kdc.EncTgsRepPart part=new org.apache.kerby.kerberos.kerb.type.kdc.EncTgsRepPart();
            part.setKey(new org.apache.kerby.kerberos.kerb.type.base.EncryptionKey(original.getSessionKey().getKeyType(),original.getSessionKey().getKeyData().clone()));
            part.setEndTime(original.getEncKdcRepPart().getEndTime());
            snapshot=new SgtTicket(original.getTicket(),part);pending++;
        }}
        // Network operations do not hold the vault lock or block sign-out on the UI thread.
        try{
            NfsClient client=new NfsClient(c.host,c.port,c.path,c.principal,snapshot,c.security);
            synchronized(TicketVault.class){
                if(credentials.peek()!=original){client.abort();throw new IOException("Export was signed out while connecting");}
                clients.put(client,c.id);
            }
            return client;
        }finally{
            Arrays.fill(snapshot.getSessionKey().getKeyData(),(byte)0);
            synchronized(TicketVault.class){pending--;}
        }
    }
    static void release(NfsClient client){
        synchronized(TicketVault.class){clients.remove(client);}
        client.close();
    }
}
