package info.gdsnyder.nfs;

import java.io.*;
import java.net.*;
import java.nio.file.Path;
import java.security.PrivilegedExceptionAction;
import java.util.*;
import java.util.concurrent.*;
import javax.security.auth.Subject;
import org.ietf.jgss.MessageProp;
import org.dcache.nfs.v4.xdr.*;
import org.dcache.oncrpc4j.xdr.ByteArrayXdr;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import static org.junit.jupiter.api.Assertions.*;

/** Socket-level NFS/RPC fixture with an independent JDK GSS acceptor; not a Linux interoperability test. */
class NfsClientTest {
    @TempDir Path directory;
    final byte[] content="hello encrypted NFS world".getBytes(java.nio.charset.StandardCharsets.UTF_8);
    static final class SharedFile {byte[] bytes;SharedFile(byte[] bytes){this.bytes=bytes;}}
    SharedFile dataFile=new SharedFile(content.clone());
    boolean unstable,corruptCommit;
    int writes,commits;
    final byte[] handle={42};
    GssInteropTest peer;
    int forcedStatus;
    int supportedMinor=2, expectedSequence=1;
    boolean created;
    boolean corruptSequence;
    final byte[] sessionBytes=new byte[16];
    java.util.concurrent.atomic.AtomicInteger renews=new java.util.concurrent.atomic.AtomicInteger();
    @ParameterizedTest @ValueSource(strings={"krb5p","krb5i","krb5","krb5p-4.1"})
    void directoryPagingStatefulOpenAndRandomReads(String flavor) throws Exception {
        if(flavor.endsWith("-4.1")){supportedMinor=1;flavor="krb5p";}
        peer=new GssInteropTest();peer.directory=directory;peer.setUp();
        ExecutorService worker=Executors.newSingleThreadExecutor();
        try(ServerSocket listener=new ServerSocket(0)){
            Future<?> service=worker.submit(()->{
                try{Subject.doAs(peer.subject,(PrivilegedExceptionAction<Void>)()->{serve(listener);return null;});}
                catch(Exception e){throw new RuntimeException(e);}
            });
            try(NfsClient client=new NfsClient("127.0.0.1",listener.getLocalPort(),"/share","user@TEST.EXAMPLE",peer.ticket,flavor)){
                java.util.List<String> trace=new java.util.concurrent.CopyOnWriteArrayList<>();client.setDiagnostics(trace::add);
                assertEquals(supportedMinor,client.minorVersion());
                List<NfsClient.Entry> entries=client.list("/");assertEquals(2,entries.size());
                assertEquals("hello.txt",entries.get(0).name);assertTrue(entries.get(0).regular());assertTrue(entries.get(1).directory());
                assertEquals(content.length,client.stat("/hello.txt").size);
                assertThrows(IOException.class,()->client.stat("/../outside"));
                client.open("/hello.txt");assertThrows(IOException.class,()->client.write(0,1,new byte[1]));assertArrayEquals(Arrays.copyOfRange(content,6,15),client.read(6,9));
                assertArrayEquals(new byte[0],client.read(content.length,5));
                long deadline=System.nanoTime()+TimeUnit.SECONDS.toNanos(3);
                while(renews.get()==0&&System.nanoTime()<deadline)Thread.sleep(20);
                assertTrue(renews.get()>0,"Open file lease should renew");
                assertTrue(trace.stream().anyMatch(t->t.startsWith("lease.config")));
                assertTrue(trace.stream().anyMatch(t->t.equals("lease.renew.begin")));
                assertTrue(trace.stream().anyMatch(t->t.startsWith("rpc.end")));
                client.close();
                service.get(5,TimeUnit.SECONDS); // Server sees EOF: no idle transport remains.
                assertThrows(IOException.class,()->client.read(0,1));
                assertTrue(trace.stream().anyMatch(t->t.equals("connection.close")));
            }
            service.get(10,TimeUnit.SECONDS);
        }finally{worker.shutdownNow();peer.cleanUp();}
    }
    @Test void wrongSecurityStatusFailsWithoutAuthenticationFallback() throws Exception {
        peer=new GssInteropTest();peer.directory=directory;peer.setUp();forcedStatus=10016;
        ExecutorService worker=Executors.newSingleThreadExecutor();
        try(ServerSocket listener=new ServerSocket(0)){
            Future<?> service=worker.submit(()->{
                try{Subject.doAs(peer.subject,(PrivilegedExceptionAction<Void>)()->{serve(listener);return null;});}
                catch(Exception e){throw new RuntimeException(e);}
            });
            IOException failure=assertThrows(IOException.class,()->new NfsClient("127.0.0.1",listener.getLocalPort(),"/share","user@TEST.EXAMPLE",peer.ticket,"krb5p"));
            assertTrue(failure.getMessage().contains("10016"));service.get(10,TimeUnit.SECONDS);
        }finally{worker.shutdownNow();peer.cleanUp();}
    }
    @Test void mismatchedSessionSequenceIsRejected() throws Exception {
        peer=new GssInteropTest();peer.directory=directory;peer.setUp();corruptSequence=true;
        ExecutorService worker=Executors.newSingleThreadExecutor();
        try(ServerSocket listener=new ServerSocket(0)){
            Future<?> service=worker.submit(()->{
                try{Subject.doAs(peer.subject,(PrivilegedExceptionAction<Void>)()->{serve(listener);return null;});}
                catch(Exception e){throw new RuntimeException(e);}
            });
            IOException failure=assertThrows(IOException.class,()->new NfsClient("127.0.0.1",listener.getLocalPort(),"/share","user@TEST.EXAMPLE",peer.ticket,"krb5p"));
            assertTrue(failure.getMessage().contains("session reply mismatch"));service.get(10,TimeUnit.SECONDS);
        }finally{worker.shutdownNow();peer.cleanUp();}
    }
    @ParameterizedTest @ValueSource(strings={"stable","unstable","bad-verifier"})
    void writesTruncateAndDurability(String behavior) throws Exception {
        unstable=!behavior.equals("stable");corruptCommit=behavior.equals("bad-verifier");
        peer=new GssInteropTest();peer.directory=directory;peer.setUp();ExecutorService worker=Executors.newSingleThreadExecutor();
        try(ServerSocket listener=new ServerSocket(0)){
            Future<?> service=worker.submit(()->{try{Subject.doAs(peer.subject,(PrivilegedExceptionAction<Void>)()->{serve(listener);return null;});}catch(Exception e){throw new RuntimeException(e);}});
            try(NfsClient client=new NfsClient("127.0.0.1",listener.getLocalPort(),"/share","user@TEST.EXAMPLE",peer.ticket,"krb5p")){
                client.open("/hello.txt",3);client.truncate(0);assertEquals(0,dataFile.bytes.length);
                byte[] payload="durable writes including short replies".getBytes(java.nio.charset.StandardCharsets.UTF_8);
                if(corruptCommit){IOException failure=assertThrows(IOException.class,()->client.write(0,payload.length,payload));assertTrue(failure.getMessage().contains("verifier changed"));}
                else{assertEquals(payload.length,client.write(0,payload.length,payload));assertArrayEquals(payload,client.read(0,payload.length));assertTrue(writes>1);
                    client.truncate(7);assertArrayEquals(Arrays.copyOf(payload,7),client.read(0,20));client.fsync();assertTrue(commits>0);}
            }
            service.get(10,TimeUnit.SECONDS);
        }finally{worker.shutdownNow();peer.cleanUp();}
    }
    @Test void guardedCreateFolderRenameAndRemove() throws Exception {
        peer=new GssInteropTest();peer.directory=directory;peer.setUp();ExecutorService worker=Executors.newSingleThreadExecutor();
        try(ServerSocket listener=new ServerSocket(0)){
            Future<?> service=worker.submit(()->{try{Subject.doAs(peer.subject,(PrivilegedExceptionAction<Void>)()->{serve(listener);return null;});}catch(Exception e){throw new RuntimeException(e);}});
            try(NfsClient client=new NfsClient("127.0.0.1",listener.getLocalPort(),"/share","user@TEST.EXAMPLE",peer.ticket,"krb5p")){
                client.createFile("/new.txt");client.mkdir("/new-folder");client.rename("/hello.txt","renamed.txt");client.delete("/renamed.txt");
                assertThrows(IOException.class,()->client.delete("/"));assertThrows(IOException.class,()->NfsClient.childPath("/","../escape"));
            }
            service.get(10,TimeUnit.SECONDS);
        }finally{worker.shutdownNow();peer.cleanUp();}
    }
    @ParameterizedTest @ValueSource(strings={"shared","separate","shared-overlap","shared-truncate"})
    void concurrentDescriptorsReadWriteDisjointRanges(String kind) throws Exception {
        peer=new GssInteropTest();peer.directory=directory;peer.setUp();
        ExecutorService servers=Executors.newFixedThreadPool(4),clients=Executors.newFixedThreadPool(4);
        List<ServerSocket> listeners=new ArrayList<>();List<Future<?>> services=new ArrayList<>(),transfers=new ArrayList<>();
        SharedFile shared=new SharedFile(new byte[16384]);CountDownLatch ready=new CountDownLatch(4),go=new CountDownLatch(1),written=new CountDownLatch(4),truncated=new CountDownLatch(1);
        try{
            for(int index=0;index<4;index++){
                final int n=index;NfsClientTest fixture=new NfsClientTest();fixture.peer=peer;fixture.dataFile=kind.startsWith("shared")?shared:new SharedFile(new byte[16384]);
                ServerSocket listener=new ServerSocket(0);listeners.add(listener);
                services.add(servers.submit(()->{try{Subject.doAs(peer.subject,(PrivilegedExceptionAction<Void>)()->{fixture.serve(listener);return null;});}catch(Exception e){throw new RuntimeException(e);}}));
                transfers.add(clients.submit(()->{
                    try(NfsClient client=new NfsClient("127.0.0.1",listener.getLocalPort(),"/share","user@TEST.EXAMPLE",peer.ticket,"krb5p")){
                        client.open("/hello.txt",3);ready.countDown();assertTrue(go.await(10,TimeUnit.SECONDS));
                        byte[] payload=new byte[256];Arrays.fill(payload,(byte)(n+1));long offset=kind.equals("shared-overlap")?0:n*4096;
                        for(int round=0;round<3;round++){client.write(offset,payload.length,payload);byte[] actual=client.read(offset,payload.length);
                            if(kind.equals("shared-overlap")){assertEquals(payload.length,actual.length);for(byte b:actual)assertTrue(b>=1&&b<=4);}else assertArrayEquals(payload,actual);
                        }
                        written.countDown();
                        if(kind.equals("shared-truncate")){assertTrue(written.await(10,TimeUnit.SECONDS));if(n==0){client.truncate(7);truncated.countDown();}assertTrue(truncated.await(10,TimeUnit.SECONDS));assertEquals(0,client.read(8,8).length);}
                        client.fsync();
                    }catch(Exception e){throw new RuntimeException(e);}
                }));
            }
            assertTrue(ready.await(15,TimeUnit.SECONDS));go.countDown();for(Future<?> f:transfers)f.get(30,TimeUnit.SECONDS);for(Future<?> f:services)f.get(10,TimeUnit.SECONDS);
            if(kind.equals("shared-truncate"))assertEquals(7,shared.bytes.length);
            if(kind.equals("shared"))for(int n=0;n<4;n++)for(int i=n*4096;i<n*4096+256;i++)assertEquals(n+1,shared.bytes[i]);
        }finally{go.countDown();for(ServerSocket listener:listeners)listener.close();clients.shutdownNow();servers.shutdownNow();peer.cleanUp();}
    }
    @Test void abortRevokesAConcurrentReader() throws Exception {
        peer=new GssInteropTest();peer.directory=directory;peer.setUp();ExecutorService workers=Executors.newFixedThreadPool(2);
        try(ServerSocket listener=new ServerSocket(0)){
            Future<?> server=workers.submit(()->{try{Subject.doAs(peer.subject,(PrivilegedExceptionAction<Void>)()->{try{serve(listener);}catch(java.net.SocketException expected){}return null;});}catch(Exception e){throw new RuntimeException(e);}});
            try(NfsClient client=new NfsClient("127.0.0.1",listener.getLocalPort(),"/share","user@TEST.EXAMPLE",peer.ticket,"krb5p")){
                client.open("/hello.txt");CountDownLatch reading=new CountDownLatch(1);
                Future<IOException> reader=workers.submit(()->{try{while(true){client.read(0,8);reading.countDown();}}catch(IOException e){return e;}});
                assertTrue(reading.await(5,TimeUnit.SECONDS));client.abort();assertNotNull(reader.get(5,TimeUnit.SECONDS));assertThrows(IOException.class,()->client.read(0,8));
            }
            server.get(10,TimeUnit.SECONDS);
        }finally{workers.shutdownNow();peer.cleanUp();}
    }
    private void serve(ServerSocket listener) throws Exception {
        org.ietf.jgss.GSSContext acceptor=org.ietf.jgss.GSSManager.getInstance().createContext((org.ietf.jgss.GSSCredential)null);
        try(Socket socket=listener.accept()){
            socket.setSoTimeout(10000);socket.setTcpNoDelay(true);DataInputStream in=new DataInputStream(socket.getInputStream());DataOutputStream out=new DataOutputStream(socket.getOutputStream());
            while(true){
                byte[] wire;try{wire=RpcTcp.readRecord(in);}catch(EOFException e){break;}
                ByteArrayXdr x=new ByteArrayXdr(wire);int xid=x.xdrDecodeInt();assertEquals(0,x.xdrDecodeInt());assertEquals(2,x.xdrDecodeInt());
                assertEquals(100003,x.xdrDecodeInt());assertEquals(4,x.xdrDecodeInt());int proc=x.xdrDecodeInt();assertEquals(6,x.xdrDecodeInt());
                byte[] cred=x.xdrDecodeDynamicOpaque();int headerLength=wire.length-x.remaining();ByteArrayXdr c=new ByteArrayXdr(cred);
                assertEquals(1,c.xdrDecodeInt());int control=c.xdrDecodeInt(),sequence=c.xdrDecodeInt(),service=c.xdrDecodeInt();byte[] context=c.xdrDecodeDynamicOpaque();c.requireEnd();
                int verifierFlavor=x.xdrDecodeInt();byte[] verifier=x.xdrDecodeDynamicOpaque();ByteArrayXdr reply=new ByteArrayXdr();reply.xdrEncodeInt(xid);reply.xdrEncodeInt(1);reply.xdrEncodeInt(0);
                if(control==1){
                    assertEquals(0,proc);assertEquals(0,verifierFlavor);assertEquals(0,context.length);byte[] token=x.xdrDecodeDynamicOpaque();x.requireEnd();
                    byte[] aprep=acceptor.acceptSecContext(token,0,token.length);assertTrue(acceptor.isEstablished());
                    reply.xdrEncodeInt(6);reply.xdrEncodeDynamicOpaque(mic(acceptor,u32(32)));reply.xdrEncodeInt(0);
                    reply.xdrEncodeDynamicOpaque(handle);reply.xdrEncodeInt(0);reply.xdrEncodeInt(0);reply.xdrEncodeInt(32);reply.xdrEncodeDynamicOpaque(aprep);
                }else{
                    assertEquals(0,control);assertEquals(1,proc);assertArrayEquals(handle,context);assertEquals(6,verifierFlavor);
                    byte[] header=Arrays.copyOf(wire,headerLength);acceptor.verifyMIC(verifier,0,verifier.length,header,0,header.length,new MessageProp(0,false));
                    byte[] args;
                    if(service==1)args=x.xdrDecodeOpaque(x.remaining());
                    else{
                        byte[] protectedBody=x.xdrDecodeDynamicOpaque(),plain;
                        if(service==2){plain=protectedBody;byte[] bodyMic=x.xdrDecodeDynamicOpaque();acceptor.verifyMIC(bodyMic,0,bodyMic.length,plain,0,plain.length,new MessageProp(0,false));}
                        else{MessageProp privacy=new MessageProp(0,false);plain=acceptor.unwrap(protectedBody,0,protectedBody.length,privacy);assertTrue(privacy.getPrivacy());}
                        x.requireEnd();ByteArrayXdr p=new ByteArrayXdr(plain);assertEquals(sequence,p.xdrDecodeInt());args=p.xdrDecodeOpaque(p.remaining());
                    }
                    byte[] body=compound(args);reply.xdrEncodeInt(6);reply.xdrEncodeDynamicOpaque(mic(acceptor,u32(sequence)));reply.xdrEncodeInt(0);
                    if(service==1)reply.xdrEncodeOpaque(body,body.length);
                    else{
                        ByteArrayXdr plain=new ByteArrayXdr();plain.xdrEncodeInt(sequence);plain.xdrEncodeOpaque(body,body.length);
                        if(service==2){reply.xdrEncodeDynamicOpaque(plain.bytes());reply.xdrEncodeDynamicOpaque(mic(acceptor,plain.bytes()));}
                        else reply.xdrEncodeDynamicOpaque(acceptor.wrap(plain.bytes(),0,plain.bytes().length,new MessageProp(0,true)));
                    }
                }
                byte[] response=reply.bytes();out.writeInt(0x80000000|response.length);out.write(response);out.flush();
            }
        }finally{acceptor.dispose();}
    }
    private byte[] mic(org.ietf.jgss.GSSContext acceptor,byte[] data) throws Exception{return acceptor.getMIC(data,0,data.length,new MessageProp(0,false));}
    private static byte[] u32(int n){ByteArrayXdr x=new ByteArrayXdr();x.xdrEncodeInt(n);return x.bytes();}
    private static void state(ByteArrayXdr x,int sequence){x.xdrEncodeInt(sequence);x.xdrEncodeOpaque(new byte[12],12);}
    private void attributes(ByteArrayXdr x,boolean lease,boolean file){
        if(lease){x.xdrEncodeInt(1);x.xdrEncodeInt(1<<10);x.xdrEncodeDynamicOpaque(u32(3));return;}
        x.xdrEncodeInt(2);x.xdrEncodeInt(18);x.xdrEncodeInt(1<<21);
        ByteArrayXdr values=new ByteArrayXdr();values.xdrEncodeInt(file?1:2);values.xdrEncodeLong(file?dataFile.bytes.length:0);values.xdrEncodeLong(1700000000);values.xdrEncodeInt(0);x.xdrEncodeDynamicOpaque(values.bytes());
    }
    private byte[] compound(byte[] bytes) throws Exception {synchronized(dataFile){return compoundLocked(bytes);}}
    private byte[] compoundLocked(byte[] bytes) throws Exception {
        ByteArrayXdr decoder=new ByteArrayXdr(bytes);COMPOUND4args args=new COMPOUND4args(decoder);decoder.requireEnd();
        if(args.minorversion.value>supportedMinor){
            ByteArrayXdr error=new ByteArrayXdr();error.xdrEncodeInt(10021);error.xdrEncodeString(args.tag.toString());error.xdrEncodeInt(0);return error.bytes();
        }
        assertEquals(supportedMinor,args.minorversion.value);
        if(created && args.argarray[0].argop!=nfs_opnum4.OP_DESTROY_SESSION)assertEquals(nfs_opnum4.OP_SEQUENCE,args.argarray[0].argop);
        ByteArrayXdr result=new ByteArrayXdr();result.xdrEncodeInt(0);result.xdrEncodeString(args.tag.toString());result.xdrEncodeInt(args.argarray.length);
        if(forcedStatus!=0){
            ByteArrayXdr error=new ByteArrayXdr();error.xdrEncodeInt(forcedStatus);error.xdrEncodeString(args.tag.toString());
            error.xdrEncodeInt(1);error.xdrEncodeInt(args.argarray[0].argop);error.xdrEncodeInt(forcedStatus);return error.bytes();
        }
        boolean file=false;
        for(nfs_argop4 op:args.argarray){
            result.xdrEncodeInt(op.argop);result.xdrEncodeInt(0);
            switch(op.argop){
                case nfs_opnum4.OP_EXCHANGE_ID:
                    assertEquals(0,op.opexchange_id.eia_state_protect.spa_how);
                    result.xdrEncodeLong(123);result.xdrEncodeInt(1);result.xdrEncodeInt(0x10000);result.xdrEncodeInt(0);
                    result.xdrEncodeLong(1);result.xdrEncodeDynamicOpaque(new byte[]{1});result.xdrEncodeDynamicOpaque(new byte[]{2});result.xdrEncodeInt(0);break;
                case nfs_opnum4.OP_CREATE_SESSION:
                    assertEquals(123,op.opcreate_session.csa_clientid.value);assertEquals(1,op.opcreate_session.csa_sequence.value);
                    result.xdrEncodeOpaque(sessionBytes,16);result.xdrEncodeInt(1);result.xdrEncodeInt(0);
                    op.opcreate_session.csa_fore_chan_attrs.xdrEncode(result);op.opcreate_session.csa_back_chan_attrs.xdrEncode(result);created=true;break;
                case nfs_opnum4.OP_SEQUENCE:
                    assertArrayEquals(sessionBytes,op.opsequence.sa_sessionid.value);assertEquals(expectedSequence,op.opsequence.sa_sequenceid.value);
                    assertEquals(0,op.opsequence.sa_slotid.value);assertEquals(0,op.opsequence.sa_highest_slotid.value);assertFalse(op.opsequence.sa_cachethis);
                    result.xdrEncodeOpaque(sessionBytes,16);result.xdrEncodeInt(expectedSequence+++(corruptSequence?1:0));result.xdrEncodeInt(0);result.xdrEncodeInt(0);result.xdrEncodeInt(0);result.xdrEncodeInt(0);
                    if(args.argarray.length==1)renews.incrementAndGet();break;
                case nfs_opnum4.OP_RECLAIM_COMPLETE:assertFalse(op.opreclaim_complete.rca_one_fs);break;
                case nfs_opnum4.OP_DESTROY_SESSION:assertArrayEquals(sessionBytes,op.opdestroy_session.dsa_sessionid.value);created=false;break;
                case nfs_opnum4.OP_PUTROOTFH:break;
                case nfs_opnum4.OP_PUTFH:file=op.opputfh.object.value[0]==3;break;
                case nfs_opnum4.OP_LOOKUP:String name=op.oplookup.objname.toString();assertTrue(name.equals("share")||name.equals("hello.txt"));file=name.equals("hello.txt");break;
                case nfs_opnum4.OP_GETFH:result.xdrEncodeDynamicOpaque(new byte[]{(byte)(file?3:2)});break;
                case nfs_opnum4.OP_GETATTR:
                    if((op.opgetattr.attr_request.value[0]&(1<<30))!=0){result.xdrEncodeInt(1);result.xdrEncodeInt(1<<30);ByteArrayXdr max=new ByteArrayXdr();max.xdrEncodeLong(512*1024);result.xdrEncodeDynamicOpaque(max.bytes());break;}
                    if((op.opgetattr.attr_request.value[0]&(1<<31))!=0){result.xdrEncodeInt(1);result.xdrEncodeInt(1<<31);ByteArrayXdr max=new ByteArrayXdr();max.xdrEncodeLong(512*1024);result.xdrEncodeDynamicOpaque(max.bytes());break;}
                    attributes(result,(op.opgetattr.attr_request.value[0]&(1<<10))!=0,file);break;
                case nfs_opnum4.OP_READDIR:
                    result.xdrEncodeOpaque(new byte[8],8);result.xdrEncodeBoolean(true);
                    boolean first=op.opreaddir.cookie.value==0;result.xdrEncodeLong(first?1:2);result.xdrEncodeString(first?"hello.txt":"nested");attributes(result,false,first);
                    result.xdrEncodeBoolean(false);result.xdrEncodeBoolean(!first);break;
                case nfs_opnum4.OP_SETCLIENTID:result.xdrEncodeLong(123);result.xdrEncodeOpaque(new byte[8],8);break;
                case nfs_opnum4.OP_SETCLIENTID_CONFIRM:assertEquals(123,op.opsetclientid_confirm.clientid.value);break;
                case nfs_opnum4.OP_OPEN:
                    assertTrue((op.opopen.share_access.value&0x10000)!=0);
                    if(op.opopen.openhow.opentype==1){assertEquals(1,op.opopen.openhow.how.mode);dataFile.bytes=new byte[0];}assertEquals(0,op.opopen.share_deny.value);assertEquals(op.opopen.openhow.opentype==1?"new.txt":"hello.txt",op.opopen.claim.file.toString());
                    state(result,1);result.xdrEncodeBoolean(true);result.xdrEncodeLong(0);result.xdrEncodeLong(0);result.xdrEncodeInt(0);result.xdrEncodeInt(0);result.xdrEncodeInt(0);file=true;break;
                case nfs_opnum4.OP_OPEN_CONFIRM:assertEquals(1,op.opopen_confirm.seqid.value);state(result,2);break;
                case nfs_opnum4.OP_READ:
                    assertEquals(1,op.opread.stateid.seqid);int offset=(int)Math.min(dataFile.bytes.length,op.opread.offset.value);int end=Math.min(dataFile.bytes.length,offset+op.opread.count.value);
                    result.xdrEncodeBoolean(end==dataFile.bytes.length);result.xdrEncodeDynamicOpaque(Arrays.copyOfRange(dataFile.bytes,offset,end));break;
                case nfs_opnum4.OP_WRITE:
                    assertEquals(2,op.opwrite.stable);int at=(int)op.opwrite.offset.value;int count=Math.min(5,op.opwrite.data.remaining());
                    dataFile.bytes=Arrays.copyOf(dataFile.bytes,Math.max(dataFile.bytes.length,at+count));op.opwrite.data.get(dataFile.bytes,at,count);writes++;
                    result.xdrEncodeInt(count);result.xdrEncodeInt(unstable?0:2);result.xdrEncodeOpaque(new byte[8],8);break;
                case nfs_opnum4.OP_COMMIT:
                    byte[] verifier=new byte[8];if(corruptCommit)verifier[0]=1;result.xdrEncodeOpaque(verifier,8);commits++;break;
                case nfs_opnum4.OP_SETATTR:
                    assertEquals(1<<4,op.opsetattr.obj_attributes.attrmask.value[0]);dataFile.bytes=Arrays.copyOf(dataFile.bytes,(int)new ByteArrayXdr(op.opsetattr.obj_attributes.attr_vals.value).xdrDecodeLong());
                    result.xdrEncodeInt(1);result.xdrEncodeInt(1<<4);break;
                case nfs_opnum4.OP_CREATE:
                    assertEquals(2,op.opcreate.objtype.type);assertEquals("new-folder",op.opcreate.objname.toString());
                    result.xdrEncodeBoolean(true);result.xdrEncodeLong(0);result.xdrEncodeLong(1);result.xdrEncodeInt(2);result.xdrEncodeInt(0);result.xdrEncodeInt(2);break;
                case nfs_opnum4.OP_SAVEFH:break;
                case nfs_opnum4.OP_RENAME:
                    assertEquals("hello.txt",op.oprename.oldname.toString());assertEquals("renamed.txt",op.oprename.newname.toString());
                    for(int i=0;i<2;i++){result.xdrEncodeBoolean(true);result.xdrEncodeLong(0);result.xdrEncodeLong(1);}break;
                case nfs_opnum4.OP_REMOVE:
                    assertEquals("renamed.txt",op.opremove.target.toString());result.xdrEncodeBoolean(true);result.xdrEncodeLong(0);result.xdrEncodeLong(1);break;
                case nfs_opnum4.OP_CLOSE:assertEquals(0,op.opclose.seqid.value);state(result,3);break;
                case nfs_opnum4.OP_RENEW:assertEquals(123,op.oprenew.clientid.value);renews.incrementAndGet();break;
                default:fail("Unexpected NFS operation "+op.argop);
            }
        }
        return result.bytes();
    }
}
