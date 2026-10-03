package info.gdsnyder.nfs;

import java.io.*;
import java.nio.*;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.*;
import java.util.concurrent.*;
import org.apache.kerby.kerberos.kerb.type.ticket.SgtTicket;
import org.dcache.nfs.v4.xdr.*;
import org.dcache.oncrpc4j.xdr.ByteArrayXdr;

/** NFSv4.1/4.2 client. Uses NFS4J's generated XDR types over RPCSEC_GSS. */
public final class NfsClient implements AutoCloseable {
    public static final int READ_SIZE=512*1024;
    private static final int PROGRAM=100003,VERSION=4;
    private final RpcTcp transport;
    private final KerberosGss gss;
    private RpcSecGss security;
    private volatile java.util.function.Consumer<String> diagnostics=message->{};
    public void setDiagnostics(java.util.function.Consumer<String> sink){diagnostics=sink==null?message->{}:sink;}
    private void trace(String message){try{diagnostics.accept(message);}catch(RuntimeException ignored){}}
    private static String causes(Throwable failure){StringBuilder s=new StringBuilder();for(int i=0;failure!=null&&i<8;i++,failure=failure.getCause())s.append(failure.getClass().getSimpleName()).append(": ").append(failure.getMessage()).append("; ");return s.toString();}
    private int xid=new SecureRandom().nextInt();
    private nfs_fh4 root;
    private clientid4 clientId;
    private stateid4 openState;
    private nfs_fh4 openHandle;
    private int ownerSequence;
    private boolean writable;
    private int writeSize=READ_SIZE;
    private int minorVersion=2, slotSequence=1, maxOperations=128, readSize=READ_SIZE, requestLimit=1024*1024, responseLimit=1024*1024;
    private sessionid4 session;
    private static final class NfsStatusException extends IOException {
        final int status;
        NfsStatusException(int status){super("NFSv4 status "+status+" ("+org.dcache.nfs.nfsstat.toString(status)+")");this.status=status;}
    }
    public int minorVersion(){return minorVersion;}
    private static channel_attrs4 channel(){
        channel_attrs4 c=new channel_attrs4();c.ca_headerpadsize=new count4(0);
        c.ca_maxrequestsize=new count4(1024*1024);c.ca_maxresponsesize=new count4(1024*1024);
        c.ca_maxresponsesize_cached=new count4(0);c.ca_maxoperations=new count4(128);
        c.ca_maxrequests=new count4(1);c.ca_rdma_ird=new uint32_t[0];return c;
    }
    private void establishSession() throws IOException {
        nfs_argop4 exchange=op(nfs_opnum4.OP_EXCHANGE_ID);exchange.opexchange_id=new EXCHANGE_ID4args();
        EXCHANGE_ID4args e=exchange.opexchange_id;e.eia_clientowner=new client_owner4();
        byte[] boot=new byte[8];new SecureRandom().nextBytes(boot);e.eia_clientowner.co_verifier=new verifier4(boot);
        e.eia_clientowner.co_ownerid=("android-saf-"+UUID.randomUUID()).getBytes(StandardCharsets.UTF_8);
        e.eia_flags=new uint32_t(0);e.eia_state_protect=new state_protect4_a();e.eia_state_protect.spa_how=0;e.eia_client_impl_id=new nfs_impl_id4[0];
        EXCHANGE_ID4resok id;
        try{id=compound(exchange).resarray.get(0).opexchange_id.eir_resok4;}
        catch(NfsStatusException ex){if(ex.status!=10021)throw ex;minorVersion=1;id=compound(exchange).resarray.get(0).opexchange_id.eir_resok4;}
        if(id.eir_state_protect.spr_how!=0)throw new IOException("Unsupported NFS state protection");
        clientId=id.eir_clientid;
        nfs_argop4 create=op(nfs_opnum4.OP_CREATE_SESSION);create.opcreate_session=new CREATE_SESSION4args();
        CREATE_SESSION4args c=create.opcreate_session;c.csa_clientid=clientId;c.csa_sequence=id.eir_sequenceid;
        c.csa_flags=new uint32_t(0);c.csa_fore_chan_attrs=channel();c.csa_back_chan_attrs=channel();
        c.csa_cb_program=new uint32_t(0);c.csa_sec_parms=new callback_sec_parms4[0];
        CREATE_SESSION4resok established=compound(create).resarray.get(0).opcreate_session.csr_resok4;
        if(established.csr_sequence.value!=c.csa_sequence.value)throw new IOException("CREATE_SESSION sequence mismatch");
        channel_attrs4 limits=established.csr_fore_chan_attrs;
        if(limits.ca_maxrequests.value<1||limits.ca_maxoperations.value<4||limits.ca_maxrequestsize.value<4096||limits.ca_maxresponsesize.value<8192)
            throw new IOException("NFS session channel limits too small");
        maxOperations=Math.min(128,limits.ca_maxoperations.value);
        requestLimit=limits.ca_maxrequestsize.value;responseLimit=limits.ca_maxresponsesize.value;
        readSize=Math.min(READ_SIZE,responseLimit-4096);
        session=established.csr_sessionid;
        nfs_argop4 reclaim=op(nfs_opnum4.OP_RECLAIM_COMPLETE);reclaim.opreclaim_complete=new RECLAIM_COMPLETE4args();reclaim.opreclaim_complete.rca_one_fs=false;compound(reclaim);
    }
    private ScheduledExecutorService renewer;
    private IOException leaseFailure;
    private volatile boolean closed;
    public static final class Entry {
        public final String name;public final int type;public final long size,modified;
        Entry(String name,int type,long size,long modified){this.name=name;this.type=type;this.size=size;this.modified=modified;}
        public boolean directory(){return type==2;}
        public boolean regular(){return type==1;}
    }
    public NfsClient(String host,int port,String export,String principal,SgtTicket ticket,String flavor) throws IOException {
        RpcSecGss.Service service;
        if("krb5p".equals(flavor))service=RpcSecGss.Service.PRIVACY;
        else if("krb5i".equals(flavor))service=RpcSecGss.Service.INTEGRITY;
        else if("krb5".equals(flavor))service=RpcSecGss.Service.AUTH;
        else throw new IOException("Unsupported security flavor");
        gss=new KerberosGss(ticket,principal);
        RpcTcp socket=null;
        try {
            socket=new RpcTcp(host,port,15000);transport=socket;
            byte[] token=gss.step(new byte[0]),handle=new byte[0];boolean continuation=false;
            for(int rounds=0;rounds<4;rounds++) {
                int id=++xid;
                RpcSecGss.InitReply reply=RpcSecGss.initReply(id,transport.exchange(RpcSecGss.initCall(id,PROGRAM,VERSION,handle,token,continuation)));
                handle=reply.handle;
                if(reply.token.length!=0)token=gss.step(reply.token);else token=new byte[0];
                if(reply.major==0){reply.verifyComplete(gss);security=new RpcSecGss(gss,handle,service);break;}
                if(token.length==0)throw new IOException("Server requested GSS continuation without a client token");continuation=true;
            }
            if(security==null)throw new IOException("RPCSEC_GSS handshake exceeded round limit");
            establishSession();
            root=compound(op(nfs_opnum4.OP_PUTROOTFH),op(nfs_opnum4.OP_GETFH)).resarray.get(1).opgetfh.resok4.object;
            root=walk(root,components(export));
        }catch(IOException|RuntimeException e){if(socket!=null)try{socket.close();}catch(IOException ignored){}gss.close();throw e;}
    }
    public static String[] components(String path) throws IOException {
        if(path==null||!path.startsWith("/")||path.indexOf('\0')>=0)throw new IOException("Invalid absolute NFS path");
        List<String> parts=new ArrayList<>();for(String p:path.split("/")){if(p.isEmpty())continue;if(p.equals(".")||p.equals(".."))throw new IOException("Relative path components are not allowed");parts.add(p);}
        if(parts.size()>128)throw new IOException("NFS path too deep");return parts.toArray(new String[0]);
    }
    private static nfs_argop4 op(int num){nfs_argop4 o=new nfs_argop4();o.argop=num;return o;}
    private static nfs_argop4 put(nfs_fh4 fh){nfs_argop4 o=op(nfs_opnum4.OP_PUTFH);o.opputfh=new PUTFH4args();o.opputfh.object=fh;return o;}
    private static bitmap4 attrs(){return new bitmap4(new int[]{(1<<1)|(1<<4),1<<(53-32)});}
    private synchronized COMPOUND4res compound(nfs_argop4... ops) throws IOException {
        if(closed)throw new IOException("NFS connection closed");if(leaseFailure!=null)throw new IOException("NFS lease renewal failed; reopen the file",leaseFailure);
        COMPOUND4args args=new COMPOUND4args();args.tag=new utf8str_cs("android-saf");args.minorversion=new uint32_t(minorVersion);
        boolean sequenced=session!=null;
        if(sequenced){
            if(ops.length+1>maxOperations)throw new IOException("NFS compound exceeds negotiated operation limit");
            nfs_argop4 sequence=op(nfs_opnum4.OP_SEQUENCE);sequence.opsequence=new SEQUENCE4args();
            sequence.opsequence.sa_sessionid=session;sequence.opsequence.sa_sequenceid=new sequenceid4(slotSequence);
            sequence.opsequence.sa_slotid=new slotid4(0);sequence.opsequence.sa_highest_slotid=new slotid4(0);sequence.opsequence.sa_cachethis=false;
            nfs_argop4[] all=new nfs_argop4[ops.length+1];all[0]=sequence;System.arraycopy(ops,0,all,1,ops.length);ops=all;
        }
        args.argarray=ops;
        byte[] encoded=NfsCompounds.encode(args);
        if(sequenced&&encoded.length+1024>requestLimit)throw new IOException("NFS request exceeds negotiated channel size");
        RpcSecGss.Request request=security.request(++xid,PROGRAM,VERSION,1,encoded);
        try {
            long rpcStart=System.nanoTime();trace("rpc.begin xid="+xid+" ops="+Arrays.toString(Arrays.stream(ops).mapToInt(o->o.argop).toArray()));
            byte[] body=security.reply(request,transport.exchange(request.wire));trace("rpc.end xid="+xid+" ms="+((System.nanoTime()-rpcStart)/1000000)+" bytes="+body.length);ByteArrayXdr decoder=new ByteArrayXdr(body);
            COMPOUND4res res=new COMPOUND4res(decoder);decoder.requireEnd();
            if(res.resarray.size()>ops.length)throw new IOException("NFS returned too many operation results");
            for(int i=0;i<res.resarray.size();i++)if(res.resarray.get(i).resop!=ops[i].argop)throw new IOException("NFS operation response mismatch");
            if(sequenced&&res.resarray.size()>0&&res.resarray.get(0).opsequence.sr_status==0){
                SEQUENCE4resok sr=res.resarray.get(0).opsequence.sr_resok4;
                if(!session.equals(sr.sr_sessionid)||sr.sr_slotid.value!=0||sr.sr_sequenceid.value!=slotSequence)
                    throw new IOException("NFS session reply mismatch");
                slotSequence++;
                if((sr.sr_status_flags.value & (0x8|0x10|0x20|0x40|0x80|0x100))!=0)
                    throw new IOException("NFS session state lost or revoked; reconnect");
            }
            if(res.status!=0)throw new NfsStatusException(res.status);
            if(res.resarray.size()!=ops.length)throw new IOException("Incomplete successful NFS compound");if(sequenced)res.resarray.remove(0);return res;
        }catch(NfsStatusException e){trace("rpc.status "+causes(e));if(!(session==null&&e.status==10021&&minorVersion==2))closeTransport();throw e;}catch(IOException|RuntimeException e){trace("rpc.failure "+causes(e));closeTransport();if(e instanceof IOException)throw (IOException)e;throw new IOException("Invalid NFS response",e);}
    }
    private nfs_fh4 resolve(String path) throws IOException {
        return walk(root,components(path));
    }
    private nfs_fh4 walk(nfs_fh4 start,String[] parts) throws IOException {
        nfs_fh4 current=start;
        for(String part:parts){
            nfs_argop4 lookup=op(nfs_opnum4.OP_LOOKUP);lookup.oplookup=new LOOKUP4args();lookup.oplookup.objname=new component4(part);
            // Small compounds work even with the server's minimum operation limit.
            current=compound(put(current),lookup,op(nfs_opnum4.OP_GETFH)).resarray.get(2).opgetfh.resok4.object;
        }
        return current;
    }
    private static nfs_argop4 getAttr(bitmap4 mask){nfs_argop4 o=op(nfs_opnum4.OP_GETATTR);o.opgetattr=new GETATTR4args();o.opgetattr.attr_request=mask;return o;}
    public synchronized Entry stat(String path) throws IOException {
        nfs_fh4 fh=resolve(path);COMPOUND4res res=compound(put(fh),getAttr(attrs()));
        String[] parts=components(path);return decodeAttrs(parts.length==0?"/":parts[parts.length-1],res.resarray.get(1).opgetattr.resok4.obj_attributes);
    }
    private static Entry decodeAttrs(String name,fattr4 attrs) throws IOException {
        ByteArrayXdr x=new ByteArrayXdr(attrs.attr_vals.value);int type=0;long size=0,modified=0;
        for(int word=0;word<attrs.attrmask.value.length;word++)for(int bit=0;bit<32;bit++)if((attrs.attrmask.value[word]&(1<<bit))!=0){
            int field=word*32+bit;
            if(field==1)type=x.xdrDecodeInt();else if(field==4){size=x.xdrDecodeLong();if(size<0)throw new IOException("File exceeds signed 64-bit size limit");}
            else if(field==53){long sec=x.xdrDecodeLong();int ns=x.xdrDecodeInt();if(ns<0||ns>=1000000000)throw new IOException("Invalid NFS timestamp");modified=sec*1000+ns/1000000;}
            else throw new IOException("Unexpected NFS attribute "+field);
        }
        x.requireEnd();if(type==0)throw new IOException("NFS server did not return file type");return new Entry(name,type,size,modified);
    }
    public synchronized List<Entry> list(String path) throws IOException {
        nfs_fh4 fh=resolve(path);long cookie=0;verifier4 verifier=new verifier4(new byte[8]);List<Entry> entries=new ArrayList<>();
        for(int page=0;page<4096;page++) {
            nfs_argop4 rd=op(nfs_opnum4.OP_READDIR);rd.opreaddir=new READDIR4args();rd.opreaddir.cookie=new nfs_cookie4(cookie);rd.opreaddir.cookieverf=verifier;
            rd.opreaddir.dircount=new count4(Math.min(16384,responseLimit-4096));rd.opreaddir.maxcount=new count4(Math.min(65536,responseLimit-4096));rd.opreaddir.attr_request=attrs();
            READDIR4resok result=compound(put(fh),rd).resarray.get(1).opreaddir.resok4;verifier=result.cookieverf;
            long last=cookie;for(entry4 e=result.reply.entries;e!=null;e=e.nextentry){
                String name=e.name.toString();if(name.isEmpty()||name.equals(".")||name.equals("..")||name.contains("/")||name.indexOf('\0')>=0)throw new IOException("Invalid NFS directory name");
                if(entries.size()>=50000)throw new IOException("Directory exceeds this client's 50,000-entry limit");
                entries.add(decodeAttrs(name,e.attrs));last=e.cookie.value;
            }
            if(result.reply.eof)return entries;if(last==cookie)throw new IOException("READDIR pagination made no progress");cookie=last;
        }
        throw new IOException("READDIR page limit exceeded");
    }
    public synchronized void open(String path) throws IOException {open(path,1,false);}
    public synchronized void open(String path,int access) throws IOException {open(path,access,false);}
    public synchronized void createFile(String path) throws IOException {open(path,2,true);}
    private void open(String path,int access,boolean create) throws IOException {
        if(access<1||access>3)throw new IOException("Invalid NFS open access");
        if(openState!=null)throw new IOException("A file is already open on this client");
        if(!create&&!stat(path).regular())throw new IOException("Only regular files can be opened");
        String[] parts=components(path);if(parts.length==0)throw new IOException("Cannot open export root as a file");
        String parent="/"+String.join("/",Arrays.copyOf(parts,parts.length-1));nfs_fh4 directory=resolve(parent);
        nfs_argop4 o=op(nfs_opnum4.OP_OPEN);o.opopen=new OPEN4args();o.opopen.seqid=new seqid4(0);o.opopen.share_access=new uint32_t(access|0x10000);o.opopen.share_deny=new uint32_t(0);
        state_owner4 owner=new state_owner4();owner.clientid=clientId;owner.owner=UUID.randomUUID().toString().getBytes(StandardCharsets.UTF_8);o.opopen.owner=new open_owner4(owner);
        o.opopen.openhow=new openflag4();o.opopen.openhow.opentype=create?1:0;
        if(create){o.opopen.openhow.how=new createhow4();o.opopen.openhow.how.mode=1;o.opopen.openhow.how.createattrs=modeAttrs(0600);}o.opopen.claim=new open_claim4();o.opopen.claim.claim=0;o.opopen.claim.file=new component4(parts[parts.length-1]);
        COMPOUND4res opened=compound(put(directory),o,op(nfs_opnum4.OP_GETFH));OPEN4resok result=opened.resarray.get(1).opopen.resok4;
        writable=(access&2)!=0;openState=result.stateid;openHandle=opened.resarray.get(2).opgetfh.resok4.object;ownerSequence=1;
        if((result.rflags.value&2)!=0)throw new IOException("Server requested OPEN_CONFIRM on an NFSv4.1/4.2 session");
        // A server may grant a read delegation even though we do not offer callbacks. Return it immediately.
        if(result.delegation.delegation_type==1){nfs_argop4 dr=op(nfs_opnum4.OP_DELEGRETURN);dr.opdelegreturn=new DELEGRETURN4args();dr.opdelegreturn.deleg_stateid=result.delegation.read.stateid;compound(put(openHandle),dr);}
        fattr4 readAttr=compound(put(openHandle),getAttr(new bitmap4(new int[]{1<<30}))).resarray.get(1).opgetattr.resok4.obj_attributes;
        if(readAttr.attrmask.value.length>0&&(readAttr.attrmask.value[0]&(1<<30))!=0){
            long maxRead=new ByteArrayXdr(readAttr.attr_vals.value).xdrDecodeLong();
            if(maxRead<=0)throw new IOException("Invalid NFS maxread");readSize=(int)Math.min(readSize,maxRead);
        }
        writeSize=Math.min(READ_SIZE,requestLimit-4096);
        if(writable){
            fattr4 writeAttr=compound(put(openHandle),getAttr(new bitmap4(new int[]{1<<31}))).resarray.get(1).opgetattr.resok4.obj_attributes;
            if(writeAttr.attrmask.value.length>0&&(writeAttr.attrmask.value[0]&(1<<31))!=0){long maxWrite=new ByteArrayXdr(writeAttr.attr_vals.value).xdrDecodeLong();
                if(maxWrite<=0)throw new IOException("Invalid NFS maxwrite");writeSize=(int)Math.min(writeSize,maxWrite);}
        }
        int lease=90;
        nfs_argop4 rootop=op(nfs_opnum4.OP_PUTROOTFH);fattr4 leaseAttr=compound(rootop,getAttr(new bitmap4(new int[]{1<<10}))).resarray.get(1).opgetattr.resok4.obj_attributes;
        if(leaseAttr.attrmask.value.length>0&&(leaseAttr.attrmask.value[0]&(1<<10))!=0)lease=new ByteArrayXdr(leaseAttr.attr_vals.value).xdrDecodeInt();
        if(lease<=0||lease>86400)throw new IOException("Invalid NFS lease duration");
        final long period=Math.max(1,lease/3);trace("lease.config seconds="+lease+" renewalSeconds="+period);
        renewer=Executors.newSingleThreadScheduledExecutor(r->{Thread t=new Thread(r,"nfs-lease");t.setDaemon(true);return t;});
        renewer.scheduleAtFixedRate(()->{synchronized(NfsClient.this){if(closed)return;try{trace("lease.renew.begin");compound();trace("lease.renew.end");}catch(IOException ex){leaseFailure=ex;trace("lease.renew.failure "+causes(ex));}}},period,period,TimeUnit.SECONDS);
    }
    private long readCalls, readBytes, readNanos, writeCalls, writeBytes, writeNanos;
    public synchronized String readStats(){return "rpcReads="+readCalls+" rpcBytes="+readBytes+" rpcReadMs="+(readNanos/1000000)+" rpcWrites="+writeCalls+" rpcWriteBytes="+writeBytes+" rpcWriteMs="+(writeNanos/1000000);}
    public synchronized void checkReadable() throws IOException {
        if(closed)throw new IOException("NFS connection closed");
        if(leaseFailure!=null)throw new IOException("NFS lease renewal failed",leaseFailure);
        if(openState==null)throw new IOException("No open NFS file");gss.checkActive();
    }
    public synchronized byte[] read(long offset,int count) throws IOException {
        checkReadable();long start=System.nanoTime();
        if(openState==null)throw new IOException("No open NFS file");if(offset<0||count<0)throw new IOException("Invalid read range");
        nfs_argop4 rd=op(nfs_opnum4.OP_READ);rd.opread=new READ4args();rd.opread.stateid=openState;rd.opread.offset=new offset4(offset);rd.opread.count=new count4(Math.min(count,readSize));
        ByteBuffer data=compound(put(openHandle),rd).resarray.get(1).opread.resok4.data;
        if(data.remaining()>Math.min(count,readSize))throw new IOException("NFS server returned excess read data");byte[] b=new byte[data.remaining()];data.get(b);readCalls++;readBytes+=b.length;readNanos+=System.nanoTime()-start;return b;
    }
    public static String childPath(String parent,String name) throws IOException {
        components(parent);
        if(name==null||name.isEmpty()||name.equals(".")||name.equals("..")||name.contains("/")||name.indexOf('\0')>=0)
            throw new IOException("Invalid document name");
        return (parent.equals("/")?"/":parent+"/")+name;
    }
    private static String parentPath(String path) throws IOException {
        String[] parts=components(path);if(parts.length==0)throw new IOException("Cannot modify export root");
        return "/"+String.join("/",Arrays.copyOf(parts,parts.length-1));
    }
    private static String basename(String path) throws IOException {String[] parts=components(path);if(parts.length==0)throw new IOException("Cannot modify export root");return parts[parts.length-1];}
    private static fattr4 modeAttrs(int mode){
        ByteArrayXdr x=new ByteArrayXdr();x.xdrEncodeInt(mode);fattr4 a=new fattr4();a.attrmask=new bitmap4(new int[]{0,1<<(33-32)});a.attr_vals=new attrlist4(x.bytes());return a;
    }
    public synchronized void mkdir(String path) throws IOException {
        nfs_fh4 parent=resolve(parentPath(path));nfs_argop4 c=op(nfs_opnum4.OP_CREATE);c.opcreate=new CREATE4args();
        c.opcreate.objtype=new createtype4();c.opcreate.objtype.type=2;c.opcreate.objname=new component4(basename(path));c.opcreate.createattrs=modeAttrs(0700);compound(put(parent),c);
    }
    public synchronized void delete(String path) throws IOException {
        nfs_fh4 parent=resolve(parentPath(path));nfs_argop4 r=op(nfs_opnum4.OP_REMOVE);r.opremove=new REMOVE4args();r.opremove.target=new component4(basename(path));compound(put(parent),r);
    }
    public synchronized void rename(String path,String name) throws IOException {
        String parent=parentPath(path);childPath(parent,name);
        if(basename(path).equals(name))return;
        for(Entry e:list(parent))if(e.name.equals(name))throw new IOException("Rename destination already exists");
        nfs_argop4 r=op(nfs_opnum4.OP_RENAME);r.oprename=new RENAME4args();r.oprename.oldname=new component4(basename(path));r.oprename.newname=new component4(name);
        compound(put(resolve(parent)),op(nfs_opnum4.OP_SAVEFH),r);
    }
    public synchronized void truncate(long size) throws IOException {
        checkReadable();if(!writable||size<0)throw new IOException("Invalid writable truncate");
        nfs_argop4 set=op(nfs_opnum4.OP_SETATTR);set.opsetattr=new SETATTR4args();set.opsetattr.stateid=openState;
        ByteArrayXdr x=new ByteArrayXdr();x.xdrEncodeLong(size);fattr4 attrs=new fattr4();attrs.attrmask=new bitmap4(new int[]{1<<4});attrs.attr_vals=new attrlist4(x.bytes());set.opsetattr.obj_attributes=attrs;compound(put(openHandle),set);
    }
    public synchronized int write(long offset,int count,byte[] data) throws IOException {
        checkReadable();if(!writable||offset<0||count<0||count>data.length||offset>Long.MAX_VALUE-count)throw new IOException("Invalid writable range");
        int done=0;
        while(done<count){int amount=Math.min(writeSize,count-done);nfs_argop4 w=op(nfs_opnum4.OP_WRITE);w.opwrite=new WRITE4args();
            w.opwrite.stateid=openState;w.opwrite.offset=new offset4(offset+done);w.opwrite.stable=2;w.opwrite.data=ByteBuffer.wrap(data,done,amount).slice();
            long writeStart=System.nanoTime();WRITE4resok result=compound(put(openHandle),w).resarray.get(1).opwrite.resok4;
            if(result.count.value<=0||result.count.value>amount||result.committed<0||result.committed>2){closeTransport();throw new IOException("Invalid NFS WRITE response");}
            if(result.committed!=2){
                nfs_argop4 c=op(nfs_opnum4.OP_COMMIT);c.opcommit=new COMMIT4args();c.opcommit.offset=new offset4(offset+done);c.opcommit.count=new count4(result.count.value);
                verifier4 verified=compound(put(openHandle),c).resarray.get(1).opcommit.resok4.writeverf;
                if(!Arrays.equals(result.writeverf.value,verified.value)){closeTransport();throw new IOException("NFS write verifier changed before COMMIT; data durability lost");}
            }
            writeCalls++;writeBytes+=result.count.value;writeNanos+=System.nanoTime()-writeStart;done+=result.count.value;
        }
        return done;
    }
    public synchronized void fsync() throws IOException {
        checkReadable();if(!writable)return;nfs_argop4 c=op(nfs_opnum4.OP_COMMIT);c.opcommit=new COMMIT4args();c.opcommit.offset=new offset4(0);c.opcommit.count=new count4(0);compound(put(openHandle),c);
    }
    private void closeTransport(){closed=true;if(renewer!=null)renewer.shutdownNow();try{transport.close();}catch(IOException ignored){}gss.close();}
    /** Interrupt an outstanding socket operation without waiting for the client lock. */
    public void abort(){trace("connection.abort");closeTransport();}
    public synchronized void close(){trace("connection.close");
        if(renewer!=null)renewer.shutdownNow();
        if(!closed&&openState!=null&&leaseFailure==null)try{nfs_argop4 c=op(nfs_opnum4.OP_CLOSE);c.opclose=new CLOSE4args();c.opclose.seqid=new seqid4(0);c.opclose.open_stateid=openState;compound(put(openHandle),c);}catch(IOException ignored){}
        openState=null;
        if(!closed&&session!=null)try{nfs_argop4 destroy=op(nfs_opnum4.OP_DESTROY_SESSION);destroy.opdestroy_session=new DESTROY_SESSION4args();destroy.opdestroy_session.dsa_sessionid=session;session=null;compound(destroy);}catch(IOException ignored){}
        closeTransport();
    }
}
