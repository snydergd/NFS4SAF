package info.gdsnyder.nfs.android;

import android.database.*;
import android.os.*;
import android.os.storage.StorageManager;
import android.provider.*;
import android.system.*;
import android.util.Base64;
import android.webkit.MimeTypeMap;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.*;
import info.gdsnyder.nfs.NfsClient;
import info.gdsnyder.nfs.ReadAhead;
import info.gdsnyder.nfs.WriteBehind;

/** SAF access to authenticated NFSv4.1/4.2 exports. */
public final class NfsDocumentsProvider extends DocumentsProvider {
    private static final String[] ROOTS={DocumentsContract.Root.COLUMN_ROOT_ID,DocumentsContract.Root.COLUMN_DOCUMENT_ID,
      DocumentsContract.Root.COLUMN_TITLE,DocumentsContract.Root.COLUMN_SUMMARY,DocumentsContract.Root.COLUMN_FLAGS,
      DocumentsContract.Root.COLUMN_MIME_TYPES};
    private static final String[] DOCS={DocumentsContract.Document.COLUMN_DOCUMENT_ID,DocumentsContract.Document.COLUMN_DISPLAY_NAME,
      DocumentsContract.Document.COLUMN_MIME_TYPE,DocumentsContract.Document.COLUMN_FLAGS,
      DocumentsContract.Document.COLUMN_SIZE,DocumentsContract.Document.COLUMN_LAST_MODIFIED};
    private static final int B64=Base64.URL_SAFE|Base64.NO_WRAP|Base64.NO_PADDING;
    @Override public boolean onCreate(){return true;}
    @Override public Cursor queryRoots(String[] projection){
        MatrixCursor result=new MatrixCursor(projection==null?ROOTS:projection);
        for(ExportConfig c:ExportStore.read(getContext()))if(c.exposed){
            MatrixCursor.RowBuilder row=result.newRow();
            add(row,result,DocumentsContract.Root.COLUMN_ROOT_ID,c.id);add(row,result,DocumentsContract.Root.COLUMN_DOCUMENT_ID,c.id+":root");
            add(row,result,DocumentsContract.Root.COLUMN_TITLE,c.label);
            add(row,result,DocumentsContract.Root.COLUMN_SUMMARY,(TicketVault.signedIn(c.id)||PasswordStore.has(getContext(),c.id))?c.host+c.path+" • "+c.security:"Sign in in NFS4SAF");
            add(row,result,DocumentsContract.Root.COLUMN_FLAGS,DocumentsContract.Root.FLAG_SUPPORTS_IS_CHILD|(c.readOnly?0:DocumentsContract.Root.FLAG_SUPPORTS_CREATE));
            add(row,result,DocumentsContract.Root.COLUMN_MIME_TYPES,"*/*");
        }
        result.setNotificationUri(getContext().getContentResolver(),DocumentsContract.buildRootsUri(ExportStore.AUTHORITY));return result;
    }
    private static final class Document {
        final ExportConfig config;final String path;
        Document(ExportConfig config,String path){this.config=config;this.path=path;}
    }
    private Document document(String id) throws FileNotFoundException {
        try {
            int colon=id.indexOf(':');if(colon<1)throw new IOException("Invalid document ID");
            String export=id.substring(0,colon),suffix=id.substring(colon+1);
            String path=suffix.equals("root")?"/":new String(Base64.decode(suffix,B64),StandardCharsets.UTF_8);
            String canonical="/"+String.join("/",NfsClient.components(path));
            if(path.equals("/")&&!suffix.equals("root")||!path.equals(canonical)||!suffix.equals("root")&&!suffix.equals(Base64.encodeToString(path.getBytes(StandardCharsets.UTF_8),B64)))throw new IOException("Invalid document path");
            for(ExportConfig c:ExportStore.read(getContext()))if(c.id.equals(export)&&c.exposed)return new Document(c,path);
            throw new IOException("Unknown or disabled export");
        }catch(Exception e){throw failure(e);}
    }
    private static String id(ExportConfig c,String path){return c.id+":"+(path.equals("/")?"root":Base64.encodeToString(path.getBytes(StandardCharsets.UTF_8),B64));}
    private static String mime(NfsClient.Entry entry){
        if(entry.directory())return DocumentsContract.Document.MIME_TYPE_DIR;
        int dot=entry.name.lastIndexOf('.');String type=dot<0?null:MimeTypeMap.getSingleton().getMimeTypeFromExtension(entry.name.substring(dot+1).toLowerCase(Locale.ROOT));
        return type==null?"application/octet-stream":type;
    }
    private static void row(MatrixCursor r,String id,String name,String mime,long size,long modified,int flags){
        MatrixCursor.RowBuilder row=r.newRow();add(row,r,DocumentsContract.Document.COLUMN_DOCUMENT_ID,id);
        add(row,r,DocumentsContract.Document.COLUMN_DISPLAY_NAME,name);add(row,r,DocumentsContract.Document.COLUMN_MIME_TYPE,mime);
        add(row,r,DocumentsContract.Document.COLUMN_FLAGS,flags);add(row,r,DocumentsContract.Document.COLUMN_SIZE,size);
        add(row,r,DocumentsContract.Document.COLUMN_LAST_MODIFIED,modified);
    }
    @Override public Cursor queryDocument(String id,String[] projection) throws FileNotFoundException {
        Document d=document(id);MatrixCursor r=new MatrixCursor(projection==null?DOCS:projection);
        if(d.path.equals("/")){row(r,id,d.config.label,DocumentsContract.Document.MIME_TYPE_DIR,0,0,d.config.readOnly?0:DocumentsContract.Document.FLAG_DIR_SUPPORTS_CREATE);return r;}
        NfsClient client=null;
        try{client=TicketVault.connect(getContext(),d.config);NfsClient.Entry e=client.stat(d.path);row(r,id,e.name,mime(e),e.size,e.modified,flags(d.config,e,false));return r;}
        catch(Exception e){throw failure(e);}finally{if(client!=null)TicketVault.release(client);}
    }
    @Override public boolean isChildDocument(String parent,String child){
        try{Document p=document(parent),c=document(child);return p.config.id.equals(c.config.id)&&!p.path.equals(c.path)&&c.path.startsWith(p.path.equals("/")?"/":p.path+"/");}
        catch(FileNotFoundException e){return false;}
    }
    @Override public Cursor queryChildDocuments(String parent,String[] projection,String sortOrder) throws FileNotFoundException {
        Document d=document(parent);NfsClient client=null;
        try{
            client=TicketVault.connect(getContext(),d.config);List<NfsClient.Entry> entries=client.list(d.path);
            entries.sort(Comparator.comparing((NfsClient.Entry e)->!e.directory()).thenComparing(e->e.name,String.CASE_INSENSITIVE_ORDER));
            MatrixCursor r=new MatrixCursor(projection==null?DOCS:projection);
            for(NfsClient.Entry e:entries)if(e.directory()||e.regular()){
                String path=(d.path.equals("/")?"/":d.path+"/")+e.name;row(r,id(d.config,path),e.name,mime(e),e.size,e.modified,flags(d.config,e,false));
            }
            r.setNotificationUri(getContext().getContentResolver(),DocumentsContract.buildChildDocumentsUri(ExportStore.AUTHORITY,parent));
            return r;
        }catch(Exception e){throw failure(e);}finally{if(client!=null)TicketVault.release(client);}
    }
    private static int flags(ExportConfig config,NfsClient.Entry entry,boolean root){
        if(config.readOnly)return 0;
        int f=root?0:DocumentsContract.Document.FLAG_SUPPORTS_DELETE|DocumentsContract.Document.FLAG_SUPPORTS_RENAME;
        return f|(entry.directory()?DocumentsContract.Document.FLAG_DIR_SUPPORTS_CREATE:DocumentsContract.Document.FLAG_SUPPORTS_WRITE);
    }
    private void writable(Document d) throws FileNotFoundException {if(d.config.readOnly)throw new FileNotFoundException("Export is configured read-only");}
    private void changed(Document d){
        getContext().getContentResolver().notifyChange(DocumentsContract.buildRootsUri(ExportStore.AUTHORITY),null);
        getContext().getContentResolver().notifyChange(DocumentsContract.buildDocumentUri(ExportStore.AUTHORITY,id(d.config,d.path)),null);
        String parent=d.path.equals("/")?"/":d.path.substring(0,d.path.lastIndexOf('/')+1);if(parent.length()>1)parent=parent.substring(0,parent.length()-1);
        getContext().getContentResolver().notifyChange(DocumentsContract.buildChildDocumentsUri(ExportStore.AUTHORITY,id(d.config,parent)),null);
    }
    @Override public String createDocument(String parent,String mimeType,String displayName) throws FileNotFoundException {
        Document d=document(parent);writable(d);NfsClient client=null;
        try{String path=NfsClient.childPath(d.path,displayName);client=TicketVault.connect(getContext(),d.config);
            if(DocumentsContract.Document.MIME_TYPE_DIR.equals(mimeType))client.mkdir(path);else client.createFile(path);
            changed(new Document(d.config,path));return id(d.config,path);
        }catch(Exception e){throw failure(e);}finally{if(client!=null)TicketVault.release(client);}
    }
    @Override public void deleteDocument(String documentId) throws FileNotFoundException {
        Document d=document(documentId);writable(d);NfsClient client=null;
        try{client=TicketVault.connect(getContext(),d.config);client.delete(d.path);changed(d);}
        catch(Exception e){throw failure(e);}finally{if(client!=null)TicketVault.release(client);}
    }
    @Override public String renameDocument(String documentId,String displayName) throws FileNotFoundException {
        Document d=document(documentId);writable(d);NfsClient client=null;
        try{client=TicketVault.connect(getContext(),d.config);client.rename(d.path,displayName);String parent=d.path.substring(0,d.path.lastIndexOf('/'));if(parent.isEmpty())parent="/";
            String path=NfsClient.childPath(parent,displayName);changed(d);changed(new Document(d.config,path));return id(d.config,path);
        }catch(Exception e){throw failure(e);}finally{if(client!=null)TicketVault.release(client);}
    }
    @Override public ParcelFileDescriptor openDocument(String id,String mode,CancellationSignal signal) throws FileNotFoundException {
        final String traceId=UUID.randomUUID().toString().substring(0,8);
        final long openStart=System.nanoTime();android.util.Log.d("NFS4SAFTrace",traceId+" open.begin mode="+mode);
        Document d=document(id);
        final boolean write=!"r".equals(mode),read="r".equals(mode)||"rw".equals(mode)||"rwt".equals(mode),append="wa".equals(mode);
        if(!Arrays.asList("r","w","wt","wa","rw","rwt").contains(mode))throw new FileNotFoundException("Unsupported open mode");
        if(write)writable(d);final AutoCloseable protection=ConnectionService.acquire(getContext());NfsClient connection=null;HandlerThread thread=null;
        try{
            if(signal!=null)signal.throwIfCanceled();connection=TicketVault.connect(getContext(),d.config);
            final NfsClient client=connection;client.setDiagnostics(message->android.util.Log.d("NFS4SAFTrace",traceId+" "+message));
            android.util.Log.d("NFS4SAFTrace",traceId+" open.connected ms="+((System.nanoTime()-openStart)/1000000));
            if(signal!=null)signal.setOnCancelListener(()->{android.util.Log.d("NFS4SAFTrace",traceId+" cancellation");client.abort();});
            NfsClient.Entry entry=client.stat(d.path);client.open(d.path,write?(read?3:2):1);
            final boolean truncate="w".equals(mode)||"wt".equals(mode)||"rwt".equals(mode);
            if(truncate)client.truncate(0);
            if(signal!=null)signal.throwIfCanceled();
            thread=new HandlerThread("nfs-saf-read");thread.start();final HandlerThread reader=thread;
            android.util.Log.d("NFS4SAFTrace",traceId+" open.ready size="+entry.size+" ms="+((System.nanoTime()-openStart)/1000000));
            final ReadAhead cache=new ReadAhead(client::read,entry.size,512*1024);
            final WriteBehind writes=new WriteBehind(client::write,512*1024);
            StorageManager storage=(StorageManager)getContext().getSystemService(android.content.Context.STORAGE_SERVICE);
            return storage.openProxyFileDescriptor(read?(write?ParcelFileDescriptor.MODE_READ_WRITE:ParcelFileDescriptor.MODE_READ_ONLY):ParcelFileDescriptor.MODE_WRITE_ONLY,new ProxyFileDescriptorCallback(){
                private final long started=System.nanoTime();
                private long lastLog=started;
                private long length=truncate?0:entry.size;
                @Override public long onGetSize(){android.util.Log.d("NFS4SAFTrace",traceId+" size="+length);return length;}
                @Override public int onWrite(long offset,int size,byte[] data) throws ErrnoException {
                    if(!write)throw new ErrnoException("NFS write",OsConstants.EBADF);
                    try{long at=append?length:offset;client.checkReadable();int n=writes.write(at,size,data);length=Math.max(length,at+n);cache.clear();long now=System.nanoTime();if(now-lastLog>=5000000000L){android.util.Log.d("NFS4SAFPerf",writes.stats()+" "+client.readStats());lastLog=now;}return n;}
                    catch(IOException e){throw new ErrnoException("NFS write",OsConstants.EIO,e);}
                }
                @Override public void onFsync() throws ErrnoException {
                    try{writes.flush();client.fsync();}catch(IOException e){throw new ErrnoException("NFS fsync",OsConstants.EIO,e);}
                }
                @Override public int onRead(long offset,int size,byte[] data) throws ErrnoException {
                    final long readStart=System.nanoTime();android.util.Log.d("NFS4SAFTrace",traceId+" read.begin offset="+offset+" requested="+size);
                    try{
                        if(!read)throw new IOException("Descriptor is not readable");
                        client.checkReadable();int count;
                        if(write){writes.flush();int wanted=(int)Math.min(Math.min(size,data.length),Math.max(0,length-offset));count=0;
                            while(count<wanted){byte[] part=client.read(offset+count,wanted-count);if(part.length==0)throw new IOException("Unexpected EOF before reported file size");System.arraycopy(part,0,data,count,part.length);count+=part.length;}}
                        else count=cache.read(offset,Math.min(size,data.length),data);
                        long now=System.nanoTime();if(now-lastLog>=5000000000L){
                            android.util.Log.d("NFS4SAFPerf","elapsedMs="+((System.nanoTime()-started)/1000000)+" "+cache.stats()+" "+client.readStats());lastLog=now;
                        }
                        android.util.Log.d("NFS4SAFTrace",traceId+" read.end offset="+offset+" returned="+count+" ms="+((System.nanoTime()-readStart)/1000000));return count;
                    }
                    catch(IOException e){android.util.Log.e("NFS4SAFTrace",traceId+" read.failure offset="+offset+" ms="+((System.nanoTime()-readStart)/1000000),e);throw new ErrnoException("NFS read",OsConstants.EIO,e);}
                }
                @Override public void onRelease(){android.util.Log.d("NFS4SAFTrace",traceId+" release elapsedMs="+((System.nanoTime()-openStart)/1000000));
                    try{if(write){writes.flush();client.fsync();}}
                    catch(IOException e){
                        android.util.Log.e("NFS4SAF", "Final write flush failed; upload is incomplete",e);
                        try{
                            File dir=new File(getContext().getFilesDir(),"failed-writes");if(!dir.exists()&&!dir.mkdirs())throw new IOException("Cannot create recovery directory");
                            String name=UUID.randomUUID().toString();
                            try(FileOutputStream out=new FileOutputStream(new File(dir,name+".bin"))){writes.savePending(out);out.getFD().sync();}
                            try(FileOutputStream out=new FileOutputStream(new File(dir,name+".txt"))){out.write((d.config.id+"\n"+d.path+"\n"+e.getMessage()).getBytes(StandardCharsets.UTF_8));out.getFD().sync();}
                        }catch(IOException recovery){android.util.Log.e("NFS4SAF","Could not retain failed write for recovery",recovery);}
                    }finally{
                        if(signal!=null)signal.setOnCancelListener(null);
                        android.util.Log.d("NFS4SAFPerf",writes.stats()+" "+client.readStats());writes.clear();cache.clear();
                        if(write)changed(d);TicketVault.release(client);reader.quitSafely();closeProtection(protection);
                    }
                }
            },new Handler(reader.getLooper()));
        }catch(Exception e){android.util.Log.e("NFS4SAFTrace",traceId+" open.failure",e);if(signal!=null)signal.setOnCancelListener(null);if(connection!=null)TicketVault.release(connection);if(thread!=null)thread.quitSafely();closeProtection(protection);throw failure(e);}
    }
    private static void closeProtection(AutoCloseable protection){try{protection.close();}catch(Exception e){android.util.Log.e("NFS4SAFTrace","connection.protection.release.failure",e);}}
    private static FileNotFoundException failure(Exception e){FileNotFoundException f=new FileNotFoundException(e.getMessage());f.initCause(e);return f;}
    private static void add(MatrixCursor.RowBuilder row,MatrixCursor cursor,String name,Object value){if(cursor.getColumnIndex(name)>=0)row.add(name,value);}
}
