package info.gdsnyder.nfs;
import java.io.*;
import java.util.Arrays;
/** Bounded per-descriptor sequential write coalescing. Errors remain sticky. */
public final class WriteBehind {
    public interface Sink { int write(long offset,int count,byte[] data) throws IOException; }
    private final Sink sink;
    private final byte[] buffer;
    private long offset,calls,bytes,flushes;
    private int used;
    private IOException failure;
    public WriteBehind(Sink sink,int capacity){if(capacity<=0)throw new IllegalArgumentException();this.sink=sink;buffer=new byte[capacity];}
    private void healthy() throws IOException {if(failure!=null)throw new IOException("Previous buffered write failed",failure);}
    public synchronized int write(long at,int count,byte[] data) throws IOException {
        healthy();if(at<0||count<0||count>data.length||at>Long.MAX_VALUE-count)throw new IOException("Invalid write range");
        if(count==0)return 0;
        if(used>0&&at!=offset+used)flush();
        int done=0;
        while(done<count){if(used==0)offset=at+done;int n=Math.min(count-done,buffer.length-used);
            System.arraycopy(data,done,buffer,used,n);used+=n;done+=n;if(used==buffer.length)flush();}
        calls++;bytes+=count;return count;
    }
    public synchronized void flush() throws IOException {
        healthy();if(used==0)return;
        try{int done=0;while(done<used){byte[] data=Arrays.copyOfRange(buffer,done,used);int n=sink.write(offset+done,data.length,data);
                if(n<=0||n>data.length)throw new IOException("Invalid buffered write progress");done+=n;}
            Arrays.fill(buffer,0,used,(byte)0);used=0;flushes++;
        }catch(IOException e){failure=e;throw e;}
    }
    /** Retain bytes after a failed close flush for manual recovery; never auto-replay. */
    public synchronized void savePending(OutputStream output) throws IOException {
        DataOutputStream out=new DataOutputStream(output);out.writeInt(0x4e465357);out.writeLong(offset);out.writeInt(used);out.write(buffer,0,used);out.flush();
    }
    public synchronized void clear(){Arrays.fill(buffer,(byte)0);used=0;}
    public synchronized String stats(){return "safWrites="+calls+" safWriteBytes="+bytes+" writeFlushes="+flushes+" pendingWriteBytes="+used;}
}
