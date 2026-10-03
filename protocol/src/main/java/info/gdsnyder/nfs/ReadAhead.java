package info.gdsnyder.nfs;

import java.io.IOException;

/** Per-open bounded cache: small sequential SAF reads share larger NFS fetches. */
public final class ReadAhead {
    public interface Source { byte[] read(long offset,int count) throws IOException; }
    private final Source source;
    private final long fileSize;
    private final byte[] cache;
    private long cacheOffset=-1, calls, servedBytes, hits, fetches;
    private int valid;
    public ReadAhead(Source source,long fileSize,int capacity){
        if(fileSize<0||capacity<=0)throw new IllegalArgumentException();
        this.source=source;this.fileSize=fileSize;cache=new byte[capacity];
    }
    public synchronized int read(long offset,int size,byte[] target) throws IOException {
        if(offset<0||size<0||size>target.length)throw new IOException("Invalid cached read range");
        calls++;int wanted=(int)Math.min(size,Math.max(0,fileSize-offset)),done=0;
        while(done<wanted){
            long position=offset+done;
            if(cacheOffset<0||position<cacheOffset||position-cacheOffset>=valid){
                cacheOffset=-1;valid=0;
                int fetch=(int)Math.min(cache.length,fileSize-position);
                // Fill short NFS responses too; SAF must return the requested size until EOF.
                while(valid<fetch){
                    byte[] bytes=source.read(position+valid,fetch-valid);fetches++;
                    if(bytes.length==0)throw new IOException("Unexpected EOF before reported NFS file size");
                    if(bytes.length>fetch-valid)throw new IOException("Excess read-ahead data");
                    System.arraycopy(bytes,0,cache,valid,bytes.length);valid+=bytes.length;
                }
                cacheOffset=position;
            }else hits++;
            int index=(int)(position-cacheOffset),count=Math.min(wanted-done,valid-index);
            System.arraycopy(cache,index,target,done,count);done+=count;
        }
        servedBytes+=done;return done;
    }
    public synchronized String stats(){return "safReads="+calls+" safBytes="+servedBytes+" cacheHits="+hits+" fetches="+fetches;}
    public synchronized void clear(){java.util.Arrays.fill(cache,(byte)0);valid=0;cacheOffset=-1;}
}
