package info.gdsnyder.nfs;
import java.io.IOException;
import java.util.Arrays;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;
class ReadAheadTest {
    byte[] content(){byte[] b=new byte[1400000];for(int i=0;i<b.length;i++)b[i]=(byte)(i*31);return b;}
    @Test void smallSequentialReadsUseThreeFetchesAndReturnExactContent() throws Exception {
        byte[] original=content(),copied=new byte[original.length];AtomicInteger requests=new AtomicInteger();
        ReadAhead cache=new ReadAhead((offset,count)->{requests.incrementAndGet();return Arrays.copyOfRange(original,(int)offset,(int)offset+count);},original.length,512*1024);
        for(int offset=0;offset<copied.length;){byte[] chunk=new byte[8192];int n=cache.read(offset,chunk.length,chunk);assertTrue(n>0);System.arraycopy(chunk,0,copied,offset,n);offset+=n;}
        assertArrayEquals(original,copied);assertEquals(3,requests.get());assertEquals(0,cache.read(original.length,8,new byte[8]));
    }
    @Test void seeksAndShortNfsRepliesStillFillSafReads() throws Exception {
        byte[] original=content();ReadAhead cache=new ReadAhead((offset,count)->Arrays.copyOfRange(original,(int)offset,(int)offset+Math.min(count,17000)),original.length,512*1024);
        for(int offset:new int[]{0,520000,1300000,100,700000}){byte[] chunk=new byte[40000];assertEquals(chunk.length,cache.read(offset,chunk.length,chunk));assertArrayEquals(Arrays.copyOfRange(original,offset,offset+chunk.length),chunk);}
        cache.clear();byte[] chunk=new byte[8];assertEquals(8,cache.read(0,8,chunk));assertArrayEquals(Arrays.copyOf(original,8),chunk);
    }
    @Test void unexpectedEofIsReportedAndZeroReadsDoNotFetch() throws Exception {
        AtomicInteger requests=new AtomicInteger();ReadAhead cache=new ReadAhead((offset,count)->{requests.incrementAndGet();return new byte[0];},100,50);
        assertEquals(0,cache.read(0,0,new byte[0]));assertEquals(0,requests.get());assertThrows(IOException.class,()->cache.read(0,1,new byte[1]));
        assertThrows(IOException.class,()->cache.read(-1,1,new byte[1]));
    }
}
