package info.gdsnyder.nfs;
import java.io.*;
import java.util.*;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;
class WriteBehindTest {
 @Test void sequentialSmallWritesCoalesceAndTailFlushes() throws Exception {
  byte[] output=new byte[1400000],input=new byte[output.length];new Random(42).nextBytes(input);int[] requests={0};
  WriteBehind w=new WriteBehind((offset,count,data)->{requests[0]++;System.arraycopy(data,0,output,(int)offset,count);return count;},512*1024);
  for(int at=0;at<input.length;at+=8192){byte[] b=Arrays.copyOfRange(input,at,Math.min(input.length,at+8192));w.write(at,b.length,b);}w.flush();
  assertArrayEquals(input,output);assertEquals(3,requests[0]);w.flush();assertEquals(3,requests[0]);
 }
 @Test void seekFlushesAndPartialSinkRepliesMakeProgress() throws Exception {
  byte[] output=new byte[100];WriteBehind w=new WriteBehind((at,count,data)->{int n=Math.min(3,count);System.arraycopy(data,0,output,(int)at,n);return n;},20);
  w.write(0,5,new byte[]{1,2,3,4,5});w.write(50,2,new byte[]{6,7});assertArrayEquals(new byte[]{1,2,3,4,5},Arrays.copyOf(output,5));w.flush();assertEquals(6,output[50]);assertEquals(7,output[51]);
 }
 @Test void flushFailureIsStickyAndPendingBytesCanBeRecovered() throws Exception {
  WriteBehind w=new WriteBehind((at,count,data)->{throw new IOException("offline");},20);w.write(10,3,new byte[]{1,2,3});assertThrows(IOException.class,w::flush);
  assertThrows(IOException.class,()->w.write(13,1,new byte[]{4}));ByteArrayOutputStream bytes=new ByteArrayOutputStream();w.savePending(bytes);
  DataInputStream in=new DataInputStream(new ByteArrayInputStream(bytes.toByteArray()));assertEquals(0x4e465357,in.readInt());assertEquals(10,in.readLong());assertEquals(3,in.readInt());byte[] pending=new byte[3];in.readFully(pending);assertArrayEquals(new byte[]{1,2,3},pending);
 }
}
