package info.gdsnyder.nfs;
import java.io.IOException;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;
class CredentialSlotTest {
 @Test void concurrentRefreshUsesOneAcquisitionAndReusesValidTicket() throws Exception {
  AtomicInteger calls=new AtomicInteger();CredentialSlot<Long> slot=new CredentialSlot<>(v->v,v->{});slot.put(0L);ExecutorService workers=Executors.newFixedThreadPool(8);
  try{CountDownLatch go=new CountDownLatch(1);List<Future<Long>> futures=new ArrayList<>();for(int i=0;i<8;i++)futures.add(workers.submit(()->{go.await();return slot.fresh(()->{calls.incrementAndGet();return System.currentTimeMillis()+300000;});}));go.countDown();Long value=futures.get(0).get(5,TimeUnit.SECONDS);for(Future<Long> f:futures)assertEquals(value,f.get(5,TimeUnit.SECONDS));assertEquals(1,calls.get());}finally{workers.shutdownNow();}
 }
 @Test void signOutDuringRefreshRejectsAndDestroysNewTicket() throws Exception {
  AtomicInteger destroyed=new AtomicInteger();CredentialSlot<Long> slot=new CredentialSlot<>(v->v,v->destroyed.incrementAndGet());CountDownLatch entered=new CountDownLatch(1),release=new CountDownLatch(1);ExecutorService worker=Executors.newSingleThreadExecutor();
  try{Future<?> result=worker.submit(()->assertThrows(IOException.class,()->slot.fresh(()->{entered.countDown();assertTrue(release.await(5,TimeUnit.SECONDS));return System.currentTimeMillis()+300000;})));assertTrue(entered.await(5,TimeUnit.SECONDS));slot.clear();release.countDown();result.get(5,TimeUnit.SECONDS);assertNull(slot.peek());assertEquals(1,destroyed.get());}finally{release.countDown();worker.shutdownNow();}
 }
 @Test void failureAndExpiredTicketsDoNotEstablishCredentials() {
  CredentialSlot<Long> slot=new CredentialSlot<>(v->v,v->{});assertThrows(IOException.class,()->slot.fresh(()->{throw new IOException("bad password");}));assertNull(slot.peek());assertThrows(IOException.class,()->slot.fresh(()->0L));assertNull(slot.peek());
 }
}
