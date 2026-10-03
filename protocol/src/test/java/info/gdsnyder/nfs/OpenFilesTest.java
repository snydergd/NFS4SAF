package info.gdsnyder.nfs;
import org.junit.jupiter.api.Test;
import java.util.concurrent.*;
import static org.junit.jupiter.api.Assertions.*;

class OpenFilesTest {
    @Test void lateShutdownCannotCloseNewDescriptorAndReleaseIsIdempotent(){
        OpenFiles files=new OpenFiles();OpenFiles.Lease first=files.acquire(),second=files.acquire();
        first.close();first.close();assertEquals(1,files.count());
        assertFalse(files.idleAt(files.generation()));second.close();
        long idle=files.generation();assertTrue(files.idleAt(idle));
        OpenFiles.Lease next=files.acquire();assertFalse(files.idleAt(idle));
        next.close();assertFalse(files.idleAt(idle));assertTrue(files.idleAt(files.generation()));
    }
    @Test void concurrentDescriptorClosesDoNotUnderflowOrStopActiveFile() throws Exception {
        OpenFiles files=new OpenFiles();OpenFiles.Lease survivor=files.acquire();
        ExecutorService executor=Executors.newFixedThreadPool(8);
        try{
            java.util.List<Future<?>> tasks=new java.util.ArrayList<>();
            for(int i=0;i<32;i++)tasks.add(executor.submit(()->{OpenFiles.Lease lease=files.acquire();for(int n=0;n<20;n++)lease.close();}));
            for(Future<?> task:tasks)task.get(5,TimeUnit.SECONDS);
            assertEquals(1,files.count());assertFalse(files.idleAt(files.generation()));
            survivor.close();assertEquals(0,files.count());assertTrue(files.idleAt(files.generation()));
        }finally{executor.shutdownNow();}
    }
}
