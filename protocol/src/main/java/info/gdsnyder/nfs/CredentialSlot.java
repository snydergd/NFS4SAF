package info.gdsnyder.nfs;
import java.io.IOException;
import java.util.concurrent.Callable;
import java.util.function.Consumer;
import java.util.function.ToLongFunction;
/** Single-flight ticket refresh, with invalidation fencing against sign-out. */
public final class CredentialSlot<T> {
    private final Object refreshLock=new Object();
    private final ToLongFunction<T> expiry;
    private final Consumer<T> destroy;
    private T value;
    private long generation;
    public CredentialSlot(ToLongFunction<T> expiry,Consumer<T> destroy){this.expiry=expiry;this.destroy=destroy;}
    public synchronized T peek(){return value;}
    public synchronized long generation(){return generation;}
    public synchronized void clear(){generation++;if(value!=null)destroy.accept(value);value=null;}
    public synchronized void put(T next){clear();value=next;}
    public T fresh(Callable<T> acquire) throws IOException {
        synchronized(refreshLock){
            long before;
            synchronized(this){if(value!=null&&expiry.applyAsLong(value)>System.currentTimeMillis())return value;before=generation;}
            T next;
            try{next=acquire.call();}catch(Exception e){throw new IOException("Ticket refresh failed; sign in again",e);}
            synchronized(this){
                if(before!=generation){destroy.accept(next);throw new IOException("Signed out while refreshing ticket");}
                if(expiry.applyAsLong(next)<=System.currentTimeMillis()){destroy.accept(next);throw new IOException("KDC returned expired ticket");}
                if(value!=null)destroy.accept(value);value=next;return next;
            }
        }
    }
}
