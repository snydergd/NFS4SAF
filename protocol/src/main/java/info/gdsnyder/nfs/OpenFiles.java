package info.gdsnyder.nfs;

/** Tracks descriptor ownership and fences delayed idle shutdowns against new opens. */
public final class OpenFiles {
    private int count;
    private long generation;
    public synchronized Lease acquire(){count++;generation++;return new Lease();}
    public synchronized int count(){return count;}
    public synchronized long generation(){return generation;}
    public synchronized boolean idleAt(long expected){return count==0&&generation==expected;}
    public final class Lease implements AutoCloseable {
        private boolean closed;
        @Override public void close(){synchronized(OpenFiles.this){if(!closed){closed=true;count--;generation++;}}}
    }
}
