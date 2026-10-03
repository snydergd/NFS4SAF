package info.gdsnyder.nfs;

import java.io.*;
import java.net.*;
import org.dcache.oncrpc4j.xdr.ByteArrayXdr;

/** One outstanding RPC at a time; bounded ONC/RPC TCP record framing. */
public final class RpcTcp implements AutoCloseable {
    private final Socket socket;
    private final DataInputStream input;
    private final DataOutputStream output;
    public RpcTcp(String host,int port,int timeoutMillis) throws IOException {
        socket=new Socket();
        try { socket.connect(new InetSocketAddress(host,port),timeoutMillis);socket.setSoTimeout(timeoutMillis);socket.setTcpNoDelay(true);
            input=new DataInputStream(new BufferedInputStream(socket.getInputStream(),64*1024));output=new DataOutputStream(new BufferedOutputStream(socket.getOutputStream(),64*1024));
        }catch(IOException e){socket.close();throw e;}
    }
    public synchronized byte[] exchange(byte[] request) throws IOException {
        if(request.length>ByteArrayXdr.MAX_BYTES)throw new IOException("RPC record too large");
        try {
            output.writeInt(request.length|0x80000000);output.write(request);output.flush();
            return readRecord(input);
        } catch(IOException e) { socket.close();throw e; } // never reuse a partially read stream
    }
    static byte[] readRecord(DataInputStream in) throws IOException {
        ByteArrayOutputStream record=new ByteArrayOutputStream();
        for(int fragments=0;fragments<1024;fragments++) {
            int mark=in.readInt(),length=mark&0x7fffffff;
            if(length>ByteArrayXdr.MAX_BYTES-record.size())throw new IOException("RPC record too large");
            byte[] part=new byte[length];in.readFully(part);record.write(part);
            if(mark<0)return record.toByteArray();
        }
        throw new IOException("Too many RPC record fragments");
    }
    public void close() throws IOException {socket.close();}
}
