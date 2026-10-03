package org.dcache.oncrpc4j.xdr;

import java.io.ByteArrayOutputStream;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;

/** Android-safe stream adapter for the unmodified ONCRPC4J XDR interfaces. */
public final class ByteArrayXdr implements XdrEncodingStream, XdrDecodingStream {
    public static final int MAX_BYTES = 4 * 1024 * 1024;
    private final ByteArrayOutputStream out;
    private final ByteBuffer in;
    public ByteArrayXdr() { out = new ByteArrayOutputStream(); in = null; }
    public ByteArrayXdr(byte[] bytes) {
        if (bytes.length > MAX_BYTES) throw new IllegalArgumentException("XDR message too large");
        in = ByteBuffer.wrap(bytes).order(ByteOrder.BIG_ENDIAN); out = null;
    }
    public byte[] bytes() { return out.toByteArray(); }
    public int remaining() { return in.remaining(); }
    public void requireEnd() throws BadXdrOncRpcException {
        if (remaining() != 0) throw new BadXdrOncRpcException("Trailing XDR bytes");
    }
    public void beginEncoding() {} public void endEncoding() {}
    public void beginDecoding() {} public void endDecoding() {}
    private void capacity(int n) {
        if (n < 0 || n > MAX_BYTES - out.size()) throw new IllegalArgumentException("XDR message too large");
    }
    private void need(int n) throws BadXdrOncRpcException {
        if (n < 0 || n > in.remaining()) throw new BadXdrOncRpcException("Truncated or oversized XDR field");
    }
    private int count(int width) throws BadXdrOncRpcException {
        int n = xdrDecodeInt();
        if (n < 0 || n > remaining()/width) throw new BadXdrOncRpcException("Invalid XDR array length");
        return n;
    }
    public void xdrEncodeInt(int v) {
        capacity(4); out.write(v >>> 24); out.write(v >>> 16); out.write(v >>> 8); out.write(v);
    }
    public int xdrDecodeInt() throws BadXdrOncRpcException { need(4); return in.getInt(); }
    public void xdrEncodeLong(long v) { xdrEncodeInt((int)(v >>> 32)); xdrEncodeInt((int)v); }
    public long xdrDecodeLong() throws BadXdrOncRpcException { need(8); return in.getLong(); }
    public void xdrEncodeBoolean(boolean v) { xdrEncodeInt(v ? 1 : 0); }
    public boolean xdrDecodeBoolean() throws BadXdrOncRpcException {
        int v=xdrDecodeInt(); if(v != 0 && v != 1) throw new BadXdrOncRpcException("Invalid XDR boolean"); return v==1;
    }
    public void xdrEncodeFloat(float v) { xdrEncodeInt(Float.floatToIntBits(v)); }
    public float xdrDecodeFloat() throws BadXdrOncRpcException { return Float.intBitsToFloat(xdrDecodeInt()); }
    public void xdrEncodeDouble(double v) { xdrEncodeLong(Double.doubleToLongBits(v)); }
    public double xdrDecodeDouble() throws BadXdrOncRpcException { return Double.longBitsToDouble(xdrDecodeLong()); }
    public void xdrEncodeByte(byte v) { xdrEncodeInt(v); }
    public byte xdrDecodeByte() throws BadXdrOncRpcException { return (byte)xdrDecodeInt(); }
    public void xdrEncodeShort(short v) { xdrEncodeInt(v); }
    public short xdrDecodeShort() throws BadXdrOncRpcException { return (short)xdrDecodeInt(); }
    public void xdrEncodeOpaque(byte[] v, int n) { xdrEncodeOpaque(v,0,n); }
    public void xdrEncodeOpaque(byte[] v, int offset, int n) {
        if (offset < 0 || n < 0 || offset > v.length-n) throw new IllegalArgumentException("Invalid opaque slice");
        int pad=(-n)&3; capacity(n+pad); out.write(v,offset,n); for(int i=0;i<pad;i++)out.write(0);
    }
    public byte[] xdrDecodeOpaque(int n) throws BadXdrOncRpcException {
        need(n); byte[] v=new byte[n]; xdrDecodeOpaque(v,0,n); return v;
    }
    public void xdrDecodeOpaque(byte[] v,int offset,int n) throws BadXdrOncRpcException {
        if(offset<0 || n<0 || offset>v.length-n)throw new BadXdrOncRpcException("Invalid opaque slice");
        need(n); in.get(v,offset,n); int pad=(-n)&3; need(pad); in.position(in.position()+pad);
    }
    public void xdrEncodeDynamicOpaque(byte[] v) { xdrEncodeInt(v.length); xdrEncodeOpaque(v,v.length); }
    public byte[] xdrDecodeDynamicOpaque() throws BadXdrOncRpcException { return xdrDecodeOpaque(xdrDecodeInt()); }
    public void xdrEncodeString(String v) { xdrEncodeDynamicOpaque(v.getBytes(StandardCharsets.UTF_8)); }
    public String xdrDecodeString() throws BadXdrOncRpcException { return new String(xdrDecodeDynamicOpaque(),StandardCharsets.UTF_8); }
    public void xdrEncodeByteBuffer(ByteBuffer b) { ByteBuffer v=b.duplicate(); byte[] bytes=new byte[v.remaining()]; v.get(bytes); xdrEncodeDynamicOpaque(bytes); }
    public ByteBuffer xdrDecodeByteBuffer() throws BadXdrOncRpcException { return ByteBuffer.wrap(xdrDecodeDynamicOpaque()); }
    public void xdrEncodeIntVector(int[] v) { xdrEncodeInt(v.length); xdrEncodeIntFixedVector(v,v.length); }
    public void xdrEncodeIntFixedVector(int[] v,int n) { if(n<0 || n>v.length)throw new IllegalArgumentException(); for(int i=0;i<n;i++)xdrEncodeInt(v[i]); }
    public int[] xdrDecodeIntVector() throws BadXdrOncRpcException { return xdrDecodeIntFixedVector(count(4)); }
    public int[] xdrDecodeIntFixedVector(int n) throws BadXdrOncRpcException { if(n<0 || n>remaining()/4)throw new BadXdrOncRpcException("Invalid array length"); int[] v=new int[n]; for(int i=0;i<n;i++)v[i]=xdrDecodeInt(); return v; }
    public void xdrEncodeLongVector(long[] v) { xdrEncodeInt(v.length); xdrEncodeLongFixedVector(v,v.length); }
    public void xdrEncodeLongFixedVector(long[] v,int n) { if(n<0 || n>v.length)throw new IllegalArgumentException(); for(int i=0;i<n;i++)xdrEncodeLong(v[i]); }
    public long[] xdrDecodeLongVector() throws BadXdrOncRpcException { return xdrDecodeLongFixedVector(count(8)); }
    public long[] xdrDecodeLongFixedVector(int n) throws BadXdrOncRpcException { if(n<0 || n>remaining()/8)throw new BadXdrOncRpcException("Invalid array length"); long[] v=new long[n]; for(int i=0;i<n;i++)v[i]=xdrDecodeLong(); return v; }
    public void xdrEncodeFloatVector(float[] v) { xdrEncodeInt(v.length); xdrEncodeFloatFixedVector(v,v.length); }
    public void xdrEncodeFloatFixedVector(float[] v,int n) { if(n<0 || n>v.length)throw new IllegalArgumentException(); for(int i=0;i<n;i++)xdrEncodeFloat(v[i]); }
    public float[] xdrDecodeFloatVector() throws BadXdrOncRpcException { return xdrDecodeFloatFixedVector(count(4)); }
    public float[] xdrDecodeFloatFixedVector(int n) throws BadXdrOncRpcException { if(n<0 || n>remaining()/4)throw new BadXdrOncRpcException("Invalid array length"); float[] v=new float[n]; for(int i=0;i<n;i++)v[i]=xdrDecodeFloat(); return v; }
    public void xdrEncodeDoubleVector(double[] v) { xdrEncodeInt(v.length); xdrEncodeDoubleFixedVector(v,v.length); }
    public void xdrEncodeDoubleFixedVector(double[] v,int n) { if(n<0 || n>v.length)throw new IllegalArgumentException(); for(int i=0;i<n;i++)xdrEncodeDouble(v[i]); }
    public double[] xdrDecodeDoubleVector() throws BadXdrOncRpcException { return xdrDecodeDoubleFixedVector(count(8)); }
    public double[] xdrDecodeDoubleFixedVector(int n) throws BadXdrOncRpcException { if(n<0 || n>remaining()/8)throw new BadXdrOncRpcException("Invalid array length"); double[] v=new double[n]; for(int i=0;i<n;i++)v[i]=xdrDecodeDouble(); return v; }
    public void xdrEncodeByteVector(byte[] v) { xdrEncodeInt(v.length); xdrEncodeByteFixedVector(v,v.length); }
    public void xdrEncodeByteFixedVector(byte[] v,int n) { if(n<0 || n>v.length)throw new IllegalArgumentException(); for(int i=0;i<n;i++)xdrEncodeByte(v[i]); }
    public byte[] xdrDecodeByteVector() throws BadXdrOncRpcException { return xdrDecodeByteFixedVector(count(4)); }
    public byte[] xdrDecodeByteFixedVector(int n) throws BadXdrOncRpcException { if(n<0 || n>remaining()/4)throw new BadXdrOncRpcException("Invalid array length"); byte[] v=new byte[n]; for(int i=0;i<n;i++)v[i]=xdrDecodeByte(); return v; }
    public void xdrEncodeShortVector(short[] v) { xdrEncodeInt(v.length); xdrEncodeShortFixedVector(v,v.length); }
    public void xdrEncodeShortFixedVector(short[] v,int n) { if(n<0 || n>v.length)throw new IllegalArgumentException(); for(int i=0;i<n;i++)xdrEncodeShort(v[i]); }
    public short[] xdrDecodeShortVector() throws BadXdrOncRpcException { return xdrDecodeShortFixedVector(count(4)); }
    public short[] xdrDecodeShortFixedVector(int n) throws BadXdrOncRpcException { if(n<0 || n>remaining()/4)throw new BadXdrOncRpcException("Invalid array length"); short[] v=new short[n]; for(int i=0;i<n;i++)v[i]=xdrDecodeShort(); return v; }
}
