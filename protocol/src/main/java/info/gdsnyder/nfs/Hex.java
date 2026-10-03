package info.gdsnyder.nfs;

/** Replacement for Java 17 HexFormat in vendored diagnostic toString methods. */
public final class Hex {
    public static String format(byte[] bytes) {
        char[] chars=new char[bytes.length*2];char[] digits="0123456789abcdef".toCharArray();
        for(int i=0;i<bytes.length;i++){chars[2*i]=digits[(bytes[i]&255)>>>4];chars[2*i+1]=digits[bytes[i]&15];}
        return new String(chars);
    }
    private Hex() {}
}
