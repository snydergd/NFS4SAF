package info.gdsnyder.nfs;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import org.dcache.nfs.v4.xdr.*;
import org.dcache.oncrpc4j.xdr.ByteArrayXdr;

/** Uses NFS4J's generated operations; no hand-written NFS wire structures. */
public final class NfsCompounds {
    public static COMPOUND4args rootAttributes() {
        nfs_argop4 root = new nfs_argop4(); root.argop = nfs_opnum4.OP_PUTROOTFH;
        nfs_argop4 attr = new nfs_argop4(); attr.argop = nfs_opnum4.OP_GETATTR;
        attr.opgetattr = new GETATTR4args();
        attr.opgetattr.attr_request = new bitmap4(new int[]{(1 << 1) | (1 << 4)}); // type,size
        COMPOUND4args c = new COMPOUND4args();
        c.tag = new utf8str_cs("root-probe");
        c.minorversion = new uint32_t(0); // NFSv4.0 diagnostic, no session required
        c.argarray = new nfs_argop4[]{root, attr};
        return c;
    }
    public static byte[] encode(COMPOUND4args c) throws IOException {
        ByteArrayXdr x = new ByteArrayXdr(); c.xdrEncode(x); return x.bytes();
    }
    private NfsCompounds() {}
}
