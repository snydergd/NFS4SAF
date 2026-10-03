package info.gdsnyder.nfs.android;
import android.test.AndroidTestCase;
import java.io.IOException;
import java.util.Arrays;
/** Requires an emulator/device: exercises the actual Android Keystore. */
public final class PasswordStoreDeviceTest extends AndroidTestCase {
    public void testRoundTripRandomizationAndRemoval() throws Exception {
        ExportConfig c=new ExportConfig();char[] password="device-test-password".toCharArray();
        try{PasswordStore.save(getContext(),c,password);assertTrue(PasswordStore.has(getContext(),c.id));
            String first=getContext().getSharedPreferences("encrypted-passwords",0).getString(c.id,null);
            char[] loaded=PasswordStore.load(getContext(),c);try{assertTrue(Arrays.equals(password,loaded));}finally{Arrays.fill(loaded,'\0');}
            PasswordStore.save(getContext(),c,password);String second=getContext().getSharedPreferences("encrypted-passwords",0).getString(c.id,null);assertFalse(first.equals(second));
            PasswordStore.forget(getContext(),c.id);assertFalse(PasswordStore.has(getContext(),c.id));
        }finally{PasswordStore.forget(getContext(),c.id);Arrays.fill(password,'\0');}
    }
    public void testChangedPrincipalAndTamperedCiphertextRejected() throws Exception {
        ExportConfig c=new ExportConfig();c.principal="alice@TEST.EXAMPLE";
        try{PasswordStore.save(getContext(),c,"secret".toCharArray());c.principal="bob@TEST.EXAMPLE";
            try{PasswordStore.load(getContext(),c);fail("Credential binding must reject a changed principal");}catch(IOException expected){}
            c.principal="alice@TEST.EXAMPLE";String encrypted=getContext().getSharedPreferences("encrypted-passwords",0).getString(c.id,null);
            String[] parts=encrypted.split(":");byte[] bytes=android.util.Base64.decode(parts[1],android.util.Base64.NO_WRAP);bytes[0]^=1;
            getContext().getSharedPreferences("encrypted-passwords",0).edit().putString(c.id,parts[0]+":"+android.util.Base64.encodeToString(bytes,android.util.Base64.NO_WRAP)).commit();
            try{PasswordStore.load(getContext(),c);fail("Tampered ciphertext must fail");}catch(IOException expected){}
        }finally{PasswordStore.forget(getContext(),c.id);}
    }
}
