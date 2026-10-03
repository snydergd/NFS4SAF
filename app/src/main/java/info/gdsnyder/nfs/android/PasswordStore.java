package info.gdsnyder.nfs.android;
import android.content.*;
import android.security.keystore.*;
import android.util.Base64;
import java.io.IOException;
import java.nio.*;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.util.Arrays;
import javax.crypto.*;
import javax.crypto.spec.GCMParameterSpec;
/** Opt-in device-local credentials. Keys remain in Android Keystore; backup disabled. */
final class PasswordStore {
    private static SharedPreferences prefs(Context context){return context.getSharedPreferences("encrypted-passwords",Context.MODE_PRIVATE);}
    static boolean has(Context context,String id){return prefs(context).contains(id);}
    static void forget(Context context,String id){if(!prefs(context).edit().remove(id).commit())throw new IllegalStateException("Could not remove saved password");}
    private static byte[] binding(ExportConfig c){return (c.id+"\n"+c.host+"\n"+c.port+"\n"+c.realm+"\n"+c.kdc+"\n"+c.kdcPort+"\n"+c.principal+"\n"+c.spn+"\n"+c.security).getBytes(StandardCharsets.UTF_8);}
    private static synchronized SecretKey key() throws Exception {
        KeyStore store=KeyStore.getInstance("AndroidKeyStore");store.load(null);String alias="kerberos-nfs-passwords-v1";
        if(store.containsAlias(alias))return (SecretKey)store.getKey(alias,null);
        KeyGenerator generator=KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES,"AndroidKeyStore");
        generator.init(new KeyGenParameterSpec.Builder(alias,KeyProperties.PURPOSE_ENCRYPT|KeyProperties.PURPOSE_DECRYPT)
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM).setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE).setKeySize(256).build());
        return generator.generateKey();
    }
    static void save(Context context,ExportConfig config,char[] password) throws IOException {
        byte[] plain=null;
        try{ByteBuffer encoded=StandardCharsets.UTF_8.encode(CharBuffer.wrap(password));plain=new byte[encoded.remaining()];encoded.get(plain);if(encoded.hasArray())Arrays.fill(encoded.array(),(byte)0);
            Cipher cipher=Cipher.getInstance("AES/GCM/NoPadding");cipher.init(Cipher.ENCRYPT_MODE,key());cipher.updateAAD(binding(config));
            byte[] encrypted=cipher.doFinal(plain);String value=Base64.encodeToString(cipher.getIV(),Base64.NO_WRAP)+":"+Base64.encodeToString(encrypted,Base64.NO_WRAP);
            if(!prefs(context).edit().putString(config.id,value).commit())throw new IOException("Could not save encrypted password");
        }catch(Exception e){throw new IOException("Could not save password securely",e);}finally{if(plain!=null)Arrays.fill(plain,(byte)0);}
    }
    static char[] load(Context context,ExportConfig config) throws IOException {
        String value=prefs(context).getString(config.id,null);if(value==null)throw new IOException("No saved password; sign in first");byte[] plain=null;
        try{String[] parts=value.split(":");if(parts.length!=2)throw new IOException("Invalid saved credential");
            Cipher cipher=Cipher.getInstance("AES/GCM/NoPadding");cipher.init(Cipher.DECRYPT_MODE,key(),new GCMParameterSpec(128,Base64.decode(parts[0],Base64.NO_WRAP)));cipher.updateAAD(binding(config));
            plain=cipher.doFinal(Base64.decode(parts[1],Base64.NO_WRAP));CharBuffer decoded=StandardCharsets.UTF_8.decode(ByteBuffer.wrap(plain));char[] result=new char[decoded.remaining()];decoded.get(result);if(decoded.hasArray())Arrays.fill(decoded.array(),'\0');return result;
        }catch(Exception e){throw new IOException("Saved password unavailable or configuration changed; sign in again",e);}finally{if(plain!=null)Arrays.fill(plain,(byte)0);}
    }
}
