package info.gdsnyder.nfs.android;

import java.util.UUID;
import org.json.*;

final class ExportConfig {
    String id=UUID.randomUUID().toString(), label="NFS export", host="", path="/", realm="",kdc="",principal="",spn="";
    int port=2049,kdcPort=88;
    boolean exposed=false,readOnly=true;
    String security="krb5p";
    JSONObject json() throws JSONException {
        return new JSONObject().put("id",id).put("label",label).put("host",host).put("path",path)
          .put("realm",realm).put("kdc",kdc).put("principal",principal).put("spn",spn)
          .put("security",security).put("readOnly",readOnly).put("port",port).put("kdcPort",kdcPort).put("exposed",exposed);
    }
    static ExportConfig parse(JSONObject j) throws JSONException {
        ExportConfig c=new ExportConfig(); c.id=j.getString("id");c.label=j.getString("label");c.host=j.getString("host");
        c.path=j.getString("path");c.realm=j.getString("realm");c.kdc=j.getString("kdc");c.principal=j.getString("principal");
        c.spn=j.getString("spn");c.port=j.getInt("port");c.kdcPort=j.getInt("kdcPort");c.exposed=j.getBoolean("exposed");c.security=j.optString("security","krb5p");c.readOnly=j.optBoolean("readOnly",true);return c;
    }
    void validate() {
        if(label.isEmpty()||host.isEmpty()||realm.isEmpty()||kdc.isEmpty()||principal.isEmpty()||spn.isEmpty())
            throw new IllegalArgumentException("Fill in all configuration fields");
        if(port<1||port>65535||kdcPort<1||kdcPort>65535)throw new IllegalArgumentException("Ports must be 1–65535");
        if(!path.startsWith("/"))throw new IllegalArgumentException("Export path must start with /");
        for(String part:path.split("/"))if(part.equals(".."))throw new IllegalArgumentException("Export path cannot contain ..");
    }
}
