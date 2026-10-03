package info.gdsnyder.nfs.android;

import android.content.Context;
import android.provider.DocumentsContract;
import java.util.*;
import org.json.*;

final class ExportStore {
    static final String AUTHORITY="info.gdsnyder.nfs.android.documents";
    static List<ExportConfig> read(Context context) {
        try {
            JSONArray a=new JSONArray(context.getSharedPreferences("exports",0).getString("configs","[]"));
            List<ExportConfig> result=new ArrayList<>();for(int i=0;i<a.length();i++)result.add(ExportConfig.parse(a.getJSONObject(i)));return result;
        }catch(JSONException e){throw new IllegalStateException("Stored export configuration is invalid",e);}
    }
    static void save(Context context,List<ExportConfig> configs) {
        try {
            JSONArray a=new JSONArray();for(ExportConfig c:configs)a.put(c.json());
            if(!context.getSharedPreferences("exports",0).edit().putString("configs",a.toString()).commit())
                throw new IllegalStateException("Unable to save configuration");
            context.getContentResolver().notifyChange(DocumentsContract.buildRootsUri(AUTHORITY),null);
        }catch(JSONException e){throw new IllegalStateException(e);}
    }
}
