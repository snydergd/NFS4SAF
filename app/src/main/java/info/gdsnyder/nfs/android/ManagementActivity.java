package info.gdsnyder.nfs.android;

import android.app.*;
import android.os.Bundle;
import android.content.Intent;
import android.provider.DocumentsContract;
import android.text.InputType;
import android.widget.*;
import java.util.*;
import java.util.concurrent.*;
import info.gdsnyder.nfs.KerbyTickets;
import info.gdsnyder.nfs.NfsClient;
import org.apache.kerby.kerberos.kerb.type.ticket.SgtTicket;

public final class ManagementActivity extends Activity {
    private LinearLayout layout;
    private final ExecutorService worker=Executors.newSingleThreadExecutor();
    private boolean busy;
    private TextView batteryStatus;
    @Override public void onCreate(Bundle state) {
        super.onCreate(state);
        android.view.Window window=getWindow();
        window.clearFlags(android.view.WindowManager.LayoutParams.FLAG_TRANSLUCENT_STATUS|android.view.WindowManager.LayoutParams.FLAG_TRANSLUCENT_NAVIGATION);
        window.addFlags(android.view.WindowManager.LayoutParams.FLAG_DRAWS_SYSTEM_BAR_BACKGROUNDS);
        window.setStatusBarColor(android.graphics.Color.WHITE);window.setNavigationBarColor(android.graphics.Color.WHITE);
        window.getDecorView().setBackgroundColor(android.graphics.Color.WHITE);
        window.getDecorView().setSystemUiVisibility(android.view.View.SYSTEM_UI_FLAG_LAYOUT_STABLE|android.view.View.SYSTEM_UI_FLAG_LAYOUT_FULLSCREEN|android.view.View.SYSTEM_UI_FLAG_LAYOUT_HIDE_NAVIGATION|android.view.View.SYSTEM_UI_FLAG_LIGHT_STATUS_BAR|android.view.View.SYSTEM_UI_FLAG_LIGHT_NAVIGATION_BAR);
        showList();
    }
    private void page(String title) {
        batteryStatus=null;
        ScrollView scroll=new ScrollView(this);
        scroll.setBackgroundColor(android.graphics.Color.WHITE);
        scroll.setOnApplyWindowInsetsListener((view,insets)->{
            view.setPadding(insets.getSystemWindowInsetLeft(),insets.getSystemWindowInsetTop(),insets.getSystemWindowInsetRight(),insets.getSystemWindowInsetBottom());
            return insets.consumeSystemWindowInsets();
        });
        layout=new LinearLayout(this);layout.setOrientation(LinearLayout.VERTICAL);
        int p=(int)(16*getResources().getDisplayMetrics().density);layout.setPadding(p,p,p,p);scroll.addView(layout);setContentView(scroll);scroll.requestApplyInsets();
        text(title);
    }
    private void text(String value) {TextView t=new TextView(this);t.setText(value);layout.addView(t);}
    private Button button(String value,Runnable action) {Button b=new Button(this);b.setText(value);b.setOnClickListener(v->action.run());layout.addView(b);return b;}
    private EditText field(String label,String value) {text(label);EditText e=new EditText(this);e.setSingleLine(true);e.setText(value);layout.addView(e);return e;}
    private void showList() {
        page("NFS4SAF — development build");
        java.io.File recovery=new java.io.File(getFilesDir(),"failed-writes");
        String[] pending=recovery.list((dir,name)->name.endsWith(".bin"));
        if(pending!=null&&pending.length>0)text("WARNING: "+pending.length+" upload(s) failed during final flush. Pending write data was retained privately for recovery. Check NFS4SAF logs; do not assume these uploads completed.");
        text("NFSv4.1/4.2 browsing and file access. Sign in, enable the export in SAF, then open the Android file picker.");
        for(ExportConfig c:ExportStore.read(this))button(c.label+" — "+c.host+c.path,()->edit(c));
        button("Add export",()->edit(new ExportConfig()));
        button("Open Android file picker",()->startActivity(new Intent(Intent.ACTION_OPEN_DOCUMENT_TREE)));
        text("Background access");
        text("Protection keeps open files available to other apps. It stops after the last file closes.");
        CheckBox autoProtection=new CheckBox(this);autoProtection.setText("Automatically protect open files");autoProtection.setChecked(ConnectionService.automatic(this));layout.addView(autoProtection);
        autoProtection.setOnCheckedChangeListener((view,checked)->{
            ConnectionService.automatic(this,checked);
            if(checked&&android.os.Build.VERSION.SDK_INT>=33&&checkSelfPermission("android.permission.POST_NOTIFICATIONS")!=android.content.pm.PackageManager.PERMISSION_GRANTED)
                requestPermissions(new String[]{"android.permission.POST_NOTIFICATIONS"},41);
        });
        batteryStatus=new TextView(this);layout.addView(batteryStatus);updateBatteryStatus();
        button("Battery settings",this::openBatterySettings);
    }
    private boolean batteryExempt(){return ((android.os.PowerManager)getSystemService(POWER_SERVICE)).isIgnoringBatteryOptimizations(getPackageName());}
    private void updateBatteryStatus(){if(batteryStatus!=null)batteryStatus.setText(batteryExempt()?"Background access enabled. NFS connects only for browsing or open files; connections close when access finishes.":"Battery optimization can interrupt media playback. Allow background access for reliable streaming. Connections close when access finishes.");}
    private void openBatterySettings(){
        try{startActivity(new Intent(android.provider.Settings.ACTION_REQUEST_IGNORE_BATTERY_OPTIMIZATIONS,android.net.Uri.parse("package:"+getPackageName())));}
        catch(RuntimeException unavailable){
            try{startActivity(new Intent(android.provider.Settings.ACTION_IGNORE_BATTERY_OPTIMIZATION_SETTINGS));}
            catch(RuntimeException fallback){try{startActivity(new Intent(android.provider.Settings.ACTION_APPLICATION_DETAILS_SETTINGS,android.net.Uri.parse("package:"+getPackageName())));}catch(RuntimeException missing){Toast.makeText(this,"Open Android Settings, then Apps, NFS4SAF, and Battery usage.",Toast.LENGTH_LONG).show();}}
        }
    }
    private void suggestBackgroundAccess(){
        android.content.SharedPreferences prefs=getSharedPreferences("setup",MODE_PRIVATE);
        if(batteryExempt()||prefs.getBoolean("battery-prompt-shown",false)||ExportStore.read(this).isEmpty())return;
        prefs.edit().putBoolean("battery-prompt-shown",true).apply();
        new AlertDialog.Builder(this).setTitle("Keep playback working in the background")
            .setMessage("Android battery optimization can interrupt files played through other apps. Allow NFS4SAF to ignore battery optimization? NFS connections still close after browsing or file access finishes.")
            .setPositiveButton("Open settings",(dialog,which)->openBatterySettings()).setNegativeButton("Not now",null).show();
    }
    @Override protected void onResume(){super.onResume();updateBatteryStatus();suggestBackgroundAccess();}
    private void edit(ExportConfig c) {
        page("Configure export");
        EditText label=field("Name",c.label),host=field("NFS hostname",c.host),port=field("NFS port",String.valueOf(c.port));
        EditText path=field("NFSv4 pseudofilesystem path",c.path),realm=field("Realm",c.realm),kdc=field("KDC hostname",c.kdc);
        EditText kdcPort=field("KDC TCP port",String.valueOf(c.kdcPort)),principal=field("User principal",c.principal),spn=field("Service principal (nfs/host@REALM)",c.spn);
        text("RPC security");
        Spinner security=new Spinner(this);String[] modes={"krb5p","krb5i","krb5"};
        security.setAdapter(new ArrayAdapter<String>(this,android.R.layout.simple_spinner_dropdown_item,modes));
        security.setSelection(Arrays.asList(modes).indexOf(c.security));layout.addView(security);
        CheckBox readOnly=new CheckBox(this);readOnly.setText("Read only");readOnly.setChecked(c.readOnly);layout.addView(readOnly);
        CheckBox exposed=new CheckBox(this);exposed.setText("Show export in SAF");exposed.setChecked(c.exposed);layout.addView(exposed);
        EditText password=field("Password (blank uses saved password)","");password.setInputType(InputType.TYPE_CLASS_TEXT|InputType.TYPE_TEXT_VARIATION_PASSWORD);
        CheckBox remember=new CheckBox(this);remember.setText("Save password encrypted on this device for automatic ticket refresh");remember.setChecked(PasswordStore.has(this,c.id));layout.addView(remember);
        TextView status=new TextView(this);layout.addView(status);
        Runnable save=()->{
            c.label=label.getText().toString().trim();c.host=host.getText().toString().trim();c.port=Integer.parseInt(port.getText().toString());
            c.path=path.getText().toString().trim();c.realm=realm.getText().toString().trim();c.kdc=kdc.getText().toString().trim();
            c.kdcPort=Integer.parseInt(kdcPort.getText().toString());c.principal=principal.getText().toString().trim();c.spn=spn.getText().toString().trim();
            c.exposed=exposed.isChecked();c.security=(String)security.getSelectedItem();c.readOnly=readOnly.isChecked();c.validate();TicketVault.clear(c.id);if(!remember.isChecked())PasswordStore.forget(this,c.id);
            List<ExportConfig> all=ExportStore.read(this);all.removeIf(old->old.id.equals(c.id));all.add(c);ExportStore.save(this,all);
        };
        button("Save",()->{try{if(busy)return;save.run();status.setText("Saved");}catch(Exception e){status.setText(e.getMessage());}});
        button("Sign in and test NFS",()->{
            if(busy)return;
            try {save.run();}catch(Exception e){status.setText(e.getMessage());return;}
            final char[] pw;
            try{if(password.length()==0)pw=PasswordStore.load(this,c);else{pw=new char[password.length()];password.getText().getChars(0,password.length(),pw,0);}}
            catch(Exception e){status.setText(e.getMessage());return;}
            password.getText().clear();final boolean storePassword=remember.isChecked();
            busy=true;status.setText("Requesting service ticket and connecting to NFS…");
            worker.execute(()->{
                String message;
                try {SgtTicket t=KerbyTickets.acquire(c.realm,c.kdc,c.kdcPort,c.principal,c.spn,pw);
                    try(NfsClient client=new NfsClient(c.host,c.port,c.path,c.principal,t,c.security)){
                        int entries=client.list("/").size();if(storePassword)PasswordStore.save(this,c,pw);TicketVault.put(c.id,t);
                        message="Signed in. NFS directory readable: "+entries+" entries ("+c.security+").";
                    }catch(Exception e){Arrays.fill(t.getSessionKey().getKeyData(),(byte)0);throw e;}
                    getContentResolver().notifyChange(DocumentsContract.buildRootsUri(ExportStore.AUTHORITY),null);
                }catch(Exception e){message="Sign-in / NFS test failed: "+e.getClass().getSimpleName()+": "+e.getMessage();}
                finally{Arrays.fill(pw,'\0');}
                final String result=message;runOnUiThread(()->{busy=false;if(!isDestroyed()){status.setText(result);suggestBackgroundAccess();}});
            });
        });
        button("Sign out and forget password",()->{if(busy)return;PasswordStore.forget(this,c.id);remember.setChecked(false);TicketVault.clear(c.id);getContentResolver().notifyChange(DocumentsContract.buildRootsUri(ExportStore.AUTHORITY),null);status.setText("Signed out; open NFS connections revoked");});
        button("Delete export",()->{if(busy)return;List<ExportConfig> all=ExportStore.read(this);all.removeIf(old->old.id.equals(c.id));ExportStore.save(this,all);PasswordStore.forget(this,c.id);TicketVault.clear(c.id);showList();});
        button("Forget saved password",()->{if(busy)return;PasswordStore.forget(this,c.id);remember.setChecked(false);status.setText("Saved password removed; current ticket remains until sign-out or expiry");});
        button("Back",()->{if(!busy)showList();});
    }
    @Override protected void onDestroy(){worker.shutdown();super.onDestroy();}
}
