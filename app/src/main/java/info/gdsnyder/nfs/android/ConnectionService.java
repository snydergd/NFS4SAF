package info.gdsnyder.nfs.android;

import android.app.*;
import android.content.*;
import android.os.*;
import android.util.Log;
import info.gdsnyder.nfs.OpenFiles;

/** Protection while SAF descriptors are open, including detached native descriptors. */
public final class ConnectionService extends Service {
    private static final String CHANNEL="nfs-connections";
    private static final int NOTIFICATION=41;
    private static final OpenFiles files=new OpenFiles();
    private static final Handler main=new Handler(Looper.getMainLooper());
    private static ConnectionService instance;
    private long idleGeneration;
    private final Runnable idle=()->{synchronized(files){if(files.idleAt(idleGeneration))finish();}};
    private boolean sawFile;

    public static boolean automatic(Context context){return context.getSharedPreferences("setup",Context.MODE_PRIVATE).getBoolean("automatic-protection",true);}
    public static void automatic(Context context,boolean enabled){context.getSharedPreferences("setup",Context.MODE_PRIVATE).edit().putBoolean("automatic-protection",enabled).apply();if(!enabled)stop(context);}
    public static AutoCloseable acquire(Context context){
        final OpenFiles.Lease lease=files.acquire();
        if(automatic(context))try{
            context.startForegroundService(new Intent(context,ConnectionService.class).putExtra("automatic",true));
            Log.d("NFS4SAFTrace","connection.service.auto.requested");
        }catch(RuntimeException e){
            Log.e("NFS4SAFTrace","connection.service.auto.rejected; enable battery exemption or start protection from the app",e);
        }
        main.post(()->{if(instance!=null)instance.update(true);});
        return ()->{lease.close();main.post(()->{if(instance!=null)instance.update(false);});};
    }
    public static void start(Context context){context.startForegroundService(new Intent(context,ConnectionService.class));}
    public static void stop(Context context){context.stopService(new Intent(context,ConnectionService.class));}
    @Override public void onCreate(){
        super.onCreate();instance=this;
        NotificationManager manager=(NotificationManager)getSystemService(NOTIFICATION_SERVICE);
        manager.createNotificationChannel(new NotificationChannel(CHANNEL,"NFS4SAF connections",NotificationManager.IMPORTANCE_LOW));
    }
    @Override public int onStartCommand(Intent intent,int flags,int startId){
        sawFile|=intent!=null&&intent.getBooleanExtra("automatic",false);
        try{startForeground(NOTIFICATION,notification());update(false);}
        catch(RuntimeException e){Log.e("NFS4SAFTrace","connection.service.start.failure",e);finish();}
        return START_NOT_STICKY;
    }
    private Notification notification(){
        Intent intent=new Intent(this,ManagementActivity.class);
        PendingIntent open=PendingIntent.getActivity(this,0,intent,PendingIntent.FLAG_UPDATE_CURRENT|PendingIntent.FLAG_IMMUTABLE);
        int count=files.count();
        return new Notification.Builder(this,CHANNEL).setSmallIcon(android.R.drawable.stat_sys_upload)
            .setContentTitle("NFS4SAF connection protection")
            .setContentText(count==0?(sawFile?"File access finished; stopping shortly":"Open a file within two minutes"):count+" open file(s)")
            .setContentIntent(open).setOngoing(true).setOnlyAlertOnce(true).build();
    }
    private void update(boolean opened){
        main.removeCallbacks(idle);int count=files.count();sawFile|=opened||count>0;
        ((NotificationManager)getSystemService(NOTIFICATION_SERVICE)).notify(NOTIFICATION,notification());
        Log.d("NFS4SAFTrace","connection.service.files="+count);
        if(count==0){idleGeneration=files.generation();main.postDelayed(idle,sawFile?5000:120000);}
    }
    private void finish(){stopForeground(true);stopSelf();}
    // API 35 callback; intentionally no @Override to support the API 27 compilation check.
    public void onTimeout(int startId,int serviceType){Log.w("NFS4SAFTrace","connection.service.timeout");finish();}
    @Override public void onDestroy(){main.removeCallbacks(idle);if(instance==this)instance=null;Log.d("NFS4SAFTrace","connection.service.stopped");super.onDestroy();}
    @Override public IBinder onBind(Intent intent){return null;}
}
