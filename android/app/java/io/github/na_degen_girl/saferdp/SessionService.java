package io.github.na_degen_girl.saferdp;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.Service;
import android.content.Context;
import android.content.Intent;
import android.content.pm.ServiceInfo;
import android.os.Build;
import android.os.IBinder;

/**
 * Runs while a session's screen is out of sight, for as long as the session outlives that
 * (SessionActivity.GRACE_MS). It does nothing itself: an app with a foreground service is not
 * frozen, and Android (15 and later) closes a frozen app's connections, a few seconds after it
 * is left. A short service: that kind needs no permission of its own and may run for some three
 * minutes, more than the session is kept. The app does not ask to show notifications, so its
 * notification is not seen.
 */
public final class SessionService extends Service {
    private static final String CHANNEL = "session";
    // Both on the main thread only.
    /** Whether it should be running: stopped before it started, it stops as soon as it has. */
    private static boolean wanted;
    private static SessionService running;

    static void start(Context c) {
        wanted = true;
        try {
            c.startForegroundService(new Intent(c, SessionService.class));
        } catch (RuntimeException e) {
            // Not allowed to start it (the app counts as in the background already): as without
            // it, a connection Android closes is made again on return.
            wanted = false;
        }
    }

    static void stop() {
        wanted = false;
        if (running != null) running.stopSelf();
    }

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        // Always, also when it is to stop at once: a service started as this one is must.
        getSystemService(NotificationManager.class).createNotificationChannel(
                new NotificationChannel(CHANNEL, getString(R.string.session_channel), NotificationManager.IMPORTANCE_LOW));
        Notification n = new Notification.Builder(this, CHANNEL)
                .setSmallIcon(R.drawable.ic_stat)
                .setContentTitle(getString(R.string.session_kept))
                .setOngoing(true)
                .build();
        try {
            if (Build.VERSION.SDK_INT >= 34) startForeground(1, n, ServiceInfo.FOREGROUND_SERVICE_TYPE_SHORT_SERVICE);
            else startForeground(1, n);
            running = this;
        } catch (RuntimeException e) {
            wanted = false;
        }
        if (!wanted) stopSelf();
        return START_NOT_STICKY;
    }

    /** A short service has run for as long as it may (Android 14 and later). */
    @Override
    public void onTimeout(int startId) {
        stopSelf();
    }

    @Override
    public void onDestroy() {
        if (running == this) running = null;
        super.onDestroy();
    }

    @Override
    public IBinder onBind(Intent intent) {
        return null;
    }
}
