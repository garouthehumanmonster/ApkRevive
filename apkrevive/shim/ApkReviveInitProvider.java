package apkrevive.shim;

import android.app.Activity;
import android.app.Application;
import android.content.ContentProvider;
import android.content.ContentValues;
import android.content.Context;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageManager;
import android.database.Cursor;
import android.net.Uri;
import android.os.Build;
import android.os.Bundle;
import android.view.Display;
import android.view.WindowManager;

/**
 * ApkReviveInitProvider - Auto-initializing lifecycle shim for legacy APK modernization.
 * Injected into AndroidManifest.xml with android:initOrder="2147483647".
 * 
 * CRITICAL MANIFEST INVARIANT:
 * If an APK specifies android:hasCode="false", the Android runtime will completely ignore classes.dex,
 * preventing this ContentProvider from ever executing. The ApkRevive AXML Surgeon MUST rewrite
 * android:hasCode="true" whenever injecting this shim.
 */
public class ApkReviveInitProvider extends ContentProvider {

    private static final String META_ENABLE_60HZ = "apkrevive.enable_60hz_lock";
    private static final String META_ENABLE_CUTOUT = "apkrevive.enable_cutout_short_edges";

    @Override
    public boolean onCreate() {
        // 1. Reflection call to StrictMode.disableDeathOnFileUriExposure() (guards API 24+ FileUriExposedException)
        try {
            java.lang.reflect.Method m = android.os.StrictMode.class.getMethod("disableDeathOnFileUriExposure");
            m.invoke(null);
        } catch (Throwable ignored) {}

        // 2. Relax StrictMode.ThreadPolicy (permitAll for legacy apps doing synchronous I/O on main thread)
        try {
            android.os.StrictMode.setThreadPolicy(new android.os.StrictMode.ThreadPolicy.Builder().permitAll().build());
        } catch (Throwable ignored) {}

        // 3. Install fallback UncaughtExceptionHandler with ApkReviveShim diagnostic tag
        try {
            final Thread.UncaughtExceptionHandler defaultHandler = Thread.getDefaultUncaughtExceptionHandler();
            Thread.setDefaultUncaughtExceptionHandler(new Thread.UncaughtExceptionHandler() {
                @Override
                public void uncaughtException(Thread t, Throwable e) {
                    android.util.Log.e("ApkReviveShim", "CRITICAL EARLY STARTUP EXCEPTION in " + t.getName() + ": " + e.getMessage(), e);
                    if (defaultHandler != null) {
                        defaultHandler.uncaughtException(t, e);
                    }
                }
            });
        } catch (Throwable ignored) {}

        Context context = getContext();
        if (context == null) return false;

        Context appCtx = context.getApplicationContext();
        if (!(appCtx instanceof Application)) return false;
        Application app = (Application) appCtx;
        android.util.Log.i("ApkRevive", "ApkReviveInitProvider initialized for " + app.getPackageName());

        boolean enable60Hz = false;
        boolean enableCutout = false;

        try {
            ApplicationInfo ai = app.getPackageManager().getApplicationInfo(
                app.getPackageName(), PackageManager.GET_META_DATA);
            if (ai != null && ai.metaData != null) {
                Object v60 = ai.metaData.get(META_ENABLE_60HZ);
                if (v60 instanceof Boolean) {
                    enable60Hz = (Boolean) v60;
                } else if (v60 != null) {
                    enable60Hz = Boolean.parseBoolean(String.valueOf(v60));
                }
                Object vCutout = ai.metaData.get(META_ENABLE_CUTOUT);
                if (vCutout instanceof Boolean) {
                    enableCutout = (Boolean) vCutout;
                } else if (vCutout != null) {
                    enableCutout = Boolean.parseBoolean(String.valueOf(vCutout));
                }
            }
        } catch (PackageManager.NameNotFoundException ignored) {
        }

        final boolean final60Hz = enable60Hz;
        final boolean finalCutout = enableCutout;

        if (!final60Hz && !finalCutout) {
            return true;
        }

        app.registerActivityLifecycleCallbacks(new Application.ActivityLifecycleCallbacks() {
            @Override
            public void onActivityCreated(Activity activity, Bundle savedInstanceState) {}

            @Override
            public void onActivityStarted(Activity activity) {
                applyWindowAttributes(activity, final60Hz, finalCutout);
            }

            @Override
            public void onActivityResumed(Activity activity) {
                applyWindowAttributes(activity, final60Hz, finalCutout);
            }

            @Override public void onActivityPaused(Activity activity) {}
            @Override public void onActivityStopped(Activity activity) {}
            @Override public void onActivitySaveInstanceState(Activity activity, Bundle outState) {}
            @Override public void onActivityDestroyed(Activity activity) {}
        });

        return true;
    }

    private void applyWindowAttributes(Activity activity, boolean enable60Hz, boolean enableCutout) {
        if (activity == null || activity.getWindow() == null) return;

        WindowManager.LayoutParams lp = activity.getWindow().getAttributes();
        boolean changed = false;

        // 1. Cutout short edges (API 28+)
        if (enableCutout && Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            if (lp.layoutInDisplayCutoutMode != WindowManager.LayoutParams.LAYOUT_IN_DISPLAY_CUTOUT_MODE_SHORT_EDGES) {
                lp.layoutInDisplayCutoutMode = WindowManager.LayoutParams.LAYOUT_IN_DISPLAY_CUTOUT_MODE_SHORT_EDGES;
                changed = true;
                android.util.Log.i("ApkRevive", "Applied transform: CUTOUT_SHORT_EDGES on " + activity.getClass().getSimpleName());
            }
        }

        // 2. 60Hz display mode lock matching CURRENT display resolution (API 23+)
        if (enable60Hz) {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
                Display display = activity.getWindowManager().getDefaultDisplay();
                if (display != null) {
                    Display.Mode currentMode = display.getMode();
                    Display.Mode[] supportedModes = display.getSupportedModes();
                    if (currentMode != null && supportedModes != null) {
                        for (Display.Mode mode : supportedModes) {
                            if (mode.getPhysicalWidth() == currentMode.getPhysicalWidth() &&
                                mode.getPhysicalHeight() == currentMode.getPhysicalHeight() &&
                                Math.abs(mode.getRefreshRate() - 60.0f) < 1.0f) {
                                if (lp.preferredDisplayModeId != mode.getModeId()) {
                                    lp.preferredDisplayModeId = mode.getModeId();
                                    changed = true;
                                    android.util.Log.i("ApkRevive", "Applied transform: LOCK_60HZ_DISPLAY_MODE on " + activity.getClass().getSimpleName());
                                }
                                break;
                            }
                        }
                    }
                }
            } else if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.LOLLIPOP) {
                if (lp.preferredRefreshRate != 60.0f) {
                    lp.preferredRefreshRate = 60.0f;
                    changed = true;
                    android.util.Log.i("ApkRevive", "Applied transform: LOCK_60HZ_DISPLAY_MODE on " + activity.getClass().getSimpleName());
                }
            }
        }

        if (changed) {
            activity.getWindow().setAttributes(lp);
        }
    }

    @Override public Cursor query(Uri uri, String[] projection, String selection, String[] selectionArgs, String sortOrder) { return null; }
    @Override public String getType(Uri uri) { return null; }
    @Override public Uri insert(Uri uri, ContentValues values) { return null; }
    @Override public int delete(Uri uri, String selection, String[] selectionArgs) { return 0; }
    @Override public int update(Uri uri, ContentValues values, String selection, String[] selectionArgs) { return 0; }
}
