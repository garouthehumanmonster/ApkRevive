package com.apkrevive.canary.physicstick;

import android.app.Activity;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageManager;
import android.os.Bundle;
import android.util.Log;

public class CanaryPhysicsTickActivity extends Activity {
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        boolean locked60 = false;
        try {
            ApplicationInfo ai = getPackageManager().getApplicationInfo(getPackageName(), PackageManager.GET_META_DATA);
            if (ai != null && ai.metaData != null) {
                locked60 = ai.metaData.getBoolean("apkrevive.enable_60hz_lock", false);
            }
        } catch (Throwable ignored) {}
        String variant = locked60 ? "control" : "failing";
        String mode = locked60 ? "locked_60hz" : "free_running";
        String line = "canary_physics_tick variant=" + variant + " enable_60hz_lock=" + locked60 + " mode=" + mode;
        Log.i("ApkReviveCanary", line);
        System.out.println("ApkReviveCanary: " + line);
    }
}
