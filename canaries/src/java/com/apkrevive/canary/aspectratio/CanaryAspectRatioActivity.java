package com.apkrevive.canary.aspectratio;

import android.app.Activity;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageManager;
import android.os.Bundle;
import android.util.Log;

public class CanaryAspectRatioActivity extends Activity {
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        boolean resizeable = true;
        String maxAspect = "none";
        try {
            ApplicationInfo ai = getPackageManager().getApplicationInfo(getPackageName(), PackageManager.GET_META_DATA);
            if (ai != null && ai.metaData != null) {
                float val = ai.metaData.getFloat("android.max_aspect", 0.0f);
                if (val > 0.0f) {
                    maxAspect = String.valueOf(val);
                    resizeable = false;
                }
            }
        } catch (Throwable ignored) {}
        String variant = "none".equals(maxAspect) ? "control" : "failing";
        String line = "canary_aspect_ratio variant=" + variant + " resizeableActivity=" + resizeable + " max_aspect=" + maxAspect;
        Log.i("ApkReviveCanary", line);
        System.out.println("ApkReviveCanary: " + line);
    }
}
