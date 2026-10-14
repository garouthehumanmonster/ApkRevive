package com.apkrevive.canary.installfloor;

import android.app.Activity;
import android.os.Bundle;
import android.util.Log;

public class CanaryInstallFloorActivity extends Activity {
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        int targetSdk = getApplicationInfo().targetSdkVersion;
        String variant = (targetSdk >= 24) ? "control" : "failing";
        String line = "canary_install_floor variant=" + variant + " targetSdk=" + targetSdk;
        Log.i("ApkReviveCanary", line);
        System.out.println("ApkReviveCanary: " + line);
    }
}
