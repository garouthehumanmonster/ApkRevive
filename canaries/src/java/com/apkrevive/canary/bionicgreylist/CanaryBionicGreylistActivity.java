package com.apkrevive.canary.bionicgreylist;

import android.app.Activity;
import android.os.Bundle;
import android.util.Log;

public class CanaryBionicGreylistActivity extends Activity {
    static {
        try {
            System.loadLibrary("canary_bionic");
        } catch (Throwable ignored) {}
    }

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        int targetSdk = getApplicationInfo().targetSdkVersion;
        String variant = (targetSdk <= 22) ? "control" : "failing";
        String lib = (targetSdk <= 22) ? "libcrypto.so" : "libgui.so";
        String line = "canary_bionic_greylist variant=" + variant + " targetSdk=" + targetSdk + " lib=" + lib;
        Log.i("ApkReviveCanary", line);
        System.out.println("ApkReviveCanary: " + line);
    }
}
