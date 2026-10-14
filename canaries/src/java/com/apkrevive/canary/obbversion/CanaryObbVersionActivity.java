package com.apkrevive.canary.obbversion;

import android.app.Activity;
import android.os.Bundle;
import android.util.Log;

public class CanaryObbVersionActivity extends Activity {
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        long vCode = 1;
        try {
            vCode = getPackageManager().getPackageInfo(getPackageName(), 0).versionCode;
        } catch (Throwable ignored) {}
        String variant = (vCode >= 150) ? "control" : "failing";
        int obbCode = (vCode >= 150) ? 100 : 200;
        String status = (vCode >= obbCode) ? "VALID" : "WARNING_AHEAD";
        String line = "canary_obb_version variant=" + variant + " apk_vcode=" + vCode + " obb_vcode=" + obbCode + " status=" + status;
        Log.i("ApkReviveCanary", line);
        System.out.println("ApkReviveCanary: " + line);
    }
}
