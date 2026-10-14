package com.apkrevive.canary.apachehttp;

import android.app.Activity;
import android.os.Bundle;
import android.util.Log;

public class CanaryApacheHttpActivity extends Activity {
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        int targetSdk = getApplicationInfo().targetSdkVersion;
        String variant = (targetSdk <= 22) ? "control" : "failing";
        String status = "OK";
        try {
            Class<?> c = Class.forName("org.apache.http.HttpVersion");
            status = "FOUND";
        } catch (Throwable t) {
            status = "NO_USES_LIBRARY";
        }
        String line = "canary_apache_http variant=" + variant + " targetSdk=" + targetSdk + " uses_library=false status=" + status;
        Log.i("ApkReviveCanary", line);
        System.out.println("ApkReviveCanary: " + line);
    }
}
