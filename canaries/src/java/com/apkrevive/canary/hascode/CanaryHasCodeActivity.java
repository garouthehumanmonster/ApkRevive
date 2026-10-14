package com.apkrevive.canary.hascode;

import android.app.Activity;
import android.os.Bundle;
import android.util.Log;

public class CanaryHasCodeActivity extends Activity {
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        String line = "canary_has_code variant=control hasCode=true";
        Log.i("ApkReviveCanary", line);
        System.out.println("ApkReviveCanary: " + line);
    }
}
