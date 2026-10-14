package com.apkrevive.canary.pagesize;

import android.app.Activity;
import android.os.Bundle;
import android.util.Log;

public class CanaryPageSizeActivity extends Activity {
    static {
        try {
            System.loadLibrary("canary_page_size");
        } catch (Throwable ignored) {}
    }

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        String line = "canary_page_size abi=arm64-v8a";
        Log.i("ApkReviveCanary", line);
        System.out.println("ApkReviveCanary: " + line);
    }
}
