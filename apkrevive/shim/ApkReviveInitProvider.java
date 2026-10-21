package com.apkrevive.shim;

import android.content.ContentProvider;
import android.content.ContentValues;
import android.database.Cursor;
import android.net.Uri;
import android.os.StrictMode;
import android.util.Log;
import java.lang.reflect.Method;

public class ApkReviveInitProvider extends ContentProvider {

    @Override
    public boolean onCreate() {
        // Hook A: API 24+ StrictMode & FileUriExposed Bypass
        try {
            try {
                Method disableDeath = StrictMode.class.getMethod("disableDeathOnFileUriExposure");
                disableDeath.invoke(null);
            } catch (Throwable ignored) {
            }

            try {
                StrictMode.setThreadPolicy(new StrictMode.ThreadPolicy.Builder().permitAll().build());
            } catch (Throwable t) {
                try {
                    StrictMode.setThreadPolicy(StrictMode.ThreadPolicy.LAX);
                } catch (Throwable ignored) {
                }
            }

            try {
                StrictMode.setVmPolicy(new StrictMode.VmPolicy.Builder().build());
            } catch (Throwable t) {
                try {
                    StrictMode.setVmPolicy(StrictMode.VmPolicy.LAX);
                } catch (Throwable ignored) {
                }
            }
        } catch (Throwable ignored) {
        }

        // Hook B: Hidden API Reflection Unlock via meta-reflection
        try {
            Method forNameMethod = Class.class.getDeclaredMethod("forName", String.class);
            Method getDeclaredMethodMethod = Class.class.getDeclaredMethod("getDeclaredMethod", String.class, Class[].class);

            Class<?> vmRuntimeClass = (Class<?>) forNameMethod.invoke(null, "dalvik.system.VMRuntime");
            Method getRuntimeMethod = (Method) getDeclaredMethodMethod.invoke(vmRuntimeClass, "getRuntime", null);
            Object vmRuntime = getRuntimeMethod.invoke(null);

            Method setHiddenApiExemptionsMethod = (Method) getDeclaredMethodMethod.invoke(
                vmRuntimeClass, "setHiddenApiExemptions", new Class<?>[]{String[].class}
            );
            setHiddenApiExemptionsMethod.invoke(vmRuntime, new Object[]{new String[]{"L"}});
        } catch (Throwable t) {
            Log.w("ApkRevive", "Failed to apply hidden API exemptions: " + t.getMessage());
        }

        Log.i("ApkRevive", "ApkReviveInitProvider initialized");
        return true;
    }

    @Override
    public Cursor query(Uri uri, String[] projection, String selection, String[] selectionArgs, String sortOrder) {
        return null;
    }

    @Override
    public String getType(Uri uri) {
        return null;
    }

    @Override
    public Uri insert(Uri uri, ContentValues values) {
        return null;
    }

    @Override
    public int delete(Uri uri, String selection, String[] selectionArgs) {
        return 0;
    }

    @Override
    public int update(Uri uri, ContentValues values, String selection, String[] selectionArgs) {
        return 0;
    }
}
