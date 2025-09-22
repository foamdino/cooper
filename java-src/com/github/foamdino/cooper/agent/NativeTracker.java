package com.github.foamdino.cooper.agent;

public class NativeTracker {
    public static native void onMethodEntry(String className, String methodName, String signature);
    public static native void onMethodExit(String className, String methodName, String signature);
}