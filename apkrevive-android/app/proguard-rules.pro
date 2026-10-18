# Keep Shizuku class and private static newProcess method used reflectively by ShizukuPackageInstallerBridge
-keep class rikka.shizuku.Shizuku {
    private static rikka.shizuku.ShizukuRemoteProcess newProcess(java.lang.String[], java.lang.String[], java.lang.String);
}
