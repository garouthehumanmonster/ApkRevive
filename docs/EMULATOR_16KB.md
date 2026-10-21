# Android 15+ 16KB Page-Size Emulator Guide

This guide details requirements and commands for verifying Android applications and ApkRevive pipelines against Android 15 (API 35+) 16KB page-size emulator environments.

## 1. System Requirements & Virtualization

The 16KB page size emulator requires hardware acceleration and 64-bit virtualization.

### Linux
- CPU with Intel VT-x or AMD-V enabled in BIOS/UEFI.
- KVM kernel module loaded (`kvm_intel` or `kvm_amd`).
- Read/write access to `/dev/kvm`. Add the current user to the `kvm` group:
  ```bash
  sudo usermod -aG kvm $USER
  ```

### Windows
- Windows 10/11 64-bit Pro, Enterprise, or Education.
- Hyper-V and Windows Hypervisor Platform (WHPX) features enabled:
  ```powershell
  Enable-WindowsOptionalFeature -Online -FeatureName HypervisorPlatform
  ```

### macOS
- Apple Silicon (M1/M2/M3/M4) or Intel x86_64 with Hypervisor.Framework.

---

## 2. Android SDK Setup

Install the required command-line tools, platform tools, and the Android 35 16KB Google APIs system image using `sdkmanager`:

```bash
# Accept SDK licenses
yes | sdkmanager --licenses

# Install platform tools and emulator engine
sdkmanager --install "platform-tools" "emulator" "cmdline-tools;latest"

# Install Android 15 (API 35) 16KB page-size x86_64 image
sdkmanager --install "system-images;android-35;google_apis_ps16k;x86_64"
```

---

## 3. Creating the 16KB AVD

Create the virtual device using `avdmanager`. We recommend the Pixel 8 device profile:

```bash
avdmanager create avd \
  -n android15_16kb \
  -k "system-images;android-35;google_apis_ps16k;x86_64" \
  --device "pixel_6" \
  --force
```

Configure optimal memory allocations in `~/.android/avd/android15_16kb.avd/config.ini`:
```ini
hw.ramSize = 4096
vm.heapSize = 512
```

---

## 4. Booting the Emulator

### Headless Execution (CI / Servers)
```bash
emulator -avd android15_16kb \
  -no-window \
  -no-audio \
  -no-snapshot \
  -gpu swiftshader_indirect
```

### Interactive Execution (Local Workstation)
```bash
emulator -avd android15_16kb \
  -no-audio \
  -no-snapshot
```

### Wait for Boot Completion
```bash
adb wait-for-device shell 'while [[ -z $(getprop sys.boot_completed) ]]; do sleep 1; done'
```

---

## 5. Verifying 16KB Kernel Page Size

Verify that the active kernel is running with a 16384-byte memory page size:

```bash
adb shell getconf PAGE_SIZE
```
Expected output:
```text
16384
```

Verify system properties:
```bash
adb shell getprop ro.product.cpu.pagesize
```
Expected output:
```text
16384
```

---

## 6. Running ApkRevive Verification Workflow

### 1. Environment Doctor
Verify ADB connectivity, platform targetSdk floor, and detected page size:
```bash
apkrevive doctor --device
```

### 2. Triage Evaluation
Evaluate candidate legacy APK against the live 16KB target:
```bash
apkrevive triage path/to/app.apk --device
```

### 3. Modernize & Patch
Run modernizer transforms:
```bash
apkrevive revive path/to/app.apk -o path/to/app-revived.apk
```

### 4. Deploy to Emulator
Install bypassing targetSdk floors when required:
```bash
apkrevive install path/to/app-revived.apk --device
```

---

## 7. Memory Mapping Alignment Forensics

When native libraries load on a 16KB kernel, `mmap` segments must be aligned to 16KB (0x4000) boundaries.

Inspect process memory mappings for native ELF binaries:
```bash
# Locate application process ID
PID=$(adb shell pidof com.example.package)

# Inspect memory mappings
adb shell cat /proc/$PID/maps | grep -E '\.so$'
```

The lowest 14 bits (3 hex digits) of starting virtual addresses must be zero (such as `0x7f...0000` or `0x7f...4000` or `0x7f...8000`).

---

## 8. Troubleshooting Linker Failures

If an unaligned 4KB ELF library is loaded on a 16KB kernel, the dynamic linker aborts with:
```text
dlopen failed: empty/missing PT_LOAD ... library has bad ELF alignment
```
Remediation:
- Recompile native code with `-Wl,-z,max-page-size=16384`.
- On Android 16 (API 36+), enable page size compat shim mode.
