"""Deterministic local catalog workload and server-side success oracle."""

from __future__ import annotations

import html
import json
import random
import re
import secrets
import threading
from dataclasses import dataclass
from urllib.parse import parse_qs, unquote, urlsplit

SESSION_RE = re.compile(r"^/s/([a-f0-9]{32})(?:/|$)")
CATALOG = (
    ("amber-mug", "Amber Mug", "kitchen"),
    ("cedar-lamp", "Cedar Desk Lamp", "home"),
    ("cloud-notebook", "Cloud Notebook", "office"),
    ("dune-bottle", "Dune Water Bottle", "outdoors"),
    ("fern-planter", "Fern Planter", "garden"),
    ("granite-tray", "Granite Serving Tray", "kitchen"),
    ("harbor-backpack", "Harbor Backpack", "outdoors"),
    ("indigo-pen", "Indigo Fountain Pen", "office"),
)
TERMS = ("amber", "cedar", "cloud", "dune", "fern", "granite", "harbor", "indigo")
DOCS = (
    ("accessibility", "Keyboard Navigation", "keyboard", "Tab", "Use Tab to move focus forward."),
    ("backups", "Backup Schedule", "backup", "daily", "The workspace is backed up daily."),
    ("retention", "Data Retention", "retention", "30 days",
     "Deleted drafts are retained for 30 days."),
    ("exports", "Export Formats", "export", "CSV", "Table exports are available as CSV files."),
    ("timezone", "Timezone Settings", "timezone", "UTC", "Audit timestamps are stored in UTC."),
    ("passwords", "Password Policy", "password", "12 characters",
     "Passwords must contain at least 12 characters."),
    ("sessions", "Session Expiry", "session", "8 hours",
     "An inactive browser session expires after 8 hours."),
    ("support", "Support Hours", "support", "09:00–17:00",
     "Support is available 09:00–17:00 local time."),
)
LARGE_ASSET = bytes((index * 31 + 17) % 256 for index in range(192 * 1024))


def cache_control_for_route(route: str) -> str:
    """Permit a narrow cache for immutable local assets; task state stays private."""
    if route in {"asset_css", "asset_js", "asset_image"}:
        return "public, max-age=3600"
    return "no-store"


HOME_PAGE = """<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>Beyond Handshake</title>
<style>
:root{color-scheme:dark;--bg:#0b1020;--panel:#141b2e;--ink:#edf2ff;--muted:#aab5ce;--line:#293450;--accent:#71e2c2}
*{box-sizing:border-box}body{margin:0;background:radial-gradient(ellipse at 85% 0%,#1a3150 0,transparent 38%),var(--bg);color:var(--ink);font:16px/1.6 system-ui,sans-serif}
main{width:min(900px,calc(100% - 36px));margin:8vh auto}.eyebrow{color:var(--accent);font-size:.78rem;letter-spacing:.16em;text-transform:uppercase}
h1{font-size:clamp(2.4rem,7vw,5rem);line-height:1.02;letter-spacing:-.045em;margin:.65rem 0 1rem;max-width:760px}
.lead{max-width:650px;color:var(--muted);font-size:1.12rem}.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:14px;margin:36px 0}
article{background:linear-gradient(145deg,#171f34,#11182a);border:1px solid var(--line);border-radius:16px;padding:20px}
article b{display:block;color:var(--accent);font-size:.78rem;letter-spacing:.1em;text-transform:uppercase;margin-bottom:8px}
article p{margin:0;color:var(--muted)}.status{border-top:1px solid var(--line);padding-top:18px;color:var(--muted);font-size:.92rem}
a{color:var(--accent)}code{color:#fff;background:#202b42;padding:.12em .4em;border-radius:5px}
</style></head><body><main><div class="eyebrow">Local network measurement prototype</div>
<h1>Beyond the TLS handshake.</h1><p class="lead">A controlled study scaffold for measuring what a browserless client reveals after it imitates browser TLS and HTTP/2 behavior.</p>
<section class="grid"><article><b>Transport</b><p>Loopback HTTPS endpoint with TLS 1.2+ and negotiated HTTP/1.1 or HTTP/2.</p></article>
<article><b>Observation</b><p>Ordered, redacted request headers plus structural HTTP/2 frame and SETTINGS events.</p></article>
<article><b>Shared workload</b><p>Deterministic local catalog task with a server-side success oracle for both protocols.</p></article></section>
<p class="status">Local research prototype. It records network-stack observations and does not infer AI identity or intent. <a href="/healthz">Health check</a></p>
</main></body></html>""".encode("utf-8")


@dataclass(slots=True)
class Session:
    seed: int
    term: str
    item_id: str
    nonce: str
    task_id: str
    expected_answer: str
    state: str = "registered"


class TaskOracle:
    """Owns labels-free task state; registration is handled by the local control plane."""

    def __init__(self) -> None:
        self._sessions: dict[str, Session] = {}
        self._lock = threading.RLock()

    def register(self, session_id: str, seed: int,
                 task_id: str = "catalog-search-detail-save-v1") -> dict:
        if not re.fullmatch(r"[a-f0-9]{32}", session_id):
            raise ValueError("session_id must be 32 lowercase hexadecimal characters")
        if not 0 <= seed <= 2**31 - 1:
            raise ValueError("seed must be between 0 and 2147483647")
        if task_id not in {"catalog-search-detail-save-v1", "docs-search-answer-v1"}:
            raise ValueError("unsupported task_id")
        rng = random.Random(seed)
        if task_id == "docs-search-answer-v1":
            item_id, _title, term, answer, _body = rng.choice(DOCS)
        else:
            term = rng.choice(TERMS)
            item_id, answer = next((item[0], "") for item in CATALOG if item[0].startswith(term))
        with self._lock:
            if session_id in self._sessions:
                raise ValueError("session_id is already registered")
            session = Session(seed, term, item_id, secrets.token_hex(16), task_id, answer)
            self._sessions[session_id] = session
        return {"session_id": session_id, "seed": seed, "task": self.task_spec(session_id)}

    def task_spec(self, session_id: str) -> dict:
        with self._lock:
            session = self._sessions.get(session_id)
            if session is None:
                raise KeyError("unknown session")
            if session.task_id == "docs-search-answer-v1":
                instructions = (f"Find the documentation for {session.term}; submit the answer shown "
                                "in its source.")
            else:
                instructions = f"Search for {session.term}; open the matching item and save it."
            return {"workload_id": session.task_id, "instructions": instructions,
                    "start_url": f"/s/{session_id}/start"}

    def outcome(self, session_id: str) -> dict:
        with self._lock:
            session = self._sessions.get(session_id)
            if session is None:
                raise KeyError("unknown session")
            return {"session_id": session_id, "state": session.state,
                    "task_success": session.state == "completed"}

    def handle(self, method: str, target: str, body: bytes = b"") -> tuple[int, bytes, str, str | None, str, list[dict]]:
        """Return status, bytes, MIME, session id, normalized route, transitions."""
        parsed = urlsplit(target)
        path = unquote(parsed.path)
        match = SESSION_RE.match(path)
        if not match:
            return self._static(method, path)
        session_id = match.group(1)
        suffix = path[len(match.group(0)) - (1 if match.group(0).endswith("/") else 0):]
        suffix = "/" + suffix.lstrip("/")
        with self._lock:
            state = self._sessions.get(session_id)
            if state is None:
                return 404, b'{"error":"Unknown session"}\n', "application/json", session_id, "unknown", []
            old_state = state.state
            status, response, mime, route = self._session_route(
                state, session_id, method, suffix, parsed.query, body
            )
            transition = []
            if state.state != old_state:
                transition.append({"old_state": old_state, "new_state": state.state,
                                  "validation": "accepted"})
            return status, response, mime, session_id, route, transition

    def _static(self, method: str, path: str) -> tuple[int, bytes, str, None, str, list[dict]]:
        if method in {"GET", "HEAD"} and path == "/healthz":
            return 200, b'{"status":"ok","phase":5}\n', "application/json", None, "healthz", []
        if method in {"GET", "HEAD"} and path == "/":
            return 200, HOME_PAGE, "text/html; charset=utf-8", None, "root", []
        return 404, b'{"error":"Route not found"}\n', "application/json", None, "not_found", []

    def _session_route(self, s: Session, session_id: str, method: str, path: str,
                       query: str, body: bytes) -> tuple[int, bytes, str, str]:
        if method == "GET" and path == "/start":
            if s.state == "registered":
                s.state = "started"
            is_docs = s.task_id == "docs-search-answer-v1"
            title = "Documentation search" if is_docs else "Local Catalog"
            action = ("Find the matching guidance and submit its answer." if is_docs
                      else "open the matching item, then save it.")
            page = ("<!doctype html><html><head><meta charset=utf-8><title>" + title + "</title>"
                    "<link rel=stylesheet href=\"assets/style.css\"></head><body><main>"
                    f"<h1>{title}</h1><p>Search for <b>{html.escape(s.term)}</b>, {action}</p>"
                    "<form id=search action=\"/s/" + session_id +
                    "/api/search\"><input name=q><button>Search</button></form><div id=result></div>"
                    "<script src=\"assets/app.js\"></script></main></body></html>")
            return 200, page.encode(), "text/html; charset=utf-8", "start"
        if method == "GET" and path == "/assets/style.css":
            return 200, b"body{font:16px system-ui;background:#f4f5f7;color:#172033}main{max-width:46rem;margin:4rem auto;background:white;padding:2rem;border-radius:1rem}button{padding:.5rem 1rem}", "text/css", "asset_css"
        if method == "GET" and path == "/assets/app.js":
            js = ("const search=document.querySelector('#search');if(search)search.addEventListener('submit',async e=>{e.preventDefault();"
                  "const data=new FormData(search);const u=new URL(search.action);u.search=new URLSearchParams(data);"
                  "const r=await fetch(u);const j=await r.json();const box=document.querySelector('#result');"
                  "box.replaceChildren();for(const item of j.items||[]){const a=document.createElement('a');a.href=item.url;a.textContent=item.name;box.append(a)}});"
                  "const save=document.querySelector('#save');if(save)save.addEventListener('submit',async e=>{e.preventDefault();"
                  "const data=new URLSearchParams(new FormData(save));await fetch(save.action,{method:'POST',body:data,"
                  "headers:{'Content-Type':'application/x-www-form-urlencoded'}});location.href=save.dataset.complete});"
                  "if(location.hash==='#autotask'){(async()=>{if(search){const q=document.querySelector('b')?.textContent||'';"
                  "const u=new URL(search.action,location.href);u.search=new URLSearchParams({q});const r=await fetch(u);"
                  "const j=await r.json();if(j.items?.length===1)location.href=j.items[0].url+'#autotask';}"
                  "else if(save){const answer=save.querySelector('input[name=answer]');if(answer)answer.value=document.querySelector('b')?.textContent||'';"
                  "const data=new URLSearchParams(new FormData(save));await fetch(save.action,{method:'POST',body:data,"
                  "headers:{'Content-Type':'application/x-www-form-urlencoded'}});"
                  "location.href=save.dataset.complete;}})().catch(console.error);}")
            return 200, js.encode(), "text/javascript", "asset_js"
        if method == "GET" and path == "/assets/large.bin":
            return 200, LARGE_ASSET, "application/octet-stream", "asset_large"
        if method == "GET" and path.startswith("/assets/img/") and path.endswith(".svg"):
            item_id = path.removeprefix("/assets/img/").removesuffix(".svg")
            item = next((row for row in CATALOG if row[0] == item_id), None)
            if item is None:
                return 404, b"not found\n", "text/plain", "asset_image"
            hue = sum(item_id.encode("ascii")) % 360
            svg = (f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 320 200">'
                   f'<rect width="320" height="200" rx="24" fill="hsl({hue},48%,36%)"/>'
                   '<circle cx="160" cy="82" r="42" fill="hsl(42,82%,72%)"/>'
                   f'<text x="160" y="158" text-anchor="middle" fill="white" font-family="sans-serif" font-size="16">{html.escape(item[1])}</text>'
                   '</svg>').encode()
            return 200, svg, "image/svg+xml", "asset_image"
        if method == "GET" and path == "/favicon.ico":
            return 204, b"", "image/x-icon", "favicon"
        if method == "GET" and path == "/api/search":
            q = parse_qs(query).get("q", [""])[0].casefold()
            if s.state not in {"started", "searched", "selected", "saved", "completed"}:
                return 409, b'{"error":"Start the task first"}\n', "application/json", "search_api"
            if q != s.term:
                return 200, b'{"items":[]}\n', "application/json", "search_api"
            if s.state == "started":
                s.state = "searched"
            if s.task_id == "docs-search-answer-v1":
                doc = next(row for row in DOCS if row[0] == s.item_id)
                item = (doc[0], doc[1])
            else:
                item = next((row[0], row[1]) for row in CATALOG if row[0] == s.item_id)
            return 200, json.dumps({"items": [{"id": item[0], "name": item[1],
                                 "url": f"/s/{session_id}/item/{item[0]}"}]}).encode(), "application/json", "search_api"
        if method == "GET" and path.startswith("/item/"):
            item_id = path.rsplit("/", 1)[-1]
            if item_id != s.item_id or s.state not in {"searched", "selected", "saved", "completed"}:
                return 409, b'{"error":"Item is not available in this task state"}\n', "application/json", "detail"
            if s.state == "searched":
                s.state = "selected"
            if s.task_id == "docs-search-answer-v1":
                doc = next(row for row in DOCS if row[0] == item_id)
                page = (f"<!doctype html><html><head><title>{html.escape(doc[1])}</title>"
                        "<script defer src=\"../assets/app.js\"></script></head><body>"
                        f"<h1>{html.escape(doc[1])}</h1><p>{html.escape(doc[4])}</p>"
                        f"<p>Submit the documented value: <b>{html.escape(s.expected_answer)}</b></p>"
                        f"<form id=save data-complete=\"/s/{session_id}/complete\" method=post "
                        f"action=\"/s/{session_id}/api/save\"><input type=hidden name=item_id value=\"{item_id}\">"
                        f"<input type=hidden name=nonce value=\"{s.nonce}\"><label>Answer "
                        "<input name=answer value=\"\"></label>"
                        "<button>Submit answer</button></form></body></html>")
            else:
                item = next(row for row in CATALOG if row[0] == item_id)
                page = (f"<!doctype html><html><head><title>{html.escape(item[1])}</title>"
                        "<script defer src=\"../assets/app.js\"></script></head><body>"
                        f"<h1>{html.escape(item[1])}</h1><img alt=\"{html.escape(item[1])}\" src=\"../assets/img/{item_id}.svg\">"
                        f"<form id=save data-complete=\"/s/{session_id}/complete\" "
                        f"method=post action=\"/s/{session_id}/api/save\"><input type=hidden name=item_id value=\"{item_id}\">"
                        f"<input type=hidden name=nonce value=\"{s.nonce}\"><button>Save</button></form></body></html>")
            return 200, page.encode(), "text/html; charset=utf-8", "detail"
        if method == "POST" and path == "/api/save":
            data = parse_qs(body.decode("utf-8", "replace"))
            if s.state in {"saved", "completed"}:
                return 200, b'{"saved":true,"duplicate":true}\n', "application/json", "save_api"
            valid = (s.state == "selected" and data.get("item_id") == [s.item_id]
                     and data.get("nonce") == [s.nonce])
            if s.task_id == "docs-search-answer-v1":
                valid = valid and data.get("answer") == [s.expected_answer]
            if not valid:
                return 409, b'{"error":"Save did not match the active task"}\n', "application/json", "save_api"
            s.state = "saved"
            return 200, b'{"saved":true,"duplicate":false}\n', "application/json", "save_api"
        if method == "GET" and path == "/complete":
            if s.state == "saved":
                s.state = "completed"
            if s.state != "completed":
                return 409, b'{"error":"Task is not complete"}\n', "application/json", "confirmation"
            return 200, b'{"task_success":true}\n', "application/json", "confirmation"
        return 404, b'{"error":"Route not found"}\n', "application/json", "unknown"
