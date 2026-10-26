"""Local task runners: an ordinary HTTP control and verified curl_cffi profiles."""

from __future__ import annotations

import http.client
import html.parser
import json
import hashlib
import re
import platform
import shutil
import ssl
import subprocess
import tempfile
import os
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Protocol


class ClientRunner(Protocol):
    def execute(self, session_id: str, origin: str, ca_file: Path,
                timeout_seconds: float) -> "ExecutionResult": ...


@dataclass(frozen=True, slots=True)
class _Response:
    status: int
    body: bytes


@dataclass(slots=True)
class ExecutionResult:
    attempt_id: str
    session_id: str
    adapter_name: str
    adapter_version: str
    client_family: str
    library_ancestry: str
    profile_name: str | None
    claimed_browser_version: str | None
    controller: str
    start_wall_ns: int
    end_wall_ns: int
    task_success: bool
    observed_protocol: str | None = None
    steps: list[dict] = field(default_factory=list)
    failure_category: str | None = None
    error: str | None = None
    imitation_stage: int | None = None
    capabilities: dict = field(default_factory=dict)
    resource_metrics: dict = field(default_factory=dict)


class _PageParser(html.parser.HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.bold_text: list[str] = []
        self.in_bold = False
        self.inputs: dict[str, str] = {}

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag == "b":
            self.in_bold = True
        if tag == "input":
            values = dict(attrs)
            if values.get("name") and values.get("value") is not None:
                self.inputs[values["name"]] = values["value"] or ""

    def handle_endtag(self, tag: str) -> None:
        if tag == "b":
            self.in_bold = False

    def handle_data(self, data: str) -> None:
        if self.in_bold:
            self.bold_text.append(data.strip())


class _ResourceParser(html.parser.HTMLParser):
    """Collect ordinary resource references from the controlled task pages."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.resources: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        values = dict(attrs)
        if tag == "link" and "stylesheet" in (values.get("rel") or "").lower().split():
            value = values.get("href")
        elif tag in {"script", "img"}:
            value = values.get("src")
        else:
            value = None
        if value:
            self.resources.append(value)


def _discover_and_fetch_resources(client: object, page: object, base: str, session_id: str,
                                  deadline: float, cache: dict[str, tuple[bytes, float]],
                                  metrics: dict[str, int], limit: int = 32) -> None:
    """Fetch bounded same-origin HTML/CSS resources, honoring explicit max-age."""
    parser = _ResourceParser()
    parser.feed(getattr(page, "text", ""))
    queue = [urllib.parse.urljoin(getattr(page, "url", base + "/"), value)
             for value in parser.resources]
    seen: set[str] = set()
    allowed_prefix = f"/s/{session_id}/assets/"
    origin_parts = urllib.parse.urlsplit(base)
    while queue and len(seen) < limit:
        target = queue.pop(0)
        parsed = urllib.parse.urlsplit(target)
        normalized = urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, parsed.path, parsed.query, ""))
        if normalized in seen:
            continue
        seen.add(normalized)
        metrics["discovered"] += 1
        if (parsed.scheme != origin_parts.scheme or parsed.netloc != origin_parts.netloc
                or not parsed.path.startswith(allowed_prefix) or parsed.username or parsed.password):
            continue
        now = time.monotonic()
        cached = cache.get(normalized)
        if cached and cached[1] > now:
            body = cached[0]
            metrics["cache_hits"] += 1
        else:
            response = client.get(normalized, timeout=_remaining(deadline), allow_redirects=False)
            _require_ok(response.status_code)
            body = bytes(response.content)
            metrics["network_fetches"] += 1
            max_age = _cache_max_age(response.headers.get("Cache-Control", ""))
            if max_age:
                cache[normalized] = (body, now + max_age)
        if parsed.path.lower().endswith(".css"):
            css = body.decode("utf-8", "replace")
            css_refs = re.findall(r"url\(\s*(['\"]?)(.*?)\1\s*\)", css, re.I)
            for _quote, value in css_refs:
                value = value.strip()
                if value and not value.startswith("data:"):
                    queue.append(urllib.parse.urljoin(normalized, value))


def _cache_max_age(header: str) -> int:
    directives = [part.strip().lower() for part in header.split(",")]
    if "no-store" in directives or "private" in directives:
        return 0
    match = re.fullmatch(r"max-age\s*=\s*(\d+)", next(
        (part for part in directives if part.startswith("max-age")), ""))
    return min(int(match.group(1)), 86_400) if match else 0


def available_impersonation_profiles() -> list[str]:
    try:
        from curl_cffi.requests.impersonate import BrowserType
    except ImportError as exc:
        raise RuntimeError("optional dependency missing; install with `uv sync --extra impersonation`") from exc
    return sorted(profile.value for profile in BrowserType)


def run_curl_cffi(session_id: str, origin: str, ca_file: Path,
                  timeout_seconds: float, profile_name: str | None,
                  control_port: int | None = None, imitation_stage: int = 1) -> ExecutionResult:
    """Run the configured curl_cffi imitation stage against the local task only."""
    try:
        from curl_cffi import __version__ as version
        from curl_cffi import requests
    except ImportError as exc:
        raise RuntimeError("optional dependency missing; install with `uv sync --extra impersonation`") from exc
    if imitation_stage not in (0, 1, 2, 3):
        raise ValueError("curl_cffi supports imitation stages 0 through 3")
    if imitation_stage == 0 and profile_name is not None:
        raise ValueError("stage 0 must not select a browser impersonation profile")
    if imitation_stage >= 1:
        if not profile_name:
            raise ValueError("stage 1 requires an explicit curl_cffi browser profile")
        profiles = available_impersonation_profiles()
        if profile_name not in profiles:
            raise ValueError(f"unsupported profile {profile_name!r}; available: {', '.join(profiles)}")
    _validate_local_origin(origin, ca_file)
    started = time.time_ns()
    mono_deadline = time.monotonic() + timeout_seconds
    attempt = ExecutionResult(uuid.uuid4().hex, session_id, "curl_cffi", version,
                              "curl-impersonate", "curl_cffi → curl-impersonate → libcurl"
                              if imitation_stage >= 1 else "curl_cffi → libcurl (default settings)",
                              profile_name, _claimed_version(profile_name) if profile_name else None, "script",
                              started, started, False, imitation_stage=imitation_stage)
    attempt.capabilities = {
        "tls_profile": imitation_stage >= 1,
        "h2_profile": imitation_stage >= 1,
        "persistent_connections": imitation_stage >= 1,
        "cookie_jar": imitation_stage >= 1,
        "resource_discovery": imitation_stage >= 3,
        "http_cache": imitation_stage >= 3,
        "task_pacing": False,
        "stage_contrast_note": (
            "I2 is not distinct from I1 for this adapter: requests.Session already retains cookies "
            "and reuses connections; no additional toggle is introduced."
            if imitation_stage == 2 else None
        ),
    }
    attempt.resource_metrics = {"discovered": 0, "network_fetches": 0, "cache_hits": 0}
    base = origin.rstrip("/")
    try:
        session_options = {"verify": str(ca_file)}
        if imitation_stage >= 1:
            session_options["impersonate"] = profile_name
        with requests.Session(**session_options) as client:
            if imitation_stage >= 1:
                # Keep this header set explicit and versioned. It represents the
                # request-header component of stage 1, not proof of Chrome parity.
                client.headers.update({
                    "User-Agent": _profile_user_agent(profile_name),
                    "Accept-Language": "en-US,en;q=0.9",
                })
            start_path = f"/s/{session_id}/start"
            response = client.get(base + start_path, timeout=_remaining(mono_deadline),
                                  allow_redirects=False)
            _require_ok(response.status_code)
            attempt.steps.append({"route": "start", "status": response.status_code})
            resource_cache: dict[str, tuple[bytes, float]] = {}
            if imitation_stage >= 3:
                _discover_and_fetch_resources(client, response, base, session_id,
                                              mono_deadline, resource_cache,
                                              attempt.resource_metrics)
            parser = _PageParser()
            parser.feed(response.text)
            if not parser.bold_text:
                raise ValueError("start page did not contain the task search term")
            term = " ".join(x for x in parser.bold_text if x)
            search_url = base + f"/s/{session_id}/api/search?" + urllib.parse.urlencode({"q": term})
            response = client.get(search_url, timeout=_remaining(mono_deadline),
                                  allow_redirects=False)
            _require_ok(response.status_code)
            items = response.json().get("items", [])
            if len(items) != 1:
                raise ValueError("search did not return exactly one catalog item")
            attempt.steps.append({"route": "search_api", "status": response.status_code})
            item_path = _validated_item_path(items[0]["url"], session_id)
            response = client.get(base + item_path,
                                  timeout=_remaining(mono_deadline), allow_redirects=False)
            _require_ok(response.status_code)
            if imitation_stage >= 3:
                _discover_and_fetch_resources(client, response, base, session_id,
                                              mono_deadline, resource_cache,
                                              attempt.resource_metrics)
            parser = _PageParser()
            parser.feed(response.text)
            item_id, nonce = parser.inputs.get("item_id"), parser.inputs.get("nonce")
            if not item_id or not nonce:
                raise ValueError("detail page did not contain the task's save fields")
            attempt.steps.append({"route": "detail", "status": response.status_code})
            response = client.post(base + f"/s/{session_id}/api/save",
                                   data={"item_id": item_id, "nonce": nonce},
                                   timeout=_remaining(mono_deadline), allow_redirects=False)
            _require_ok(response.status_code)
            attempt.steps.append({"route": "save_api", "status": response.status_code})
            response = client.get(base + f"/s/{session_id}/complete",
                                  timeout=_remaining(mono_deadline), allow_redirects=False)
            _require_ok(response.status_code)
            attempt.steps.append({"route": "confirmation", "status": response.status_code})
            attempt.observed_protocol = _response_protocol(response)
        task_port = int(urllib.parse.urlsplit(origin).port or 443)
        outcome = read_task_outcome(session_id, control_port or task_port + 1)
        attempt.task_success = bool(outcome["task_success"])
        if not attempt.task_success:
            attempt.failure_category = "oracle_failure"
    except Exception as exc:
        attempt.failure_category = _failure_category(exc)
        attempt.error = f"{type(exc).__name__}: {exc}"
    finally:
        attempt.end_wall_ns = time.time_ns()
    return attempt


def run_stdlib(session_id: str, origin: str, ca_file: Path, timeout_seconds: float,
               control_port: int | None = None) -> ExecutionResult:
    """Ordinary trusted HTTP/1.1 control using one persistent stdlib connection."""
    _validate_local_origin(origin, ca_file)
    started = time.time_ns()
    deadline = time.monotonic() + timeout_seconds
    attempt = ExecutionResult(uuid.uuid4().hex, session_id, "stdlib-http.client",
                              platform.python_version(), "python-stdlib",
                              "Python http.client / ssl", None, None, "script",
                              started, started, False, imitation_stage=0)
    parsed_origin = urllib.parse.urlsplit(origin)
    host = parsed_origin.hostname or "localhost"
    port = parsed_origin.port or 443
    context = ssl.create_default_context(cafile=str(ca_file))
    context.set_alpn_protocols(["http/1.1"])
    connection = http.client.HTTPSConnection(host, port, context=context,
                                             timeout=timeout_seconds)
    try:
        start_path = f"/s/{session_id}/start"
        response = _stdlib_request(connection, "GET", start_path, deadline)
        attempt.steps.append({"route": "start", "status": response.status})
        parser = _PageParser()
        parser.feed(response.body.decode("utf-8"))
        if not parser.bold_text:
            raise ValueError("start page did not contain the task search term")
        term = " ".join(x for x in parser.bold_text if x)
        search_path = f"/s/{session_id}/api/search?" + urllib.parse.urlencode({"q": term})
        response = _stdlib_request(connection, "GET", search_path, deadline)
        items = json.loads(response.body).get("items", [])
        if response.status != 200 or len(items) != 1:
            raise ValueError("search did not return exactly one catalog item")
        attempt.steps.append({"route": "search_api", "status": response.status})
        item_path = _validated_item_path(items[0]["url"], session_id)
        response = _stdlib_request(connection, "GET", item_path, deadline)
        parser = _PageParser()
        parser.feed(response.body.decode("utf-8"))
        item_id, nonce = parser.inputs.get("item_id"), parser.inputs.get("nonce")
        if response.status != 200 or not item_id or not nonce:
            raise ValueError("detail page did not contain the task's save fields")
        attempt.steps.append({"route": "detail", "status": response.status})
        save_path = f"/s/{session_id}/api/save"
        save_body = urllib.parse.urlencode({"item_id": item_id, "nonce": nonce}).encode()
        response = _stdlib_request(connection, "POST", save_path, deadline, save_body,
                                   {"Content-Type": "application/x-www-form-urlencoded"})
        if response.status != 200:
            raise ValueError("save action was rejected")
        attempt.steps.append({"route": "save_api", "status": response.status})
        response = _stdlib_request(connection, "GET", f"/s/{session_id}/complete", deadline)
        if response.status != 200:
            raise ValueError("task confirmation was rejected")
        attempt.steps.append({"route": "confirmation", "status": response.status})
        attempt.observed_protocol = connection.sock.selected_alpn_protocol() if connection.sock else None
        outcome = read_task_outcome(session_id, control_port or port + 1)
        attempt.task_success = bool(outcome["task_success"])
        if not attempt.task_success:
            attempt.failure_category = "oracle_failure"
    except Exception as exc:
        attempt.failure_category = _failure_category(exc)
        attempt.error = f"{type(exc).__name__}: {exc}"
    finally:
        connection.close()
        attempt.end_wall_ns = time.time_ns()
    return attempt


def run_go_stdlib(session_id: str, origin: str, ca_file: Path, timeout_seconds: float,
                  control_port: int | None = None, binary_path: Path | None = None) -> ExecutionResult:
    """Run the same task with Go's independent net/http and crypto/tls stack."""
    _validate_local_origin(origin, ca_file)
    binary = binary_path or Path(__file__).resolve().parents[2] / "local/bin/bh-go-client"
    if not binary.is_file():
        raise RuntimeError("Go adapter is not built; run `go build -o ../../local/bin/bh-go-client .` "
                           "from clients/go_stdlib")
    version = subprocess.run([str(binary), "--version"], capture_output=True, text=True, timeout=5)
    if version.returncode:
        raise RuntimeError("could not query Go adapter version")
    started = time.time_ns()
    attempt = ExecutionResult(uuid.uuid4().hex, session_id, "go-stdlib",
                              version.stdout.strip(), "go-net-http", "Go net/http / crypto/tls",
                              None, None, "script", started, started, False, imitation_stage=0)
    try:
        completed = subprocess.run([str(binary), "--session", session_id, "--origin", origin,
                                    "--ca", str(ca_file.resolve()), "--timeout", f"{timeout_seconds}s"],
                                   capture_output=True, text=True, timeout=timeout_seconds + 5)
        result = json.loads(completed.stdout)
        attempt.steps = result.get("steps", [])
        attempt.observed_protocol = result.get("protocol")
        if completed.returncode or result.get("error"):
            raise ValueError(result.get("error") or f"Go adapter exited {completed.returncode}")
        port = int(urllib.parse.urlsplit(origin).port or 443)
        outcome = read_task_outcome(session_id, control_port or port + 1)
        attempt.task_success = bool(outcome["task_success"])
        if not attempt.task_success:
            attempt.failure_category = "oracle_failure"
    except Exception as exc:
        attempt.failure_category = _failure_category(exc)
        attempt.error = f"{type(exc).__name__}: {exc}"
    finally:
        attempt.end_wall_ns = time.time_ns()
    return attempt


def run_go_tls_client(session_id: str, origin: str, ca_file: Path, timeout_seconds: float,
                      profile_name: str, control_port: int | None = None,
                      binary_path: Path | None = None) -> ExecutionResult:
    """Run the pinned Go tls-client browser-profile adapter (stage 1)."""
    _validate_local_origin(origin, ca_file)
    if profile_name != "chrome_150":
        raise ValueError("Go tls-client currently supports only the pinned chrome_150 stage-1 profile")
    binary = binary_path or Path(__file__).resolve().parents[2] / "local/bin/bh-go-tls-client"
    if not binary.is_file():
        raise RuntimeError("Go tls-client adapter is not built; run `make go-tls-client`")
    version = subprocess.run([str(binary), "--version"], capture_output=True, text=True, timeout=5)
    if version.returncode:
        raise RuntimeError("could not query Go tls-client adapter version")
    started = time.time_ns()
    attempt = ExecutionResult(uuid.uuid4().hex, session_id, "go-tls-client", version.stdout.strip(),
                              "go-tls-client", "Go tls-client → fhttp / uTLS", profile_name,
                              "Chrome 150 profile target", "script", started, started, False,
                              imitation_stage=1)
    try:
        completed = subprocess.run([str(binary), "--session", session_id, "--origin", origin,
                                    "--ca", str(ca_file.resolve()), "--timeout", f"{timeout_seconds}s",
                                    "--profile", profile_name], capture_output=True, text=True,
                                   timeout=timeout_seconds + 5)
        result = json.loads(completed.stdout)
        attempt.steps = result.get("steps", [])
        attempt.observed_protocol = result.get("protocol")
        if completed.returncode or result.get("error"):
            raise ValueError(result.get("error") or f"Go tls-client exited {completed.returncode}")
        port = int(urllib.parse.urlsplit(origin).port or 443)
        outcome = read_task_outcome(session_id, control_port or port + 1)
        attempt.task_success = bool(outcome["task_success"])
        if not attempt.task_success:
            attempt.failure_category = "oracle_failure"
    except Exception as exc:
        attempt.failure_category = _failure_category(exc)
        attempt.error = f"{type(exc).__name__}: {exc}"
    finally:
        attempt.end_wall_ns = time.time_ns()
    return attempt


def run_firefox(session_id: str, origin: str, ca_file: Path, timeout_seconds: float,
                control_port: int | None = None) -> ExecutionResult:
    """Run a pinned local Firefox binary with an isolated profile and per-profile lab CA trust."""
    _validate_local_origin(origin, ca_file)
    binary = shutil.which("firefox")
    if not binary:
        raise RuntimeError("Firefox is not installed")
    source_root = _firefox_install_root(binary)
    source_executable = source_root / "firefox"
    version = subprocess.run([str(source_executable), "--version"], capture_output=True, text=True, timeout=10)
    if version.returncode:
        raise RuntimeError(f"could not query Firefox version: {version.stderr[-500:]}")
    started = time.time_ns()
    attempt = ExecutionResult(uuid.uuid4().hex, session_id, "firefox-headless",
                              version.stdout.strip(), "mozilla-firefox", "Mozilla Firefox / NSS / Gecko",
                              None, version.stdout.strip(), "script", started, started, False)
    browser_url = origin.rstrip("/") + f"/s/{session_id}/start#autotask"
    process = None
    try:
        with tempfile.TemporaryDirectory(prefix="bh-firefox-profile-") as directory:
            temporary_root = Path(directory)
            install = temporary_root / "firefox-install"
            shutil.copytree(source_root, install, copy_function=_link_or_copy, symlinks=True)
            profile = temporary_root / "profile"
            profile.mkdir()
            policy_dir = install / "distribution"
            policy_dir.mkdir(exist_ok=True)
            policy_dir.chmod(policy_dir.stat().st_mode | 0o700)
            policy = {"policies": {"Certificates": {"Install": [str(ca_file.resolve())]}}}
            (policy_dir / "policies.json").write_text(json.dumps(policy), encoding="utf-8")
            environment = dict(__import__("os").environ)
            environment["MOZ_HEADLESS"] = "1"
            install_executable = install / "firefox"
            process = subprocess.Popen([str(install_executable), "--headless", "--no-remote", "--new-instance",
                                        "--profile", str(profile), browser_url],
                                       stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                       stderr=subprocess.PIPE, text=True, env=environment)
            endpoint_port = int(urllib.parse.urlsplit(origin).port or 443)
            admin_port = control_port or endpoint_port + 1
            deadline = time.monotonic() + timeout_seconds
            last_error = None
            try:
                while time.monotonic() < deadline:
                    if process.poll() is not None:
                        details = process.stderr.read()[-1000:] if process.stderr else ""
                        raise RuntimeError(f"Firefox exited early ({process.returncode}): {details}")
                    try:
                        outcome = read_task_outcome(session_id, admin_port)
                        if outcome.get("task_success"):
                            attempt.task_success = True
                            attempt.observed_protocol = "see server connection events"
                            attempt.steps.append({"route": "oracle", "state": outcome.get("state")})
                            break
                    except (OSError, urllib.error.URLError):
                        last_error = "control plane not reachable yet"
                    time.sleep(0.25)
                else:
                    raise TimeoutError(f"Firefox task timed out; last control status: {last_error}")
            finally:
                _stop_process(process)
    except Exception as exc:
        attempt.failure_category = _failure_category(exc)
        attempt.error = f"{type(exc).__name__}: {exc}"
    finally:
        if process is not None:
            _stop_process(process)
        attempt.end_wall_ns = time.time_ns()
    attempt.steps.append({"firefox_binary_sha256": _file_sha256(source_executable),
                          "profile_isolation": "temporary; removed on exit",
                          "lab_ca_trust": "temporary install-tree enterprise policy"})
    return attempt


def _firefox_install_root(launcher: str) -> Path:
    candidates = [Path(launcher).resolve().parent / "../lib64/firefox",
                  Path("/usr/lib64/firefox"), Path("/usr/lib/firefox")]
    for candidate in candidates:
        root = candidate.resolve()
        if (root / "application.ini").is_file() and (root / "firefox").is_file():
            return root
    raise RuntimeError("could not locate Firefox application directory (application.ini)")


def _link_or_copy(source: str, destination: str) -> str:
    try:
        os.link(source, destination)
    except OSError:
        shutil.copy2(source, destination)
    return destination


def _stop_process(process: subprocess.Popen) -> None:
    if process.poll() is None:
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=3)


def _stdlib_request(connection: http.client.HTTPSConnection, method: str, path: str,
                    deadline: float, body: bytes | None = None,
                    headers: dict[str, str] | None = None) -> _Response:
    connection.timeout = _remaining(deadline)
    connection.request(method, path, body=body, headers=headers or {})
    response = connection.getresponse()
    payload = response.read(2 * 1024 * 1024 + 1)
    if len(payload) > 2 * 1024 * 1024:
        raise ValueError("response exceeded the client body limit")
    # Preserve the small response body for the route parser.
    if not 200 <= response.status < 300:
        raise ValueError(f"server returned HTTP {response.status}")
    return _Response(response.status, payload)


def _remaining(deadline: float) -> float:
    remain = deadline - time.monotonic()
    if remain <= 0:
        raise TimeoutError("task deadline exceeded")
    return remain


def _require_ok(status: int) -> None:
    if status != 200:
        raise ValueError(f"task endpoint returned HTTP {status}")


def _validated_item_path(value: str, session_id: str) -> str:
    parsed = urllib.parse.urlsplit(value)
    expected = f"/s/{session_id}/item/"
    if parsed.scheme or parsed.netloc or not parsed.path.startswith(expected) or parsed.query or parsed.fragment:
        raise ValueError("task item URL escaped the registered local session")
    return parsed.path


def _validate_local_origin(origin: str, ca_file: Path) -> None:
    parsed = urllib.parse.urlsplit(origin)
    if parsed.scheme != "https" or parsed.hostname not in {"localhost", "127.0.0.1", "::1"}:
        raise ValueError("client runners are restricted to the configured localhost HTTPS endpoint")
    if not ca_file.is_file():
        raise FileNotFoundError(f"trusted lab CA not found: {ca_file}")


def _claimed_version(profile: str | None) -> str | None:
    if not profile:
        return None
    for prefix in ("chrome", "edge", "firefox", "safari", "tor"):
        if profile.startswith(prefix):
            suffix = profile[len(prefix):].lstrip("_a")
            return suffix or None
    return None


def _profile_user_agent(profile: str | None) -> str:
    if profile and profile.startswith("chrome"):
        version = _claimed_version(profile) or "150"
        return ("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
                f"(KHTML, like Gecko) Chrome/{version}.0.0.0 Safari/537.36")
    if profile and profile.startswith("firefox"):
        version = _claimed_version(profile) or ""
        return f"Mozilla/5.0 (X11; Linux x86_64; rv:{version}) Gecko/20100101 Firefox/{version}"
    raise ValueError(f"no pinned request-header template for profile {profile!r}")


def _response_protocol(response: object) -> str | None:
    value = getattr(response, "http_version", None)
    if isinstance(value, str) and not value.isdigit():
        return value
    if isinstance(value, (int, str)) and str(value).isdigit():
        return {0: None, 1: "http/1.0", 2: "http/1.1", 3: "h2", 4: "h2",
                5: "h2", 30: "http/3", 31: "http/3"}.get(int(value))
    curl = getattr(response, "curl", None)
    getinfo = getattr(curl, "getinfo", None)
    if callable(getinfo):
        try:
            version = getinfo(2097198)  # libcurl CURLINFO_HTTP_VERSION
            return {2: "h2", 3: "http/3", 1: "http/1.1"}.get(int(version), str(version))
        except Exception:
            return None
    return None


def _failure_category(exc: Exception) -> str:
    if isinstance(exc, (TimeoutError,)):
        return "timeout"
    if isinstance(exc, (ssl.SSLError,)):
        return "tls_failure"
    if isinstance(exc, (OSError, urllib.error.URLError)):
        return "connection_failure"
    if isinstance(exc, ValueError):
        return "task_flow_failure"
    return "client_error"


def read_task_outcome(session_id: str, control_port: int) -> dict:
    request = urllib.request.Request(
        f"http://127.0.0.1:{control_port}/sessions/{session_id}/outcome"
    )
    with urllib.request.urlopen(request, timeout=3) as response:
        return json.load(response)


def write_attempt(result: ExecutionResult, output_dir: Path) -> Path:
    path = output_dir / f"{result.attempt_id}.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(asdict(result), indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return path


def _file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()
