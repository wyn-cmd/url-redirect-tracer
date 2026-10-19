#!/usr/bin/env python3
# URL Redirect Tracer - follow HTTP redirect chains and flag risky hops.

import argparse
import json
import sys
import urllib.error
import urllib.parse
import urllib.request

DEFAULT_USER_AGENT = "url-redirect-tracer/1.0 (+https://github.com/wyn-cmd/url-redirect-tracer)"
REDIRECT_CODES = (301, 302, 303, 307, 308)


# Refuse to follow redirects automatically so every hop can be inspected.
class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _normalize(url):
    # Canonical form used only for loop detection: lowercased scheme and host,
    # fragment removed, empty path promoted to "/"
    parts = urllib.parse.urlsplit(url)
    path = parts.path or "/"
    return urllib.parse.urlunsplit(
        (parts.scheme.lower(), parts.netloc.lower(), path, parts.query, "")
    )


def _cookie_names(headers):
    # Collect cookie names only. Values may be session tokens and are never
    # copied into the report.
    if headers is None:
        return []
    try:
        raw = headers.get_all("Set-Cookie") or []
    except AttributeError:
        single = headers.get("Set-Cookie")
        raw = [single] if single else []
    names = []
    for entry in raw:
        first = entry.split(";", 1)[0]
        if "=" not in first:
            continue
        name = first.split("=", 1)[0].strip()
        if name and name not in names:
            names.append(name)
    return names


def fetch_once(url, timeout=5.0, user_agent=DEFAULT_USER_AGENT):
    # Single request, no redirect following. Returns (status, headers, error).
    request = urllib.request.Request(
        url,
        method="GET",
        headers={"User-Agent": user_agent, "Accept": "*/*"},
    )
    opener = urllib.request.build_opener(_NoRedirectHandler())
    try:
        with opener.open(request, timeout=timeout) as response:
            status = getattr(response, "status", None) or response.getcode()
            return status, response.headers, None
    except urllib.error.HTTPError as exc:
        # 3xx responses arrive here because the redirect handler declined them.
        # A 4xx or 5xx also arrives here and is a legitimate final answer.
        return exc.code, exc.headers, None
    except urllib.error.URLError as exc:
        reason = getattr(exc, "reason", exc)
        return None, None, str(reason)
    except (TimeoutError, OSError) as exc:
        return None, None, str(exc)


def transition_warnings(current_url, next_url, visited):
    # Compare two consecutive URLs and return the kinds of concern they raise.
    kinds = []
    current = urllib.parse.urlsplit(current_url)
    nxt = urllib.parse.urlsplit(next_url)
    if current.scheme == "https" and nxt.scheme == "http":
        kinds.append("https_downgrade")
    if nxt.netloc and nxt.netloc.lower() != current.netloc.lower():
        kinds.append("cross_domain")
    if _normalize(next_url) in visited:
        kinds.append("redirect_loop")
    return kinds


def trace(start_url, max_hops=10, timeout=5.0, user_agent=DEFAULT_USER_AGENT):
    parts = urllib.parse.urlsplit(start_url)
    if parts.scheme not in ("http", "https") or not parts.netloc:
        raise ValueError("starting URL must be an absolute http or https URL")

    hops = []
    warnings = []
    visited = {_normalize(start_url)}
    current = start_url
    final_status = None
    error = None

    while len(hops) < max_hops:
        status, headers, failure = fetch_once(current, timeout, user_agent)
        if failure is not None:
            error = failure
            warnings.append({"kind": "request_error", "url": current, "detail": failure})
            break

        hop = {
            "url": current,
            "status": status,
            "location": headers.get("Location") if headers is not None else None,
            "server": headers.get("Server") if headers is not None else None,
            "cookies": _cookie_names(headers),
        }
        hops.append(hop)
        final_status = status

        if status not in REDIRECT_CODES:
            break
        if not hop["location"]:
            warnings.append(
                {"kind": "missing_location", "url": current, "detail": str(status)}
            )
            break

        nxt = urllib.parse.urljoin(current, hop["location"])
        hop["next"] = nxt
        for kind in transition_warnings(current, nxt, visited):
            warnings.append({"kind": kind, "url": current, "next": nxt})
        if _normalize(nxt) in visited:
            break
        visited.add(_normalize(nxt))
        current = nxt
    else:
        # The loop ran out of budget while the chain was still redirecting.
        warnings.append(
            {"kind": "hop_limit", "url": current, "detail": f"stopped after {max_hops} hops"}
        )

    return {
        "start_url": start_url,
        "final_url": hops[-1]["url"] if hops else start_url,
        "final_status": final_status,
        "hops": hops,
        "warnings": warnings,
        "error": error,
    }


def format_report(result, show_cookies=False):
    lines = [f"Start: {result['start_url']}"]
    for index, hop in enumerate(result["hops"], start=1):
        lines.append(f"  [{index}] {hop['status']}  {hop['url']}")
        if hop.get("location"):
            lines.append(f"        location: {hop['location']}")
        if hop.get("server"):
            lines.append(f"        server: {hop['server']}")
        if show_cookies and hop.get("cookies"):
            lines.append(f"        cookies: {', '.join(hop['cookies'])}")
    if result["error"]:
        lines.append(f"Failed: {result['error']}")
    elif result["final_status"] is not None:
        lines.append(f"Final: {result['final_url']} ({result['final_status']})")
    if result["warnings"]:
        lines.append("Warnings:")
        for warning in result["warnings"]:
            detail = warning.get("detail") or warning.get("next") or ""
            suffix = f" - {detail}" if detail else ""
            lines.append(f"  - {warning['kind']}: {warning['url']}{suffix}")
    else:
        lines.append("No warnings.")
    return "\n".join(lines)


def build_parser():
    parser = argparse.ArgumentParser(
        description="Trace an HTTP redirect chain and report what happens at each hop."
    )
    parser.add_argument("url", help="absolute http or https URL to trace")
    parser.add_argument(
        "--max-hops", type=int, default=10, help="maximum redirect hops to follow (default 10)"
    )
    parser.add_argument(
        "--timeout", type=float, default=5.0, help="per-request timeout in seconds (default 5)"
    )
    parser.add_argument("--json", action="store_true", help="emit JSON instead of text")
    parser.add_argument(
        "--show-cookies", action="store_true", help="list cookie names seen at each hop"
    )
    return parser


def main(argv=None):
    args = build_parser().parse_args(argv)
    if args.max_hops < 1:
        print("error: --max-hops must be at least 1", file=sys.stderr)
        return 2
    try:
        result = trace(args.url, max_hops=args.max_hops, timeout=args.timeout)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    if args.json:
        print(json.dumps(result, indent=2))
    else:
        print(format_report(result, show_cookies=args.show_cookies))

    if result["error"]:
        return 3
    return 1 if result["warnings"] else 0


if __name__ == "__main__":
    sys.exit(main())
