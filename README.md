# URL Redirect Tracer

URL Redirect Tracer is a lightweight, zero-dependency Python tool that follows HTTP and HTTPS redirect chains and reports exactly what happened at each hop. It is built for web forensics, security audits, link hygiene checks and debugging stale or suspicious URLs, where "where does this actually go?" is the only question that matters.

The tool records the status code, effective URL, `Location` header and server banner for every hop, then flags behaviour worth a second look: HTTPS-to-HTTP downgrades, redirect loops, cross-domain jumps, and chains that exceed the configured hop limit. It lists the cookie names offered along the way without ever printing cookie values, and it emits either a human-readable summary or machine-readable JSON.

Everything runs on the Python standard library. There is nothing to install beyond Python 3.8 or newer.

## Install

Clone the repository and run the script directly:

```
git clone https://github.com/wyn-cmd/url-redirect-tracer.git
cd url-redirect-tracer
python3 redirect_tracer.py https://example.com
```

No packaging step is required for CLI use. For library use, import `trace` or `RedirectTracer` helpers from `redirect_tracer.py`.

## Usage

Trace a single URL with human-readable output:

```
python3 redirect_tracer.py https://httpbin.org/redirect/2
```

Emit JSON for scripting:

```
python3 redirect_tracer.py --json https://httpbin.org/absolute-redirect/3
```

Change the redirect ceiling (default 10) and the per-request timeout in seconds (default 5):

```
python3 redirect_tracer.py --max-hops 5 --timeout 3 https://example.com
```

List the cookie names seen on each response:

```
python3 redirect_tracer.py --show-cookies https://example.com
```

## What gets reported

- Every hop with its URL, HTTP status, `Location` target and server header.
- The final destination URL and status code after following the chain.
- Flags for HTTPS-to-HTTP downgrade, redirect loops, cross-domain hops, missing `Location` headers, hop-limit overruns and request failures.
- Optional cookie names per hop. Values are never printed, since they can carry session tokens.

## Exit codes

- `0`: chain resolved without warnings.
- `1`: chain resolved but warnings were raised.
- `2`: usage or input error, including a malformed starting URL.
- `3`: the request failed before any redirect could be traced.

## Testing

The test suite spins up a local HTTP server and exercises redirect chains without touching the public internet:

```
python3 -m unittest discover -s tests -v
```

## Limitations

The tracer issues `GET` requests and reads no response bodies beyond what urllib buffers, so it is a redirect and header inspector rather than a page fetcher. It does not execute JavaScript, so client-side redirects are invisible to it. TLS certificates are verified by the standard library defaults.

## License

MIT. See `LICENSE`.
