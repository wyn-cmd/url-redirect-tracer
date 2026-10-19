import io
import json
import os
import sys
import threading
import unittest
from contextlib import redirect_stdout
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import redirect_tracer


class _Handler(BaseHTTPRequestHandler):
    routes = {}

    def do_GET(self):
        path = self.path.split("?", 1)[0]
        route = self.routes.get(path)
        if route is None:
            self.send_response(404)
            self.end_headers()
            self.wfile.write(b"not found")
            return
        status, headers, body = route
        self.send_response(status)
        for key, value in headers.items():
            self.send_header(key, value)
        self.end_headers()
        self.wfile.write(body)

    # Keep the test output clean; the default handler prints every request.
    def log_message(self, fmt, *args):
        pass


class TracerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        _Handler.routes = {
            "/start": (302, {"Location": "/middle"}, b""),
            "/middle": (301, {"Location": "/end"}, b"moved"),
            "/end": (200, {"Server": "test-server"}, b"done"),
            "/loop-a": (302, {"Location": "/loop-b"}, b""),
            "/loop-b": (302, {"Location": "/loop-a"}, b""),
            "/noloc": (302, {}, b""),
            "/cookie": (302, {"Location": "/end", "Set-Cookie": "session=supersecret; Path=/"}, b""),
            "/chain/0": (200, {}, b"root"),
            "/chain/1": (302, {"Location": "/chain/0"}, b""),
            "/chain/2": (302, {"Location": "/chain/1"}, b""),
            "/chain/3": (302, {"Location": "/chain/2"}, b""),
        }
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.base = f"http://127.0.0.1:{cls.server.server_address[1]}"

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()

    def test_follows_relative_redirects_to_final_url(self):
        result = redirect_tracer.trace(self.base + "/start")
        self.assertIsNone(result["error"])
        self.assertEqual([hop["status"] for hop in result["hops"]], [302, 301, 200])
        self.assertEqual(result["final_status"], 200)
        self.assertEqual(result["final_url"], self.base + "/end")
        self.assertEqual(result["hops"][0]["location"], "/middle")
        self.assertEqual(
            result["hops"][2]["server"], f"{_Handler.server_version} {_Handler.sys_version}".strip()
        )
        self.assertEqual(result["warnings"], [])

    def test_redirect_loop_is_flagged_and_stopped(self):
        result = redirect_tracer.trace(self.base + "/loop-a")
        kinds = [warning["kind"] for warning in result["warnings"]]
        self.assertIn("redirect_loop", kinds)
        self.assertEqual(len(result["hops"]), 2)

    def test_missing_location_header_is_flagged(self):
        result = redirect_tracer.trace(self.base + "/noloc")
        kinds = [warning["kind"] for warning in result["warnings"]]
        self.assertIn("missing_location", kinds)
        self.assertEqual(len(result["hops"]), 1)

    def test_hop_limit_stops_long_chain(self):
        result = redirect_tracer.trace(self.base + "/chain/3", max_hops=2)
        kinds = [warning["kind"] for warning in result["warnings"]]
        self.assertIn("hop_limit", kinds)
        self.assertEqual(len(result["hops"]), 2)

    def test_cookie_names_are_reported_without_values(self):
        result = redirect_tracer.trace(self.base + "/cookie")
        self.assertIn("session", result["hops"][0]["cookies"])
        self.assertNotIn("supersecret", json.dumps(result))

    def test_invalid_start_url_raises(self):
        with self.assertRaises(ValueError):
            redirect_tracer.trace("example.com/no-scheme")
        with self.assertRaises(ValueError):
            redirect_tracer.trace("ftp://example.com/file")

    def test_transition_warnings_detect_downgrade_and_cross_domain(self):
        kinds = redirect_tracer.transition_warnings(
            "https://secure.example/a", "http://other.example/b", set()
        )
        self.assertIn("https_downgrade", kinds)
        self.assertIn("cross_domain", kinds)
        self.assertNotIn("redirect_loop", kinds)

    def test_transition_warnings_detect_loop(self):
        visited = {redirect_tracer._normalize("https://example.com/a")}
        kinds = redirect_tracer.transition_warnings(
            "https://example.com/b", "https://example.com/a#fragment", visited
        )
        self.assertEqual(kinds, ["redirect_loop"])

    def test_main_exit_codes(self):
        self.assertEqual(redirect_tracer.main([self.base + "/start"]), 0)
        self.assertEqual(redirect_tracer.main([self.base + "/loop-a"]), 1)
        self.assertEqual(redirect_tracer.main(["not-a-url"]), 2)

    def test_json_output_is_valid(self):
        buffer = io.StringIO()
        with redirect_stdout(buffer):
            code = redirect_tracer.main(["--json", self.base + "/start"])
        payload = json.loads(buffer.getvalue())
        self.assertEqual(code, 0)
        self.assertEqual(payload["final_url"], self.base + "/end")
        self.assertEqual(len(payload["hops"]), 3)


if __name__ == "__main__":
    unittest.main()
