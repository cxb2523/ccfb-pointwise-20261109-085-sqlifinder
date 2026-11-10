"""Local delay page for verifying sqlifinder time-based detection."""
import http.server
import time
from urllib.parse import parse_qs, urlparse

PAGE = """<!DOCTYPE html>
<html><body>
<h1>test app</h1>
<a href="/search?q=test">search</a>
<a href="/unstable?x=1">unstable endpoint</a>
<form action="/login" method="post">
  <input type="text" name="username" value="admin">
  <input type="password" name="password" value="">
  <input type="hidden" name="csrf" value="token-abc-123">
  <select name="role">
    <option value="user" selected>user</option>
    <option value="admin">admin</option>
  </select>
  <textarea name="note">default note</textarea>
  <button type="submit" name="submitbtn">Go</button>
</form>
</body></html>"""

counter = {'unstable': 0}


class Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def _send(self, body):
        self.send_response(200)
        self.send_header('Content-Type', 'text/html')
        self.end_headers()
        self.wfile.write(body.encode())

    def do_GET(self):
        path = urlparse(self.path).path
        if path == '/search':
            q = parse_qs(urlparse(self.path).query).get('q', [''])[0]
            if 'SLEEP' in q:
                time.sleep(5)
            return self._send(PAGE)
        if path == '/unstable':
            # Alternating latency: baseline must be judged unstable.
            idx = counter['unstable']
            counter['unstable'] += 1
            time.sleep(0.05 if idx % 2 == 0 else 1.3)
            return self._send(PAGE)
        return self._send(PAGE)

    def do_POST(self):
        length = int(self.headers.get('Content-Length', 0))
        form = parse_qs(self.rfile.read(length).decode())
        username = form.get('username', [''])[0]
        if 'SLEEP' in username:
            time.sleep(5)
        self._send('<html><body>login ok</body></html>')


if __name__ == '__main__':
    server = http.server.HTTPServer(('127.0.0.1', 8931), Handler)
    print('serving on 8931', flush=True)
    server.serve_forever()
