"""Fictional read-only site deliberately missing security headers. No user data."""
from http.server import BaseHTTPRequestHandler, HTTPServer

class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path not in ['/', '/about']:
            self.send_error(404); return
        body=b'<!doctype html><html lang="en"><head><title>Fictional scanner fixture</title></head><body><h1>Fictional scanner fixture</h1><a href="/about">About</a><p>No forms, secrets, accounts or real data.</p></body></html>'
        self.send_response(200)
        self.send_header('Content-Type','text/html; charset=utf-8')
        self.send_header('Content-Length',str(len(body)))
        self.end_headers(); self.wfile.write(body)
    def log_message(self, *_): pass

if __name__=='__main__': HTTPServer(('0.0.0.0',8000),Handler).serve_forever()
