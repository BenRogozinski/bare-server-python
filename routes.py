from http.server import BaseHTTPRequestHandler
import psutil
import server_info
import error_handler
from v1 import *
import json
from logger import get_logger

logger = get_logger("BARE")

process = psutil.Process()

def root_request(self):
    if self.command == "OPTIONS":
        self.send_response(200)
        self.end_headers()
    else:
        self.send_response(200)
        self.send_header("Content-type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps({
            "versions": server_info.server_versions,
            "language": server_info.server_language,
            "memoryUsage": round(process.memory_info().rss / 1024 / 1024, 2),
            "maintainer": server_info.maintainer_data,
            "project": server_info.project_data,
        }, indent=4).encode())

routes = {
    "/": root_request,
    "/v1/": v1_request,
    "/v1/ws-new-meta": v1_new_websocket
}

class BareHTTPRequestHandler(BaseHTTPRequestHandler):
    def do_HEAD(self):
        self.handle_request()
    def do_GET(self):
        self.handle_request()
    def do_POST(self):
        self.handle_request()
    def do_PUT(self):
        self.handle_request()
    def do_DELETE(self):
        self.handle_request()
    def do_OPTIONS(self):
        self.handle_request()
    def do_TRACE(self):
        self.handle_request()
    def do_CONNECT(self):
        self.handle_request()
    def handle_request(self):
        try:
            routes[self.path](self)
        except KeyError:
            error_handler.return_error(self, 404, {
                "code": "UNKNOWN",
                "id": "error.NotFoundError",
                "message": "Not Found"
            })
            return
    def log_message(self, format, *args):
        logger.info(format, *args)