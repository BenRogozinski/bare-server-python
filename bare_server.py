from routes import BareHTTPRequestHandler, routes
from http.server import HTTPServer
from socketserver import ThreadingMixIn
import multiprocessing
from pyfiglet import Figlet
import argparse
from logger import get_logger
import asyncio

class ThreadingServer(ThreadingMixIn, HTTPServer):
    pass

def run_bare(address="0.0.0.0", port=8080):
    server_address = (address, port)
    httpd = ThreadingServer(server_address, BareHTTPRequestHandler)
    httpd.serve_forever()

if __name__ == '__main__':
    root_logger = get_logger("ROOT")
    parser = argparse.ArgumentParser("bare_server.py")
    parser.add_argument("--host", help="Host IP to bind to", default="127.0.0.1")
    parser.add_argument("--port", help="Port to bind to", default=8080, type=int)
    args = parser.parse_args()
    f = Figlet(font="slant")

    print(f.renderText("TIW ProxyNET"))
    print("By Ben_Da_Builder")
    print("Based on https://github.com/tomphttp/specifications")
    print()

    root_logger.info("Initialized logger")
    root_logger.info(f"Starting Bare server at http://{args.host}:{args.port}/")
    bare_server = multiprocessing.Process(target=run_bare, args=(args.host, args.port))
    bare_server.daemon = False
    bare_server.start()
    logger = get_logger("ROUTES")
    for route in routes:
        logger.debug(f"Registered route: {route.ljust(20)} ==> {routes[route]}")
    root_logger.debug("Starting async IO handler")
    asyncio.get_event_loop().run_forever()