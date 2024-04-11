from request_utils import BareHTTPRequestHandler
from http.server import HTTPServer
from socketserver import ThreadingMixIn
import threading

class ThreadingServer(ThreadingMixIn, HTTPServer):
    pass

def main(server_class=HTTPServer, handler_class=BareHTTPRequestHandler, port=8000):
    server_address = ('', port)
    httpd = ThreadingServer(server_address, handler_class)
    print(f'Starting http server on port {port}...')
    httpd.serve_forever()

if __name__ == '__main__':
    main()