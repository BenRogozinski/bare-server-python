import error_handler
import json
import http.client
import validators
import dns.resolver
import ssl
import random
from logger import get_logger
from urllib.parse import unquote

websocket_logger = get_logger("WEBSOCKET")

required_headers = [
    "X-Bare-Host",
    "X-Bare-Port",
    "X-Bare-Protocol",
    "X-Bare-Path",
    "X-Bare-Headers",
    "X-Bare-Forward-Headers"
]
forbidden_pass_headers = [
    "vary",
    "connection",
    "transfer-encoding",
    "access-control-allow-headers",
    "access-control-allow-methods",
    "access-control-expose-headers",
    "access-control-max-age",
    "access-control-request-headers",
    "access-control-request-method"
]
global_headers = {
    "X-Robots-Tag": "noindex",
    "Access-Control-Allow-Headers": "*",
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Methods": "*",
    "Access-Control-Expose-Headers": "*",
    "Access-Control-Max-Age": "7200"
}

valid_http_protocols = ["http:", "https:"]

valid_websocket_protocols = ["ws:", "wss:"]
websocket_required_data = [
    "remote",
    "headers",
    "forward_headers",
]
websocket_remote_required_data = [
    "host",
    "port",
    "path",
    "protocol"
]

valid_ports = range(1,65536)

def validate_websocket_json(websocket_json):
    for _ in websocket_required_data:
        if _ not in websocket_json:
            return False
    for _ in websocket_remote_required_data:
        if _ not in websocket_json["remote"]:
            return False
    if websocket_json["remote"]["protocol"] not in valid_websocket_protocols:
        return False
    return True

def create_websocket_proxy(self, data):
    websocket_uri = f"{data['remote']['protocol']}//{data['remote']['host']}:{data['remote']['port']}{data['remote']['path']}"
    websocket_headers = data["headers"]
    websocket_forwarded_headers = {}
    for header in data["forward_headers"]:
        websocket_forwarded_headers[header] = self.headers.get(header)
    websocket_headers.update(websocket_forwarded_headers)
    websocket_logger.debug(f"Opening tunnel to {websocket_uri}")

    return False

def v1_request(self):
    # Handle websocket upgrade requests
    if self.headers.get("Upgrade") == "websocket":
        if self.headers.get("Sec-WebSocket-Protocol") != None:
            websocket_protocol = self.headers.get("Sec-WebSocket-Protocol").replace(" ", "").split(",")
            if websocket_protocol[0] == "bare":
                try:
                    websocket_data = json.loads(unquote(websocket_protocol[1]))
                    print(validate_websocket_json(websocket_data))
                    if not create_websocket_proxy(self, websocket_data):
                        error_handler.return_error(self, 400, {
                            "code": "WEBSOCKET_CONNECT_ERROR",
                            "id": "response",
                            "message": "Failed to open websocket connection to remote."
                        })
                        return
                except json.decoder.JSONDecodeError:
                    error_handler.return_error(self, 400, {
                        "code": "INVALID_WEBSOCKET_HEADER",
                        "id": "request.headers.Sec-WebSocket-Protocol",
                        "message": "Websocket JSON data was formatted incorrectly."
                    })
                    return
                except IndexError:
                    error_handler.return_error(self, 400, {
                        "code": "INVALID_WEBSOCKET_HEADER",
                        "id": "request.headers.Sec-WebSocket-Protocol",
                        "message": "Websocket JSON data was not specified"
                    })
                    return
            else:
                error_handler.return_error(self, 400, {
                    "code": "INVALID_WEBSOCKET_HEADER",
                    "id": "request.headers.Sec-WebSocket-Protocol",
                    "message": "An invalid websocket protocol was specified."
                })
                return
        else:
            error_handler.return_error(self, 400, {
                "code": "MISSING_WEBSOCKET_HEADER",
                "id": "request.headers.Sec-WebSocket-Protocol",
                "message": "Websocket upgrade was requested but no protocol was specified."
            })
            return

    # Check if required headers are present
    for header in required_headers:
        if self.headers.get(header) == None:
            error_handler.return_error(self, 400, {
                "code": "MISSING_BARE_HEADER",
                "id": f"bare.headers.{header}",
                "message": "Header was not specified."
            })
            return

    # Get Bare host
    if validators.domain(self.headers.get("X-Bare-Host")):
        try:
            dns.resolver.resolve(self.headers.get("X-Bare-Host"))[0]
        except dns.resolver.NXDOMAIN:
            error_handler.return_error(self, 400, {
                "code": "HOST_NOT_FOUND",
                "id": "error.NXDOMAIN",
                "message": "The specified host could not be resolved."
            })
            return
    elif not (validators.ipv4(self.headers.get("X-Bare-Host")) or validators.ipv6(self.headers.get("X-Bare-Host"))):
        error_handler.return_error(self, 400, {
            "code": "HOST_NOT_FOUND",
            "id": "error.InvalidURI",
            "message": "Host header contained an invalid host."
        })
        return
    request_bare_host = self.headers.get("X-Bare-Host")
    
    # Get Bare port
    try:
        request_bare_port = int(self.headers.get("X-Bare-Port"))
        if request_bare_port not in valid_ports:
            error_handler.return_error(self, 400, {
                "code": "INVALID_BARE_HEADER",
                "id": "bare.headers.X-Bare-Port",
                "message": "Requested port not in valid range (1-65535)."
            })
            return
    except ValueError:
        error_handler.return_error(self, 400, {
            "code": "INVALID_BARE_HEADER",
            "id": "bare.headers.X-Bare-Port",
            "message": "Requested port was not a valid integer."
        })
        return
    
    # Get Bare protocol
    if self.headers.get("X-Bare-Protocol") not in valid_http_protocols:
        error_handler.return_error(self, 400, {
            "code": "INVALID_BARE_HEADER",
            "id": "bare.headers.X-Bare-Protocol",
            "message": "Invalid protocol was specified."
        })
        return
    request_bare_protocol = self.headers.get("X-Bare-Protocol")

    # Get Bare path
    if "/" in self.headers.get("X-Bare-Path"):
        request_bare_path = self.headers.get("X-Bare-Path")
    else:
        error_handler.return_error(self, 400, {
            "code": "INVALID_BARE_HEADER",
            "id": "bare.headers.X-Bare-Path",
            "message": "Invalid path was specified."
        })

    # Get Bare headers
    try:
        request_bare_headers = json.loads(self.headers.get("X-Bare-Headers"))
    except json.decoder.JSONDecodeError:
        error_handler.return_error(self, 400, {
            "code": "INVALID_BARE_HEADER",
            "id": "bare.headers.X-Bare-Headers",
            "message": "Header conatined invalid JSON."
        })
        return

    # Get Bare forward headers
    try:
        request_bare_forward_headers = json.loads(self.headers.get("X-Bare-Forward-Headers"))
    except json.decoder.JSONDecodeError:
        error_handler.return_error(self, 400, {
            "code": "INVALID_BARE_HEADER",
            "id": "bare.headers.X-Bare-Forward-Headers",
            "message": "Header contained invalid JSON."
        })
        return

    # Get Bare pass headers
    if self.headers.get("X-Bare-Pass-Headers") == None:
        request_bare_pass_headers = []
    else:
        try:
            request_bare_pass_headers = json.loads(self.headers.get("X-Bare-Pass-Headers"))
        except json.decoder.JSONDecodeError:
            error_handler.return_error(self, 400, {
                "code": "INVALID_BARE_HEADER",
                "id": "bare.headers.X-Bare-Pass-Headers",
                "message": "Header contained invalid JSON"
            })
            return
        for pass_header in request_bare_pass_headers:
            if pass_header.lower() in forbidden_pass_headers:
                error_handler.return_error(self, 401, {
                    "code": "FORBIDDEN_BARE_HEADER",
                    "id": f"bare.headers.X-Bare-Pass-Headers.{pass_header}",
                    "message": "Invalid pass header specified."
                })
                return
    
    # Get Bare pass status
    if self.headers.get("X-Bare-Pass-Status") == None:
        request_bare_pass_status = []
    else:
        try:
            request_bare_pass_status = json.loads(self.headers.get("X-Bare-Pass-Status"))
        except json.decoder.JSONDecodeError:
            error_handler.return_error(self, 400, {
                "code": "INVALID_BARE_HEADER",
                "id": "bare.headers.X-Bare-Pass-Status",
                "message": "Header contained invalid JSON."
            })
            return
        if not all(isinstance(sub, int) for sub in request_bare_pass_status):
            error_handler.return_error(self, 400, {
                "code": "INVALID_BARE_HEADER",
                "id": "bare.headers.X-Bare-Pass-Status",
                "message": "Header contained invalid value."
            })
            return

    # Prepare header array
    remote_send_headers = request_bare_headers
    for header in request_bare_forward_headers:
        remote_send_headers.update(
            {header: self.headers.get(header)}
        )

    # Handle HTTP(S) requests
    if request_bare_protocol in ["http:", "https:"]:
        try:
            if request_bare_protocol == "https:":
                remote_connection = http.client.HTTPSConnection(request_bare_host, request_bare_port)
            else:
                remote_connection = http.client.HTTPConnection(request_bare_host, request_bare_port)
            request_body = None
            if self.headers.get("Content-Length") != None:
                request_body = self.rfile.read(int(self.headers.get("Content-Length")))
            remote_connection.request(
                method = self.command,
                url = request_bare_path,
                body = request_body,
                headers=remote_send_headers
            )
            remote_response = remote_connection.getresponse()
            response_bare_pass_headers = {}
            response_bare_pass_headers.update(global_headers)
            request_bare_pass_headers.extend([
                "Content-Encoding",
                "Content-Length"
            ])
            for header in request_bare_pass_headers:
                if remote_response.headers.get(header) != None:
                    response_bare_pass_headers.update(
                        {header: remote_response.headers.get(header)}
                    )
            response_bare_headers = {}
            for header, value in remote_response.getheaders():
                response_bare_headers[header] = value
            response_bare_status = remote_response.getcode()
            response_bare_pass_headers["X-Bare-Status"] = response_bare_status
            response_bare_pass_headers["X-Bare-Status-Text"] = http.client.responses[response_bare_status]
            response_bare_pass_headers["X-Bare-Headers"] = json.dumps(response_bare_headers)
            if response_bare_status in request_bare_pass_status:
                self.send_response(response_bare_status)
            else:
                self.send_response(200)
            for header in response_bare_pass_headers:
                self.send_header(header, response_bare_pass_headers[header])
            self.end_headers()
            self.wfile.write(remote_response.read())
        except TimeoutError:
            error_handler.return_error(self, 500, {
                "code": "CONNECTION_TIMEOUT",
                "id": "remote.connectionTimeout",
                "message": "Connection timed out while connecting to remote."
            })
            return
        except ConnectionRefusedError:
            error_handler.return_error(self, 500, {
                "code": "CONNECTION_REFUSED",
                "id": "remote.connectionRefused",
                "message": "Connection refused while connecting to remote."
            })
            return
        except ConnectionResetError:
            error_handler.return_error(self, 500, {
                "code": "CONNECTION_RESET",
                "id": "remote.connectionReset",
                "message": "Connection reset while connecting to remote."
            })
            return
        except ssl.SSLError:
            error_handler.return_error(self, 500, {
                "code": "SSL_ERROR",
                "id": "remote.SSLError",
                "message": "SSL error while connecting to remote."
            })

def v1_new_websocket(self):
    websocket_id = ''.join(random.choice('0123456789abcdef') for _ in range(32))
    websocket_logger.debug(f"New websocket created with ID {websocket_id}")
    self.send_response(200)
    self.send_header("Content-Type", "text/plain")
    self.end_headers()
    self.wfile.write(websocket_id.encode())