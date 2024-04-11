import error_handler
import json
import http.client
import validators
import dns.resolver
import select

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

valid_protocols = ["http:", "https:", "ws:", "wss:"]

valid_ports = range(1,65536)

global_headers = {
    "X-Robots-Tag": "noindex",
    "Access-Control-Allow-Headers": "*",
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Methods": "*",
    "Access-Control-Expose-Headers": "*",
    "Access-Control-Max-Age": "7200"
}

def v1_request(self):
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
    if self.headers.get("X-Bare-Protocol") not in valid_protocols:
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
                remote_connection = http.client.HTTPSConnection(request_bare_host)
            else:
                remote_connection = http.client.HTTPConnection(request_bare_host)
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