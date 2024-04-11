import json

def return_error(self, response_code, error):
    self.send_response(response_code)
    self.send_header("Content-Type", "application/json")
    self.end_headers()
    self.wfile.write(json.dumps(error, indent=4).encode())