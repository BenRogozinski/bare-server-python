import json
from logger import get_logger

logger = get_logger("ERROR_HANDLER")

def return_error(self, response_code, error):
    self.send_response(response_code)
    self.send_header("Content-Type", "application/json")
    self.end_headers()
    self.wfile.write(json.dumps(error, indent=4).encode())
    logger.error(f"ERROR: {error['code']} - {error['id']} - {error['message']}")
