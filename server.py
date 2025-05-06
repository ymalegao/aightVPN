import http.server
import socketserver
import logging

# Set up logging
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

# Create the HTTP server with detailed logging
handler = http.server.SimpleHTTPRequestHandler
handler.protocol_version = "HTTP/1.1"  # Use HTTP/1.1 to see more detailed headers

# You can subclass the handler to add more debugging
class DebugHandler(http.server.SimpleHTTPRequestHandler):
    def log_message(self, format, *args):
        logging.info("%s - %s" % (self.client_address[0], format % args))

    def do_GET(self):
        # Log full request headers
        logging.debug(f"Full request headers: {self.headers}")
        return super().do_GET()

# Use the debug handler
PORT = 8080
with socketserver.TCPServer(("0.0.0.0", PORT), DebugHandler) as httpd:
    print(f"Serving at port {PORT}")
    httpd.serve_forever()
