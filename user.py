import http.server
import socketserver
import webbrowser
import threading
import time
import os

# Configuration
PORT = 8000
DIRECTORY = os.path.dirname(os.path.abspath(__file__))

class MyHandler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=DIRECTORY, **kwargs)
    
    def end_headers(self):
        # Disable caching for development
        self.send_header('Cache-Control', 'no-store, no-cache, must-revalidate')
        super().end_headers()

def start_server():
    socketserver.TCPServer.allow_reuse_address = True
    with socketserver.TCPServer(("", PORT), MyHandler) as httpd:
        print(f"\n[USER SIDE] Server started at http://localhost:{PORT}")
        print("Press Ctrl+C to stop the server.")
        httpd.serve_forever()

if __name__ == "__main__":
    # Start the server in a separate thread
    server_thread = threading.Thread(target=start_server, daemon=True)
    server_thread.start()
    
    # Give the server a second to initialize
    time.sleep(1)
    
    # Open the user login page
    print(f"Opening User Portal (login.html)...")
    webbrowser.open(f"http://localhost:{PORT}/login.html")
    
    # Keep the main thread alive to sustain the server
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nShutting down user server...")
