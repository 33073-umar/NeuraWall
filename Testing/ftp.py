from pyftpdlib.authorizers import DummyAuthorizer
from pyftpdlib.handlers import FTPHandler
from pyftpdlib.servers import FTPServer
import os

def run_ftp_server():
    # Ensure directory exists
    ftp_directory = "C:/FTP"
    if not os.path.exists(ftp_directory):
        os.makedirs(ftp_directory)

    # Instantiate an authorizer object
    authorizer = DummyAuthorizer()

    # Add user permissions: ('user', 'password', 'directory', perm)
    authorizer.add_user("testuser", "password123", ftp_directory, perm="elradfmw")

    # Instantiate a handler object
    handler = FTPHandler
    handler.authorizer = authorizer

    # Instantiate the FTP server and specify the handler
    server = FTPServer(("0.0.0.0", 2121), handler)  # Use port 2121 for testing

    # Start the server
    print("Starting FTP server on port 2121...")
    server.serve_forever()

if __name__ == "__main__":
    run_ftp_server()
