# Python Interceptor Proxy

A HTTP/HTTPS proxy for man-in-the-middle attacks in Python. This is a personal project and not refined for real-world use.

Install ca/rootCA.pem onto the target device.
Run mproxy.py with Python 3 on some server (make sure your firewall will allow connections from the outside world).
Set up target device to proxy through mproxy (default port 8080).

ca/             ca/ contains the certificate and key for the root CA. Install the .pem file on the target device.
certs/          certs/ is where the proxy generates fake certificate files for HTTPS websites.
logs/           logs/ is where the log files are stored. Cleared on startup.
cert_gen.py     cert_gen is used to generate and sign certificates the CA.
mproxy.py       Main program that defines and runs the server.
README.txt
