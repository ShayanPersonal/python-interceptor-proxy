#!/usr/bin/python3
import re
import gzip
import zlib
import subprocess
import threading
import os
import ssl
import http.server
import http.client
import argparse
#from bs4 import BeautifulSoup 
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor
from socketserver import ThreadingMixIn

#Use cert_gen to create a key/certificate pair. E.G. cert_gen("google.com")
from cert_gen import cert_gen

class PoolMixIn(ThreadingMixIn):
  #Supposedly makes shutting down the program faster, skips cleaning up their resources.
  daemon_threads = True
  #Overwrites process_request to use a set pool of threads. Pool is created in  main().
  def process_request(self, request, client_address):
    self.pool.submit(self.process_request_thread, request, client_address)

class ProxyServer(PoolMixIn, http.server.HTTPServer):
  file_lock = threading.Lock()
  request_count = 0

class ProxyHandler(http.server.BaseHTTPRequestHandler):
  ssl_mode = 0
  log = False
  request_body = None
  response_body = None
  response_headers = None
  request_id = 0

  def decompress(self, body):
    if ('Content-Encoding', 'gzip') in self.response_headers:
      return zlib.decompress(body, zlib.MAX_WBITS | 16)
    return body

  def compress(self, body):
    if ('Content-Encoding', 'gzip') in self.response_headers:
      return gzip.compress(body)
    return body

  """
  Modify_* methods are applied to the packets after they are intercepted
  """

  def modify_request_path(self, path):
    return path

  def modify_request_headers(self, request):
    return request

  def modify_request_body(self, request):
    return request

  def modify_response_headers(self, response):
    return response

  def modify_response_body(self, response):
    return response
    """
    Example usage
    body = self.decompress(response)
    return self.compress(body.replace(b'I love dogs', b'You are hacked!'))
    """


  #Extend log_request to support logging to file.
  def log_request(self, code='-', size='-'):
    if self.log:
      if self.command == "CONNECT":
        return
      self.server.request_count += 1
      self.request_id = self.server.request_count
      with open('./logs/%d_%s_%s.txt' % (self.request_id, self.address_string(), self.headers.get('Host')), 'w') as log_file:
        log_file.write("%s\n" % self.requestline)
        log_file.write("%s" % self.headers)
        #Delete extra new line
        log_file.seek(log_file.tell() - 4)
        if self.request_body:
          log_file.write("\nRequest body:\n%s" % self.request_body)
        log_file.write("\n\n")
    else:
      super(type(self), self).log_request(code, size)

  #Create new log_response method.
  def log_response(self):
    if self.log:
      if self.command == "CONNECT":
        return
      with open('./logs/%d_%s_%s.txt' % (self.request_id, self.address_string(), self.headers.get('Host')), 'a') as log_file:
        log_file.write("%s\n" % self.response_headers)
        if self.response_body:
          uncompressed = self.decompress(self.response_body)
          log_file.write("Response body:\n%s" % uncompressed)


  def web_response(self):
    self.send_response(200)
    self.send_header("Content-type", "text/html")
    self.end_headers()
    self.wfile.write(b"This is a HTTP/HTTPS MITM proxy for CS176b by Shayan Sadigh.")

  def respond_to_client(self, response):
    self.send_response(response.status)
    #Not filtering these headers leads to errors.
    #See https://www.w3.org/Protocols/rfc2616/rfc2616-sec13.html
    hop_by_hop_headers = ['connection', 'keep-alive', 'proxy-authenticate', 'proxy-authorization', 'te', 'trailers', 'transfer-encoding', 'upgrade']
    self.response_headers = self.modify_response_headers(response.getheaders())
    for pair in self.response_headers:
      if pair[0].lower() in hop_by_hop_headers:
        continue
      self.send_header(*pair)
    self.end_headers()
    self.response_body = self.modify_response_body(response.read())
    self.log_response()
    self.wfile.write(self.response_body)

  def do_GET(self):
    #When client uses a proxy it includes entire host + path in the path. When it thinks it's SSL tunnelling it ignores the proxy and just includes the path as normal.
    #Thus we have to fix the path so it's readable by urlparse if we're in ssl mode.
    if self.ssl_mode:
      scheme, netloc, path, params, query, fragment = urlparse('https://' + self.headers.get('Host') + self.path)
    else:
      scheme, netloc, path, params, query, fragment = urlparse(self.path)
    #If there's no netloc then we weren't in SSL mode and the server got a bare path, which means someone is trying to connect to the proxy as though it's a website.
    if not netloc:
      self.web_response()
      return
    if params:    path += ';' + params
    if query:     path += '?' + query
    if fragment:  path += '#' + fragment
    body_size = self.headers.get('Content-Length', 0)
    #Modify request here.
    self.request_body = self.modify_request_body(self.rfile.read(int(body_size)))
    self.headers = self.modify_request_headers(self.headers)
    path = self.modify_request_path(path)
    #Some websites present bad certificates or something so I skip that check.
    try:
      server_side = http.client.HTTPSConnection(netloc, context=ssl._create_unverified_context())
      server_side.request(self.command, path, self.request_body, self.headers)
      self.respond_to_client(server_side.getresponse())
    #Ignore errors
    except:
      pass

  do_POST, do_HEAD, do_PUT, do_DELETE, do_OPTIONS = do_GET, do_GET, do_GET, do_GET, do_GET

  def do_CONNECT(self):
    #Generate a fake certificate for the site to present to client. If it already exists, use the old one.
    self.send_response(200, 'Connection Established')
    self.end_headers()
    #Create a cert for the domain directly. Tried wildcards but they have issues.
    domain =  self.path.split(':')[0]
    self.server.file_lock.acquire()
    if os.path.isfile('./certs/' + domain + '.crt'):
      site_cert, site_key = './certs/' + domain + '.crt', './certs/' + domain + '.key'
    else:
      site_cert, site_key = cert_gen(domain)
    self.server.file_lock.release()
    try:
      self.connection = ssl.wrap_socket(self.connection, keyfile=site_key, certfile=site_cert, server_side=True)
    #Ignore errors
    except:
      pass
    #New rfile and wfile need to be set up for socket as the originals point to unwrapped socket.
    #See https://hg.python.org/cpython/file/3.5/Lib/socketserver.py#l731
    self.rfile = self.connection.makefile('rb', self.rbufsize)
    self.wfile = self.connection.makefile('wb', self.wbufsize)
    #This ensures the handler with our new socket will be used for future requests.
    #See https://hg.python.org/cpython/file/3.5/Lib/http/server.py#l423
    self.close_connection = False
    self.ssl_mode = 1


def clear_logs():
  #Was using subprocess.run but CSIL only has Python 3.4.
  subprocess.call("rm ./logs/*.txt", shell=True)

def main():
  #Parse arguments
  parser = argparse.ArgumentParser(description='mproxy')
  parser.add_argument('-v', '--version', action='version', version= "mproxy 0.1 by Shayan Sadigh")
  parser.add_argument('-p', '--port', type=int, default = 8080, help='port number to run on')
  parser.add_argument('-n', '--numworker', type=int, default = 10, help='number of threads')
  parser.add_argument('-t', '--timeout', type=float, default = -1, help='timeout after n seconds')
  parser.add_argument('-l', '--log', help='create a log', action="store_true")
  
  args = parser.parse_args()

  #Modfiy classes with project requirements.
  setattr(ProxyServer, 'pool', ThreadPoolExecutor(max_workers = args.numworker))
  setattr(ProxyHandler, 'log', args.log)
  #Python's StreamRequestHandler comes with a "timeout" attribute that defaults to None.
  setattr(ProxyHandler, 'timeout', args.timeout if args.timeout > 0 else None)
  
  #Clear old logs
  clear_logs()

  #Create proxy server
  proxy_server = ProxyServer(('0.0.0.0', args.port), ProxyHandler)
  print("Proxy started...")
  proxy_server.serve_forever()

if __name__=="__main__":
  main()
