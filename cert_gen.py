import subprocess

def ca_gen():
  #Creates new root CA certificate if we need one. The .pem has to be installed on device. Put both files in ca/ folder.
  subprocess.call("openssl genrsa -out rootCA.key 2048", shell=True)
  subprocess.call("openssl req -new -x509 -days 10000 -key rootCA.key -out rootCA.pem", shell=True)

def cert_gen(common_name):
  #Creates fake certificate with our CA for a website. Will be trusted if you install CA certificate onto device.
  #This can run faster is you use rsa:1024 or lower but your browser may throw security errors.
  #subprocess.call("export SAN=DNS:%s" % common_name)
  subprocess.call("openssl req -new -nodes -newkey rsa:2048 -keyout ./certs/%s.key -out ./certs/%s.csr -subj /CN=%s" % (common_name, common_name, common_name), shell=True)
  subprocess.call("openssl x509 -req -CA ./ca/rootCA.pem -CAkey ./ca/rootCA.key -days 365 -in ./certs/%s.csr -CAcreateserial -out ./certs/%s.crt" % (common_name, common_name), shell=True)
  return "./certs/%s.crt" % common_name, "./certs/%s.key" % common_name 

if __name__ == '__main__':
  import sys
  if sys.argv[1] == "ca":
    ca_gen()
  else:
    cert_gen(sys.argv[1])
