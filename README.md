# SSL Socket Server Client

The goal of this project is to have an insight vision of how to establish an server/client SSL connection to secure the traffic.
Today, cryptography is an indeniable mathematical tool that should be used to secure data transfert from malicious purposes.

This project is a just a POC but it mights be a base for bigger project such as Auth application or Secure Data Transfert.

There are yet 3 versions :

* Unsecure Socket, to understand the base of data transfert through socket
* Version 1 of SSL Server, which is based on old python functions
* Version 2 of SSL Server, which is based on actual supported python functions. Also, it has some more functionnality such has pipe state verification
* Version 3 of SSL Server, which is based on version 2 but come along with a PIN for MFA


Please note that the configurations of certificates, ports, IP server, etc, are reffered in the config.ini file, present in the directory of each versions.

To generate the approriate authority of certification and the server certificate and client certificate signed by it, do the following commands :

```
# Generate the CA (for 3 years) and its key

openssl req -x509 -new -nodes -key CA_key.key -sha256 -days 1095 -out CA_cert.pem

# Generate the CSR of the Server and its key

openssl req -new -nodes -out SRV_cert.csr -newkey rsa:4096 -keyout SRV_key.key 

# Generate the file configuration for the server certificate

cat > SRV_cert.v3.ext << EOF
authorityKeyIdentifier=keyid,issuer
basicConstraints=CA:FALSE
keyUsage = digitalSignature, nonRepudiation, keyEncipherment, dataEncipherment
subjectAltName = @alt_names

[alt_names]
DNS.1 = a.local
DNS.2 = b.local
IP.1 = 192.168.1.1
IP.2 = 192.168.2.1
EOF

Please note that you have to adjust the values to the expected result/futur server configurations (DNS Name, IP private or public, etc)

# Sign the server certificate with the CA

openssl x509 -req -in SRV_cert.csr -CA CA_cert.pem -CAkey CA_key.key -CAcreateserial -out SRV_cert.crt -days 365 -sha256 -extfile SRV_cert.v3.ext

# Repeat the previous actions for the client certificate (no need to generate a v3.ext file this time !!!)
