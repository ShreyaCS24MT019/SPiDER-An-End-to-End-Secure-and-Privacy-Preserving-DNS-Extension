# SPiDER-An-End-to-End-Secure-and-Privacy-Preserving-DNS-Extension
## Configuration Details

The SPiDER configuration spans both the recursive resolver and authoritative nameserver, each extended to handle encrypted DNS communication and domain-specific routing.

### *Recursive Resolver*

The PowerDNS Recursor is configured to listen on both the internal subnet and the local loopback interface. In this configuration, the placeholder `@rr_ip` represents the IP address assigned to the Recursive Resolver. The relevant section of the configuration file (`/etc/powerdns/recursor.conf`) is shown below.

```bash
local-address=@rr_ip,127.0.0.1
allow-from=10.230.3.0/24,127.0.0.0/8
```
DNSSEC validation is disabled to avoid conflicts with SPiDER’s cryptographic layer. A Lua script (recursor.lua) implements domain-based routing: queries for our SPiDER-compliant domain roydns.xyz -- the domain we purchased from Namecheap (https://www.namecheap.com/
) and configured for end-to-end encrypted resolution -- are redirected to the encrypted channel on TCP port 5354, while all other domains are resolved conventionally over port 53.

Structured logging and query timing are enabled to support performance monitoring. The logging configuration is shown below.
```bash
structured-logging=yes
log-dns-queries=yes
loglevel=9
```
Authoritative Nameserver

This is hosted on a Microsoft Azure virtual machine to ensure global reachability and public accessibility. The configuration file (/etc/powerdns/pdns.conf) employs MySQL as the backend for zone data management, as shown below.
```bash
launch=gmysql
gmysql-host=127.0.0.1
gmysql-user=powerdns
gmysql-password=<secure_password>
gmysql-dbname=powerdns
```
The authoritative nameserver listens on all interfaces and exposes DNS and API endpoints as given below.
```bash
local-address=0.0.0.0
local-port=53
api=yes
api-key=changeme
webserver=yes
webserver-port=8081
```
Glue records are registered with the domain registrar (Namecheap) to associate ns1.roydns.xyz and ns2.roydns.xyz with the Azure-assigned static IP address. This configuration enables external DNS queries to traverse the global DNS hierarchy and reach the authoritative nameserver under SPiDER’s encrypted framework.
## Key Management and Encryption Integration

SPiDER employs asymmetric RSA key pairs at each of the three cryptographic entities -- the local resolver, recursive resolver, and authoritative nameserver. Keys are generated using:
```bash
openssl genrsa -out private.pem 2048
openssl rsa -in private.pem -pubout -out public.pem
```
Public keys are exchanged out-of-band through authenticated distribution before system initialization, although they can also be exchanged via Certificate Authorities (CAs) or standardized key exchange mechanisms. Each middleware component enforces a two-layer asymmetric cryptographic model:

1. The inner layer (authentication) signs packets with the sender’s private key using RSA-PKCS#1 v1.5 and SHA-256
2. The outer layer (confidentiality) encrypts the signed payload using RSA-OAEP with chunking support as described in Section packet for large DNS payloads.
