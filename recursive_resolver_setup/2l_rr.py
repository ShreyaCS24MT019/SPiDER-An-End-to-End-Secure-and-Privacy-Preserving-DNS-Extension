#!/usr/bin/env python3
import socket
import threading
import subprocess
import sys
import os
import time
import struct
import base64
import json
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend

sys.path.append('/etc/powerdns')

class EncryptedDNSServer:
    def decrypt_packet(self, encrypted_data):
        """
        Decrypts a two-layer encrypted packet from proxy:
        1. First decrypt chunked RSA with RR private key (removes confidentiality layer)
        2. Then verify signature with proxy public key (removes authentication layer)
        """
        try:
            print(f"🔓 Starting packet decryption, data length: {len(encrypted_data)} bytes")
        
            # Layer 1: Decrypt confidentiality layer using chunked RSA decryption
            print("🔓 Layer 1: Decrypting confidentiality layer (chunked RSA)...")
            signed_data = self.decrypt_rsa_chunked(encrypted_data)
            if signed_data is None:
                print("❌ Failed to decrypt confidentiality layer")
                return None
        
            print(f"✅ Confidentiality layer decrypted, signed data length: {len(signed_data)} bytes")
        
            # Layer 2: Split signed data and verify signature
            print("🔓 Layer 2: Verifying authentication layer...")
            parts = signed_data.split(b'|||SIGNATURE|||')
            if len(parts) != 2:
                print("❌ Invalid signed data format - signature delimiter not found")
                return None
        
            original_dns_data = parts[0]
            signature = parts[1]
        
            print(f"📝 Original DNS data: {len(original_dns_data)} bytes")
            print(f"🖊️  Signature: {len(signature)} bytes")
        
            # Verify proxy signature using proxy public key
            try:
                self.proxy_public_key.verify(
                    signature,
                    original_dns_data,
                    padding.PSS(
                        mgf=padding.MGF1(hashes.SHA256()),
                        salt_length=padding.PSS.MAX_LENGTH
                    ),
                    hashes.SHA256()
                )
                print("✅ Proxy signature verified successfully")
            except Exception as e:
                print(f"❌ Proxy signature verification failed: {e}")
                return None
        
            print(f"🎉 Packet decryption completed successfully!")
            return original_dns_data
        
        except Exception as e:
            print(f"❌ Packet decryption failed: {e}")
            import traceback
            traceback.print_exc()
            return None
    def __init__(self, listen_port=5354, powerdns_port=53):
        self.listen_port = listen_port
        self.powerdns_port = powerdns_port
        self.load_keys()
    
    def load_keys(self):
        """Load all required keys for RR"""
        try:
            # Load RR private key (for decryption and signing)
            with open('/etc/powerdns/keys/recursor_private_key.pem', 'rb') as f:
                self.rr_private_key = serialization.load_pem_private_key(
                    f.read(), password=None, backend=default_backend()
                )
            
            # Load Proxy public key (for verifying proxy signatures)
            with open('/etc/powerdns/proxy_public_key.pem', 'rb') as f:
                self.proxy_public_key = serialization.load_pem_public_key(
                    f.read(), backend=default_backend()
                )
            
            # Load ANS public key (for encrypting to ANS)
            with open('/etc/powerdns/keys/ans_public_key.pem', 'rb') as f:
                self.ans_public_key = serialization.load_pem_public_key(
                    f.read(), backend=default_backend()
                )
            
            # Load ANS private key (for verifying ANS signatures)
                        
            print("✅ All RR encryption keys loaded successfully")
            
        except Exception as e:
            print(f"❌ Error loading keys: {e}")
            sys.exit(1)
    def decrypt_rsa_chunked(self, encrypted_data):
        """Decrypts RSA-encrypted data split into multiple 2-byte length-prefixed chunks."""
        decrypted_chunks = []
        offset = 0
        try:
            while offset < len(encrypted_data):
                if offset + 2 > len(encrypted_data):
                    print("❌ Malformed chunked RSA: missing length header")
                    return None
                chunk_len = struct.unpack('!H', encrypted_data[offset:offset + 2])[0]
                offset += 2
                if offset + chunk_len > len(encrypted_data):
                    print("❌ Malformed chunked RSA: incomplete chunk")
                    return None
                encrypted_chunk = encrypted_data[offset:offset + chunk_len]
                offset += chunk_len

                decrypted_chunk = self.rr_private_key.decrypt(
                    encrypted_chunk,
                    padding.OAEP(
                        mgf=padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None
                    )
                )
                decrypted_chunks.append(decrypted_chunk)
            return b''.join(decrypted_chunks)
        except Exception as e:
            print(f"❌ RSA chunk decryption failed: {e}")
            return None

    def decrypt_from_proxy(self, encrypted_packet):
        """Decrypt packet from proxy using pure asymmetric encryption"""
        try:
            packet = json.loads(encrypted_packet)
            
            # Layer 1: Decrypt confidentiality layer with RR private key
            encrypted_auth_layer = base64.b64decode(packet['encrypted_data'])
            decrypted_auth_layer = self.decrypt_rsa_chunked(encrypted_auth_layer)
            if not decrypted_auth_layer:
                print("❌ Failed to decrypt confidentiality layer from proxy")
                return None

            
            # Layer 2: Verify authentication (proxy signature) with proxy public key
            auth_packet = json.loads(decrypted_auth_layer.decode())
            signature = base64.b64decode(auth_packet['signature'])
            dns_data = base64.b64decode(auth_packet['dns_data'])
            
            self.proxy_public_key.verify(
                signature,
                dns_data,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            print("✅ Proxy signature verified")
            
            return dns_data
            
        except Exception as e:
            print(f"❌ Decryption from proxy failed: {e}")
            return None
    
    def encrypt_for_proxy(self, dns_response):
        """Encrypt response for proxy using pure asymmetric encryption"""
        try:
            # Layer 1: Sign with RR private key (authentication)
            signature = self.rr_private_key.sign(
                dns_response,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            
            auth_packet = {
                'dns_data': base64.b64encode(dns_response).decode(),
                'signature': base64.b64encode(signature).decode(),
                'timestamp': int(time.time())
            }
            
            # Layer 2: Encrypt with proxy public key (confidentiality)
            # Note: We need proxy public key here, but since it's not loaded in original,
            # we'll use a placeholder. In real implementation, load proxy public key.
            encrypted_data = self.proxy_public_key.encrypt(
                json.dumps(auth_packet).encode(),
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            
            response_packet = {
                'encrypted_data': base64.b64encode(encrypted_data).decode(),
                'timestamp': int(time.time())
            }
            
            return json.dumps(response_packet)
            
        except Exception as e:
            print(f"❌ Encryption for proxy failed: {e}")
            return None
    
    def encrypt_for_ans(self, dns_packet):
        """Encrypt DNS packet for ANS using 2-layer asymmetric encryption with chunked RSA"""
        try:
            print("🔒 Starting 2-layer encryption for ANS...")
            
            # Layer 1: Create signature with RR private key (authentication)
            signature = self.rr_private_key.sign(
                dns_packet,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            
            print(f"✅ Layer 1 (Authentication): Created signature ({len(signature)} bytes)")
            
            # Combine DNS packet with signature using same format as other communications
            signed_data = dns_packet + b'|||SIGNATURE|||' + signature
            
            # Layer 2: Encrypt with ANS public key (confidentiality) - chunked RSA
            print("🔒 Layer 2: Encrypting with ANS public key...")
            key_size = self.ans_public_key.key_size // 8
            max_chunk_size = key_size - 2 * hashes.SHA256().digest_size - 2  # OAEP padding overhead
    
            encrypted_chunks = []
            for i in range(0, len(signed_data), max_chunk_size):
                chunk = signed_data[i:i + max_chunk_size]
                encrypted_chunk = self.ans_public_key.encrypt(
                    chunk,
                    padding.OAEP(
                        mgf=padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None
                    )
                )
                chunk_len = struct.pack('!H', len(encrypted_chunk))
                encrypted_chunks.append(chunk_len + encrypted_chunk)
    
            encrypted_data = b''.join(encrypted_chunks)
            
            print(f"✅ Layer 2 (Confidentiality): Encrypted data ({len(encrypted_data)} bytes)")
            print("🎉 2-layer encryption for ANS completed!")
            
            return encrypted_data
            
        except Exception as e:
            print(f"❌ Encryption for ANS failed: {e}")
            import traceback
            traceback.print_exc()
            return None
    
    def decrypt_from_ans(self, encrypted_response):
        """Decrypt response from ANS using 2-layer asymmetric decryption with chunked RSA"""
        try:
            print(f"🔓 Starting ANS response decryption, data length: {len(encrypted_response)} bytes")
            
            # Layer 1: Decrypt confidentiality layer using chunked RSA decryption with RR private key
            print("🔓 Layer 1: Decrypting confidentiality layer (chunked RSA)...")
            signed_data = self.decrypt_rsa_chunked(encrypted_response)
            if signed_data is None:
                print("❌ Failed to decrypt confidentiality layer from ANS")
                return None
            
            print(f"✅ Confidentiality layer decrypted, signed data length: {len(signed_data)} bytes")
            
            # Layer 2: Split signed data and verify ANS signature
            print("🔓 Layer 2: Verifying ANS authentication layer...")
            parts = signed_data.split(b'|||SIGNATURE|||')
            if len(parts) != 2:
                print("❌ Invalid signed data format from ANS - signature delimiter not found")
                return None
            
            original_dns_response = parts[0]
            signature = parts[1]
            
            print(f"📝 Original DNS response: {len(original_dns_response)} bytes")
            print(f"🖊️  ANS signature: {len(signature)} bytes")
            
            # Verify ANS signature using ANS public key
            try:
                self.ans_public_key.verify(
                    signature,
                    original_dns_response,
                    padding.PSS(
                        mgf=padding.MGF1(hashes.SHA256()),
                        salt_length=padding.PSS.MAX_LENGTH
                    ),
                    hashes.SHA256()
                )
                print("✅ ANS signature verified successfully")
            except Exception as e:
                print(f"❌ ANS signature verification failed: {e}")
                return None
            
            print(f"🎉 ANS response decryption completed successfully!")
            return original_dns_response
            
        except Exception as e:
            print(f"❌ ANS response decryption failed: {e}")
            import traceback
            traceback.print_exc()
            return None    
        def encrypt_rsa_chunked(self, data):
            """Encrypts data using RSA with chunking for large data"""
            
            try:
                key_size = self.proxy_public_key.key_size // 8
                max_chunk_size = key_size - 2 * hashes.SHA256().digest_size - 2  # OAEP padding overhead
    
                encrypted_chunks = []
                for i in range(0, len(data), max_chunk_size):
                    chunk = data[i:i + max_chunk_size]
                    encrypted_chunk = self.proxy_public_key.encrypt(
                        chunk,
                        padding.OAEP(
                            mgf=padding.MGF1(algorithm=hashes.SHA256()),
                            algorithm=hashes.SHA256(),
                            label=None
                        )
                    )
                    chunk_len = struct.pack('!H', len(encrypted_chunk))
                    encrypted_chunks.append(chunk_len + encrypted_chunk)
    
                return b''.join(encrypted_chunks)
    
            except Exception as e:
                print(f"❌ RSA chunk encryption failed: {e}")
                return None
    def send_encrypted_to_ans(self, dns_packet, ans_host='4.247.24.171', ans_port=5354):
        """Send encrypted DNS packet to ANS using the same format as ANS expects"""
        try:
            print(f"🔐 Connecting to ANS at {ans_host}:{ans_port}")
            
            # TIMING: Record start time for ANS encryption
            print(f"TIMESTAMP: {time.time():.6f} - TW12 STARTS ENCRYPTING FOR ANS")
            
            # Encrypt for ANS using chunked RSA
            encrypted_packet = self.encrypt_for_ans(dns_packet)
            if not encrypted_packet:
                print("❌ Failed to encrypt packet for ANS")
                return None
            
            print(f"TIMESTAMP: {time.time():.6f} - TW13 ENDS ENCRYPTION FOR ANS")
            
            # Connect to ANS
            ans_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            ans_socket.settimeout(30)
            print(f"🔗 Connecting to ANS...")
            ans_socket.connect((ans_host, ans_port))
            
            print(f"TIMESTAMP: {time.time():.6f} - TW14 SENDS ENCRYPTED QUERY TO ANS")
            
            # Send encrypted packet (raw bytes, same format as ANS expects)
            print(f"📤 Sending encrypted packet to ANS ({len(encrypted_packet)} bytes)")
            ans_socket.send(struct.pack('!I', len(encrypted_packet)))
            ans_socket.send(encrypted_packet)
            
            # Receive encrypted response
            print("📥 Receiving response from ANS...")
            response_len_data = ans_socket.recv(4)
            if len(response_len_data) != 4:
                print("❌ Failed to receive response length from ANS")
                ans_socket.close()
                return None
                
            response_len = struct.unpack('!I', response_len_data)[0]
            print(f"📥 ANS response length: {response_len} bytes")
            
            # Receive the full encrypted response
            encrypted_response = b''
            while len(encrypted_response) < response_len:
                chunk = ans_socket.recv(response_len - len(encrypted_response))
                if not chunk:
                    print("❌ Connection closed while receiving ANS response")
                    ans_socket.close()
                    return None
                encrypted_response += chunk
            
            ans_socket.close()
            
            print(f"TIMESTAMP: {time.time():.6f} - TW20 RECEIVES ENCRYPTED RESPONSE FROM ANS")
            print(f"✅ Received encrypted response from ANS ({len(encrypted_response)} bytes)")
            
            # Decrypt response from ANS
            print(f"TIMESTAMP: {time.time():.6f} - TW21 STARTS DECRYPTING FROM ANS")
            decrypted_response = self.decrypt_from_ans(encrypted_response)
            print(f"TIMESTAMP: {time.time():.6f} - TW22 ENDS DECRYPTION FROM ANS")
            
            if decrypted_response:
                print(f"✅ Successfully decrypted ANS response ({len(decrypted_response)} bytes)")
            
            return decrypted_response
            
        except Exception as e:
            print(f"❌ ANS communication error: {e}")
            import traceback
            traceback.print_exc()
            return None
    
    def handle_encrypted_dns(self, conn, addr):
        """Handle encrypted DNS connection"""
        try:
            # TIMING: Record RR start time
            rr_start_time = time.time()
            print(f"TIMESTAMP: {time.time():.6f} - TW6 RR RECEIVES THE PACKET FROM PROXY")
            print(f"🔐 Encrypted DNS connection from: {addr}")
        
            # Helper function to receive exact number of bytes
            def recv_exact(sock, n):
                data = b''
                while len(data) < n:
                    try:
                        packet = sock.recv(n - len(data))
                        if not packet:
                            raise ConnectionError(f"Connection closed while expecting {n} bytes")
                        data += packet
                        print(f"📥 Received {len(packet)} bytes, total: {len(data)}/{n}")
                    except socket.timeout:
                        raise ConnectionError(f"Timeout while receiving {n} bytes")
                return data
        
            # Set socket timeout
            conn.settimeout(30)
        
            # Receive encrypted packet length
            print("📥 Reading packet length...")
            packet_len_data = recv_exact(conn, 4)
            packet_len = struct.unpack('!I', packet_len_data)[0]
            print(f"📥 Packet length: {packet_len} bytes")
        
            if packet_len > 50_000_000:  # Sanity check - 10KB max
                raise ValueError(f"Packet length too large: {packet_len}")
            
            # Receive encrypted packet
            encrypted_packet = recv_exact(conn, packet_len)
            timestamp_data = recv_exact(conn, 4)
            timestamp = struct.unpack('!I', timestamp_data)[0]

            print(f"✅ Encrypted packet received")
        
            print(f"🎉 Complete packet received successfully!")
            print("=" * 60)
            print("📦 ENCRYPTED PACKET FROM PROXY:")
            print("=" * 60)
            print(f"📊 Total Packet Size: {packet_len} bytes")
            print(f"🔒 Encrypted Data (first 100 chars): {encrypted_packet[:100]}...")
            print("=" * 60)
        
            # Decrypt DNS packet from proxy
            print(f"TIMESTAMP: {time.time():.6f} - TW7 BEGINS DECRYPTION FROM PROXY")
            print("🔓 Attempting to decrypt...")
            dns_packet = self.decrypt_packet(encrypted_packet)
            if not dns_packet:
                print("❌ Failed to decrypt DNS packet from proxy")
                return
            print(f"TIMESTAMP: {time.time():.6f} - TW8 ENDS DECRYPTION FROM PROXY")
            print(f"✅ Decrypted DNS packet ({len(dns_packet)} bytes)")
            print("🔓 DECRYPTED DNS PACKET:")
            print(f"   Raw bytes (hex): {dns_packet.hex()}")
            print(f"   ASCII view: {dns_packet.decode('utf-8', errors='ignore')}")
            print("=" * 60) 
            
            # Forward to PowerDNS or ANS
            print("📡 Forwarding DNS query...")
            dns_response = self.forward_to_powerdns(dns_packet)
            if not dns_response:
                print("❌ No response from DNS server")
                return
            print(f"✅ Received DNS response ({len(dns_response)} bytes)")
        
            # Encrypt response for proxy
            # Replace the response encryption section with this:

            # Encrypt response for proxy (create signed data with signature delimiter)
            print(f"TIMESTAMP: {time.time():.6f} - TW22 STARTS ENCRYPTING FOR PROXY")
            print("🔒 Encrypting response...")

            # Layer 1: Create signature with RR's private key (authentication)
            signature = self.rr_private_key.sign(
                dns_response,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )

            # Combine response with signature using same format as proxy
            signed_response = dns_response + b'|||SIGNATURE|||' + signature

            # Layer 2: Encrypt with proxy's public key (confidentiality) - chunked RSA
            key_size = self.proxy_public_key.key_size // 8
            max_chunk_size = key_size - 2 * hashes.SHA256().digest_size - 2  # OAEP padding overhead

            encrypted_chunks = []
            for i in range(0, len(signed_response), max_chunk_size):
                 chunk = signed_response[i:i + max_chunk_size]
                 encrypted_chunk = self.proxy_public_key.encrypt(
                     chunk,
                     padding.OAEP(
                         mgf=padding.MGF1(algorithm=hashes.SHA256()),
                         algorithm=hashes.SHA256(),
                         label=None
                     )
                 )
                 chunk_len = struct.pack('!H', len(encrypted_chunk))
                 encrypted_chunks.append(chunk_len + encrypted_chunk)

            encrypted_response = b''.join(encrypted_chunks)

            if not encrypted_response:
                print("❌ Failed to encrypt response")
                return

            print(f"✅ Response encrypted: {len(encrypted_response)} bytes")
            print(f"TIMESTAMP: {time.time():.6f} - TW23 ENDS ENCRYPTION FOR PROXY")      
            # Send response back to proxy
            print(f"TIMESTAMP: {time.time():.6f} - TW24 SENDS PACKET TO PROXY")
            print("📤 Sending encrypted response...")
            conn.send(struct.pack('!H', len(encrypted_response)))
            conn.send(encrypted_response)
            conn.send(struct.pack('!I', int(time.time())))
        
            # TIMING: Record RR end time and calculate RTT
            rr_end_time = time.time()
            rr_rtt = (rr_end_time - rr_start_time) * 1000
            print(f"RR RTT: {rr_rtt:.2f}ms")
            print("🎉 Encrypted DNS response sent successfully!")
        
        except Exception as e:
            print(f"❌ Error handling encrypted DNS: {e}")
            import traceback
            traceback.print_exc()
        finally:
            conn.close()
    
    def forward_to_powerdns(self, dns_packet):
        """Forward DNS packet - with domain-based routing"""
        try:
            # Check if this is YOUR domain that needs encrypted ANS
            if self.should_use_encrypted_ans(dns_packet):
                print("🔐 Custom domain detected - using encrypted ANS")
                return self.forward_to_encrypted_ans(dns_packet)
            else:
                print(f"TIMESTAMP: {time.time():.6f} - TW9 SENDS IT TO GLOBAL DNS")
                print("🌐 Global domain - using normal PowerDNS")
                return self.forward_to_normal_powerdns(dns_packet)
            
        except Exception as e:
            print(f"❌ Forwarding error: {e}")
            return None

    def should_use_encrypted_ans(self, dns_packet):
        """Check if domain needs encrypted ANS"""
        try:
            import dns.message
            dns_msg = dns.message.from_wire(dns_packet)
            query_name = str(dns_msg.question[0].name).lower()
        
            print(f"🔍 Checking domain: {query_name}")
        
            # Only YOUR domains use encrypted ANS
            if 'roydns.xyz' in query_name:
                return True
            else:
                return False
            
        except Exception as e:
            print(f"❌ Error parsing DNS: {e}")
            return False

    def forward_to_encrypted_ans(self, dns_packet):
        """Forward to YOUR encrypted ANS"""
        try:
            # TIMING: Record start time for ANS communication
            ans_start_time = time.time()
            print("🔐 Sending to encrypted ANS...")
            response = self.send_encrypted_to_ans(
                dns_packet,
                ans_host='4.247.24.171',  # Your ANS IP
                ans_port=5354
            )
            # TIMING: Record end time and calculate ANS RTT
            print(f"TIMESTAMP: {time.time():.6f} - TW19 RECEIVES CUSTOM DNS RESULT")
            ans_end_time = time.time()
            ans_rtt = (ans_end_time - ans_start_time) * 1000
            print(f"ANS RTT: {ans_rtt:.2f}ms")
            
            if response:
                print("✅ Got encrypted response from ANS")
                
            return response
        except Exception as e:
            print(f"❌ Encrypted ANS error: {e}")
            return None

    def forward_to_normal_powerdns(self, dns_packet):
        """Forward to normal PowerDNS"""
        try:
            # TIMING: Record start time for PowerDNS communication
            powerdns_start_time = time.time()
            
            dns_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            dns_socket.settimeout(30)
        
            dns_socket.sendto(dns_packet, ('127.0.0.1', self.powerdns_port))
            response, _ = dns_socket.recvfrom(512)
            dns_socket.close()
        
            # TIMING: Record end time and calculate PowerDNS RTT
            print(f"TIMESTAMP: {time.time():.6f} - TW11 RECEIVES THE GLOBAL DNS RESULT")
            powerdns_end_time = time.time()
            powerdns_rtt = (powerdns_end_time - powerdns_start_time) * 1000
            print(f"PowerDNS RTT: {powerdns_rtt:.2f}ms")
            print(f"✅ Got response from PowerDNS")
            return response
        except Exception as e:
            print(f"❌ PowerDNS error: {e}")
            return None 
    
    def start_server(self):
        """Start encrypted DNS server"""
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_socket.bind(('0.0.0.0', self.listen_port))
        server_socket.listen(10)
        
        print(f"🔐 Encrypted DNS Server listening on port {self.listen_port}")
        print("📡 Forwarding to PowerDNS on port 53")
        print("🚀 Ready for encrypted DNS queries!")
        
        while True:
            conn, addr = server_socket.accept()
            thread = threading.Thread(
                target=self.handle_encrypted_dns,
                args=(conn, addr)
            )
            thread.daemon = True
            thread.start()

if __name__ == "__main__":
    server = EncryptedDNSServer()
    server.start_server()
