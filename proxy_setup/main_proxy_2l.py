#!/usr/bin/env python3
import socket
import threading
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
import struct
import time
import dns.message
import dns.name

class DoubleLayerAsymmetricDNSProxy:
    def __init__(self):
        # Load keys
        self.load_keys()
    
    def load_keys(self):
        """Load proxy's private key and middleware's public key"""
        try:
            # Load proxy's private key
            with open('proxy_private_key.pem', 'rb') as f:
                self.proxy_private_key = serialization.load_pem_private_key(
                    f.read(),
                    password=None,
                    backend=default_backend()
                )
            
            # Load middleware's (recursor's) public key
            with open('recursor_public_key.pem', 'rb') as f:
                self.middleware_public_key = serialization.load_pem_public_key(
                    f.read(),
                    backend=default_backend()
                )
            
            print("Keys loaded successfully")
            
        except FileNotFoundError as e:
            print(f"Key file not found: {e}")
            print("Please run key_generator.py first and exchange public keys")
            exit(1)
    
    def create_authentication_signature(self, data):
        """Layer 1: Create digital signature for authentication"""
        try:
            signature = self.proxy_private_key.sign(
                data,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            return signature
        except Exception as e:
            print(f"Signature creation error: {e}")
            return None
    
    def encrypt_rsa_chunked(self, data):
        """Layer 2: Encrypt data using chunked RSA for confidentiality"""
        try:
            key_size = self.middleware_public_key.key_size // 8
            max_chunk_size = key_size - 2 * hashes.SHA256().digest_size - 2  # OAEP padding overhead
            
            # Check if chunking is necessary
            if len(data) <= max_chunk_size:
                print(f"Data size ({len(data)} bytes) <= max chunk size ({max_chunk_size} bytes) - no chunking needed")
                # Single chunk encryption
                encrypted_data = self.middleware_public_key.encrypt(
                    data,
                    padding.OAEP(
                        mgf=padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None
                    )
                )
                # Format as single chunk with length prefix
                return struct.pack('!H', len(encrypted_data)) + encrypted_data
            else:
                print(f"Data size ({len(data)} bytes) > max chunk size ({max_chunk_size} bytes) - chunking required")
                # Multi-chunk encryption
                encrypted_chunks = []
                for i in range(0, len(data), max_chunk_size):
                    chunk = data[i:i + max_chunk_size]
                    encrypted_chunk = self.middleware_public_key.encrypt(
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
            print(f"RSA chunk encryption error: {e}")
            return None
    
    def decrypt_rsa_chunked(self, encrypted_data):
        """Decrypt chunked RSA encrypted data"""
        try:
            decrypted_chunks = []
            offset = 0
            
            while offset < len(encrypted_data):
                if offset + 2 > len(encrypted_data):
                    print("Malformed chunked RSA: missing length header")
                    return None
                    
                chunk_len = struct.unpack('!H', encrypted_data[offset:offset + 2])[0]
                offset += 2
                
                if offset + chunk_len > len(encrypted_data):
                    print("Malformed chunked RSA: incomplete chunk")
                    return None
                    
                encrypted_chunk = encrypted_data[offset:offset + chunk_len]
                offset += chunk_len

                decrypted_chunk = self.proxy_private_key.decrypt(
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
            print(f"RSA chunk decryption error: {e}")
            return None
    
    def create_double_asymmetric_packet(self, dns_data):
        """Create double-layer asymmetric encrypted packet"""
        try:
            print(f"Original DNS data: {len(dns_data)} bytes")  
            print("=" * 60)
            print("ORIGINAL DNS PACKET:")
            print("=" * 60)
            print(f"Raw DNS bytes (hex): {dns_data.hex()}")
            print(f"ASCII view: {dns_data.decode('utf-8', errors='ignore')}")
            print("=" * 60)
            
            # Layer 1: Authentication - Sign the DNS data
            signature = self.create_authentication_signature(dns_data)
            if signature is None:
                return None
            print(f"Signature size: {len(signature)} bytes")
            print(f"RSA Signature (first 32 bytes): {signature[:32].hex()}")
            
            # Combine DNS data with signature using delimiter
            signed_data = dns_data + b'|||SIGNATURE|||' + signature
            print(f"Signed data size: {len(signed_data)} bytes")
            
            # Layer 2: Confidentiality - Encrypt the signed data with chunked RSA
            encrypted_data = self.encrypt_rsa_chunked(signed_data)
            if encrypted_data is None:
                return None
            print(f"Total encrypted packet: {len(encrypted_data)} bytes")
            
            print("=" * 60)
            print("FINAL ENCRYPTED PACKET SUMMARY:")
            print("=" * 60)
            print(f"Authentication: {len(signature)} bytes signature")
            print(f"Confidentiality: {len(encrypted_data)} bytes encrypted data")
            print(f"Encrypted Data (first 32 bytes): {encrypted_data[:32].hex()}")
            print("=" * 60)
            
            return encrypted_data
            
        except Exception as e:
            print(f"Double asymmetric encryption error: {e}")
            return None
    
    def decrypt_response_packet(self, encrypted_response):
        """Decrypt response from middleware using chunked RSA"""
        try:
            # Decrypt the response using chunked RSA
            signed_response = self.decrypt_rsa_chunked(encrypted_response)
            if signed_response is None:
                print("Failed to decrypt response")
                return None
            
            # Split signed data and verify signature
            parts = signed_response.split(b'|||SIGNATURE|||')
            if len(parts) != 2:
                print("Invalid response format - signature delimiter not found")
                return None
            
            original_dns_response = parts[0]
            signature = parts[1]
            
            # Verify middleware signature using middleware's public key
            try:
                self.middleware_public_key.verify(
                    signature,
                    original_dns_response,
                    padding.PSS(
                        mgf=padding.MGF1(hashes.SHA256()),
                        salt_length=padding.PSS.MAX_LENGTH
                    ),
                    hashes.SHA256()
                )
                print("Middleware signature verified successfully")
            except Exception as e:
                print(f"Middleware signature verification failed: {e}")
                return None
            
            return original_dns_response
            
        except Exception as e:
            print(f"Response decryption error: {e}")
            return None
    
    def send_encrypted_dns_tcp(self, encrypted_packet, host, port):
        """Send encrypted DNS packet via TCP"""
        try:
            # TIMING: Record proxy start time
            proxy_start_time = time.time()
            
            tcp_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            tcp_socket.settimeout(60)
            tcp_socket.connect((host, port))
            
            # Send packet length and encrypted data
            tcp_socket.send(struct.pack('!I', len(encrypted_packet)))
            tcp_socket.send(encrypted_packet)
            tcp_socket.send(struct.pack('!I', int(time.time())))
            
            print("Sent encrypted DNS packet via TCP")
            
            # Receive encrypted response (RR sends 2-byte length prefix)
            response_len_data = tcp_socket.recv(2)
            if len(response_len_data) != 2:
                print("Failed to receive response length")
                tcp_socket.close()
                return None
                
            response_len = struct.unpack('!H', response_len_data)[0]
            
            # Receive the full encrypted response
            encrypted_response = b''
            while len(encrypted_response) < response_len:
                chunk = tcp_socket.recv(response_len - len(encrypted_response))
                if not chunk:
                    break
                encrypted_response += chunk
            
            # Receive timestamp
            timestamp_data = tcp_socket.recv(4)
            tcp_socket.close()
            
            # TIMING: Record proxy end time and calculate RTT
            proxy_end_time = time.time()
            proxy_rtt = (proxy_end_time - proxy_start_time) * 1000
            print(f"PROXY RTT: {proxy_rtt:.2f}ms")
            
            return encrypted_response
            
        except Exception as e:
            print(f"TCP DNS communication error: {e}")
            return None

    def handle_dns_query(self, data, client_address, server_socket):
        """Handle DNS query with double-layer asymmetric encryption"""
        start_time = time.time()
        print(f"\n--- DNS Query from {client_address} at {start_time}  ---")
        
        try:
            # Step 1: Extract the original DNS query from the packet
            print(f"Original DNS packet size: {len(data)} bytes")
            
            # Step 2: Create double-layer asymmetric encrypted packet
            encrypted_packet = self.create_double_asymmetric_packet(data)
            if encrypted_packet is None:
                print("Failed to create encrypted packet")
                return
            
            print("Layer 1 (Authentication): Digital signature created")
            print("Layer 2 (Confidentiality): DNS packet encrypted with chunked RSA")
            
            # Step 3: Send encrypted DNS packet via TCP
            response_packet = self.send_encrypted_dns_tcp(
                encrypted_packet,
                '10.230.3.83',  # Recursor IP
                5354            # Custom encrypted DNS port
            )
            
            if response_packet is None:
                print("Failed to get encrypted response")
                return
            
            # Step 4: Decrypt the DNS response
            decrypted_response = self.decrypt_response_packet(response_packet)
            if decrypted_response is None:
                print("Failed to decrypt DNS response")
                return
            
            print("DNS response decrypted successfully")
            
            # Step 5: Send the original DNS response back to client
            server_socket.sendto(decrypted_response, client_address)
            print(f"DNS response sent back to client {client_address}")
            end_time = time.time()
            total_time = (end_time - start_time) * 1000
            print(f"Total processing time: {total_time:.2f}ms")
            
        except Exception as e:
            print(f"Error handling DNS query: {e}")
            
    def start_server(self):
        """Start the double-layer asymmetric encrypted DNS proxy"""
        
        HOST = '10.230.3.85'
        PORT = 53
        
        print("=== Double Layer Asymmetric Encrypted DNS Proxy ===")
        print("Layer 1: Authentication (RSA Digital Signatures)")
        print("Layer 2: Confidentiality (Chunked RSA Encryption)")
        print("===================================================")
        
        try:
            server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server_socket.bind((HOST, PORT))
            
            print(f"Server listening on {HOST}:{PORT}")
            print("Waiting for DNS queries...\n")
            
            while True:
                try:
                    data, client_address = server_socket.recvfrom(512)
                    
                    query_thread = threading.Thread(
                        target=self.handle_dns_query,
                        args=(data, client_address, server_socket)
                    )
                    query_thread.daemon = True
                    query_thread.start()
                    
                except Exception as e:
                    print(f"Error receiving DNS query: {e}")
                    
        except Exception as e:
            print(f"Error starting server: {e}")
        finally:
            server_socket.close()

if __name__ == "__main__":
    proxy = DoubleLayerAsymmetricDNSProxy()
    proxy.start_server()
