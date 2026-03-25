import socket
import threading
# from cryptography.hazmat.primitives.asymmetric import rsa, padding
# from cryptography.hazmat.primitives import hashes, serialization, hmac
# from cryptography.fernet import Fernet
# from cryptography.hazmat.backends import default_backend
import struct
import os
import time
import json
import base64
import dns.message
import dns.name
import time

class DoubleLayerDNSProxy:
    def __init__(self):
        # Load keys
        # self.load_keys()
        
        # Generate session key for confidentiality layer
        # self.session_key = Fernet.generate_key()
        # self.cipher = Fernet(self.session_key)
        pass
    
    def load_keys(self):
        """Load proxy's private key and middleware's public key"""
        # try:
        #     # Load proxy's private key
        #     with open('proxy_private_key.pem', 'rb') as f:
        #         self.proxy_private_key = serialization.load_pem_private_key(
        #             f.read(),
        #             password=None,
        #             backend=default_backend()
        #         )
        #     
        #     # Load middleware's public key (you need to copy this file)
        #     with open('recursor_public_key.pem', 'rb') as f:
        #         self.middleware_public_key = serialization.load_pem_public_key(
        #             f.read(),
        #             backend=default_backend()
        #         )
        #     
        #     print("Keys loaded successfully")
        #     
        # except FileNotFoundError as e:
        #     print(f"Key file not found: {e}")
        #     print("Please run key_generator.py first and exchange public keys")
        #     exit(1)
        pass
    
    def create_authentication_signature(self, data):
        """Layer 1: Create digital signature for authentication"""
        # try:
        #     signature = self.proxy_private_key.sign(
        #         data,
        #         padding.PSS(
        #             mgf=padding.MGF1(hashes.SHA256()),
        #             salt_length=padding.PSS.MAX_LENGTH
        #         ),
        #         hashes.SHA256()
        #     )
        #     return signature
        # except Exception as e:
        #     print(f"Signature creation error: {e}")
        #     return None
        return b"dummy_signature"
    
    def encrypt_confidentiality_layer(self, data):
        """Layer 2: Encrypt data for confidentiality"""
        # try:
        #     encrypted_data = self.cipher.encrypt(data)
        #     return encrypted_data
        # except Exception as e:
        #     print(f"Confidentiality encryption error: {e}")
        #     return None
        return data  # Return original data without encryption
    
    def decrypt_confidentiality_layer(self, encrypted_data):
        """Layer 2: Decrypt data"""
        # try:
        #     decrypted_data = self.cipher.decrypt(encrypted_data)
        #     return decrypted_data
        # except Exception as e:
        #     print(f"Confidentiality decryption error: {e}")
        #     return None
        return encrypted_data  # Return data as-is
    
    def encrypt_session_key_for_middleware(self):
        """Encrypt session key using middleware's public key"""
        # try:
        #     encrypted_session_key = self.middleware_public_key.encrypt(
        #         self.session_key,
        #         padding.OAEP(
        #             mgf=padding.MGF1(algorithm=hashes.SHA256()),
        #             algorithm=hashes.SHA256(),
        #             label=None
        #         )
        #     )
        #     return encrypted_session_key
        # except Exception as e:
        #     print(f"Session key encryption error: {e}")
        #     return None
        return b"dummy_session_key"
    
    def create_double_encrypted_packet(self, dns_data):
        """Create double-layer encrypted packet"""
        try:
            print(f"📊 Original DNS data: {len(dns_data)} bytes")  
            print("=" * 60)
            print("📦 ORIGINAL DNS PACKET:")
            print("=" * 60)
            print(f"🔍 Raw DNS bytes (hex): {dns_data.hex()}")
            print(f"🔍 ASCII view: {dns_data.decode('utf-8', errors='ignore')}")
            print("=" * 60)
            
            # Layer 2: Confidentiality - Encrypt DNS data with session key
            # confidential_data = self.encrypt_confidentiality_layer(dns_data)
            confidential_data = dns_data  # Skip encryption
            if confidential_data is None:
                return None
            print(f"📊 After AES encryption (SKIPPED): {len(confidential_data)} bytes")
            print(f"🔒 AES Encrypted Data (SKIPPED - first 32 bytes): {confidential_data[:32].hex()}")
         
            # Layer 1: Authentication - Sign the encrypted data
            # signature = self.create_authentication_signature(confidential_data)
            signature = b"dummy_signature"  # Skip signature
            if signature is None:
                return None
            print(f"📊 Signature size (DUMMY): {len(signature)} bytes")
        
            # ADD THIS: Show signature
            print(f"🖊️  RSA Signature (DUMMY - first 32 bytes): {signature[:32].hex()}")
            
            # Encrypt session key for middleware
            # encrypted_session_key = self.encrypt_session_key_for_middleware()
            encrypted_session_key = b"dummy_session_key"  # Skip session key encryption
            if encrypted_session_key is None:
                return None
            print(f"📊 Encrypted session key (DUMMY): {len(encrypted_session_key)} bytes")
        
            # ADD THIS: Show encrypted session key
            print(f"🔑 Encrypted Session Key (DUMMY - first 32 bytes): {encrypted_session_key[:32].hex()}")
        
            # Create packet structure
            packet = {
                'encrypted_session_key': encrypted_session_key,
                'signature': signature,
                'encrypted_data': confidential_data,
                'timestamp': int(time.time())
            }
            total_size = len(encrypted_session_key) + len(signature) + len(confidential_data) + 4
            print(f"📊 Total encrypted packet (NO ENCRYPTION): {total_size} bytes")
        
            # ADD THIS: Show complete encrypted packet summary
            print("=" * 60)
            print("📦 FINAL PACKET SUMMARY (NO ENCRYPTION):")
            print("=" * 60)
            print(f"🔑 Session Key (DUMMY): {len(encrypted_session_key)} bytes → {encrypted_session_key[:16].hex()}...")
            print(f"🖊️  Signature (DUMMY):   {len(signature)} bytes → {signature[:16].hex()}...")
            print(f"🔒 Data (PLAIN):   {len(confidential_data)} bytes → {confidential_data[:16].hex()}...")
            print(f"⏰ Timestamp:   {packet['timestamp']}")
            print("=" * 60)
            return packet
            
        except Exception as e:
            print(f"Double encryption error: {e}")
            return None
    
    def decrypt_response_packet(self, response_packet):
        """Decrypt response from middleware"""
        # try:
        #     # Decrypt session key (middleware encrypted it with our public key)
        #     response_session_key = self.proxy_private_key.decrypt(
        #         response_packet['encrypted_session_key'],
        #         padding.OAEP(
        #             mgf=padding.MGF1(algorithm=hashes.SHA256()),
        #             algorithm=hashes.SHA256(),
        #             label=None
        #         )
        #     )
        #     
        #     # Create cipher with response session key
        #     response_cipher = Fernet(response_session_key)
        #     
        #     # Decrypt the response data
        #     decrypted_response = response_cipher.decrypt(response_packet['encrypted_data'])
        #     
        #     return decrypted_response
        #     
        # except Exception as e:
        #     print(f"Response decryption error: {e}")
        #     return None
        
        # Skip decryption, return data as-is
        return response_packet['encrypted_data']
    
    def send_encrypted_dns_tcp(self, encrypted_packet, host, port):
        """Send encrypted DNS packet via TCP (like DNSCrypt)"""
        try:
            # TIMING: Record proxy start time
            proxy_start_time = time.time()
            
            tcp_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            tcp_socket.settimeout(60)
            tcp_socket.connect((host, port))
            
            # Send encrypted session key
            session_key_len = len(encrypted_packet['encrypted_session_key'])
            tcp_socket.send(struct.pack('!H', session_key_len))
            tcp_socket.send(encrypted_packet['encrypted_session_key'])
            
            # Send signature
            signature_len = len(encrypted_packet['signature'])
            tcp_socket.send(struct.pack('!H', signature_len))
            tcp_socket.send(encrypted_packet['signature'])
            
            # Send encrypted DNS data
            data_len = len(encrypted_packet['encrypted_data'])
            tcp_socket.send(struct.pack('!H', data_len))
            tcp_socket.send(encrypted_packet['encrypted_data'])
            
            # Send timestamp
            tcp_socket.send(struct.pack('!I', encrypted_packet['timestamp']))
            
            print("✓ Sent DNS packet via TCP (NO ENCRYPTION)")
            
            # Receive encrypted response
            response_session_key_len = struct.unpack('!H', tcp_socket.recv(2))[0]
            response_encrypted_session_key = tcp_socket.recv(response_session_key_len)
            
            response_signature_len = struct.unpack('!H', tcp_socket.recv(2))[0]
            response_signature = tcp_socket.recv(response_signature_len)
            
            response_data_len = struct.unpack('!H', tcp_socket.recv(2))[0]
            response_encrypted_data = tcp_socket.recv(response_data_len)
            
            response_timestamp = struct.unpack('!I', tcp_socket.recv(4))[0]
            
            tcp_socket.close()
            
            # TIMING: Record proxy end time and calculate RTT
            proxy_end_time = time.time()
           
            proxy_rtt = (proxy_end_time - proxy_start_time) * 1000
            print(f"PROXY RTT: {proxy_rtt:.2f}ms")
            
            return {
                'encrypted_session_key': response_encrypted_session_key,
                'signature': response_signature,
                'encrypted_data': response_encrypted_data,
                'timestamp': response_timestamp
            }
            
        except Exception as e:
            print(f"TCP DNS communication error: {e}")
            return None

    def handle_dns_query(self, data, client_address, server_socket):
        """Handle DNS query with double-layer encryption of actual DNS packet"""
        start_time = time.time()
        print(f"TIMESTAMP: {time.time():.6f} - TW2 PROXY RECIVED PACKET FROM CLINET")
        print(f"\n--- DNS Query from {client_address} at {start_time}  ---")
        
        try:
            # Step 1: Extract the original DNS query from the packet
            print(f"✓ Original DNS packet size: {len(data)} bytes")
            
            # Step 2: Create double-encrypted packet from the actual DNS data
            # print(f"TIMESTAMP: {time.time():.6f} - TW3 ENCRYPTION OF CLIENT QUERY STARTS")
            print(f"TIMESTAMP: {time.time():.6f} - TW3 PACKET PREPARATION STARTS (NO ENCRYPTION)")
            encrypted_packet = self.create_double_encrypted_packet(data)
            if encrypted_packet is None:
                print("Failed to create packet")
                return
            # print(f"TIMESTAMP: {time.time():.6f} - TW4 ENCRYPTION COMPLETED")
            print(f"TIMESTAMP: {time.time():.6f} - TW4 PACKET PREPARATION COMPLETED (NO ENCRYPTION)")
            # print("✓ Layer 1 (Authentication): Digital signature created")
            # print("✓ Layer 2 (Confidentiality): DNS packet encrypted")
            print("✓ Layer 1 (Authentication): SKIPPED")
            print("✓ Layer 2 (Confidentiality): SKIPPED")
            
            # Step 3: Send encrypted DNS packet via TCP (like DNSCrypt)
            # print(f"TIMESTAMP: {time.time():.6f} - TW5 SENDING ENCRYPTED PACKET TO RR")
            print(f"TIMESTAMP: {time.time():.6f} - TW5 SENDING PACKET TO RR (NO ENCRYPTION)")
            response_packet = self.send_encrypted_dns_tcp(
                encrypted_packet,
                '10.230.3.83',  # Recursor IP
                5354            # Custom encrypted DNS port
            )
            
            if response_packet is None:
                print("Failed to get response")
                return
            print(f"TIMESTAMP: {time.time():.6f} - TW25 RECIVED PACKETS AT PROXY FROM RR")
            
            # Step 4: Decrypt the DNS response
            # print(f"TIMESTAMP: {time.time():.6f} - TW26 DECRYPTION STARTS OF PROXY PACKET")
            print(f"TIMESTAMP: {time.time():.6f} - TW26 PROCESSING PROXY PACKET (NO DECRYPTION)")
            decrypted_response = self.decrypt_response_packet(response_packet)
            if decrypted_response is None:
                print("Failed to process DNS response")
                return
            # print(f"TIMESTAMP: {time.time():.6f} - TW27 Proxy response decryption completed")
            print(f"TIMESTAMP: {time.time():.6f} - TW27 Proxy response processing completed (NO DECRYPTION)")
            # print("✓ DNS response decrypted successfully")
            print("✓ DNS response processed successfully (NO DECRYPTION)")
            
            # Step 5: Send the original DNS response back to client
            server_socket.sendto(decrypted_response, client_address)
            print(f"TIMESTAMP: {time.time():.6f} - TW28 Proxy sends back to client")
            print(f"✓ DNS response sent back to client {client_address}")
            end_time = time.time()
            total_time = (end_time - start_time) * 1000
            print(f"Total processing time: {total_time:.2f}ms")
            
        except Exception as e:
            print(f"Error handling DNS query: {e}")
            
    def start_server(self):
        """Start the double-layer encrypted DNS proxy"""
        
        HOST = '10.230.3.85'
        PORT = 53
        
        print("=== DNS Proxy (NO ENCRYPTION) ===")
        # print("Layer 1: Authentication (Digital Signatures)")
        # print("Layer 2: Confidentiality (AES Encryption)")
        print("Layer 1: Authentication (DISABLED)")
        print("Layer 2: Confidentiality (DISABLED)")
        print("=========================================")
        
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
    proxy = DoubleLayerDNSProxy()
    proxy.start_server()
