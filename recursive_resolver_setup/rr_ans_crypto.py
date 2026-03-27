#!/usr/bin/env python3
import socket
import struct
import base64
import json
import time
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend

class RRANSCrypto:
    def __init__(self):
        self.load_keys()
        
    def load_keys(self):
        """Load RR keys for ANS communication"""
        try:
            # Load RR private key for ANS communication
            with open('/etc/powerdns/keys/rr-to-ans_private_key.pem', 'rb') as f:
                self.rr_private_key = serialization.load_pem_private_key(
                    f.read(), password=None, backend=default_backend()
                )
            
            # Load ANS public key
            with open('/etc/powerdns/keys/ans_public_key.pem', 'rb') as f:
                self.ans_public_key = serialization.load_pem_public_key(
                    f.read(), backend=default_backend()
                )
            
            print("✅ RR-ANS encryption keys loaded")
            
        except Exception as e:
            print(f"❌ Error loading RR-ANS keys: {e}")
            raise
    
    def encrypt_for_ans(self, dns_query):
        """Encrypt DNS query for ANS"""
        try:
            # <<< CHANGE 1: START ENCRYPTION TIMESTAMP >>>
            print(f"TIMESTAMP: {time.time():.6f} - TW10 STARTS ENCRYPTING THE PACKET FOR ANS")

            # Generate session key
            session_key = Fernet.generate_key()
            cipher = Fernet(session_key)
            
            # Encrypt DNS query
            encrypted_data = cipher.encrypt(dns_query)
            
            # Sign with RR private key
            signature = self.rr_private_key.sign(
                encrypted_data,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            
            # Encrypt session key with ANS public key
            encrypted_session_key = self.ans_public_key.encrypt(
                session_key,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            
            packet = {
                'encrypted_session_key': base64.b64encode(encrypted_session_key).decode(),
                'signature': base64.b64encode(signature).decode(),
                'encrypted_data': base64.b64encode(encrypted_data).decode(),
                'timestamp': int(time.time())
            }
            
            # <<< CHANGE 2: END ENCRYPTION TIMESTAMP >>>
            print(f"TIMESTAMP: {time.time():.6f} - TW12 ENDS ENCRYPTION FOR ANS")
            
            return json.dumps(packet)
            
        except Exception as e:
            print(f"❌ ANS encryption error: {e}")
            return None
    
    def send_encrypted_to_ans(self, dns_query, ans_host='4.247.24.171', ans_port=5354):
        """Send encrypted query to ANS"""
        try:
            # Encrypt the query by calling the function above
            encrypted_data = self.encrypt_for_ans(dns_query)
            if not encrypted_data:
                return None

            # Send via TCP
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(30)
            sock.connect((ans_host, ans_port))

            # Send encrypted data
            data_bytes = encrypted_data.encode()
            
            # <<< CHANGE 3: SEND PACKET TIMESTAMP >>>
            print(f"TIMESTAMP: {time.time():.6f} - TW13 SENDS PACKET TO CUSTOM ANS")
            sock.send(struct.pack('!I', len(data_bytes)))
            sock.send(data_bytes)

            print(f"📤 Sent encrypted query to ANS ({len(data_bytes)} bytes)")

            # Receive encrypted response
            response_len_data = sock.recv(4)
            if not response_len_data:
                print("❌ No response length received from ANS.")
                return None
            response_len = struct.unpack('!I', response_len_data)[0]
            
            encrypted_response = b''
            while len(encrypted_response) < response_len:
                packet = sock.recv(response_len - len(encrypted_response))
                if not packet:
                    break
                encrypted_response += packet

            sock.close()

            # Decrypt response
            decrypted_response = self.decrypt_from_ans(encrypted_response.decode())
            return decrypted_response

        except Exception as e:
            print(f"❌ ANS communication error: {e}")
            return None
    
    def decrypt_from_ans(self, encrypted_response):
        """Decrypt response from ANS"""
        try:
            print(f"TIMESTAMP: {time.time():.6f} - TW20 STARTS DECRYPTION FROM ANS")
            packet = json.loads(encrypted_response)
            
            # Decrypt session key
            session_key = self.rr_private_key.decrypt(
                base64.b64decode(packet['encrypted_session_key']),
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            
            # Verify ANS signature
            signature = base64.b64decode(packet['signature'])
            encrypted_data = base64.b64decode(packet['encrypted_data'])
            
            self.ans_public_key.verify(
                signature,
                encrypted_data,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            
            # Decrypt response
            cipher = Fernet(session_key)
            decrypted_response = cipher.decrypt(encrypted_data)
            
            print(f"TIMESTAMP: {time.time():.6f} - TW21 ENDS DECRYPTION FROM ANS")
            print("✅ ANS response decrypted successfully")
            return decrypted_response
            
        except Exception as e:
            print(f"❌ ANS decryption error: {e}")
            return None

# Test function
if __name__ == "__main__":
    crypto = RRANSCrypto()
    print("RR-ANS crypto module ready!")
