#!/usr/bin/env python3
import socket
import threading
import subprocess
import sys
import os
import time
sys.path.append('/etc/powerdns')
# from recursor_crypto import RecursorCrypto
# try:
#     from recursor_crypto import RecursorCrypto
#     from rr_ans_crypto import RRANSCrypto  # Add this line
# except ImportError as e:
#     print(f"Error: Could not import crypto modules: {e}")
#     sys.exit(1)

class EncryptedDNSServer:
    def __init__(self, listen_port=5354, powerdns_port=53):
        self.listen_port = listen_port
        self.powerdns_port = powerdns_port
    
        # try:
        #     self.crypto = RecursorCrypto()  # For proxy communication
        #     self.ans_crypto = RRANSCrypto()  # Add this line - for ANS communication
        #     print("✅ Both crypto modules loaded successfully")
        # except Exception as e:
        #     print(f"❌ Error loading crypto modules: {e}")
        #     sys.exit(1)
        print("✅ DNS Server loaded successfully (NO ENCRYPTION)")
        
    def handle_encrypted_dns(self, conn, addr):
        "Handle encrypted DNS connection"
        try:
            # TIMING: Record RR start time
            rr_start_time = time.time()
            print(f"TIMESTAMP: {time.time():.6f} - TW6 RR RECEIVES THE PACKET FROM PROXY")
            print(f"🔐 DNS connection from: {addr}")
        
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
        
            # Receive encrypted session key
            print("📥 Reading session key length...")
            session_key_len_data = recv_exact(conn, 2)
            session_key_len = struct.unpack('!H', session_key_len_data)[0]
            print(f"📥 Session key length: {session_key_len} bytes")
        
            if session_key_len > 1024:  # Sanity check
                raise ValueError(f"Session key length too large: {session_key_len}")
            
            encrypted_session_key = recv_exact(conn, session_key_len)
            print(f"✅ Session key received (DUMMY)")
        
            # Receive signature
            print("📥 Reading signature length...")
            signature_len_data = recv_exact(conn, 2)
            signature_len = struct.unpack('!H', signature_len_data)[0]
            print(f"📥 Signature length: {signature_len} bytes")
        
            if signature_len > 1024:  # Sanity check
                raise ValueError(f"Signature length too large: {signature_len}")
            
            signature = recv_exact(conn, signature_len)
            print(f"✅ Signature received (DUMMY)")
        
            # Receive encrypted data
            print("📥 Reading data length...")
            data_len_data = recv_exact(conn, 2)
            data_len = struct.unpack('!H', data_len_data)[0]
            print(f"📥 Data length: {data_len} bytes")
        
            if data_len > 10240:  # Sanity check - 10KB max
                raise ValueError(f"Data length too large: {data_len}")
            
            encrypted_data = recv_exact(conn, data_len)
            print(f"✅ Data received (PLAIN)")
        
            # Receive timestamp
            print("📥 Reading timestamp...")
            timestamp_data = recv_exact(conn, 4)
            timestamp = struct.unpack('!I', timestamp_data)[0]
            print(f"✅ Timestamp received: {timestamp}")
        
            print(f"🎉 Complete packet received successfully!")
            print("=" * 60)
            print("📦 PACKET CONTENTS (NO ENCRYPTION):")
            print("=" * 60)
            print(f"🔑 Session Key (DUMMY - first 32 bytes): {encrypted_session_key[:32].hex()}")
            print(f"🖊️  Signature (DUMMY - first 32 bytes): {signature[:32].hex()}")
            print(f"🔒 DNS Data (PLAIN - first 32 bytes): {encrypted_data[:32].hex()}")
            print(f"⏰ Timestamp: {timestamp}")
            print(f"📊 Total Packet Size: {len(encrypted_session_key) + len(signature) + len(encrypted_data) + 4} bytes")
            print("=" * 60)
        
            # Create packet for decryption
            # packet = {
            #     'encrypted_session_key': base64.b64encode(encrypted_session_key).decode(),
            #     'signature': base64.b64encode(signature).decode(),
            #     'encrypted_data': base64.b64encode(encrypted_data).decode(),
            #     'timestamp': timestamp
            # }
            # print("📄 JSON PACKET STRUCTURE:")
            # print(f"   Session Key Length: {len(packet['encrypted_session_key'])} chars")
            # print(f"   Signature Length: {len(packet['signature'])} chars") 
            # print(f"   Encrypted Data Length: {len(packet['encrypted_data'])} chars")
            # print(f"   JSON Sample: {json.dumps(packet)[:100]}...")
            # print("=" * 60)
        
            # Decrypt DNS packet
            # print(f"TIMESTAMP: {time.time():.6f} - TW7 BEGINS DECRYPTION FROM PROXY")
            print(f"TIMESTAMP: {time.time():.6f} - TW7 PROCESSING PACKET FROM PROXY (NO DECRYPTION)")
            print("🔓 Processing packet...")
            # decrypted_dns = self.crypto.decrypt_dns_query(json.dumps(packet))
            # if not decrypted_dns:
            #     print("❌ Failed to decrypt DNS packet")
            #     return
            # print(f"TIMESTAMP: {time.time():.6f} - TW8 ENDS DECRYPTION FROM PROXY")
            print(f"TIMESTAMP: {time.time():.6f} - TW8 PROCESSING COMPLETED (NO DECRYPTION)")
            # dns_packet = base64.b64decode(decrypted_dns)
            dns_packet = encrypted_data  # Use data as-is
            print(f"✅ DNS packet processed ({len(dns_packet)} bytes)")
            print("🔓 DNS PACKET:")
            print(f"   Raw bytes (hex): {dns_packet.hex()}")
            print(f"   ASCII view: {dns_packet.decode('utf-8', errors='ignore')}")
            print("=" * 60) 
            
            # Forward to PowerDNS
            print("📡 Forwarding to PowerDNS...")
            dns_response = self.forward_to_powerdns(dns_packet)
            if not dns_response:
                print("❌ No response from PowerDNS")
                return
            print(f"✅ Received response from PowerDNS ({len(dns_response)} bytes)")
        
            # Encrypt response
            # print(f"TIMESTAMP: {time.time():.6f} - TW22 STARTS ENCRYPTING FOR PROXY")
            print(f"TIMESTAMP: {time.time():.6f} - TW22 PREPARING RESPONSE FOR PROXY (NO ENCRYPTION)")
            print("🔒 Preparing response...")
            # encrypted_response = self.crypto.encrypt_dns_response(
            #     base64.b64encode(dns_response).decode()
            # )
            # if not encrypted_response:
            #     print("❌ Failed to encrypt response")
            #     return
            # print(f"TIMESTAMP: {time.time():.6f} - TW23 ENDS ENCRYPTION FOR PROXY")
            print(f"TIMESTAMP: {time.time():.6f} - TW23 RESPONSE PREPARATION COMPLETED (NO ENCRYPTION)")
            # response_packet = json.loads(encrypted_response)
            
            # Create dummy response packet
            response_packet = {
                'encrypted_session_key': base64.b64encode(b"dummy_response_session_key").decode(),
                'signature': base64.b64encode(b"dummy_response_signature").decode(),
                'encrypted_data': base64.b64encode(dns_response).decode(),
                'timestamp': int(time.time())
            }
        
            # Send response back
            print(f"TIMESTAMP: {time.time():.6f} - TW24 SENDS PACKET TO PROXY")
            print("📤 Sending response...")
            session_key = base64.b64decode(response_packet['encrypted_session_key'])
            signature = base64.b64decode(response_packet['signature'])
            encrypted_data = base64.b64decode(response_packet['encrypted_data'])
        
            conn.send(struct.pack('!H', len(session_key)))
            conn.send(session_key)
            conn.send(struct.pack('!H', len(signature)))
            conn.send(signature)
            conn.send(struct.pack('!H', len(encrypted_data)))
            conn.send(encrypted_data)
            conn.send(struct.pack('!I', response_packet['timestamp']))
        
            # TIMING: Record RR end time and calculate RTT
            rr_end_time = time.time()
            rr_rtt = (rr_end_time - rr_start_time) * 1000
            print(f"RR RTT: {rr_rtt:.2f}ms")
            print("🎉 DNS response sent successfully!")
        
        except Exception as e:
            print(f"❌ Error handling DNS: {e}")
            import traceback
            traceback.print_exc()
        finally:
            conn.close()
    
    def forward_to_powerdns(self, dns_packet):
        """Forward DNS packet - with domain-based routing"""
        try:
            # Check if this is YOUR domain that needs encrypted ANS
            if self.should_use_encrypted_ans(dns_packet):
                # print("🔐 Custom domain detected - using encrypted ANS")
                print("🔐 Custom domain detected - using ANS (NO ENCRYPTION)")
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
            print(f"TIMESTAMP: {time.time():.6f} - TW10 SENDS IT TO CUSTOM DNS")
            # print("🔐 Sending to encrypted ANS...")
            print("🔐 Sending to ANS (NO ENCRYPTION)...")
            # response = self.ans_crypto.send_encrypted_to_ans(
            #     dns_packet,
            #     ans_host='4.247.24.171',  # Your ANS IP
            #     ans_port=5354
            # )
            
            # Direct TCP connection to ANS without encryption
            response = self.send_to_ans_direct(dns_packet, '4.247.24.171', 5354)
            
            # TIMING: Record end time and calculate ANS RTT
            print(f"TIMESTAMP: {time.time():.6f} - TW19 RECEIVES CUSTOM DNS RESULT")
            ans_end_time = time.time()
            ans_rtt = (ans_end_time - ans_start_time) * 1000
            print(f"ANS RTT: {ans_rtt:.2f}ms")
            
            if response:
                print(f"TIMESTAMP: {time.time():.6f} - TW20 PROCESSING ANS RESPONSE (NO DECRYPTION)")
                print("✅ Got response from ANS")
                print(f"TIMESTAMP: {time.time():.6f} - TW21 ANS RESPONSE PROCESSING COMPLETED (NO DECRYPTION)")
            
            return response
            
        except Exception as e:
            print(f"❌ ANS error: {e}")
            return None

    def send_to_ans_direct(self, dns_packet, ans_host, ans_port):
        """Send DNS packet directly to ANS without encryption"""
        try:
            # Create direct TCP connection to ANS
            ans_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            ans_socket.settimeout(30)
            ans_socket.connect((ans_host, ans_port))
            
            # Send DNS packet length and data
            dns_len = len(dns_packet)
            ans_socket.send(struct.pack('!H', dns_len))
            ans_socket.send(dns_packet)
            
            # Receive response length and data
            response_len = struct.unpack('!H', ans_socket.recv(2))[0]
            response_data = ans_socket.recv(response_len)
            
            ans_socket.close()
            return response_data
            
        except Exception as e:
            print(f"❌ Direct ANS communication error: {e}")
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
        """Start DNS server"""
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_socket.bind(('0.0.0.0', self.listen_port))
        server_socket.listen(10)
        
        print(f"🔐 DNS Server listening on port {self.listen_port} (NO ENCRYPTION)")
        print("📡 Forwarding to PowerDNS on port 53")
        print("🚀 Ready for DNS queries!")
        
        while True:
            conn, addr = server_socket.accept()
            thread = threading.Thread(
                target=self.handle_encrypted_dns,
                args=(conn, addr)
            )
            thread.daemon = True
            thread.start()

if __name__ == "__main__":
    import struct
    import base64
    import json
    
    server = EncryptedDNSServer()
    server.start_server()
