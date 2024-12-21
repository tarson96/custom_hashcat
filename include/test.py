import socket
import json

def test_hashcat_server():
    # Connect to server
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect(('114.34.116.46', 41110))
    
    # Test command
    cmd = "hashcat -m 0 cc03e747a6afbbcbf8be7668acfebee5 -a 3 -1 ?l?d ?1?1?1?1?1?1"
    
    try:
        # Send command
        sock.send(cmd.encode())
        
        # Get response
        response = sock.recv(4096)
        result = json.loads(response.decode())
        
        print("Server Response:", result)
        
        if result['status'] == 'completed':
            print("Success!")
            if 'stdout' in result:
                print("Output:", result['stdout'])
        else:
            print("Error:", result.get('error', 'Unknown error'))
            
    finally:
        sock.close()

if __name__ == "__main__":
    test_hashcat_server()