from unforgeableAES import unforgeableAES
from groupHash import groupHash
from socket_helper import close_socket, create_socket, send, receive
from Crypto.Random import random, get_random_bytes
import hashlib, hmac
import socket
import time

P = (2**1001 - 335529)
Q = (2**1000 - 167765)

CTXT_SIZE = 154_000_000 + 32 + 16


def PPMR_client(sock:socket.socket, p:int, q:int, pwd:str, uid:int):
    t = time.time()
    r = random.randrange(q)
    r_inv = pow(r, -1, q)               # Modular inverse of r
    
    hash2 = hashlib.new('sha3_256')     # Prep for k_C calculation
    hash2.update(uid)                   # First part added

    hash1 = groupHash(p, q)

    a = pow((hash1.ghash(pwd)), r, p)

    assert hash1.L(a, p) == 1

    to_send = int.to_bytes(a, 126, byteorder='big')

    # send a using socket 
    sent = send(sock, to_send)
    if sent != len(to_send): return None

    # receive b from the server
    received = receive(sock, 126)
    if len(received) != 126: print(f"Client: received {len(received)} instead of {126}"); return None

    b = int.from_bytes(received, 'big')
    assert hash1.L(b, p) == 1

    to_hash = int.to_bytes(pow(b, r_inv, p), 126, 'big')
    hash2.update(to_hash)      # Final addition

    k_C = hash2.digest()        # Finalized kC

    # receive ctxt from server
    nonce = receive(sock, 16)

    h = hmac.new(k_C[16:], digestmod='sha3_256')
    
    alpha_len = 0
    alpha = bytearray()
    
    while alpha_len < 154_000_000:
        remaining = 154_000_000 - alpha_len
        al = sock.recv(min(2*4_194_304, remaining))
        alpha_len += len(al)
        alpha += al
        h.update(al)

    beta = receive(sock, 32)


    if (len(nonce)+len(alpha)+len(beta)) != CTXT_SIZE: print(f"Client: received {len(nonce)+len(alpha)+len(beta)} instead of {CTXT_SIZE}"); return None
    
    beta_ = h.digest()

    uAES = unforgeableAES(keys=(k_C[:16], k_C[16:]))

    if beta == beta_: msg = uAES.Dec(nonce, bytes(alpha))
    else: print(f"Client: Received tag (beta) doesn't match computed tag"); return None

    return k_C, msg


def client_setup(ip:str, port:int):
    cli = create_socket(ip, port, listen=False)

    t = time.time()         # Start the timer for client-side communication

    k_C, msg = PPMR_client(cli, p=P, q=Q, pwd=b"ExamplePassword", uid=b"123456")

    print(f"Client: Established a key in {time.time() - t} seconds")

    close_socket(cli)

    return k_C, msg


if __name__ == "__main__":
    # NOTE: To test the scheme, edit IP and PORT below
    IP = "00.00.000.00"
    PORT = 0000
    k_c, msg = client_setup(IP, PORT)