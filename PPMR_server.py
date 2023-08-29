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

def PPMR_server(sock:socket.socket, p:int, q:int, ctxt:bytes, k_uid:int):

    hash1 = groupHash(p, q)

    # receive a from client
    received = receive(sock, 126)
    if len(received) != 126: print(f"Server: received {len(received)} instead of {126}"); return None

    a = int.from_bytes(received, 'big')
    if hash1.L(a, p) != 1 : print(f"Server: a = {a} is not in the group G!"); return None

    # calculate b
    b = pow(a, k_uid, p)
    assert hash1.L(b, p) == 1

    # send b to client
    to_send = int.to_bytes(b, 126, 'big') # + ctxt

    sent = send(sock, to_send)
    if sent != len(to_send): return None
    print("Server: sent b with length ", len(to_send), "and ctxt")

    # send ctxt to client
    sent = send(sock, ctxt)
    if sent != CTXT_SIZE: print(f"Server: tried to send ctxt ({len(ctxt)} bytes), actually sent {sent} bytes"); return None
    print("Server: sent ctxt")


    return


def server_setup(ip:str, port:int):

    # NOTE  In the actual system the client generates k_uid at enrolment
    #       Here we assume client has already enrolled 
    k_uid = random.randrange(Q)
    # print(k_uid)

    hash2 = hashlib.new('sha3_256')     # Prep for k_C calculation
    hash2.update(b"123456")                   # First part added

    hash1 = groupHash(P, Q)

    to_hash = int.to_bytes(pow((hash1.ghash(b"ExamplePassword")), k_uid, P), 126, 'big')

    hash2.update(to_hash)
    k_C = hash2.digest()
    print("k_c generated")

    with open("ctxt.bin", "rb") as file:
        helper = file.read()

    uAES = unforgeableAES(keys=(k_C[:16], k_C[16:]))

    nonce, alpha, beta = uAES.unforgeable_Enc(helper)

    print(f"ctxt encrypted, {len(alpha)}, {len(beta)}")
    
    serv = create_socket(ip, port, listen=True)

    try:
        cli, addr = serv.accept()

        print(f"Server: Got a connection from {addr}")

        PPMR_server(cli, p=P, q=Q, ctxt=nonce+alpha+beta, k_uid=k_uid)
    except:
        pass
    
    close_socket(serv)

    return k_C


if __name__ == "__main__":
    # NOTE: To test the scheme, edit IP and PORT below
    IP = "00.00.000.00"
    PORT = 0000
    k_c = server_setup(IP, PORT)