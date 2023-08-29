import socket


def close_socket( sock ):
    """A helper function to close sockets"""
    sock.shutdown(socket.SHUT_RDWR)
    sock.close()
    return None


def create_socket( ip:str, port:int, listen:bool=False ) -> socket.socket:
    """Create a TCP/IP socket at the specified port, and do the setup
        necessary to turn it into a connecting or receiving socket. Do
        not actually send or receive data here, and do not accept any
        incoming connections!

    PARAMETERS
    ==========
    ip: A string representing the IP address to connect/bind to.
    port: An integer representing the port to connect/bind to.
    listen: A boolean that flags whether or not to set the socket up
        for connecting or receiving.

    RETURNS
    =======
    If successful, a socket object that's been prepared according to 
        the instructions. Otherwise, return None.
    """

    assert type(ip) == str
    assert type(port) == int

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    try:
        if listen:
            sock.bind( (ip, port) )
            sock.listen(2)
        else:
            sock.connect( (ip, port) )

        return sock
    except:
        return None

def send( sock:socket.socket, data:bytes ) -> int:
    """Send the provided data across the given socket. This is a
        'reliable' send, in the sense that the function retries sending
        until either a) all data has been sent, or b) the socket 
        closes.

    PARAMETERS
    ==========
    sock: A socket object to use for sending and receiving.
    data: A bytes object containing the data to send.

    RETURNS
    =======
    The number of bytes sent. If this value is less than len(data),
        the socket is dead plus an unknown amount of the data was transmitted.
    """

    assert type(sock) == socket.socket
    assert type(data) == bytes


    sent = 0
    while sent < len(data):
        try:
            out = sock.send( data[sent:] )
        except:
            return sent

        if out <= 0:
            return sent
        sent += out

    return sent


def receive( sock:socket.socket, length:int ) -> bytes:
    """Receive the provided data across the given socket. This is a
        'reliable' receive, in the sense that the function never returns
        until either a) the specified number of bytes was received, or b) 
        the socket closes. Never returning is an option.

    PARAMETERS
    ==========
    sock: A socket object to use for sending and receiving.
    length: A positive integer representing the number of bytes to receive.

    RETURNS
    =======
    A bytes object containing the received data. If this value is less than 
        length, the socket is dead.
    """

    assert type(sock) == socket.socket
    assert length > 0

    receieved = b''
    while len(receieved) < length:

        rem = length - len(receieved)
        try:
            input_ = sock.recv( min(rem, 2*4_194_304) )
        except:
            return receieved

        if input_ == b'':
            return receieved
        receieved = receieved + input_

    return receieved



