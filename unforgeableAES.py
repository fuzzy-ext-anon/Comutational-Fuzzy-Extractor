from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import sslcrypto
import hmac

import time


class unforgeableAES:

    def __init__(self, lbd=128, aes_mode=AES.MODE_CTR, hmac_digest='sha3_256', keys=None):
        '''
        Constructor for the Strongly Unforgeable AES class
        ---
        Input:
        lbd - Security parameter. Length of AES and HMAC keys (bits). Defalut: 128 bits
        aes_mode - AES mode of operation. Default: Counter mode
        hmac_digest - HMAC digest. Default: SHA3-256 
        key - Used to specify AES and HMAC keys. If None, generate secure random keys using Crypto.Random.get_randombytes(). Default: None

                
        Output:
        Unforgeable AES object
        '''

        self.lbd = lbd
        self.mode = aes_mode
        self.digest = hmac_digest
        self.nonce = get_random_bytes(16)
        
        # Generate keys
        k = self.keygen(key=keys)
        # print("Testing keys: ", k, len(k[0]), len(k[1]))

        # Initialize AES and HMAC
        self.hmac = hmac.digest


    def keygen(self, key=None):
        '''
        Key Generation Function
        ---
        Inputs:
        key (Optional): Used to specify AES and HMAC keys. If None, generate secure random keys using Crypto.Random.get_randombytes().

        Output:
        keys: Key of the unforgeable encryption system. Tuple of AES and HMAC keys.
        '''
        if key:
            assert(type(key) == tuple and len(key) == 2)
            assert(type(key[0]) == bytes and type(key[1]) == bytes)

            self.aeskey = key[0]
            self.hmackey = key[1]

            return (self.aeskey, self.hmackey)

        bytelen = self.lbd//8
        k = get_random_bytes(bytelen*2)
        self.aeskey, self.hmackey = k[:bytelen], k[bytelen:]

        return (self.aeskey, self.hmackey)



    def unforgeable_Enc(self, msg):
        '''
        Strongly Unforgeable AES encryption function
        ---
        Inputs:
        * `msg`: Message to encrypt. Must be of type `bytes`
        
        Outputs: Ciphertext containing
        * `nonce`: AES nonce
        * `alpha`: AES ciphertext
        * `beta`: HMAC tag
        '''

        t = time.time()
        alpha, nonce = sslcrypto.aes.encrypt(msg, self.aeskey, algo="aes-128-ctr")
        print(f"Encryption took {time.time() - t} seconds")
        beta = self.hmac(self.hmackey, alpha, self.digest)

        return (nonce, alpha, beta)


    def unforgeable_Dec(self, nonce, alpha_, beta_):
        '''
        
        '''
        beta = self.hmac(self.hmackey, alpha_, self.digest)
        if beta != beta_ : return None
        return sslcrypto.aes.decrypt(alpha_, nonce, self.aeskey, algo="aes-128-ctr")
        

    def Dec(self, nonce, alpha_):
        '''
        
        '''
        return sslcrypto.aes.decrypt(alpha_, nonce, self.aeskey, algo="aes-128-ctr")

# ciph = unforgeableAES()
# keys = ciph.keygen(key=(get_random_bytes(16), get_random_bytes(16)))

# print(keys, len(keys[0]), len(keys[1]))

# message = get_random_bytes(154_000_000 + 32 + 16)

# t1 = time.time()

# nonce, a, b = ciph.unforgeable_Enc(message)

# t2 = time.time()
# print(t2-t1, " seconds")

# m = ciph.unforgeable_Dec(nonce, a, b)

# t3 = time.time()
# print(t3-t2, " seconds")

# print(message == m)
