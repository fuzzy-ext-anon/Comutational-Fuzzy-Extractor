import hashlib

class groupHash:
    def __init__(self, p: int = (2**1001 - 335529), q: int = (2**1000 - 167765)) -> None:
        
        self.p = p
        self.q = q
    
    def L(self, x: int, t: int) -> int:
        '''
        Check if x is in group G of order q. Where t = 2 * q + 1
        ---
        Inputs:
        `x`: Element to check
        `t`: Safe prime where `t = 2 * q + 1`. q is also a prime, and the order of group G
        
        Output:
        Outputs a flag (`1`, `0`, or `-1`) to indicate whether x is an element of group G or not.
        '''
        if x in [0, 1]: return x

        if (x % 4 == 3 and t % 4 == 3): return -(self.L(t % x, x))

        if x % 2 == 0:
            i = t % 8
            if i in [1,7]: return self.L(x // 2, t)
            else: return -(self.L(x // 2, t))

        else: return self.L(t % x, x)


    def ghash(self, msg) -> int:
        '''
        Hash function that maps any message to an element of group G of order p
        ---
        Inputs:
        * `msg`: Message to be hashed. Accepts the same input types as md5

        Output:
        * Element of group G. Integer.
        '''
        
        # Compute s - the first 1000 bits of MD5(1|x)||...||MD5(10|x)
        s = b""

        for i in range(1,9):
            h = hashlib.new("md5")
            h.update(bytes("{}{}".format(i, msg), 'utf-8'))
            s += h.digest()

        # Cast the first 1000 bits of s to an int
        s = int.from_bytes(s[:125], 'big')
        # print(s)

        # Compute flag = L(s, p)
        if self.L(s, self.p) == 1:
            # If L(s, p) = 1, return s
            return s
        # It it's 0 or -1, return p-s
        return self.p - s




