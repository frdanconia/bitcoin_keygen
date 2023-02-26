import hashlib
import base58
import numpy as np

class EllipticCurve:
    def __init__(self, p, order, gen, a, b):
        self.p = p
        self.order = order
        self.gen = gen
        self.a = a
        self.b = b
    
    def point_add(self, P, Q):
        if P == "infinity":
            return Q
        elif Q == "infinity":
            return P
        elif P[0] == Q[0] and (P[1] != Q[1] or P[1] == 0):
            return "infinity"
        else:
            if P == Q:
                slope = ((3 * P[0] * P[0] + self.a) * pow(2 * P[1], self.p - 2, self.p)) % self.p
            else:
                slope = ((Q[1] - P[1]) * pow(Q[0] - P[0], self.p - 2, self.p)) % self.p
            xR = (slope * slope - P[0] - Q[0]) % self.p
            yR = (slope * (P[0] - xR) - P[1]) % self.p
            return (xR, -yR % self.p)

    def point_double(self, P):
        if P[1] == 0:
            return "infinity"
        else:
            slope = ((3 * P[0] * P[0] + self.a) * pow(2 * P[1], self.p - 2, self.p)) % self.p
            xR = (slope * slope - 2 * P[0]) % self.p
            yR = (slope * (P[0] - xR) - P[1]) % self.p
            return (xR, -yR % self.p)

    def point_multiply(self, k):
        if k == 0 or k >= self.order:
            raise ValueError("Invalid scalar")
        binary_k = bin(k)[2:]
        P = "infinity"
        for bit in binary_k:
            P = self.point_double(P)
            if bit == "1":
                P = self.point_add(P, self.gen)
        return P


class PublicKey:
    def __init__(self, public_key: str):
        self.public_key = public_key

    def convert_base_58_to_decimal(self, x):
        base58array = list('123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz')
        return base58array.index(x)

    def convert_hex_to_decimal(self, x):
        hexarray = list('0123456789ABCDEF')
        return hexarray.index(x)

    def decimal_to_base_58(self, x):
        base_10 = 0
        x_str = str(x)
        for index, y in enumerate(x_str):
            base58value = self.convert_base_58_to_decimal(y)
            newsummand = base58value * 58**(len(x_str) - index - 1)
            base_10 += newsummand
        return base_10

    def hex_to_base_58(self, x):
        base_10 = 0
        for index, y in enumerate(x):
            base58value = self.convert_hex_to_decimal(y)
            newsummand = base58value * 58**(len(x) - index - 1)
            base_10 += newsummand
        return base_10

    def mmi(self, x, p):
        return pow(x, -1, p)

    def double_point(self, x, y, p):
        slope = (3*x**2 * self.mmi(2*y, p)) % p
        new_x = (slope**2 - 2*x) % p
        new_y = ((slope*(x - new_x)) - y) % p
        return new_x, new_y

    def add_point(self, x, y, a, b, p):
        if x == a and y == b:
            return self.double_point(x, y, p)
        slope = ((y - b) * self.mmi(x - a, p)) % p
        return_x = ((slope**2) - x - a) % p
        return_y = (slope * (x - return_x) - y) % p
        return return_x, return_y

    def multiply_point(self, k, genX, genY, p):
        current_gen_x = genX
        current_gen_y = genY
        binary_point = (bin(k)[3:])
        binary_point_no_slice = (bin(k))
        for index, y in enumerate(binary_point):
            current_gen_x, current_gen_y = self.double_point(current_gen_x, current_gen_y, p)
            if y == '1': 
                current_gen_x, current_gen_y = self.add_point(current_gen_x, current_gen_y, genX, genY, p)
        return current_gen_x, current_gen_y

    def get_public_key(self):
        base_10 = self.hex_to_base_58(self.public_key)
        public_key_decimal = self.decimal_to_base_58(base_10)
        public_key_x, public_key_y = self.multiply_point(public_key_decimal, genX, genY, p)
        return "04" + hex(public_key_x)[2:].zfill(64) + hex(public_key_y)[2:].zfill(64)



class PrivateKey:
    def __init__(self, private_key_string):
        self.private_key_string = private_key_string
        self.private_key_int = int(private_key_string, 16)
        self.private_key_decimal = self.convert_base_58_to_decimal(private_key_string)
    
    def get_public_key(self):
        curve = EllipticCurve(p, order, gen, a, b)
        return curve.point_multiply(self.private_key_int)
    
    def sign(self, message):
        curve = EllipticCurve(p, order, gen, a, b)
        z = int.from_bytes(hashlib.sha256(message.encode()).digest(), byteorder="big")
        k = np.random.randint(1, curve.order)
        r = curve.point_multiply(k)[0] % curve.p % curve.order
        s = (self.private_key_int * r - k * z) * pow(r, -1, curve.order) % curve.order
        if r == 0 or s == 0:
            return None
        else:
            return (r, s)

    @staticmethod
    def convert_base_58_to_decimal(base58_string):
        base58array = list('123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz')
        base_10 = 0
        for index, char in enumerate(base58_string):
            base58value = base58array.index(char)
            newsummand = base58value * 58**(len(base58_string) - index - 1)
            base_10 += newsummand
        return base_10

    def to_decimal(self):
        return self.private_key_decimal

class ECC:
    base58array = list('123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz')
    hexarray = list('0123456789ABCDEF')
    p = 2**256 - 2**32 - 2**9 - 2**8 - 2**7 - 2**6 - 2**4 - 1
    order = 115792089237316195423570985008687907852837564279074904382605163141518161494337
    genX = 55066263022277343669578718895168534326250603453777594175500187360389116729240
    genY = 32670510020758816978083085130507043184471273380659243275938904335757337482424
    
    def __init__(self, private_key, public_key):
        self.private_key = private_key
        self.public_key = public_key
    
    @staticmethod
    def convert_base_58_to_decimal(x):
        return ECC.base58array.index(x)

    @staticmethod
    def convert_hex_to_decimal(x):
        return ECC.hexarray.index(x)

    @staticmethod
    def decimal_to_base_58(x):
        base_10 = 0
        for index, y in enumerate(x):
            base58value = ECC.convert_base_58_to_decimal(y)
            newsummand = base58value * 58**(len(x) - index - 1)
            base_10 += newsummand
        return base_10

    @staticmethod
    def hex_to_base_58(x):
        base_10 = 0
        for index, y in enumerate(x):
            base58value = ECC.convert_hex_to_decimal(y)
            newsummand = base58value * 58**(len(x) - index - 1)
            base_10 += newsummand
        return base_10

    @staticmethod
    def mmi(x, p):
        return pow(x, -1, p)

    @staticmethod
    def double_point(x, y):
        slope = (3*x**2 * ECC.mmi(2*y, ECC.p)) % ECC.p
        new_x = (slope**2 - 2*x) % ECC.p
        new_y = ((slope*(x - new_x)) - y) % ECC.p
        return new_x, new_y

    @staticmethod
    def add_point(x, y, a, b):
        if x == a and y == b:
            return ECC.double_point(x, y)
        slope = ((y - b) * ECC.mmi(x - a, ECC.p)) % ECC.p
        return_x = ((slope**2) - x - a) % ECC.p
        return_y = (slope * (x - return_x) - y) % ECC.p
        return return_x, return_y

    @staticmethod
    def multiply_point(k, genX, genY):
        current_gen_x = genX
        current_gen_y = genY
        binary_point = (bin(k)[3:])
        binary_point_no_slice = (bin(k))
        for index, y in enumerate(binary_point):
            current_gen_x, current_gen_y = ECC.double_point(current_gen_x, current_gen_y)
            if y == '1': 
                current_gen_x, current_gen_y = ECC.add_point(current_gen_x, current_gen_y, genX, genY
