import base64
from sage.stats.distributions.discrete_gaussian_integer import DiscreteGaussianDistributionIntegerSampler
from sage.all import *

class LWE:
    def __init__(self, q=2**20, t=1000, n=6, m=4, l=5, r=6, sigma=3, chunk_size=1000):
        self.q = q
        self.t = t
        self.n = n
        self.m = m
        self.l = l
        self.r = r
        self.sigma = sigma
        self.chunk_size = chunk_size
        self.Zq = Zmod(q)
        self.secret_key = None
        self.public_key = None
        #print ( f"The message space is (Z_{self.t})^{self.l}")
        
    def generate_secret_key(self):
        self.secret_key = random_matrix(self.Zq, self.n, self.l)
        return self.secret_key
    
    def generate_public_key(self):
        if self.secret_key is None:
            raise ValueError("Secret key not generated yet")
            
        A = random_matrix(self.Zq, self.m, self.n)
        E = matrix(self.Zq, [[DiscreteGaussianDistributionIntegerSampler(sigma = self.sigma)() 
                           for _ in range(self.l)] for _ in range(self.m)])
        P = A * self.secret_key + E
        self.public_key = (A, P)
        return self.public_key
    
    def _f(self, v):
        return vector([round(ZZ(_) * self.q / self.t) % self.q for _ in v])
    
    def _f_inverse(self, x):
        return vector([round(ZZ(_) * self.t / self.q) % self.t for _ in x])
    
    def encrypt(self, v):
        if self.public_key is None:
            raise ValueError("Public key not generated yet")
            
        A, P = self.public_key
        a = vector([randint(-self.r, self.r) for _ in range(A.nrows())])
        u = A.transpose() * a 
        c = P.transpose() * a + self._f(v) 
        return (u, c)
    
    def decrypt(self, cypher):
        if self.secret_key is None:
            raise ValueError("Secret key not generated yet")
        u,c = cypher
            
        return self._f_inverse(c - self.secret_key.transpose() * u)

    def random_safe_prime(self, bits =10):
        while True:
            p = random_prime(2^bits - 1, False, 2^(bits-1))
            q = ZZ((p - 1) // 2)
            if q.is_prime():
                return p
    
    def split_into_blocks(self,s, pad_char='~'):
        blocks = []
        block_size=self.l
        for i in range(0, len(s), block_size):
            block = s[i:i + block_size]
            if len(block) < block_size and pad_char is not None:
                # Pad the last block if it's shorter than block_size
                block = block.ljust(block_size, pad_char)
            blocks.append(block)
        return blocks

    def encode_blocks(self, blocks):
        result =[]
        for block in blocks:
            encoded_block = tuple([ord(c) for c in block])
            result.append(encoded_block)
        return result
    
    def encrypt_blocks (self,blocks):
        cypher = []
        for b in blocks:
            cypher.append(self.encrypt(b))
        return cypher

    def convert_tuple(self, t):
        max_unicode=0x10FFFF
        return tuple(chr(int(x) % (max_unicode + 1)) for x in t)

    def inverse_convert_tuple(self, t):
        return tuple(ord(c) for c in t)

    def decrypt_blocks(self,cypher):
        result = []
        for k in range (len(cypher)):
            result.append(self.decrypt(cypher[k]))
        return result

    def decode_blocks(self,blocks):
        str_blocks=[]
        for block in blocks:
            str_blocks.append([chr(n) for n in block])
        return ''.join([''.join(block) for block in str_blocks])

    def send_encrypted_message (self,clear_message):
        splitted = self.split_into_blocks(clear_message)
        encoded = self.encode_blocks(splitted)
        encrypted= self.encrypt_blocks(encoded)
        cyphered = [(self.convert_tuple(t1), self.convert_tuple(t2)) for (t1,t2) in encrypted]
        return cyphered
    
    def decrypt_message(self,cypher):
        decyphered = [(self.inverse_convert_tuple(t1), self.inverse_convert_tuple(t2)) for (t1,t2) in cypher]
        decyphered_vectors = [(vector(t1), vector(t2)) for (t1, t2) in decyphered]
        decrypted = self.decrypt_blocks(decyphered_vectors)
        return self.decode_blocks(decrypted).rstrip('~')

    def random_safe_prime(self, bits = 10):
        while True:
            q = random_prime(2**(bits-1) - 1, False, 2**(bits-2))
            p = 2*q + 1
            if is_prime(p):
                return p
    
    def encapsulate(self, x):
        e =65537
        p,q = 887, 983
        n = p*q
        return pow(x,e,n)

        
    def to_key (self, pwd):
        if len(pwd)!= self.n * self.l:
            raise ValueError ('The password does not have the correct length')
        else : 
            return Matrix(self.n, self.l, [self.encapsulate(x= ord(c)) for c in pwd])

    def encode_image_to_string(self, image_path):
        with open(image_path, 'rb') as img_file:
            encoded_img = base64.b64encode(img_file.read()).decode('utf-8')
        return encoded_img

    def decode_string_to_image(self, encoded_string, output_name):
        image_data = base64.b64decode(encoded_string)
        with open(output_name, 'wb') as image_file:
            image_file.write(image_data)
