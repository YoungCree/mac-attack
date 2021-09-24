old_message = 'No one has completed lab 2 so give them all a 0'

def sha1(data):
    bytes = ""

    #sha1 implementation
    h0 = 0x67452301
    h1 = 0xEFCDAB89
    h2 = 0x98BADCFE
    h3 = 0x10325476
    h4 = 0xC3D2E1F0

    #mac attack
    h0 = 0xe384efad
    h1 = 0xf26767a6
    h2 = 0x13162142
    h3 = 0xb5ef0efb
    h4 = 0xb9d7659a

    for n in range(len(data)):
        bytes+='{0:08b}'.format(ord(data[n]))
    bits = bytes+"1"
    pBits = bits
    #pad until length equals 448 mod 512
    while len(pBits)%512 != 448:
        pBits+="0"
    #append the original length add previous message length + padding here 1024
    pBits+='{0:064b}'.format(len(bits)+1024-1)

    def chunks(l, n):
        return [l[i:i+n] for i in range(0, len(l), n)]

    def rol(n, b):
        return ((n << b) | (n >> (32 - b))) & 0xffffffff

    for c in chunks(pBits, 512): 
        words = chunks(c, 32)
        w = [0]*80
        for n in range(0, 16):
            w[n] = int(words[n], 2)
        for i in range(16, 80):
            w[i] = rol((w[i-3] ^ w[i-8] ^ w[i-14] ^ w[i-16]), 1)  

        a = h0
        b = h1
        c = h2
        d = h3
        e = h4

        #Main loop
        for i in range(0, 80):
            if 0 <= i <= 19:
                f = (b & c) | ((~b) & d)
                k = 0x5A827999
            elif 20 <= i <= 39:
                f = b ^ c ^ d
                k = 0x6ED9EBA1
            elif 40 <= i <= 59:
                f = (b & c) | (b & d) | (c & d) 
                k = 0x8F1BBCDC
            elif 60 <= i <= 79:
                f = b ^ c ^ d
                k = 0xCA62C1D6

            temp = rol(a, 5) + f + e + k + w[i] & 0xffffffff
            e = d
            d = c
            c = rol(b, 30)
            b = a
            a = temp

        h0 = h0 + a & 0xffffffff
        h1 = h1 + b & 0xffffffff
        h2 = h2 + c & 0xffffffff
        h3 = h3 + d & 0xffffffff
        h4 = h4 + e & 0xffffffff

    return '%08x%08x%08x%08x%08x' % (h0, h1, h2, h3, h4)

ext_str = " except for Corey Devenport"
ext = sha1(ext_str)
print(ext)
print(ext_str.encode('utf-8'))
old_msg_hex = ''.join('{:02x}'.format(x) for x in old_message.encode('ascii'))
new_msg_hex = ''.join('{:02x}'.format(x) for x in ext_str.encode('ascii'))
padding = '80'
for i in range(56):
    padding += '00'

old_size = "00000000000001f8"
new_message_str = old_msg_hex + padding + old_size + new_msg_hex
print(new_message_str)
