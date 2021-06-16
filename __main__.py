from rsa.rsa import RSA

if __name__ == '__main__':
    rsa = RSA(53, 59)
    result = rsa.encrypt('HI')
    print('encrypt', result)
    print('decrypt', rsa.decrypt(result))
    print('str -> ', str(rsa))