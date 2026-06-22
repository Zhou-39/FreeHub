from argon2 import PasswordHasher, exceptions

class Password:
    def __init__(self):
        self.ph = PasswordHasher()

    def hash_pw(self, pw):
        return self.ph.hash(pw)

    def verify_pw(self, pw, crypto_pw):
        try:
            return self.ph.verify(crypto_pw, pw), 'OK'
        except exceptions.VerifyMismatchError:
            return False, '密码错误'
        except exceptions.InvalidHashError:
            return False, '哈希无效'
        except exceptions.VerificationError:
            return False, '验证错误'
    
    def needs_rehash(self):
        return self.ph.check_needs_rehash(self.crypto_pw)
    