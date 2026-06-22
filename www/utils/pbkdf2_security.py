# utils/pbkdf2_security.py
import secrets
import random
import time

class PBKDF2Security:
    def __init__(self):
        # 迭代次数范围
        self.min_iterations = 50000
        self.max_iterations = 150000
        # 临时存储新用户的参数（注册过程中使用）
        self.temp_user_params = {}
    
    def generate_user_salt(self, length=32):
        """为用户生成唯一的salt"""
        return secrets.token_hex(length)
    
    def generate_iterations(self):
        """生成随机迭代次数"""
        return random.randint(self.min_iterations, self.max_iterations)
    
    def get_pbkdf2_params_for_new_user(self, temp_key=None):
        """为新用户生成PBKDF2参数"""
        salt = self.generate_user_salt()
        iterations = self.generate_iterations()
        
        # 临时存储，用于注册时的验证
        if temp_key:
            self.temp_user_params[temp_key] = {
                'salt': salt,
                'iterations': iterations,
                'created_at': time.time()
            }
        
        return salt, iterations
    
    def get_pbkdf2_params_for_existing_user(self, user):
        """为现有用户获取PBKDF2参数"""
        if user.pbkdf2_salt and user.pbkdf2_iterations:
            # 返回用户特定的参数
            return user.pbkdf2_salt, user.pbkdf2_iterations
        else:
            # 兼容旧用户：生成并保存新参数
            salt, iterations = self.get_pbkdf2_params_for_new_user()
            user.pbkdf2_salt = salt
            user.pbkdf2_iterations = iterations
            # 需要在外部提交数据库会话
            return salt, iterations
    
    def verify_temp_params(self, temp_key, salt, iterations):
        """验证临时参数是否匹配"""
        if temp_key not in self.temp_user_params:
            return False
        
        stored = self.temp_user_params[temp_key]
        
        # 检查是否过期（10分钟）
        if time.time() - stored['created_at'] > 600:
            del self.temp_user_params[temp_key]
            return False
        
        # 验证参数匹配
        if stored['salt'] == salt and stored['iterations'] == int(iterations):
            # 验证成功后删除临时参数
            del self.temp_user_params[temp_key]
            return True
        
        return False
    
    def cleanup_expired_temp_params(self):
        """清理过期的临时参数"""
        current_time = time.time()
        expired_keys = [
            key for key, data in self.temp_user_params.items()
            if current_time - data['created_at'] > 600
        ]
        for key in expired_keys:
            del self.temp_user_params[key]
