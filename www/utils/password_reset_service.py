import secrets
import hashlib
from datetime import datetime, timedelta
from itsdangerous import URLSafeTimedSerializer

class PasswordResetService:
    def __init__(self, app, db):
        self.app = app
        self.db = db
        self.serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])

    def generate_reset_token(self, user_id):
        """生成安全的密码重置令牌"""
        # 生成随机令牌
        raw_token = secrets.token_urlsafe(32)

        # 创建哈希令牌用于存储
        token_hash = hashlib.sha256(raw_token.encode()).hexdigest()

        # 设置过期时间（15分钟）
        expires_at = datetime.utcnow() + timedelta(minutes=15)

        # 存储到数据库
        reset_token = self.db.password_reset_tokens(
            user_id=user_id,
            token=token_hash,
            expires_at=expires_at
        )
        self.db.session.add(reset_token)
        self.db.session.commit()

        # 返回给用户的令牌（包含用户ID和原始令牌）
        return self.serializer.dumps({'user_id': user_id, 'token': raw_token})

    def validate_reset_token(self, signed_token):
        """验证密码重置令牌"""
        try:
            # 验证签名和过期时间
            data = self.serializer.loads(signed_token, max_age=900)  # 15分钟
            user_id = data['user_id']
            raw_token = data['token']

            # 计算哈希
            token_hash = hashlib.sha256(raw_token.encode()).hexdigest()

            # 查询数据库
            reset_token = self.db.password_reset_tokens.query.filter_by(
                token=token_hash,
                user_id=user_id,
                used=False
            ).first()

            if not reset_token:
                return None, "无效的令牌"

            if reset_token.expires_at < datetime.utcnow():
                return None, "令牌已过期"

            return reset_token, "验证成功"

        except Exception as e:
            return None, f"令牌验证失败: {str(e)}"

    def mark_token_used(self, token_id):
        """标记令牌为已使用"""
        reset_token = self.db.password_reset_tokens.query.get(token_id)
        if reset_token:
            reset_token.used = True
            self.db.session.commit()

    def cleanup_expired_tokens(self):
        """清理过期的令牌"""
        expired_tokens = self.db.password_reset_tokens.query.filter(
            self.db.password_reset_tokens.expires_at < datetime.utcnow()
        ).all()

        for token in expired_tokens:
            self.db.session.delete(token)

        self.db.session.commit()
