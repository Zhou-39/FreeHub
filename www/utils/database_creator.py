from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
import datetime
import os

class DatabaseCreator:
    def __init__(self, app):
        self.init_db(app)

    def init_db(self, app):
        """Initialize the database."""
        self.db = SQLAlchemy(app)
        self.app = app

    def generate_user_tables(self, db, bind_key='users'):
        """生成普通用户表"""
        
        # ========== 令牌表 ==========
        class PasswordResetTokens(db.Model):
            __bind_key__ = bind_key
            __tablename__ = 'PasswordResetTokens'
            id = db.Column(db.Integer, primary_key=True)
            user_id = db.Column(db.Integer, db.ForeignKey('IDs.id'), nullable=False)
            token = db.Column(db.String(100), unique=True, nullable=False)
            expires_at = db.Column(db.DateTime, nullable=False)
            used = db.Column(db.Boolean, default=False)
            user = db.relationship('IDs', foreign_keys=[user_id])

        class EmailVerificationTokens(db.Model):
            __bind_key__ = bind_key
            __tablename__ = 'EmailVerificationTokens'
            id = db.Column(db.Integer, primary_key=True)
            user_id = db.Column(db.Integer, db.ForeignKey('IDs.id'), nullable=False)
            token = db.Column(db.String(100), unique=True, nullable=False)
            email = db.Column(db.String(30), nullable=False)
            expires_at = db.Column(db.DateTime, nullable=False)
            used = db.Column(db.Boolean, default=False)
            user = db.relationship('IDs', foreign_keys=[user_id])

        # ========== 内容表 ==========
        class Posts(db.Model):
            __bind_key__ = bind_key
            __tablename__ = 'Posts'
            id = db.Column(db.Integer, primary_key=True)
            title = db.Column(db.String(100), nullable=False)
            content = db.Column(db.Text, nullable=False)
            author_id = db.Column(db.Integer, db.ForeignKey('UIDs.uid'), nullable=False)
            created_at = db.Column(db.DateTime, nullable=False, default=datetime.datetime.now)
            updated_at = db.Column(db.DateTime, nullable=False, default=datetime.datetime.now, onupdate=datetime.datetime.now)
            views = db.Column(db.Integer, default=0)
            is_deleted = db.Column(db.Boolean, default=False)
            deleted_at = db.Column(db.DateTime, nullable=True)
            author = db.relationship('UIDs', foreign_keys=[author_id])

        class Articles(db.Model):
            __bind_key__ = bind_key
            __tablename__ = 'Articles'
            arid = db.Column(db.Integer, primary_key=True)
            title = db.Column(db.String(50), nullable=False)
            content = db.Column(db.Text, nullable=False)
            time = db.Column(db.DateTime, nullable=False, default=datetime.datetime.now)
            author_id = db.Column(db.Integer, db.ForeignKey('UIDs.uid'), nullable=False)
            views = db.Column(db.Integer, default=0)
            is_deleted = db.Column(db.Boolean, default=False)
            author = db.relationship('UIDs', foreign_keys=[author_id])
            comments = db.relationship('Comments', lazy=True, uselist=True, back_populates='article')

        class Comments(db.Model):
            __bind_key__ = bind_key
            __tablename__ = 'Comments'
            id = db.Column(db.Integer, primary_key=True)
            content = db.Column(db.Text, nullable=False)
            time = db.Column(db.DateTime, nullable=False, default=datetime.datetime.now)
            author_id = db.Column(db.Integer, db.ForeignKey('UIDs.uid'), nullable=False)
            article_id = db.Column(db.Integer, db.ForeignKey('Articles.arid'), nullable=False)
            is_deleted = db.Column(db.Boolean, default=False)
            author = db.relationship('UIDs', foreign_keys=[author_id])
            article = db.relationship('Articles', foreign_keys=[article_id])

        # ========== 用户互动表 ==========
        class Likes(db.Model):
            """点赞记录"""
            __bind_key__ = bind_key
            __tablename__ = 'Likes'
            id = db.Column(db.Integer, primary_key=True)
            uid = db.Column(db.Integer, db.ForeignKey('UIDs.uid'), nullable=False)
            target_type = db.Column(db.String(20), nullable=False)
            target_id = db.Column(db.Integer, nullable=False)
            created_at = db.Column(db.DateTime, default=datetime.datetime.now)
            __table_args__ = (db.UniqueConstraint('uid', 'target_type', 'target_id', name='unique_like'),)
            author = db.relationship('UIDs', foreign_keys=[uid])

        class Favorites(db.Model):
            """收藏记录"""
            __bind_key__ = bind_key
            __tablename__ = 'Favorites'
            id = db.Column(db.Integer, primary_key=True)
            uid = db.Column(db.Integer, db.ForeignKey('UIDs.uid'), nullable=False)
            target_type = db.Column(db.String(20), nullable=False)
            target_id = db.Column(db.Integer, nullable=False)
            created_at = db.Column(db.DateTime, default=datetime.datetime.now)
            __table_args__ = (db.UniqueConstraint('uid', 'target_type', 'target_id', name='unique_favorite'),)
            author = db.relationship('UIDs', foreign_keys=[uid])

        class Follows(db.Model):
            """关注关系"""
            __bind_key__ = bind_key
            __tablename__ = 'Follows'
            id = db.Column(db.Integer, primary_key=True)
            follower_uid = db.Column(db.Integer, db.ForeignKey('UIDs.uid'), nullable=False)
            following_uid = db.Column(db.Integer, db.ForeignKey('UIDs.uid'), nullable=False)
            created_at = db.Column(db.DateTime, default=datetime.datetime.now)
            __table_args__ = (db.UniqueConstraint('follower_uid', 'following_uid', name='unique_follow'),)
            follower = db.relationship('UIDs', foreign_keys=[follower_uid])
            following = db.relationship('UIDs', foreign_keys=[following_uid])

        # ========== 举报系统 ==========
        class Reports(db.Model):
            """举报记录"""
            __bind_key__ = bind_key
            __tablename__ = 'Reports'
            id = db.Column(db.Integer, primary_key=True)
            reporter_uid = db.Column(db.Integer, db.ForeignKey('UIDs.uid'), nullable=False)  # 举报人
            target_type = db.Column(db.String(20), nullable=False)  # post, article, upload
            target_id = db.Column(db.Integer, nullable=False)  # 被举报内容的ID
            target_uid = db.Column(db.Integer, db.ForeignKey('UIDs.uid'), nullable=True)  # 被举报内容的作者UID
            target_id_id = db.Column(db.Integer, db.ForeignKey('IDs.id'), nullable=True)  # 被举报内容作者所属的ID
            reason = db.Column(db.String(50), nullable=False)  # 举报原因分类
            description = db.Column(db.Text, nullable=True)  # 详细描述
            status = db.Column(db.String(20), default='pending')  # pending, reviewed, resolved, rejected, rewarded
            created_at = db.Column(db.DateTime, default=datetime.datetime.now)
            updated_at = db.Column(db.DateTime, default=datetime.datetime.now, onupdate=datetime.datetime.now)
            reviewed_by = db.Column(db.Integer, nullable=True)  # 审核人ID（管理员）
            reviewed_at = db.Column(db.DateTime, nullable=True)  # 审核时间
            review_comment = db.Column(db.Text, nullable=True)  # 审核意见
            action_taken = db.Column(db.String(50), nullable=True)  # 采取的措施：delete, warn, ban, ignore
            # 积分相关
            points_awarded = db.Column(db.Numeric(10, 1), default=0, nullable=False)  # 奖励的积分
            awarded_at = db.Column(db.DateTime, nullable=True)  # 奖励时间
            
            # 关系
            reporter = db.relationship('UIDs', foreign_keys=[reporter_uid], backref='reports')
            target_author = db.relationship('UIDs', foreign_keys=[target_uid])
            target_id_author = db.relationship('IDs', foreign_keys=[target_id_id])
            
            __table_args__ = (
                db.Index('idx_reports_target', 'target_type', 'target_id'),
                db.Index('idx_reports_status', 'status'),
                db.Index('idx_reports_created', 'created_at'),
                db.Index('idx_reports_target_uid', 'target_uid'),
            )

        class ReportReasons(db.Model):
            """举报原因预设（可配置）"""
            __bind_key__ = bind_key
            __tablename__ = 'ReportReasons'
            id = db.Column(db.Integer, primary_key=True)
            target_type = db.Column(db.String(20), nullable=False)  # post, article, upload
            reason_code = db.Column(db.String(50), nullable=False)  # spam, illegal, porn, violence, etc.
            reason_text = db.Column(db.String(100), nullable=False)  # 显示文本
            description = db.Column(db.String(200), nullable=True)  # 详细说明
            sort_order = db.Column(db.Integer, default=0)  # 排序
            is_active = db.Column(db.Boolean, default=True)  # 是否启用
            created_at = db.Column(db.DateTime, default=datetime.datetime.now)
            
            __table_args__ = (
                db.UniqueConstraint('target_type', 'reason_code', name='unique_reason'),
            )

        # ========== 积分历史记录表 ==========
        class PointsHistory(db.Model):
            """积分历史记录"""
            __bind_key__ = bind_key
            __tablename__ = 'PointsHistory'
            id = db.Column(db.Integer, primary_key=True)
            user_id = db.Column(db.Integer, db.ForeignKey('IDs.id'), nullable=False)  # 主账户ID
            amount = db.Column(db.Numeric(10, 1), nullable=False)  # 积分变动数量
            type = db.Column(db.String(50), nullable=False)  # daily_claim, allocate, receive, content_earning, monthly_reward
            description = db.Column(db.String(200))  # 描述
            target_uid = db.Column(db.Integer, db.ForeignKey('UIDs.uid'), nullable=True)  # 目标UID
            is_uid = db.Column(db.Boolean, default=False)  # 是否是UID的积分变动
            created_at = db.Column(db.DateTime, default=datetime.datetime.now)
            
            # 关系
            user = db.relationship('IDs', foreign_keys=[user_id], backref='points_history')
            target = db.relationship('UIDs', foreign_keys=[target_uid])

        # ========== 仓库表 ==========
        class Uploads(db.Model):
            """文件上传记录（仓库）"""
            __bind_key__ = bind_key
            __tablename__ = 'Uploads'
            id = db.Column(db.Integer, primary_key=True)
            uid = db.Column(db.Integer, db.ForeignKey('UIDs.uid'), nullable=False)
            filename = db.Column(db.String(255), nullable=False)
            original_filename = db.Column(db.String(255), nullable=False)
            file_size = db.Column(db.Integer, nullable=False)
            file_hash = db.Column(db.String(64), nullable=False)
            mime_type = db.Column(db.String(100), nullable=False)
            file_path = db.Column(db.String(500), nullable=False)
            file_category = db.Column(db.String(50), default='other')
            description = db.Column(db.Text)
            downloads = db.Column(db.Integer, default=0)
            is_public = db.Column(db.Boolean, default=True)
            is_deleted = db.Column(db.Boolean, default=False)
            created_at = db.Column(db.DateTime, default=datetime.datetime.now)
            updated_at = db.Column(db.DateTime, default=datetime.datetime.now, onupdate=datetime.datetime.now)
            deleted_at = db.Column(db.DateTime, nullable=True)
            has_preview = db.Column(db.Boolean, default=False)
            preview_path = db.Column(db.String(500), nullable=True)
            preview_info = db.Column(db.JSON, nullable=True)
            scanned = db.Column(db.Boolean, default=False)
            scan_result = db.Column(db.String(50), default='pending')
            scan_details = db.Column(db.JSON, nullable=True)
            scan_time = db.Column(db.DateTime, nullable=True)
            author = db.relationship('UIDs', foreign_keys=[uid])

        # ========== 用户表 ==========
        class IDs(db.Model, UserMixin):
            """主账户（存储真实信息）"""
            __bind_key__ = bind_key
            __tablename__ = 'IDs'
            id = db.Column(db.Integer, primary_key=True)
            crypto_pw = db.Column(db.String(256), nullable=False)
            level = db.Column(db.Integer, nullable=False, default=0)
            status = db.Column(db.Boolean, nullable=False, default=True)
            nickname = db.Column(db.String(15), nullable=True, unique=True)
            email = db.Column(db.String(30), nullable=True, unique=True)
            email_verified = db.Column(db.Boolean, default=False, nullable=False)
            all_points = db.Column(db.Integer, default=0, nullable=False)
            last_points = db.Column(db.Integer, default=0, nullable=False)
            points = db.Column(db.Numeric(10, 1), default=0, nullable=False)
            last_points_claim = db.Column(db.DateTime, nullable=True)
            pbkdf2_salt = db.Column(db.String(64), nullable=True)
            pbkdf2_iterations = db.Column(db.Integer, nullable=True)
            bio = db.Column(db.Text)
            profile_visibility = db.Column(db.String(20), default='public')
            online_status = db.Column(db.Boolean, default=True)
            activity_feed = db.Column(db.Boolean, default=True)
            data_collection = db.Column(db.Boolean, default=False)
            language = db.Column(db.String(10), default='zh-CN')
            timezone = db.Column(db.String(20), default='UTC+8')
            date_format = db.Column(db.String(10), default='Y-m-d')
            font_size = db.Column(db.String(10), default='medium')
            created_at = db.Column(db.DateTime, default=datetime.datetime.now)
            last_login = db.Column(db.DateTime, nullable=True)
            uids = db.relationship('UIDs', lazy=True, uselist=True, back_populates='user', cascade='all, delete-orphan')
            report_count = db.Column(db.Integer, default=0, nullable=False)
            is_banned = db.Column(db.Boolean, default=False, nullable=False)
            banned_at = db.Column(db.DateTime, nullable=True)
            banned_reason = db.Column(db.String(200), nullable=True)
            ban_expires_at = db.Column(db.DateTime, nullable=True)

        class UIDs(db.Model):
            """子账户（匿名身份）"""
            __bind_key__ = bind_key
            __tablename__ = 'UIDs'
            uid = db.Column(db.Integer, primary_key=True)
            crypto_pw = db.Column(db.String(256), nullable=False)
            level = db.Column(db.Integer, nullable=False, default=1)
            status = db.Column(db.Boolean, nullable=False, default=True)
            points = db.Column(db.Numeric(10, 1), default=0, nullable=False)
            nickname = db.Column(db.String(15), nullable=True)
            bio = db.Column(db.Text)
            pbkdf2_salt = db.Column(db.String(64), nullable=True)
            pbkdf2_iterations = db.Column(db.Integer, nullable=True)
            followers_count = db.Column(db.Integer, default=0)
            following_count = db.Column(db.Integer, default=0)
            posts_count = db.Column(db.Integer, default=0)
            articles_count = db.Column(db.Integer, default=0)
            uploads_count = db.Column(db.Integer, default=0)
            likes_count = db.Column(db.Integer, default=0)
            favorites_count = db.Column(db.Integer, default=0)
            profile_visibility = db.Column(db.String(20), default='public')
            online_status = db.Column(db.Boolean, default=True)
            activity_feed = db.Column(db.Boolean, default=True)
            data_collection = db.Column(db.Boolean, default=False)
            language = db.Column(db.String(10), default='zh-CN')
            timezone = db.Column(db.String(20), default='UTC+8')
            date_format = db.Column(db.String(10), default='Y-m-d')
            font_size = db.Column(db.String(10), default='medium')
            created_at = db.Column(db.DateTime, default=datetime.datetime.now)
            last_active = db.Column(db.DateTime, default=datetime.datetime.now, onupdate=datetime.datetime.now)
            id = db.Column(db.Integer, db.ForeignKey('IDs.id'), nullable=False)
            user = db.relationship('IDs', foreign_keys=[id])
            enable_paid_content = db.Column(db.Boolean, default=False)
            paid_content_price = db.Column(db.Numeric(3, 1), default=1.0)
            paid_min_like_rate = db.Column(db.Float, default=3.0)
            auto_enable_paid = db.Column(db.Boolean, default=True)
            report_count = db.Column(db.Integer, default=0, nullable=False)
            is_banned = db.Column(db.Boolean, default=False, nullable=False)
            banned_at = db.Column(db.DateTime, nullable=True)
            banned_reason = db.Column(db.String(200), nullable=True)
            ban_expires_at = db.Column(db.DateTime, nullable=True)

        # ========== 私信系统（扩展版） ==========
        class Messages(db.Model):
            """私信记录（扩展版）"""
            __bind_key__ = bind_key
            __tablename__ = 'Messages'
            id = db.Column(db.Integer, primary_key=True)
            from_uid = db.Column(db.Integer, db.ForeignKey('UIDs.uid'), nullable=False)
            to_uid = db.Column(db.Integer, db.ForeignKey('UIDs.uid'), nullable=False)
            content = db.Column(db.Text, nullable=False)
            is_read = db.Column(db.Boolean, default=False)
            is_deleted_by_sender = db.Column(db.Boolean, default=False)
            is_deleted_by_receiver = db.Column(db.Boolean, default=False)
            created_at = db.Column(db.DateTime, default=datetime.datetime.now)
            read_at = db.Column(db.DateTime, nullable=True)
            
            # 新增字段
            bounty_task_id = db.Column(db.Integer, db.ForeignKey('BountyTasks.id'), nullable=True)
            message_type = db.Column(db.String(20), default='normal')  # normal, friend_request, bounty_offer, bounty_deliver, system
            amount = db.Column(db.Numeric(10, 1), default=0)
            is_system = db.Column(db.Boolean, default=False)
            
            sender = db.relationship('UIDs', foreign_keys=[from_uid], backref='sent_messages')
            receiver = db.relationship('UIDs', foreign_keys=[to_uid], backref='received_messages')
            bounty_task = db.relationship('BountyTasks', foreign_keys=[bounty_task_id])

        class Conversations(db.Model):
            """会话列表（扩展版）"""
            __bind_key__ = bind_key
            __tablename__ = 'Conversations'
            id = db.Column(db.Integer, primary_key=True)
            user_uid = db.Column(db.Integer, db.ForeignKey('UIDs.uid'), nullable=False)
            other_uid = db.Column(db.Integer, db.ForeignKey('UIDs.uid'), nullable=False)
            last_message_id = db.Column(db.Integer, db.ForeignKey('Messages.id'), nullable=True)
            unread_count = db.Column(db.Integer, default=0)
            updated_at = db.Column(db.DateTime, default=datetime.datetime.now, onupdate=datetime.datetime.now)
            
            # 新增字段
            conversation_type = db.Column(db.String(20), default='normal')  # normal, friend, bounty_temp
            is_friend = db.Column(db.Boolean, default=False)
            bounty_task_id = db.Column(db.Integer, db.ForeignKey('BountyTasks.id'), nullable=True)
            
            user = db.relationship('UIDs', foreign_keys=[user_uid])
            other = db.relationship('UIDs', foreign_keys=[other_uid])
            last_message = db.relationship('Messages', foreign_keys=[last_message_id])
            bounty_task = db.relationship('BountyTasks', foreign_keys=[bounty_task_id])
            
            __table_args__ = (db.UniqueConstraint('user_uid', 'other_uid', name='unique_conversation'),)
        
        # ========== 接单系统表 ==========
        class BountyTasks(db.Model):
            """悬赏任务表（赏金池模式）"""
            __bind_key__ = bind_key
            __tablename__ = 'BountyTasks'
            id = db.Column(db.Integer, primary_key=True, autoincrement=True)
            
            # 基本信息
            title = db.Column(db.String(200), nullable=False)
            description = db.Column(db.Text, nullable=False)
            publisher_uid = db.Column(db.Integer, db.ForeignKey('UIDs.uid'), nullable=False)
            
            # 赏金池（四六开）
            total_points = db.Column(db.Numeric(10, 1), default=0)           # 总赏金 T
            static_pool = db.Column(db.Numeric(10, 1), default=0)           # 静态池 60%（冻结）
            dynamic_pool = db.Column(db.Numeric(10, 1), default=0)          # 动态池 40%（激励）
            
            # 约束条件（二选一）
            max_uploaders = db.Column(db.Integer, default=0)                # 最大上传人数（0=不限）
            min_total_points = db.Column(db.Numeric(10, 1), default=0)      # 最低总赏金
            
            # 成交信息
            winner_uid = db.Column(db.Integer, db.ForeignKey('UIDs.uid'), nullable=True)  # 最终成交者
            completed_at = db.Column(db.DateTime, nullable=True)            # 成交时间
            
            # 状态
            status = db.Column(db.String(20), default='open')               # open, closed, expired, cancelled
            
            # 无人成交处理选项
            no_deal_action = db.Column(db.String(20), default='refund')     # refund（退还95%）, distribute（分给上传者）
            
            # 时间戳
            created_at = db.Column(db.DateTime, default=datetime.datetime.now)
            updated_at = db.Column(db.DateTime, default=datetime.datetime.now, onupdate=datetime.datetime.now)
            expired_at = db.Column(db.DateTime, nullable=True)              # 过期时间（达最大人数后+3天）
            
            # 关系
            publisher = db.relationship('UIDs', foreign_keys=[publisher_uid], backref='published_bounties')
            winner = db.relationship('UIDs', foreign_keys=[winner_uid], backref='won_bounties')
            
            # 附件
            attachments = db.Column(db.Text, default='[]')                  # JSON 格式

        class BountyUploads(db.Model):
            """悬赏作品上传表"""
            __bind_key__ = bind_key
            __tablename__ = 'BountyUploads'
            id = db.Column(db.Integer, primary_key=True, autoincrement=True)
            
            bounty_id = db.Column(db.Integer, db.ForeignKey('BountyTasks.id'), nullable=False)
            uploader_uid = db.Column(db.Integer, db.ForeignKey('UIDs.uid'), nullable=False)
            
            # 作品信息
            title = db.Column(db.String(200), nullable=True)                # 作品标题
            description = db.Column(db.Text, nullable=True)                 # 作品说明
            file_path = db.Column(db.String(500), nullable=True)            # 托管文件路径
            file_size = db.Column(db.Integer, default=0)                    # 文件大小
            
            # 奖励记录
            upload_reward = db.Column(db.Numeric(10, 1), default=0)         # 已获得的上传奖励（5%）
            view_reward = db.Column(db.Numeric(10, 1), default=0)           # 已获得的查看奖励（20%-已给）
            total_reward = db.Column(db.Numeric(10, 1), default=0)          # 总奖励
            
            # 查看记录
            is_viewed = db.Column(db.Boolean, default=False)                # 是否被悬赏者查看过
            viewed_at = db.Column(db.DateTime, nullable=True)               # 查看时间
            view_order = db.Column(db.Integer, default=0)                   # 查看顺序（第几个被查看）
            
            # 状态
            status = db.Column(db.String(20), default='pending')            # pending, viewed, selected, rejected
            
            # 是否是前三名（特权上传者）
            is_privileged = db.Column(db.Boolean, default=False)            # 前三名按总动态池5%算
            
            # 时间戳
            created_at = db.Column(db.DateTime, default=datetime.datetime.now)
            updated_at = db.Column(db.DateTime, default=datetime.datetime.now, onupdate=datetime.datetime.now)
            
            # 关系
            bounty = db.relationship('BountyTasks', foreign_keys=[bounty_id], backref='uploads')
            uploader = db.relationship('UIDs', foreign_keys=[uploader_uid], backref='bounty_uploads')

        class BountyRewardLogs(db.Model):
            """悬赏奖励发放日志表"""
            __bind_key__ = bind_key
            __tablename__ = 'BountyRewardLogs'
            id = db.Column(db.Integer, primary_key=True, autoincrement=True)
            
            bounty_id = db.Column(db.Integer, db.ForeignKey('BountyTasks.id'), nullable=False)
            upload_id = db.Column(db.Integer, db.ForeignKey('BountyUploads.id'), nullable=True)
            target_uid = db.Column(db.Integer, db.ForeignKey('UIDs.uid'), nullable=False)
            
            reward_type = db.Column(db.String(20), nullable=False)          # upload, view, win, refund, distribute
            amount = db.Column(db.Numeric(10, 1), nullable=False)           # 奖励金额
            
            # 当时的池子状态（用于审计）
            snapshot_dynamic_pool = db.Column(db.Numeric(10, 1), nullable=True)
            snapshot_static_pool = db.Column(db.Numeric(10, 1), nullable=True)
            
            created_at = db.Column(db.DateTime, default=datetime.datetime.now)
            
            # 关系
            bounty = db.relationship('BountyTasks', foreign_keys=[bounty_id])
            upload = db.relationship('BountyUploads', foreign_keys=[upload_id])
            target = db.relationship('UIDs', foreign_keys=[target_uid])

        class BountyAppendLogs(db.Model):
            """静态池追加记录表"""
            __bind_key__ = bind_key
            __tablename__ = 'BountyAppendLogs'
            id = db.Column(db.Integer, primary_key=True, autoincrement=True)
            
            bounty_id = db.Column(db.Integer, db.ForeignKey('BountyTasks.id'), nullable=False)
            added_points = db.Column(db.Numeric(10, 1), nullable=False)      # 追加的积分数
            new_static_pool = db.Column(db.Numeric(10, 1), nullable=False)   # 追加后的静态池
            new_total_points = db.Column(db.Numeric(10, 1), nullable=False)  # 追加后的总赏金
            append_uid = db.Column(db.Integer, db.ForeignKey('UIDs.uid'), nullable=False)  # 追加者（悬赏者）
            
            created_at = db.Column(db.DateTime, default=datetime.datetime.now)
            
            # 关系
            bounty = db.relationship('BountyTasks', foreign_keys=[bounty_id])
            appender = db.relationship('UIDs', foreign_keys=[append_uid])

        class PointsEarnings(db.Model):
            """积分赚取记录"""
            __bind_key__ = bind_key
            __tablename__ = 'PointsEarnings'
            id = db.Column(db.Integer, primary_key=True, autoincrement=True)
            uid = db.Column(db.Integer, db.ForeignKey('UIDs.uid'), nullable=False)
            source_type = db.Column(db.String(30), nullable=False)
            source_id = db.Column(db.Integer, nullable=True)
            points = db.Column(db.Numeric(10, 1), nullable=False)
            created_at = db.Column(db.DateTime, default=datetime.datetime.now)
            earner = db.relationship('UIDs', foreign_keys=[uid], backref='earnings')

        # ========== 致谢系统表 ==========
        class Thanks(db.Model):
            """致谢记录表"""
            __bind_key__ = bind_key
            __tablename__ = 'Thanks'
            id = db.Column(db.Integer, primary_key=True, autoincrement=True)
            name = db.Column(db.String(50), nullable=False)
            contact = db.Column(db.String(100), nullable=True)
            achievement = db.Column(db.Text, nullable=False)
            avatar_id = db.Column(db.Integer, default=0)
            achievement_date = db.Column(db.Date, nullable=True)
            sort_order = db.Column(db.Integer, default=0)
            is_visible = db.Column(db.Boolean, default=True)
            created_by = db.Column(db.Integer, nullable=True)
            created_at = db.Column(db.DateTime, default=datetime.datetime.now)
            updated_at = db.Column(db.DateTime, default=datetime.datetime.now, onupdate=datetime.datetime.now)
            
            def masked_contact(self):
                if not self.contact:
                    return "***"
                if '@' in self.contact:
                    local, domain = self.contact.split('@', 1)
                    if len(local) <= 2:
                        masked_local = local[0] + '***' if local else '***'
                    else:
                        masked_local = local[0] + '***' + local[-1]
                    return f"{masked_local}@{domain}"
                elif len(self.contact) <= 4:
                    return self.contact[0] + '***' if self.contact else '***'
                else:
                    return self.contact[:2] + '***' + self.contact[-1]
        
        class EmailRecoveryRequests(db.Model):
            """邮箱恢复请求表"""
            __bind_key__ = bind_key
            __tablename__ = 'EmailRecoveryRequests'
            id = db.Column(db.Integer, primary_key=True)
            token = db.Column(db.String(64), unique=True, nullable=False, index=True)
            user_id = db.Column(db.Integer, db.ForeignKey('IDs.id'), nullable=False)
            old_email = db.Column(db.String(30), nullable=False)
            new_email = db.Column(db.String(30), nullable=False)
            code = db.Column(db.String(6), nullable=False)
            expires_at = db.Column(db.DateTime, nullable=False)
            created_at = db.Column(db.DateTime, default=datetime.datetime.now)
            used = db.Column(db.Boolean, default=False)
            user = db.relationship('IDs', foreign_keys=[user_id])

        # ========== 新增表：好友系统 ==========
        class Friends(db.Model):
            """好友关系表"""
            __bind_key__ = bind_key
            __tablename__ = 'Friends'
            id = db.Column(db.Integer, primary_key=True, autoincrement=True)
            user_uid = db.Column(db.Integer, db.ForeignKey('UIDs.uid'), nullable=False)
            friend_uid = db.Column(db.Integer, db.ForeignKey('UIDs.uid'), nullable=False)
            status = db.Column(db.String(20), default='pending')  # pending, accepted, rejected, blocked
            created_at = db.Column(db.DateTime, default=datetime.datetime.now)
            updated_at = db.Column(db.DateTime, default=datetime.datetime.now, onupdate=datetime.datetime.now)
            
            user = db.relationship('UIDs', foreign_keys=[user_uid])
            friend = db.relationship('UIDs', foreign_keys=[friend_uid])
            __table_args__ = (db.UniqueConstraint('user_uid', 'friend_uid', name='unique_friendship'),)

        class FriendRequests(db.Model):
            """好友申请记录表"""
            __bind_key__ = bind_key
            __tablename__ = 'FriendRequests'
            id = db.Column(db.Integer, primary_key=True, autoincrement=True)
            from_uid = db.Column(db.Integer, db.ForeignKey('UIDs.uid'), nullable=False)
            to_uid = db.Column(db.Integer, db.ForeignKey('UIDs.uid'), nullable=False)
            message = db.Column(db.String(200), default='')
            status = db.Column(db.String(20), default='pending')  # pending, accepted, rejected
            created_at = db.Column(db.DateTime, default=datetime.datetime.now)
            responded_at = db.Column(db.DateTime, nullable=True)
            
            sender = db.relationship('UIDs', foreign_keys=[from_uid])
            receiver = db.relationship('UIDs', foreign_keys=[to_uid])
            __table_args__ = (db.UniqueConstraint('from_uid', 'to_uid', name='unique_request'),)

        # ========== 新增表：积分转账 ==========
        class PointsTransfers(db.Model):
            """积分转账记录表"""
            __bind_key__ = bind_key
            __tablename__ = 'PointsTransfers'
            id = db.Column(db.Integer, primary_key=True, autoincrement=True)
            from_uid = db.Column(db.Integer, db.ForeignKey('UIDs.uid'), nullable=False)
            to_uid = db.Column(db.Integer, db.ForeignKey('UIDs.uid'), nullable=False)
            amount = db.Column(db.Numeric(10, 1), nullable=False)
            message = db.Column(db.String(500), nullable=True)
            status = db.Column(db.String(20), default='completed')
            created_at = db.Column(db.DateTime, default=datetime.datetime.now)
            completed_at = db.Column(db.DateTime, nullable=True)
            
            sender = db.relationship('UIDs', foreign_keys=[from_uid])
            receiver = db.relationship('UIDs', foreign_keys=[to_uid])

        # ========== 新增表：黑名单 ==========
        class BlockList(db.Model):
            """黑名单表"""
            __bind_key__ = bind_key
            __tablename__ = 'BlockList'
            id = db.Column(db.Integer, primary_key=True, autoincrement=True)
            blocker_uid = db.Column(db.Integer, db.ForeignKey('UIDs.uid'), nullable=False)
            blocked_uid = db.Column(db.Integer, db.ForeignKey('UIDs.uid'), nullable=False)
            reason = db.Column(db.String(200), nullable=True)
            created_at = db.Column(db.DateTime, default=datetime.datetime.now)
            
            blocker = db.relationship('UIDs', foreign_keys=[blocker_uid])
            blocked = db.relationship('UIDs', foreign_keys=[blocked_uid])
            __table_args__ = (db.UniqueConstraint('blocker_uid', 'blocked_uid', name='unique_block'),)

        # ========== 新增表：悬赏子任务 ==========
        class BountySubTasks(db.Model):
            """悬赏子任务表（用于多人接单）"""
            __bind_key__ = bind_key
            __tablename__ = 'BountySubTasks'
            id = db.Column(db.Integer, primary_key=True, autoincrement=True)
            parent_task_id = db.Column(db.Integer, db.ForeignKey('BountyTasks.id'), nullable=False)
            assignee_uid = db.Column(db.Integer, db.ForeignKey('UIDs.uid'), nullable=False)
            sub_points = db.Column(db.Numeric(10, 1), nullable=False)
            title = db.Column(db.String(200), nullable=True)
            description = db.Column(db.Text, nullable=True)
            status = db.Column(db.String(20), default='pending')
            created_at = db.Column(db.DateTime, default=datetime.datetime.now)
            updated_at = db.Column(db.DateTime, default=datetime.datetime.now, onupdate=datetime.datetime.now)
            completed_at = db.Column(db.DateTime, nullable=True)
            delivery_note = db.Column(db.Text, nullable=True)
            reviewer_rating = db.Column(db.Integer, nullable=True)
            reviewer_comment = db.Column(db.Text, nullable=True)
            
            parent_task = db.relationship('BountyTasks', foreign_keys=[parent_task_id])
            assignee = db.relationship('UIDs', foreign_keys=[assignee_uid])

        return (IDs, UIDs, Posts, Articles, Comments, 
                PasswordResetTokens, EmailVerificationTokens,
                Likes, Favorites, Follows, Uploads, PointsHistory, 
                Messages, Conversations, Reports, ReportReasons, 
                BountyTasks, PointsEarnings, Thanks, EmailRecoveryRequests,
                Friends, FriendRequests, PointsTransfers, BlockList, BountySubTasks, 
                BountyUploads, BountyRewardLogs, BountyAppendLogs)

    def generate_admin_tables(self, db, bind_key='admins'):
        """生成管理员表"""
        
        class Announcements(db.Model):
            __bind_key__ = bind_key
            __tablename__ = 'Announcements'
            id = db.Column(db.Integer, primary_key=True)
            title = db.Column(db.String(100), nullable=False)
            content = db.Column(db.Text, nullable=False)
            category = db.Column(db.String(20), default='info')
            target_role = db.Column(db.String(20), default='all')
            created_at = db.Column(db.DateTime, default=datetime.datetime.now)
            updated_at = db.Column(db.DateTime, default=datetime.datetime.now, onupdate=datetime.datetime.now)
            start_at = db.Column(db.DateTime, default=datetime.datetime.now)
            end_at = db.Column(db.DateTime, nullable=True)
            is_active = db.Column(db.Boolean, default=True)
            is_pinned = db.Column(db.Boolean, default=False)
            is_deleted = db.Column(db.Boolean, default=False)
            author_id = db.Column(db.Integer, nullable=False)
            author_name = db.Column(db.String(20), nullable=False)
            author_role = db.Column(db.String(20), nullable=False)
            views = db.Column(db.Integer, default=0)

        class AnnouncementReads(db.Model):
            __bind_key__ = bind_key
            __tablename__ = 'AnnouncementReads'
            id = db.Column(db.Integer, primary_key=True)
            announcement_id = db.Column(db.Integer, db.ForeignKey('Announcements.id'), nullable=False)
            user_id = db.Column(db.Integer, nullable=False)
            user_role = db.Column(db.String(20), nullable=False)
            read_at = db.Column(db.DateTime, default=datetime.datetime.now)
            __table_args__ = (db.UniqueConstraint('announcement_id', 'user_id', 'user_role', name='unique_read'),)

        class AdminPosts(db.Model):
            __bind_key__ = bind_key
            __tablename__ = 'AdminPosts'
            id = db.Column(db.Integer, primary_key=True)
            title = db.Column(db.String(100), nullable=False)
            content = db.Column(db.Text, nullable=False)
            author_id = db.Column(db.Integer, db.ForeignKey('Admins.id'), nullable=False)
            created_at = db.Column(db.DateTime, nullable=False, default=datetime.datetime.now)
            updated_at = db.Column(db.DateTime, nullable=False, default=datetime.datetime.now, onupdate=datetime.datetime.now)
            views = db.Column(db.Integer, default=0)
            is_deleted = db.Column(db.Boolean, default=False)
            deleted_at = db.Column(db.DateTime, nullable=True)
            author = db.relationship('Admins', foreign_keys=[author_id])

        class AdminArticles(db.Model):
            __bind_key__ = bind_key
            __tablename__ = 'AdminArticles'
            arid = db.Column(db.Integer, primary_key=True)
            title = db.Column(db.String(50), nullable=False)
            content = db.Column(db.Text, nullable=False)
            time = db.Column(db.DateTime, nullable=False, default=datetime.datetime.now)
            author_id = db.Column(db.Integer, db.ForeignKey('Admins.id'), nullable=False)
            views = db.Column(db.Integer, default=0)
            is_deleted = db.Column(db.Boolean, default=False)
            author = db.relationship('Admins', foreign_keys=[author_id])
            comments = db.relationship('AdminComments', lazy=True, uselist=True, back_populates='article')

        class AdminComments(db.Model):
            __bind_key__ = bind_key
            __tablename__ = 'AdminComments'
            id = db.Column(db.Integer, primary_key=True)
            content = db.Column(db.Text, nullable=False)
            time = db.Column(db.DateTime, nullable=False, default=datetime.datetime.now)
            author_id = db.Column(db.Integer, db.ForeignKey('Admins.id'), nullable=False)
            article_id = db.Column(db.Integer, db.ForeignKey('AdminArticles.arid'), nullable=False)
            is_deleted = db.Column(db.Boolean, default=False)
            author = db.relationship('Admins', foreign_keys=[author_id])
            article = db.relationship('AdminArticles', foreign_keys=[article_id])

        class Admins(db.Model, UserMixin):
            __bind_key__ = bind_key
            __tablename__ = 'Admins'
            id = db.Column(db.Integer, primary_key=True)
            nickname = db.Column(db.String(20), nullable=False, unique=True)
            crypto_pw = db.Column(db.String(256), nullable=False)
            email = db.Column(db.String(30), nullable=False, unique=True)
            email_verified = db.Column(db.Boolean, default=False, nullable=False)
            status = db.Column(db.Boolean, nullable=False, default=True)
            level = db.Column(db.Integer, nullable=False, default=0)
            invite_code = db.Column(db.String(64), unique=True, nullable=True)
            invite_code_used = db.Column(db.Boolean, default=False)
            invite_code_created_at = db.Column(db.DateTime, nullable=True)
            invited_by = db.Column(db.Integer, nullable=True)
            pbkdf2_salt = db.Column(db.String(64), nullable=True)
            pbkdf2_iterations = db.Column(db.Integer, nullable=True)
            bio = db.Column(db.Text)
            profile_visibility = db.Column(db.String(20), default='public')
            online_status = db.Column(db.Boolean, default=True)
            can_post_announcement = db.Column(db.Boolean, default=True)
            can_manage_users = db.Column(db.Boolean, default=False)
            can_manage_admins = db.Column(db.Boolean, default=False)
            created_at = db.Column(db.DateTime, default=datetime.datetime.now)
            last_login = db.Column(db.DateTime, nullable=True)
            logs = db.relationship('AdminLogs', lazy=True, uselist=True, back_populates='admin', cascade='all, delete-orphan')
            posts = db.relationship('AdminPosts', lazy=True, uselist=True, back_populates='author', cascade='all, delete-orphan')
            articles = db.relationship('AdminArticles', lazy=True, uselist=True, back_populates='author', cascade='all, delete-orphan')
            comments = db.relationship('AdminComments', lazy=True, uselist=True, back_populates='author', cascade='all, delete-orphan')

        class AdminPasswordResetTokens(db.Model):
            __bind_key__ = bind_key
            __tablename__ = 'AdminPasswordResetTokens'
            id = db.Column(db.Integer, primary_key=True)
            admin_id = db.Column(db.Integer, db.ForeignKey('Admins.id'), nullable=False)
            token = db.Column(db.String(100), unique=True, nullable=False)
            expires_at = db.Column(db.DateTime, nullable=False)
            used = db.Column(db.Boolean, default=False)
            admin = db.relationship('Admins', foreign_keys=[admin_id])

        class AdminEmailVerificationTokens(db.Model):
            __bind_key__ = bind_key
            __tablename__ = 'AdminEmailVerificationTokens'
            id = db.Column(db.Integer, primary_key=True)
            admin_id = db.Column(db.Integer, db.ForeignKey('Admins.id'), nullable=False)
            token = db.Column(db.String(100), unique=True, nullable=False)
            email = db.Column(db.String(30), nullable=False)
            expires_at = db.Column(db.DateTime, nullable=False)
            used = db.Column(db.Boolean, default=False)
            admin = db.relationship('Admins', foreign_keys=[admin_id])

        class AdminLogs(db.Model):
            __bind_key__ = bind_key
            __tablename__ = 'AdminLogs'
            id = db.Column(db.Integer, primary_key=True)
            time = db.Column(db.DateTime, nullable=False, default=datetime.datetime.now)
            action = db.Column(db.String(50), nullable=False)
            target_type = db.Column(db.String(50), nullable=True)
            target_id = db.Column(db.Integer, nullable=True)
            content = db.Column(db.Text, nullable=False)
            ip_address = db.Column(db.String(45), nullable=True)
            admin_id = db.Column(db.Integer, db.ForeignKey('Admins.id'), nullable=False)
            admin = db.relationship('Admins', foreign_keys=[admin_id])

        return (Admins, AdminPasswordResetTokens, AdminEmailVerificationTokens, 
                AdminLogs, Announcements, AnnouncementReads,
                AdminPosts, AdminArticles, AdminComments)

    def generate_super_admin_tables(self, db, bind_key='admins'):
        """生成超级管理员表"""
        
        class SuperAdminAnnouncements(db.Model):
            __bind_key__ = bind_key
            __tablename__ = 'SuperAdminAnnouncements'
            id = db.Column(db.Integer, primary_key=True)
            title = db.Column(db.String(100), nullable=False)
            content = db.Column(db.Text, nullable=False)
            category = db.Column(db.String(20), default='info')
            target_role = db.Column(db.String(20), default='all')
            created_at = db.Column(db.DateTime, default=datetime.datetime.now)
            updated_at = db.Column(db.DateTime, default=datetime.datetime.now, onupdate=datetime.datetime.now)
            start_at = db.Column(db.DateTime, default=datetime.datetime.now)
            end_at = db.Column(db.DateTime, nullable=True)
            is_active = db.Column(db.Boolean, default=True)
            is_pinned = db.Column(db.Boolean, default=False)
            is_deleted = db.Column(db.Boolean, default=False)
            author_id = db.Column(db.Integer, db.ForeignKey('SuperAdmins.id'), nullable=False)
            author_name = db.Column(db.String(20), nullable=False)
            views = db.Column(db.Integer, default=0)
            author = db.relationship('SuperAdmins', foreign_keys=[author_id])

        class SuperAdminAnnouncementReads(db.Model):
            __bind_key__ = bind_key
            __tablename__ = 'SuperAdminAnnouncementReads'
            id = db.Column(db.Integer, primary_key=True)
            announcement_id = db.Column(db.Integer, db.ForeignKey('SuperAdminAnnouncements.id'), nullable=False)
            user_id = db.Column(db.Integer, nullable=False)
            user_role = db.Column(db.String(20), nullable=False)
            read_at = db.Column(db.DateTime, default=datetime.datetime.now)
            __table_args__ = (db.UniqueConstraint('announcement_id', 'user_id', 'user_role', name='unique_sa_read'),)

        class SuperAdminPosts(db.Model):
            __bind_key__ = bind_key
            __tablename__ = 'SuperAdminPosts'
            id = db.Column(db.Integer, primary_key=True)
            title = db.Column(db.String(100), nullable=False)
            content = db.Column(db.Text, nullable=False)
            author_id = db.Column(db.Integer, db.ForeignKey('SuperAdmins.id'), nullable=False)
            created_at = db.Column(db.DateTime, nullable=False, default=datetime.datetime.now)
            updated_at = db.Column(db.DateTime, nullable=False, default=datetime.datetime.now, onupdate=datetime.datetime.now)
            views = db.Column(db.Integer, default=0)
            is_deleted = db.Column(db.Boolean, default=False)
            deleted_at = db.Column(db.DateTime, nullable=True)
            author = db.relationship('SuperAdmins', foreign_keys=[author_id])

        class SuperAdminArticles(db.Model):
            __bind_key__ = bind_key
            __tablename__ = 'SuperAdminArticles'
            arid = db.Column(db.Integer, primary_key=True)
            title = db.Column(db.String(50), nullable=False)
            content = db.Column(db.Text, nullable=False)
            time = db.Column(db.DateTime, nullable=False, default=datetime.datetime.now)
            author_id = db.Column(db.Integer, db.ForeignKey('SuperAdmins.id'), nullable=False)
            views = db.Column(db.Integer, default=0)
            is_deleted = db.Column(db.Boolean, default=False)
            author = db.relationship('SuperAdmins', foreign_keys=[author_id])
            comments = db.relationship('SuperAdminComments', lazy=True, uselist=True, back_populates='article')

        class SuperAdminComments(db.Model):
            __bind_key__ = bind_key
            __tablename__ = 'SuperAdminComments'
            id = db.Column(db.Integer, primary_key=True)
            content = db.Column(db.Text, nullable=False)
            time = db.Column(db.DateTime, nullable=False, default=datetime.datetime.now)
            author_id = db.Column(db.Integer, db.ForeignKey('SuperAdmins.id'), nullable=False)
            article_id = db.Column(db.Integer, db.ForeignKey('SuperAdminArticles.arid'), nullable=False)
            is_deleted = db.Column(db.Boolean, default=False)
            author = db.relationship('SuperAdmins', foreign_keys=[author_id])
            article = db.relationship('SuperAdminArticles', foreign_keys=[article_id])

        class SuperAdmins(db.Model, UserMixin):
            __bind_key__ = bind_key
            __tablename__ = 'SuperAdmins'
            id = db.Column(db.Integer, primary_key=True)
            nickname = db.Column(db.String(20), nullable=False, unique=True)
            crypto_pw = db.Column(db.String(256), nullable=False)
            email = db.Column(db.String(30), nullable=False, unique=True)
            email_verified = db.Column(db.Boolean, default=False, nullable=False)
            status = db.Column(db.Boolean, nullable=False, default=True)
            level = db.Column(db.Integer, nullable=False, default=0)
            invite_code = db.Column(db.String(64), unique=True, nullable=True)
            invite_code_used = db.Column(db.Boolean, default=False)
            invite_code_created_at = db.Column(db.DateTime, nullable=True)
            invited_by = db.Column(db.Integer, nullable=True)
            pbkdf2_salt = db.Column(db.String(64), nullable=True)
            pbkdf2_iterations = db.Column(db.Integer, nullable=True)
            bio = db.Column(db.Text)
            profile_visibility = db.Column(db.String(20), default='public')
            online_status = db.Column(db.Boolean, default=True)
            can_post_announcement = db.Column(db.Boolean, default=True)
            can_manage_admins = db.Column(db.Boolean, default=True)
            can_manage_superadmins = db.Column(db.Boolean, default=False)
            created_at = db.Column(db.DateTime, default=datetime.datetime.now)
            last_login = db.Column(db.DateTime, nullable=True)
            logs = db.relationship('SuperAdminLogs', lazy=True, uselist=True, back_populates='super_admin', cascade='all, delete-orphan')
            announcements = db.relationship('SuperAdminAnnouncements', lazy=True, uselist=True, back_populates='author', cascade='all, delete-orphan')
            posts = db.relationship('SuperAdminPosts', lazy=True, uselist=True, back_populates='author', cascade='all, delete-orphan')
            articles = db.relationship('SuperAdminArticles', lazy=True, uselist=True, back_populates='author', cascade='all, delete-orphan')
            comments = db.relationship('SuperAdminComments', lazy=True, uselist=True, back_populates='author', cascade='all, delete-orphan')

        class SuperAdminPasswordResetTokens(db.Model):
            __bind_key__ = bind_key
            __tablename__ = 'SuperAdminPasswordResetTokens'
            id = db.Column(db.Integer, primary_key=True)
            superadmin_id = db.Column(db.Integer, db.ForeignKey('SuperAdmins.id'), nullable=False)
            token = db.Column(db.String(100), unique=True, nullable=False)
            expires_at = db.Column(db.DateTime, nullable=False)
            used = db.Column(db.Boolean, default=False)
            super_admin = db.relationship('SuperAdmins', foreign_keys=[superadmin_id])

        class SuperAdminEmailVerificationTokens(db.Model):
            __bind_key__ = bind_key
            __tablename__ = 'SuperAdminEmailVerificationTokens'
            id = db.Column(db.Integer, primary_key=True)
            superadmin_id = db.Column(db.Integer, db.ForeignKey('SuperAdmins.id'), nullable=False)
            token = db.Column(db.String(100), unique=True, nullable=False)
            email = db.Column(db.String(30), nullable=False)
            expires_at = db.Column(db.DateTime, nullable=False)
            used = db.Column(db.Boolean, default=False)
            super_admin = db.relationship('SuperAdmins', foreign_keys=[superadmin_id])

        class SuperAdminLogs(db.Model):
            __bind_key__ = bind_key
            __tablename__ = 'SuperAdminLogs'
            id = db.Column(db.Integer, primary_key=True)
            time = db.Column(db.DateTime, nullable=False, default=datetime.datetime.now)
            action = db.Column(db.String(50), nullable=False)
            target_type = db.Column(db.String(50), nullable=True)
            target_id = db.Column(db.Integer, nullable=True)
            content = db.Column(db.Text, nullable=False)
            ip_address = db.Column(db.String(45), nullable=True)
            super_admin_id = db.Column(db.Integer, db.ForeignKey('SuperAdmins.id'), nullable=False)
            super_admin = db.relationship('SuperAdmins', foreign_keys=[super_admin_id])

        return (SuperAdmins, SuperAdminPasswordResetTokens, 
                SuperAdminEmailVerificationTokens, SuperAdminLogs,
                SuperAdminAnnouncements, SuperAdminAnnouncementReads,
                SuperAdminPosts, SuperAdminArticles, SuperAdminComments)

    def generate_owner_tables(self, db, bind_key='admins'):
        """生成所有者表"""
        
        class OwnerAnnouncements(db.Model):
            __bind_key__ = bind_key
            __tablename__ = 'OwnerAnnouncements'
            id = db.Column(db.Integer, primary_key=True)
            title = db.Column(db.String(100), nullable=False)
            content = db.Column(db.Text, nullable=False)
            category = db.Column(db.String(20), default='info')
            target_role = db.Column(db.String(20), default='all')
            created_at = db.Column(db.DateTime, default=datetime.datetime.now)
            updated_at = db.Column(db.DateTime, default=datetime.datetime.now, onupdate=datetime.datetime.now)
            start_at = db.Column(db.DateTime, default=datetime.datetime.now)
            end_at = db.Column(db.DateTime, nullable=True)
            is_active = db.Column(db.Boolean, default=True)
            is_pinned = db.Column(db.Boolean, default=False)
            is_deleted = db.Column(db.Boolean, default=False)
            author_id = db.Column(db.Integer, db.ForeignKey('Owners.id'), nullable=False)
            author_name = db.Column(db.String(20), nullable=False)
            views = db.Column(db.Integer, default=0)
            author = db.relationship('Owners', foreign_keys=[author_id])

        class OwnerAnnouncementReads(db.Model):
            __bind_key__ = bind_key
            __tablename__ = 'OwnerAnnouncementReads'
            id = db.Column(db.Integer, primary_key=True)
            announcement_id = db.Column(db.Integer, db.ForeignKey('OwnerAnnouncements.id'), nullable=False)
            user_id = db.Column(db.Integer, nullable=False)
            user_role = db.Column(db.String(20), nullable=False)
            read_at = db.Column(db.DateTime, default=datetime.datetime.now)
            __table_args__ = (db.UniqueConstraint('announcement_id', 'user_id', 'user_role', name='unique_owner_read'),)

        class InviteCodes(db.Model):
            __bind_key__ = bind_key
            __tablename__ = 'InviteCodes'
            id = db.Column(db.Integer, primary_key=True)
            code = db.Column(db.String(64), unique=True, nullable=False)
            code_type = db.Column(db.String(20), default='temporary')
            target_role = db.Column(db.String(20), nullable=False)
            max_uses = db.Column(db.Integer, default=1)
            used_count = db.Column(db.Integer, default=0)
            expires_at = db.Column(db.DateTime, nullable=True)
            created_at = db.Column(db.DateTime, default=datetime.datetime.now)
            is_active = db.Column(db.Boolean, default=True)
            created_by_id = db.Column(db.Integer, db.ForeignKey('Owners.id'), nullable=False)
            creator = db.relationship('Owners', foreign_keys=[created_by_id], back_populates='invite_codes')
            used_by = db.relationship('InviteCodeUses', lazy=True, uselist=True, back_populates='invite_code', cascade='all, delete-orphan')

        class InviteCodeUses(db.Model):
            __bind_key__ = bind_key
            __tablename__ = 'InviteCodeUses'
            id = db.Column(db.Integer, primary_key=True)
            invite_code_id = db.Column(db.Integer, db.ForeignKey('InviteCodes.id'), nullable=False)
            used_by_id = db.Column(db.Integer, nullable=False)
            used_by_role = db.Column(db.String(20), nullable=False)
            used_at = db.Column(db.DateTime, default=datetime.datetime.now)
            ip_address = db.Column(db.String(45), nullable=True)
            invite_code = db.relationship('InviteCodes', foreign_keys=[invite_code_id])

        class OwnerPosts(db.Model):
            __bind_key__ = bind_key
            __tablename__ = 'OwnerPosts'
            id = db.Column(db.Integer, primary_key=True)
            title = db.Column(db.String(100), nullable=False)
            content = db.Column(db.Text, nullable=False)
            author_id = db.Column(db.Integer, db.ForeignKey('Owners.id'), nullable=False)
            created_at = db.Column(db.DateTime, nullable=False, default=datetime.datetime.now)
            updated_at = db.Column(db.DateTime, nullable=False, default=datetime.datetime.now, onupdate=datetime.datetime.now)
            views = db.Column(db.Integer, default=0)
            is_deleted = db.Column(db.Boolean, default=False)
            deleted_at = db.Column(db.DateTime, nullable=True)
            author = db.relationship('Owners', foreign_keys=[author_id])

        class OwnerArticles(db.Model):
            __bind_key__ = bind_key
            __tablename__ = 'OwnerArticles'
            arid = db.Column(db.Integer, primary_key=True)
            title = db.Column(db.String(50), nullable=False)
            content = db.Column(db.Text, nullable=False)
            time = db.Column(db.DateTime, nullable=False, default=datetime.datetime.now)
            author_id = db.Column(db.Integer, db.ForeignKey('Owners.id'), nullable=False)
            views = db.Column(db.Integer, default=0)
            is_deleted = db.Column(db.Boolean, default=False)
            author = db.relationship('Owners', foreign_keys=[author_id])
            comments = db.relationship('OwnerComments', lazy=True, uselist=True, back_populates='article')

        class OwnerComments(db.Model):
            __bind_key__ = bind_key
            __tablename__ = 'OwnerComments'
            id = db.Column(db.Integer, primary_key=True)
            content = db.Column(db.Text, nullable=False)
            time = db.Column(db.DateTime, nullable=False, default=datetime.datetime.now)
            author_id = db.Column(db.Integer, db.ForeignKey('Owners.id'), nullable=False)
            article_id = db.Column(db.Integer, db.ForeignKey('OwnerArticles.arid'), nullable=False)
            is_deleted = db.Column(db.Boolean, default=False)
            author = db.relationship('Owners', foreign_keys=[author_id])
            article = db.relationship('OwnerArticles', foreign_keys=[article_id])

        class Owners(db.Model, UserMixin):
            __bind_key__ = bind_key
            __tablename__ = 'Owners'
            id = db.Column(db.Integer, primary_key=True)
            nickname = db.Column(db.String(20), nullable=False, unique=True)
            email = db.Column(db.String(30), default=os.getenv('EMAIL_BOX'), nullable=False, unique=True)
            email_verified = db.Column(db.Boolean, default=True, nullable=False)
            crypto_pw = db.Column(db.String(256), nullable=False)
            pbkdf2_salt = db.Column(db.String(64), nullable=True)
            pbkdf2_iterations = db.Column(db.Integer, nullable=True)
            bio = db.Column(db.Text)
            profile_visibility = db.Column(db.String(20), default='private')
            online_status = db.Column(db.Boolean, default=True)
            can_post_announcement = db.Column(db.Boolean, default=True)
            created_at = db.Column(db.DateTime, default=datetime.datetime.now)
            last_login = db.Column(db.DateTime, nullable=True)
            logs = db.relationship('OwnerLogs', lazy=True, uselist=True, back_populates='owner', cascade='all, delete-orphan')
            invite_codes = db.relationship('InviteCodes', lazy=True, uselist=True, back_populates='creator', cascade='all, delete-orphan')
            announcements = db.relationship('OwnerAnnouncements', lazy=True, uselist=True, back_populates='author', cascade='all, delete-orphan')
            posts = db.relationship('OwnerPosts', lazy=True, uselist=True, back_populates='author', cascade='all, delete-orphan')
            articles = db.relationship('OwnerArticles', lazy=True, uselist=True, back_populates='author', cascade='all, delete-orphan')
            comments = db.relationship('OwnerComments', lazy=True, uselist=True, back_populates='author', cascade='all, delete-orphan')

        class OwnerLogs(db.Model):
            __bind_key__ = bind_key
            __tablename__ = 'OwnerLogs'
            id = db.Column(db.Integer, primary_key=True)
            time = db.Column(db.DateTime, nullable=False, default=datetime.datetime.now)
            action = db.Column(db.String(50), nullable=False)
            target_type = db.Column(db.String(50), nullable=True)
            target_id = db.Column(db.Integer, nullable=True)
            content = db.Column(db.Text, nullable=False)
            ip_address = db.Column(db.String(45), nullable=True)
            owner_id = db.Column(db.Integer, db.ForeignKey('Owners.id'), nullable=False)
            owner = db.relationship('Owners', foreign_keys=[owner_id])

        return (Owners, OwnerLogs, InviteCodes, InviteCodeUses,
                OwnerAnnouncements, OwnerAnnouncementReads,
                OwnerPosts, OwnerArticles, OwnerComments)

    # ========== 初始化方法 ==========
    
    def user_tables(self):
        """初始化用户表"""
        db = self.db
        (self.ids, self.uids, self.posts, self.articles, 
         self.comments, self.password_reset_tokens, 
         self.email_verification_tokens, self.likes, 
         self.favorites, self.follows, self.uploads, 
         self.points_history, self.messages, self.conversations, 
         self.reports, self.report_reasons, self.bounty_tasks, 
         self.points_earnings, self.thanks, self.email_recovery_requests,
         self.friends, self.friend_requests, self.points_transfers, 
         self.block_list, self.bounty_sub_tasks, 
         self.bounty_uploads, self.bounty_reward_logs, self.bounty_append_logs) = self.generate_user_tables(db)

    def admin_tables(self):
        """初始化管理员表"""
        db = self.db
        (self.admins, self.admin_password_reset_tokens, 
         self.admin_email_verification_tokens, self.admin_logs,
         self.announcements, self.announcement_reads,
         self.admin_posts, self.admin_articles, self.admin_comments) = self.generate_admin_tables(db)

    def super_admin_tables(self):
        """初始化超级管理员表"""
        db = self.db
        (self.super_admins, self.super_admin_password_reset_tokens,
         self.super_admin_email_verification_tokens, self.super_admin_logs,
         self.super_admin_announcements, self.super_admin_announcement_reads,
         self.super_admin_posts, self.super_admin_articles, self.super_admin_comments) = self.generate_super_admin_tables(db)

    def owner_tables(self):
        """初始化所有者表"""
        db = self.db
        (self.owners, self.owner_logs, self.invite_codes, self.invite_code_uses,
         self.owner_announcements, self.owner_announcement_reads,
         self.owner_posts, self.owner_articles, self.owner_comments) = self.generate_owner_tables(db)

