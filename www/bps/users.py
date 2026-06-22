from flask import Blueprint, render_template, request, jsonify, redirect, url_for, session, send_file, current_app
from flask_login import login_user, logout_user, login_required, current_user
from utils.password_checker import Password
from utils.email_sender import EmailSender, generate_reset_token
from utils.pbkdf2_security import PBKDF2Security
from utils.utils import RenderTemplate, anonymous_required, require_csrf
from utils.file_scanner import FileScanner
from utils.content_filter import ContentFilter
import os
import secrets
import time
from datetime import datetime, timedelta
from PIL import Image
from werkzeug.utils import secure_filename
from utils.utils import validate_email, validate_password, validate_nickname, validate_url, sanitize_html, validate_role, validate_user_id
from utils.utils import rate_limit, sanitize_form_data
from functools import wraps
import hashlib
import json
import math
import re

user_bp = Blueprint('user', __name__, url_prefix='/user')

# 初始化 PBKDF2 安全模块
pbkdf2_security = PBKDF2Security()

# 初始化文件扫描器
file_scanner = FileScanner()

# 需要在主app中初始化db后传入
def init_user_bp(app, db, cache, IDs, UIDs, EmailVerificationTokens, PasswordResetTokens, 
                 Posts, Articles, Comments, Likes, Favorites, Follows, Uploads, PointsHistory, Messages, 
                 Conversations, Reports, ReportReasons, BountyTasks, PointsEarnings, EmailRecoveryRequests, 
                 Friends, FriendRequests, PointsTransfers, BlockList, BountySubTasks):
    """初始化用户蓝图"""
    # 存储数据库相关对象
    user_bp.db = db
    user_bp.cache = cache
    user_bp.IDs = IDs
    user_bp.UIDs = UIDs
    user_bp.EmailVerificationTokens = EmailVerificationTokens
    user_bp.PasswordResetTokens = PasswordResetTokens
    user_bp.Posts = Posts
    user_bp.Articles = Articles
    user_bp.Comments = Comments
    user_bp.Likes = Likes
    user_bp.Favorites = Favorites
    user_bp.Follows = Follows
    user_bp.Uploads = Uploads
    user_bp.PointsHistory = PointsHistory
    user_bp.Messages = Messages
    user_bp.Conversations = Conversations
    user_bp.Reports = Reports
    user_bp.ReportReasons = ReportReasons
    user_bp.BountyTasks = BountyTasks
    user_bp.PointsEarnings = PointsEarnings
    user_bp.EmailRecoveryRequests = EmailRecoveryRequests
    user_bp.Friends = Friends
    user_bp.FriendRequests = FriendRequests
    user_bp.PointsTransfers = PointsTransfers
    user_bp.BlockList = BlockList
    user_bp.BountySubTasks = BountySubTasks
    user_bp.app = app
    
    # 创建蓝图特定的模型字典
    user_models = {
        'IDs': IDs,
        'UIDs': UIDs,
        'Posts': Posts,
        'Articles': Articles,
        'PointsHistory': PointsHistory,
        'Reports': Reports
    }
    
    # 初始化蓝图特定的渲染实例
    user_bp.renderTemplate = RenderTemplate(db, models=user_models).renderTemplate

    # 添加自定义过滤器
    user_bp.add_app_template_filter(timesince, 'timesince')
    user_bp.add_app_template_filter(safe_post_content, 'safe_post')
    
    return user_bp


# ========== 辅助函数 ==========

def get_current_uid():
    """获取当前活跃的UID"""
    try:
        return session.get('current_uid')
    except RuntimeError:
        return None

def get_current_identity():
    """获取当前身份信息（主账户或子账户）"""
    try:
        current_uid = get_current_uid()
        user_id = session.get('user_id')
        
        if current_uid and user_id:
            uid_record = user_bp.UIDs.query.get(current_uid)
            if uid_record and uid_record.id == user_id:
                return {
                    'type': 'uid',
                    'uid': uid_record.uid,
                    'nickname': uid_record.nickname,
                    'level': uid_record.level,
                    'object': uid_record
                }
        
        if user_id:
            user = user_bp.IDs.query.get(user_id)
            if user:
                return {
                    'type': 'id',
                    'id': user.id,
                    'nickname': user.nickname,
                    'level': user.level,
                    'object': user
                }
        
        return None
    except RuntimeError:
        return None

def get_session_key():
    """生成唯一的会话标识符"""
    if 'session_key' not in session:
        session['session_key'] = secrets.token_hex(16)
    return session['session_key']


def get_user_by_id(user_id):
    """根据ID获取用户信息（辅助模板函数）"""
    try:
        return user_bp.IDs.query.get(user_id)
    except:
        return None


def get_uid_by_id(uid):
    """根据UID获取UID信息（辅助模板函数）"""
    try:
        return user_bp.UIDs.query.get(uid)
    except:
        return None


def get_article_by_id(arid):
    """根据文章ID获取文章信息（辅助模板函数）"""
    try:
        return user_bp.Articles.query.get(arid)
    except:
        return None


def get_post_by_id(post_id):
    """根据帖子ID获取帖子信息（辅助模板函数）"""
    try:
        return user_bp.Posts.query.get(post_id)
    except:
        return None


def timesince(dt, default="刚刚"):
    """
    将时间转换为相对时间（如：5分钟前、2小时前）
    """
    if not dt:
        return default
    
    now = datetime.now()
    diff = now - dt
    
    seconds = diff.total_seconds()
    
    if seconds < 60:
        return "刚刚"
    elif seconds < 3600:
        minutes = int(seconds // 60)
        return f"{minutes}分钟前"
    elif seconds < 86400:
        hours = int(seconds // 3600)
        return f"{hours}小时前"
    elif seconds < 2592000:
        days = int(seconds // 86400)
        return f"{days}天前"
    elif seconds < 31536000:
        months = int(seconds // 2592000)
        return f"{months}个月前"
    else:
        years = int(seconds // 31536000)
        return f"{years}年前"


def safe_post_content(content):
    """模板过滤器：安全显示帖子内容"""
    if not content:
        return ""
    return ContentFilter.sanitize_post_content(content)


# ========== 权限装饰器 ==========

def require_uid_only(f):
    """只允许子账户（UID）访问的装饰器（用于发帖等社区功能）"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        current_uid = session.get('current_uid')
        if not current_uid:
            return user_bp.renderTemplate('/system-files/403.html'), 403
        
        uid_record = user_bp.UIDs.query.filter_by(
            uid=current_uid,
            id=current_user.id,
            status=True
        ).first()
        
        if not uid_record:
            session.pop('current_uid', None)
            session.pop('current_uid_nickname', None)
            return user_bp.renderTemplate('/system-files/403.html'), 403
        
        kwargs['uid_record'] = uid_record
        return f(*args, **kwargs)
    return decorated_function


def require_main_account(f):
    """只允许主账户访问的装饰器（用于管理子账户、修改邮箱等）"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if session.get('current_uid'):
            return user_bp.renderTemplate('/system-files/403.html'), 403
        return f(*args, **kwargs)
    return decorated_function


def require_post_author(f):
    """确保用户是帖子的作者"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        post_id = kwargs.get('post_id')
        if not post_id:
            return user_bp.renderTemplate('/system-files/400.html'), 400
        
        post = user_bp.Posts.query.filter_by(id=post_id, is_deleted=False).first()
        if not post:
            return user_bp.renderTemplate('/system-files/404.html'), 404
        
        current_uid = session.get('current_uid')
        if not current_uid or current_uid != post.author_id:
            return user_bp.renderTemplate('/system-files/403.html'), 403
        
        uid_record = user_bp.UIDs.query.filter_by(
            uid=current_uid,
            id=current_user.id
        ).first()
        
        if not uid_record:
            return user_bp.renderTemplate('/system-files/403.html'), 403
        
        kwargs['post'] = post
        kwargs['uid_record'] = uid_record
        return f(*args, **kwargs)
    return decorated_function


def require_article_author(f):
    """确保用户是文章的作者"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        arid = kwargs.get('arid')
        if not arid:
            return user_bp.renderTemplate('/system-files/400.html'), 400
        
        article = user_bp.Articles.query.filter_by(arid=arid, is_deleted=False).first()
        if not article:
            return user_bp.renderTemplate('/system-files/404.html'), 404
        
        current_uid = session.get('current_uid')
        if not current_uid or current_uid != article.author_id:
            return user_bp.renderTemplate('/system-files/403.html'), 403
        
        uid_record = user_bp.UIDs.query.filter_by(
            uid=current_uid,
            id=current_user.id
        ).first()
        
        if not uid_record:
            return user_bp.renderTemplate('/system-files/403.html'), 403
        
        kwargs['article'] = article
        kwargs['uid_record'] = uid_record
        return f(*args, **kwargs)
    return decorated_function


def require_upload_owner(f):
    """确保用户是上传文件的拥有者"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        file_id = kwargs.get('file_id')
        if not file_id:
            return user_bp.renderTemplate('/system-files/400.html'), 400
        
        upload = user_bp.Uploads.query.get(file_id)
        if not upload or upload.is_deleted:
            return user_bp.renderTemplate('/system-files/404.html'), 404
        
        current_uid = session.get('current_uid')
        if not current_uid or current_uid != upload.uid:
            return user_bp.renderTemplate('/system-files/403.html'), 403
        
        kwargs['upload'] = upload
        return f(*args, **kwargs)
    return decorated_function


def check_ban(f):
    """检查用户是否被封禁的装饰器"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        try:
            current_uid = session.get('current_uid')
            if not current_uid:
                return f(*args, **kwargs)  # 未登录不检查
            
            uid_record = user_bp.UIDs.query.get(current_uid)
            if not uid_record:
                return f(*args, **kwargs)
            
            # 检查UID是否被封禁
            if uid_record.is_banned:
                return user_bp.renderTemplate(
                    '/system-files/banned.html',
                    ban_reason=uid_record.banned_reason,
                    ban_time=uid_record.banned_at,
                    ban_expires=uid_record.ban_expires_at,
                    report_count=uid_record.report_count,
                    is_uid=True
                ), 403
            
            # 检查所属ID是否被封禁
            if uid_record.user and uid_record.user.is_banned:
                return user_bp.renderTemplate(
                    '/system-files/banned.html',
                    ban_reason=uid_record.user.banned_reason,
                    ban_time=uid_record.user.banned_at,
                    ban_expires=uid_record.user.ban_expires_at,
                    report_count=uid_record.user.report_count,
                    is_uid=False
                ), 403
            
            return f(*args, **kwargs)
            
        except Exception as e:
            print(f"封禁检查失败: {e}")
            return f(*args, **kwargs)
    
    return decorated_function


# ========== 开发者权限装饰器 ==========

def developer_required(f):
    """仅开发者（主账户 ID=3）可访问的装饰器"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated:
            return jsonify({'error': '未登录'}), 401
        
        # 检查是否是主账户且 ID=3
        if current_user.__class__.__name__ == 'IDs' and current_user.id == 3:
            return f(*args, **kwargs)
        
        return jsonify({'error': '无权限访问'}), 403
    return decorated_function


# ========== 强制邮箱验证装饰器 ==========

def require_verified_email(f):
    """强制要求邮箱已验证（用于接单、IDE等核心功能）"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated:
            return jsonify({'error': '未登录', 'login_required': True}), 401
        
        # 只对普通用户检查
        if current_user.__class__.__name__ == 'IDs':
            if not current_user.email_verified:
                return jsonify({
                    'error': '请先验证邮箱后再使用此功能',
                    'need_verify': True,
                    'verify_url': url_for('user.verify_reminder')
                }), 403
        
        return f(*args, **kwargs)
    return decorated_function


def require_verified_email_web(f):
    """强制要求邮箱已验证（Web页面版，重定向到验证提醒页）"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated:
            return redirect(url_for('user.login'))
        
        if current_user.__class__.__name__ == 'IDs':
            if not current_user.email_verified:
                return redirect(url_for('user.verify_reminder'))
        
        return f(*args, **kwargs)
    return decorated_function
    

# ========== 账户管理路由 ==========

@user_bp.route('/api/pbkdf2-salt')
def get_user_pbkdf2_salt():
    """获取PBKDF2参数 - 用户特定版本"""
    try:
        user_id = session.get('user_id')
        
        if user_id:
            user = user_bp.IDs.query.get(user_id)
            if user:
                salt, iterations = pbkdf2_security.get_pbkdf2_params_for_existing_user(user)
                user_bp.db.session.commit()
                return jsonify({
                    'success': True,
                    'salt': salt,
                    'iterations': iterations,
                    'is_user_specific': True
                })
            else:
                return jsonify({'success': False, 'error': '用户不存在'}), 404
        else:
            session_key = get_session_key()
            temp_key = f"temp_{session_key}"
            salt, iterations = pbkdf2_security.get_pbkdf2_params_for_new_user(temp_key)
            return jsonify({
                'success': True,
                'salt': salt,
                'iterations': iterations,
                'is_user_specific': False
            })
            
    except Exception as e:
        print(f"获取PBKDF2参数失败: {e}")
        return jsonify({'success': False, 'error': '服务器错误'}), 500


@user_bp.route('/api/user-pbkdf2-params')
def get_user_specific_pbkdf2_params():
    """获取用户特定的PBKDF2参数"""
    try:
        account = request.args.get('account')
        
        if not account:
            return jsonify({'success': False, 'error': '账号参数缺失'})
        
        user = user_bp.IDs.query.filter(
            (user_bp.IDs.nickname == account) | (user_bp.IDs.email == account)
        ).first()
        
        if user:
            if not user.pbkdf2_salt or not user.pbkdf2_iterations:
                user.pbkdf2_salt, user.pbkdf2_iterations = pbkdf2_security.get_pbkdf2_params_for_new_user()
                user_bp.db.session.commit()
            
            return jsonify({
                'success': True,
                'salt': user.pbkdf2_salt,
                'iterations': user.pbkdf2_iterations,
                'is_user_specific': True
            })
        else:
            session_key = get_session_key()
            temp_key = f"temp_{session_key}"
            salt, iterations = pbkdf2_security.get_pbkdf2_params_for_new_user(temp_key)
            
            return jsonify({
                'success': True,
                'salt': salt,
                'iterations': iterations,
                'is_user_specific': False
            })
            
    except Exception as e:
        print(f"获取用户PBKDF2参数失败: {e}")
        return jsonify({'success': False, 'error': '服务器错误'}), 500


# ========== 第三方登录认证路由 ==========

@user_bp.route('/api/auth/token', methods=['POST'])
def generate_auth_token():
    """生成用于第三方服务（IDE等）的临时认证令牌"""
    try:
        data = request.get_json()
        service = data.get('service', 'ide')
        callback_url = data.get('callback_url', '')
        
        if not current_user.is_authenticated:
            return jsonify({'success': False, 'error': '未登录', 'login_required': True}), 401
        
        # 强制邮箱验证检查
        if current_user.__class__.__name__ == 'IDs':
            if not current_user.email_verified:
                return jsonify({
                    'success': False,
                    'error': '邮箱未验证，请先验证邮箱',
                    'need_verify': True,
                    'verify_url': url_for('user.verify_reminder')
                }), 403
        
        identity = get_current_identity()
        if not identity:
            return jsonify({'success': False, 'error': '无效的身份信息'}), 400
        
        # 生成临时令牌
        auth_token = secrets.token_urlsafe(32)
        expires_at = datetime.now() + timedelta(minutes=5)
        
        # 存储到缓存
        token_data = {
            'service': service,
            'user_id': current_user.id,
            'current_uid': session.get('current_uid'),
            'callback_url': callback_url,
            'created_at': datetime.now().isoformat(),
            'expires_at': expires_at.isoformat()
        }
        
        user_bp.cache.set(f'auth_token_{auth_token}', token_data, timeout=300)
        
        # 构建用户信息
        user_info = {
            'user_id': current_user.id,
            'nickname': current_user.nickname,
            'email': current_user.email,
            'avatar': None,
            'level': current_user.level,
            'points': float(current_user.points or 0),
            'role': session.get('role', 'user')
        }
        
        if identity['type'] == 'uid':
            user_info['current_uid'] = {
                'uid': identity['uid'],
                'nickname': identity['nickname'],
                'level': identity['level']
            }
        
        return jsonify({
            'success': True,
            'token': auth_token,
            'expires_in': 300,
            'user_info': user_info,
            'service': service
        })
        
    except Exception as e:
        print(f"生成认证令牌失败: {e}")
        return jsonify({'success': False, 'error': '生成令牌失败'}), 500


@user_bp.route('/api/auth/verify', methods=['POST'])
def verify_auth_token():
    """验证第三方服务传来的令牌并返回用户信息"""
    try:
        data = request.get_json()
        token = data.get('token')
        service = data.get('service', 'ide')
        
        if not token:
            return jsonify({'success': False, 'error': '缺少令牌'}), 400
        
        token_data = user_bp.cache.get(f'auth_token_{token}')
        
        if not token_data:
            return jsonify({'success': False, 'error': '无效或已过期的令牌'}), 401
        
        if token_data.get('service') != service:
            return jsonify({'success': False, 'error': '服务不匹配'}), 401
        
        expires_at = datetime.fromisoformat(token_data['expires_at'])
        if expires_at < datetime.now():
            user_bp.cache.delete(f'auth_token_{token}')
            return jsonify({'success': False, 'error': '令牌已过期'}), 401
        
        user = user_bp.IDs.query.get(token_data['user_id'])
        if not user:
            return jsonify({'success': False, 'error': '用户不存在'}), 401
        
        user_info = {
            'user_id': user.id,
            'nickname': user.nickname,
            'email': user.email,
            'level': user.level,
            'points': float(user.points or 0),
            'email_verified': user.email_verified,
            'created_at': user.created_at.isoformat() if user.created_at else None
        }
        
        uid_info = None
        if token_data.get('current_uid'):
            uid_record = user_bp.UIDs.query.get(token_data['current_uid'])
            if uid_record:
                uid_info = {
                    'uid': uid_record.uid,
                    'nickname': uid_record.nickname,
                    'level': uid_record.level,
                    'points': float(uid_record.points or 0),
                    'bio': uid_record.bio
                }
        
        user_bp.cache.delete(f'auth_token_{token}')
        
        return jsonify({
            'success': True,
            'user_info': user_info,
            'uid_info': uid_info,
            'service': service
        })
        
    except Exception as e:
        print(f"验证认证令牌失败: {e}")
        return jsonify({'success': False, 'error': '验证失败'}), 500


@user_bp.route('/api/auth/sso-login', methods=['POST'])
def sso_login():
    """第三方服务单点登录 - 通过共享密钥直接登录"""
    try:
        data = request.get_json()
        service = data.get('service', 'ide')
        user_id = data.get('user_id')
        sso_token = data.get('sso_token')
        
        SSO_SECRET = os.environ.get("SSO_SHARED_SECRET", "freehub-default-secret-change-me")
        
        expected_token = hashlib.sha256(
            f"{user_id}:{service}:{SSO_SECRET}".encode()
        ).hexdigest()
        
        if sso_token != expected_token:
            return jsonify({'success': False, 'error': '无效的 SSO 令牌'}), 401
        
        user = user_bp.IDs.query.get(user_id)
        if not user or not user.status:
            return jsonify({'success': False, 'error': '用户不存在或已禁用'}), 404
        
        user_info = {
            'user_id': user.id,
            'nickname': user.nickname,
            'email': user.email,
            'level': user.level,
            'points': float(user.points or 0)
        }
        
        uids = []
        for uid in user.uids:
            if uid.status:
                uids.append({
                    'uid': uid.uid,
                    'nickname': uid.nickname,
                    'level': uid.level,
                    'points': float(uid.points or 0)
                })
        
        return jsonify({
            'success': True,
            'user_info': user_info,
            'uids': uids,
            'service': service
        })
        
    except Exception as e:
        print(f"SSO登录失败: {e}")
        return jsonify({'success': False, 'error': '登录失败'}), 500


@user_bp.route('/api/auth/ide-login', methods=['GET'])
def ide_login_redirect():
    """IDE 登录重定向页面"""
    from flask import render_template_string
    
    nonce = request.nonce if hasattr(request, 'nonce') else secrets.token_urlsafe(16)
    ide_url = request.args.get('ide_url', 'https://ide.free-hub.cn')
    
    html_template = '''
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="UTF-8">
        <title>IDE 登录 - Free Hub</title>
        <style nonce="{{ nonce }}">
            body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; display: flex; justify-content: center; align-items: center; min-height: 100vh; margin: 0; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); }
            .container { background: white; padding: 2rem; border-radius: 16px; box-shadow: 0 10px 40px rgba(0,0,0,0.2); text-align: center; max-width: 400px; }
            .status { margin: 1rem 0; padding: 0.5rem; border-radius: 8px; }
            .success { background: #d4edda; color: #155724; }
            .error { background: #f8d7da; color: #721c24; }
            .loading { background: #e2e3e5; color: #383d41; }
            button { background: #667eea; color: white; border: none; padding: 10px 20px; border-radius: 8px; cursor: pointer; margin-top: 1rem; }
            button:hover { background: #5a67d8; }
            a { color: #667eea; text-decoration: none; }
        </style>
    </head>
    <body>
        <div class="container">
            <h2>🚀 IDE 登录授权</h2>
            <div id="status" class="status loading">正在检查登录状态...</div>
            <div id="info" style="font-size: 14px; color: #666;"></div>
        </div>
        <script nonce="{{ nonce }}">
            const IDE_URL = '{{ ide_url }}';
            async function checkLogin() {
                try {
                    const resp = await fetch('/user/api/auth/check', { credentials: 'same-origin' });
                    const data = await resp.json();
                    if (data.logged_in) {
                        const tokenResp = await fetch('/user/api/auth/token', {
                            method: 'POST',
                            headers: { 'Content-Type': 'application/json' },
                            credentials: 'same-origin',
                            body: JSON.stringify({ service: 'ide', callback_url: IDE_URL })
                        });
                        const tokenData = await tokenResp.json();
                        if (tokenData.success) {
                            showStatus('登录成功！正在跳转到 IDE...', 'success');
                            window.location.href = IDE_URL + '/api/auth/callback?token=' + tokenData.token;
                        } else {
                            showStatus('生成令牌失败: ' + (tokenData.error || '未知错误'), 'error');
                        }
                    } else {
                        showStatus('请先登录主站', 'error');
                        document.getElementById('info').innerHTML = '<a href="/user/login">前往登录</a> | <a href="/">返回首页</a>';
                    }
                } catch (err) {
                    showStatus('请求失败: ' + err.message, 'error');
                }
            }
            function showStatus(msg, type) {
                const statusDiv = document.getElementById('status');
                statusDiv.textContent = msg;
                statusDiv.className = 'status ' + type;
            }
            checkLogin();
        </script>
    </body>
    </html>
    '''
    
    return render_template_string(html_template, ide_url=ide_url, nonce=nonce)


@user_bp.route('/api/auth/share-login', methods=['GET'])
def share_login_redirect():
    """Share 登录重定向页面"""
    from flask import render_template_string
    
    nonce = request.nonce if hasattr(request, 'nonce') else secrets.token_urlsafe(16)
    share_url = request.args.get('share_url', 'https://share.free-hub.cn')
    
    html_template = '''
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="UTF-8">
        <title>Share 登录 - Free Hub</title>
        <style nonce="{{ nonce }}">
            body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; display: flex; justify-content: center; align-items: center; min-height: 100vh; margin: 0; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); }
            .container { background: white; padding: 2rem; border-radius: 16px; box-shadow: 0 10px 40px rgba(0,0,0,0.2); text-align: center; max-width: 400px; }
            .status { margin: 1rem 0; padding: 0.5rem; border-radius: 8px; }
            .success { background: #d4edda; color: #155724; }
            .error { background: #f8d7da; color: #721c24; }
            .loading { background: #e2e3e5; color: #383d41; }
            button { background: #667eea; color: white; border: none; padding: 10px 20px; border-radius: 8px; cursor: pointer; margin-top: 1rem; }
            button:hover { background: #5a67d8; }
            a { color: #667eea; text-decoration: none; }
        </style>
    </head>
    <body>
        <div class="container">
            <h2>📁 Share 登录授权</h2>
            <div id="status" class="status loading">正在检查登录状态...</div>
            <div id="info" style="font-size: 14px; color: #666;"></div>
        </div>
        <script nonce="{{ nonce }}">
            const SHARE_URL = '{{ share_url }}';
            async function checkLogin() {
                try {
                    const resp = await fetch('/user/api/auth/check', { credentials: 'same-origin' });
                    const data = await resp.json();
                    if (data.logged_in) {
                        const tokenResp = await fetch('/user/api/auth/token', {
                            method: 'POST',
                            headers: { 'Content-Type': 'application/json' },
                            credentials: 'same-origin',
                            body: JSON.stringify({ service: 'share', callback_url: SHARE_URL })
                        });
                        const tokenData = await tokenResp.json();
                        if (tokenData.success) {
                            showStatus('登录成功！正在跳转到 Share...', 'success');
                            window.location.href = SHARE_URL + '/api/auth/callback?token=' + tokenData.token;
                        } else {
                            showStatus('生成令牌失败: ' + (tokenData.error || '未知错误'), 'error');
                        }
                    } else {
                        showStatus('请先登录主站', 'error');
                        document.getElementById('info').innerHTML = '<a href="/user/login">前往登录</a> | <a href="/">返回首页</a>';
                    }
                } catch (err) {
                    showStatus('请求失败: ' + err.message, 'error');
                }
            }
            function showStatus(msg, type) {
                const statusDiv = document.getElementById('status');
                statusDiv.textContent = msg;
                statusDiv.className = 'status ' + type;
            }
            checkLogin();
        </script>
    </body>
    </html>
    '''
    
    return render_template_string(html_template, share_url=share_url, nonce=nonce)


@user_bp.route('/api/auth/check', methods=['GET'])
def check_auth_status():
    """检查当前登录状态"""
    try:
        if not current_user.is_authenticated:
            return jsonify({'success': True, 'logged_in': False})
        
        identity = get_current_identity()
        
        result = {
            'success': True,
            'logged_in': True,
            'user_id': current_user.id,
            'nickname': current_user.nickname,
            'email': current_user.email,
            'level': current_user.level
        }
        
        if identity and identity['type'] == 'uid':
            result['current_uid'] = {
                'uid': identity['uid'],
                'nickname': identity['nickname'],
                'level': identity['level']
            }
        
        return jsonify(result)
        
    except Exception as e:
        print(f"检查登录状态失败: {e}")
        return jsonify({'success': False, 'error': '检查失败'}), 500


# ========== 登录/注册/登出 ==========

@user_bp.route('/login', methods=['GET', 'POST'])
@anonymous_required
@require_csrf
def login():
    """用户登录"""
    if request.method == 'POST':
        account = request.form.get('account')
        client_hashed_pw = request.form.get('password')
        salt = request.form.get('salt')
        iterations = request.form.get('iterations')
        captcha_text = request.form.get('captcha')
        
        expected_captcha = session.get('captcha_expected', '')
        if not expected_captcha or captcha_text.lower() != expected_captcha.lower():
            return jsonify({'error': '验证码错误'})
        
        if account and client_hashed_pw and salt and iterations:
            user = user_bp.IDs.query.filter(
                (user_bp.IDs.nickname == account) | (user_bp.IDs.email == account)
            ).first()

            if user:
                if not user.pbkdf2_salt or not user.pbkdf2_iterations:
                    user.pbkdf2_salt, user.pbkdf2_iterations = pbkdf2_security.get_pbkdf2_params_for_new_user()
                    user_bp.db.session.commit()
                    return jsonify({'error': '账户安全升级，请刷新页面重新登录'})
                
                if user.pbkdf2_salt != salt or user.pbkdf2_iterations != int(iterations):
                    return jsonify({'error': '安全参数不匹配，请刷新页面重试'})
                
                if Password().verify_pw(client_hashed_pw, user.crypto_pw)[0]:
                    # 检查邮箱验证
                    if not user.email_verified:
                        existing_token = user_bp.EmailVerificationTokens.query.filter_by(
                            user_id=user.id, used=False
                        ).first()
                        
                        if not existing_token or existing_token.expires_at < datetime.now():
                            user_bp.EmailVerificationTokens.query.filter_by(
                                user_id=user.id, used=False
                            ).delete()
                            
                            verification_token = generate_reset_token()
                            expires_at = datetime.now() + timedelta(hours=24)
                            token_entry = user_bp.EmailVerificationTokens(
                                user_id=user.id,
                                token=verification_token,
                                email=user.email,
                                expires_at=expires_at,
                                used=False
                            )
                            user_bp.db.session.add(token_entry)
                            user_bp.db.session.commit()
                            
                            email_sender = EmailSender(user_bp.app, request.host_url, user_bp.url_prefix, user_bp.name)
                            email_sender.send_verification_email(user.email, verification_token, user.id)
                        
                        return jsonify({
                            'error': '邮箱未验证，请查收验证邮件完成验证后再登录',
                            'need_verify': True
                        }), 403
                    
                    session.clear()
                    session['user_id'] = user.id
                    session['nickname'] = user.nickname
                    session['role'] = 'user'
                    session['logged-in'] = True
                    login_user(user)
                    
                    user.last_login = datetime.now()
                    user_bp.db.session.commit()
                    
                    session.pop('captcha_expected', None)
                    
                    return jsonify({'success': '登录成功'})
                else:
                    return jsonify({'error': '用户名或密码错误'})
            else:
                return jsonify({'error': '用户不存在'})
        else:
            return jsonify({'error': '请填写完整信息'})
            
    return user_bp.renderTemplate('/base-files/login.html')


@user_bp.route('/register', methods=['GET', 'POST'])
@anonymous_required
@require_csrf
def register():
    """用户注册"""
    if request.method == 'POST':
        nickname = request.form.get('nickname')
        email = request.form.get('email')
        client_hashed_pw = request.form.get('password')
        salt = request.form.get('salt')
        iterations = request.form.get('iterations')
        captcha_text = request.form.get('captcha')
        
        expected_captcha = session.get('captcha_expected', '')
        if not expected_captcha or captcha_text.lower() != expected_captcha.lower():
            return jsonify({'error': '验证码错误'})
        
        if nickname and email and client_hashed_pw and salt and iterations:
            if not re.match(r'^[a-zA-Z0-9]{4,20}$', nickname):
                return jsonify({'error': '昵称只能包含字母和数字，长度4-20个字符'})
            
            if not re.match(r'^[^\s@]+@[^\s@]+\.[^\s@]+$', email):
                return jsonify({'error': '邮箱格式不正确'})
            
            if user_bp.IDs.query.filter_by(nickname=nickname).first():
                return jsonify({'error': '昵称已存在'})

            if user_bp.IDs.query.filter_by(email=email).first():
                return jsonify({'error': '邮箱已被注册'})

            session_key = get_session_key()
            temp_key = f"temp_{session_key}"
            if not pbkdf2_security.verify_temp_params(temp_key, salt, int(iterations)):
                return jsonify({'error': '安全参数无效，请刷新页面重试'})

            newuser = user_bp.IDs(
                nickname=nickname,
                email=email,
                crypto_pw=Password().hash_pw(client_hashed_pw),
                pbkdf2_salt=salt,
                pbkdf2_iterations=int(iterations),
                level=0,
                status=True,
                email_verified=False,
                created_at=datetime.now()
            )
            user_bp.db.session.add(newuser)
            user_bp.db.session.commit()

            send_verification_email(newuser)
            
            session.pop('captcha_expected', None)

            return jsonify({'success': '注册成功，请查收验证邮件完成邮箱验证'})
        else:
            return jsonify({'error': '请填写完整信息'})
            
    return user_bp.renderTemplate('/base-files/register.html')


@user_bp.route('/logout')
@login_required
def logout():
    """用户登出"""
    logout_user()
    session.clear()
    session['logged-in'] = False
    return redirect(url_for('index'))


# ========== 邮箱验证强制 ==========

@user_bp.route('/verify-reminder')
@login_required
def verify_reminder():
    """邮箱验证提醒页面"""
    user = current_user
    
    if user.email_verified:
        return redirect(url_for('user.profile'))
    
    has_valid_token = False
    token_record = user_bp.EmailVerificationTokens.query.filter_by(
        user_id=user.id, used=False
    ).first()
    
    if token_record and token_record.expires_at > datetime.now():
        has_valid_token = True
    else:
        user_bp.EmailVerificationTokens.query.filter_by(
            user_id=user.id, used=False
        ).delete()
        
        verification_token = generate_reset_token()
        expires_at = datetime.now() + timedelta(hours=24)
        new_token = user_bp.EmailVerificationTokens(
            user_id=user.id,
            token=verification_token,
            email=user.email,
            expires_at=expires_at,
            used=False
        )
        user_bp.db.session.add(new_token)
        user_bp.db.session.commit()
        
        try:
            email_sender = EmailSender(user_bp.app, request.host_url, user_bp.url_prefix, user_bp.name)
            email_sender.send_verification_email(user.email, verification_token, user.id)
        except Exception as e:
            print(f"发送验证邮件失败: {e}")
        
        has_valid_token = True
    
    last_send_time = session.get('last_verify_email_sent')
    
    return user_bp.renderTemplate(
        '/base-files/verify-reminder.html',
        email=user.email,
        has_valid_token=has_valid_token,
        last_send_time=last_send_time
    )


@user_bp.route('/resend-verification', methods=['POST'])
@login_required
def resend_verification():
    """重新发送验证邮件"""
    user = current_user
    
    last_send = session.get('last_verify_email_sent')
    if last_send:
        last_send_time = datetime.fromisoformat(last_send) if isinstance(last_send, str) else last_send
        if (datetime.now() - last_send_time).total_seconds() < 60:
            return jsonify({'error': '请等待60秒后再试'}), 429
    
    if user.email_verified:
        return jsonify({'error': '邮箱已验证'}), 400
    
    user_bp.EmailVerificationTokens.query.filter_by(
        user_id=user.id, used=False
    ).delete()
    
    verification_token = generate_reset_token()
    expires_at = datetime.now() + timedelta(hours=24)
    token_entry = user_bp.EmailVerificationTokens(
        user_id=user.id,
        token=verification_token,
        email=user.email,
        expires_at=expires_at,
        used=False
    )
    user_bp.db.session.add(token_entry)
    user_bp.db.session.commit()
    
    email_sender = EmailSender(user_bp.app, request.host_url, user_bp.url_prefix, user_bp.name)
    email_sender.send_verification_email(user.email, verification_token, user.id)
    
    session['last_verify_email_sent'] = datetime.now().isoformat()
    
    return jsonify({'success': '验证邮件已发送，请检查邮箱'})


@user_bp.route('/check-email-verified')
@login_required
def check_email_verified():
    """检查邮箱验证状态（用于前端轮询）"""
    user = current_user
    
    if user.__class__.__name__ == 'IDs':
        return jsonify({
            'verified': user.email_verified,
            'email': user.email
        })
    
    return jsonify({'verified': True})


@user_bp.route('/verify-email', methods=['GET'])
def verify_email():
    """验证邮箱"""
    token = request.args.get('token')
    user_id = request.args.get('user_id')
    
    print(f"验证邮箱 - token: {token}, user_id: {user_id}")
    
    if not token or not user_id:
        return user_bp.renderTemplate(
            '/base-files/email-verification-result.html', 
            success=False, 
            message='验证链接无效：缺少必要参数'
        )

    user = user_bp.IDs.query.get(user_id)
    if not user:
        return user_bp.renderTemplate(
            '/base-files/email-verification-result.html', 
            success=False, 
            message='用户不存在'
        )
    
    if user.email_verified:
        return user_bp.renderTemplate(
            '/base-files/email-verification-result.html', 
            success=True, 
            message='邮箱已验证'
        )

    verification_token = user_bp.EmailVerificationTokens.query.filter_by(
        token=token,
        user_id=user_id,
        used=False
    ).first()

    if not verification_token:
        return user_bp.renderTemplate(
            '/base-files/email-verification-result.html', 
            success=False, 
            message='验证链接无效或已使用'
        )

    if verification_token.expires_at < datetime.now():
        return user_bp.renderTemplate(
            '/base-files/email-verification-result.html', 
            success=False, 
            message='验证链接已过期'
        )

    if user.email != verification_token.email:
        return user_bp.renderTemplate(
            '/base-files/email-verification-result.html', 
            success=False, 
            message='邮箱不匹配'
        )
    
    user.email_verified = True
    verification_token.used = True
    
    try:
        user_bp.db.session.commit()
        return user_bp.renderTemplate(
            '/base-files/email-verification-result.html', 
            success=True, 
            message='邮箱验证成功！'
        )
    except Exception as e:
        user_bp.db.session.rollback()
        print(f"验证邮箱失败: {e}")
        return user_bp.renderTemplate(
            '/base-files/email-verification-result.html', 
            success=False, 
            message='验证失败，请重试'
        )


# ========== 邮箱恢复（假邮箱用户自救） ==========

import secrets
import re
from datetime import datetime, timedelta


def generate_verification_code(length=6):
    """生成纯数字验证码"""
    return ''.join([str(secrets.randbelow(10)) for _ in range(length)])


@user_bp.route('/account/recover', methods=['POST'])
def account_recover():
    """
    第一步：验证用户名+密码+假邮箱，向新邮箱发送验证码
    请求体: { nickname, password, fake_email, new_email }
    """
    data = request.get_json()
    
    nickname = data.get('nickname', '').strip()
    password = data.get('password', '')
    fake_email = data.get('fake_email', '').strip().lower()
    new_email = data.get('new_email', '').strip().lower()
    
    # 1. 参数校验
    if not all([nickname, password, fake_email, new_email]):
        return jsonify({'success': False, 'error': '请填写完整信息'}), 400
    
    # 2. 查找用户
    user = user_bp.IDs.query.filter_by(nickname=nickname).first()
    if not user:
        return jsonify({'success': False, 'error': '用户名不存在'}), 404
    
    # 3. 验证密码
    if not Password().verify_pw(password, user.crypto_pw)[0]:
        return jsonify({'success': False, 'error': '密码错误'}), 401
    
    # 4. 验证假邮箱（关键步骤）
    if user.email != fake_email:
        return jsonify({'success': False, 'error': '假邮箱不匹配'}), 401
    
    # 5. 检查是否已经是已验证邮箱（防止滥用）
    if user.email_verified:
        return jsonify({'success': False, 'error': '该账号邮箱已验证，请使用正常登录流程'}), 400
    
    # 6. 检查新邮箱格式
    if not re.match(r'^[^\s@]+@[^\s@]+\.[^\s@]+$', new_email):
        return jsonify({'success': False, 'error': '新邮箱格式不正确'}), 400
    
    # 7. 检查新邮箱是否已被其他账号占用
    existing_user = user_bp.IDs.query.filter(
        user_bp.IDs.email == new_email, 
        user_bp.IDs.id != user.id
    ).first()
    if existing_user:
        return jsonify({'success': False, 'error': '新邮箱已被其他账号使用'}), 409
    
    # 8. 检查是否有未过期的恢复请求（防刷）
    existing_request = user_bp.EmailRecoveryRequests.query.filter_by(
        user_id=user.id, 
        used=False
    ).filter(user_bp.EmailRecoveryRequests.expires_at > datetime.now()).first()
    
    if existing_request:
        return jsonify({
            'success': False, 
            'error': '已有进行中的恢复请求，请查收邮件或等待5分钟后重试'
        }), 429
    
    # 9. 生成验证码和令牌
    code = generate_verification_code()
    token = secrets.token_urlsafe(32)
    expires_at = datetime.now() + timedelta(minutes=5)
    
    # 10. 存储到数据库
    recovery_req = user_bp.EmailRecoveryRequests(
        token=token,
        user_id=user.id,
        old_email=fake_email,
        new_email=new_email,
        code=code,
        expires_at=expires_at,
        used=False
    )
    user_bp.db.session.add(recovery_req)
    
    # 11. 清理该用户过期的旧请求
    user_bp.EmailRecoveryRequests.query.filter(
        user_bp.EmailRecoveryRequests.user_id == user.id,
        user_bp.EmailRecoveryRequests.expires_at < datetime.now()
    ).delete()
    
    user_bp.db.session.commit()
    
    # 12. 发送验证码到新邮箱
    try:
        from utils.email_sender import EmailSender
        email_sender = EmailSender(user_bp.app, request.host_url, 'user', 'user')
        email_sender.send_verification_code(new_email, code, purpose='recover')
    except Exception as e:
        # 发送失败时回滚数据库记录
        user_bp.db.session.delete(recovery_req)
        user_bp.db.session.commit()
        print(f"发送验证码失败: {e}")
        return jsonify({'success': False, 'error': '验证码发送失败，请稍后重试'}), 500
    
    return jsonify({
        'success': True,
        'message': '验证码已发送到新邮箱',
        'token': token
    })


@user_bp.route('/account/recover/verify', methods=['POST'])
def account_recover_verify():
    """
    第二步：验证验证码，正式更新邮箱
    请求体: { token, code }
    """
    data = request.get_json()
    
    token = data.get('token', '')
    code = data.get('code', '').strip()
    
    if not token or not code:
        return jsonify({'success': False, 'error': '参数不完整'}), 400
    
    # 1. 查找恢复请求
    recovery_req = user_bp.EmailRecoveryRequests.query.filter_by(
        token=token,
        used=False
    ).first()
    
    if not recovery_req:
        return jsonify({'success': False, 'error': '请求已过期或无效，请重新发起'}), 400
    
    # 2. 检查是否过期
    if datetime.now() > recovery_req.expires_at:
        recovery_req.used = True
        user_bp.db.session.commit()
        return jsonify({'success': False, 'error': '验证码已过期，请重新发起'}), 400
    
    # 3. 验证验证码
    if recovery_req.code != code:
        return jsonify({'success': False, 'error': '验证码错误'}), 401
    
    # 4. 获取用户
    user = user_bp.IDs.query.get(recovery_req.user_id)
    if not user:
        return jsonify({'success': False, 'error': '用户不存在'}), 404
    
    # 5. 再次确认用户仍然处于未验证状态
    if user.email_verified:
        recovery_req.used = True
        user_bp.db.session.commit()
        return jsonify({'success': False, 'error': '该账号邮箱已验证，无需恢复'}), 400
    
    # 6. 检查新邮箱是否仍可用
    existing_user = user_bp.IDs.query.filter(
        user_bp.IDs.email == recovery_req.new_email, 
        user_bp.IDs.id != user.id
    ).first()
    if existing_user:
        recovery_req.used = True
        user_bp.db.session.commit()
        return jsonify({'success': False, 'error': '新邮箱已被其他账号使用，请重新发起'}), 409
    
    # 7. 更新用户邮箱
    old_email = user.email
    user.email = recovery_req.new_email
    user.email_verified = False
    
    # 8. 标记请求为已使用
    recovery_req.used = True
    user_bp.db.session.commit()
    
    # 9. 发送新验证邮件到新邮箱
    from utils.email_sender import generate_reset_token
    verification_token = generate_reset_token()
    
    token_entry = user_bp.EmailVerificationTokens(
        user_id=user.id,
        token=verification_token,
        email=recovery_req.new_email,
        expires_at=datetime.now() + timedelta(hours=24),
        used=False
    )
    user_bp.db.session.add(token_entry)
    user_bp.db.session.commit()
    
    try:
        from utils.email_sender import EmailSender
        email_sender = EmailSender(user_bp.app, request.host_url, 'user', 'user')
        email_sender.send_verification_email(recovery_req.new_email, verification_token, user.id)
    except Exception as e:
        print(f"发送新验证邮件失败: {e}")
    
    # 10. 可选：向旧邮箱发送通知（如果旧邮箱格式正确）
    if '@' in old_email and '.' in old_email:
        try:
            from utils.email_sender import EmailSender
            email_sender = EmailSender(user_bp.app, request.host_url, 'user', 'user')
            email_sender.send_email_change_notification(old_email, recovery_req.new_email)
        except Exception as e:
            print(f"发送通知邮件失败: {e}")
    
    return jsonify({
        'success': True,
        'message': '邮箱已更新！请查收新邮箱的验证邮件，验证成功后即可登录。'
    })
    

@user_bp.route('/account-recover')
def account_recover_page():
    """账号恢复页面"""
    return user_bp.renderTemplate('/base-files/account-recover.html')
    

# ========== 个人资料 ==========

@user_bp.route('/profile')
@login_required
@require_main_account
@require_verified_email_web
def profile():
    """主账户个人资料"""
    user = current_user
    uids = user.uids
    return user_bp.renderTemplate('/base-files/profile.html', uids=uids)


@user_bp.route('/settings', methods=['GET', 'POST'])
@login_required
@require_verified_email_web
def settings():
    """用户设置页面"""
    if request.method == 'POST':
        try:
            identity = get_current_identity()
            if not identity:
                return jsonify({'error': '未登录'}), 401
            
            if identity['type'] == 'id':
                user = identity['object']
            else:
                user = identity['object']
            
            if request.is_json:
                data = request.get_json()
                
                if 'profileVisibility' in data:
                    user.profile_visibility = data['profileVisibility']
                if 'onlineStatus' in data:
                    user.online_status = bool(data['onlineStatus'])
                if 'activityFeed' in data:
                    user.activity_feed = bool(data['activityFeed'])
                if 'dataCollection' in data:
                    user.data_collection = bool(data['dataCollection'])
                if 'language' in data:
                    user.language = data['language']
                if 'timezone' in data:
                    user.timezone = data['timezone']
                if 'dateFormat' in data:
                    user.date_format = data['dateFormat']
                if 'font_size' in data:
                    user.font_size = data['font_size']
                
                user_bp.db.session.commit()
                return jsonify({'success': True, 'message': '设置已保存'})
            else:
                nickname = request.form.get('nickname')
                email = request.form.get('email')
                bio = request.form.get('bio')
                
                if identity['type'] == 'id':
                    if nickname and nickname != user.nickname:
                        if user_bp.IDs.query.filter_by(nickname=nickname).first():
                            return jsonify({'success': False, 'error': '昵称已存在'})
                        user.nickname = nickname
                    
                    if email and email != user.email:
                        if user_bp.IDs.query.filter_by(email=email).first():
                            return jsonify({'success': False, 'error': '邮箱已被使用'})
                        user.email = email
                        user.email_verified = False
                else:
                    if bio is not None:
                        user.bio = bio
                
                if bio is not None:
                    user.bio = bio
                
                user_bp.db.session.commit()
                
                if identity['type'] == 'id':
                    session['nickname'] = user.nickname
                
                return jsonify({'success': True, 'message': '个人资料已更新'})
                
        except Exception as e:
            user_bp.db.session.rollback()
            print(f"保存设置失败: {e}")
            return jsonify({'success': False, 'error': f'保存失败: {str(e)}'}), 500
    
    identity = get_current_identity()
    if not identity:
        return redirect(url_for('user.login'))
    
    if identity['type'] == 'id':
        user = identity['object']
    else:
        user = identity['object']
    
    settings_data = {
        'nickname': user.nickname or '',
        'email': getattr(user, 'email', '') if identity['type'] == 'id' else '',
        'bio': getattr(user, 'bio', '') or '',
        'profile_visibility': getattr(user, 'profile_visibility', 'public') or 'public',
        'online_status': bool(getattr(user, 'online_status', True)),
        'activity_feed': bool(getattr(user, 'activity_feed', True)),
        'data_collection': bool(getattr(user, 'data_collection', False)),
        'language': getattr(user, 'language', 'zh-CN') or 'zh-CN',
        'timezone': getattr(user, 'timezone', 'UTC+8') or 'UTC+8',
        'date_format': getattr(user, 'date_format', 'Y-m-d') or 'Y-m-d',
        'font_size': getattr(user, 'font_size', 'medium') or 'medium',
        'is_main_account': identity['type'] == 'id'
    }
    
    return user_bp.renderTemplate(
        '/base-files/settings.html',
        settings=settings_data,
        identity=identity
    )


@user_bp.route('/change-password', methods=['GET', 'POST'])
@login_required
def change_password():
    """修改密码"""
    if request.method == 'POST':
        old_password = request.form.get('oldPassword')
        new_password = request.form.get('newPassword')
        salt = request.form.get('salt')
        iterations = request.form.get('iterations')
        captcha_text = request.form.get('captcha')

        expected_captcha = session.get('captcha_expected', '')
        if not expected_captcha or captcha_text.lower() != expected_captcha.lower():
            return jsonify({'error': '验证码错误'})
        
        identity = get_current_identity()
        if not identity:
            return jsonify({'error': '未登录'}), 401
        
        user = identity['object']
        
        if not user.pbkdf2_salt or not user.pbkdf2_iterations:
            return jsonify({'error': '用户安全参数异常'})
        
        if user.pbkdf2_salt != salt or user.pbkdf2_iterations != int(iterations):
            return jsonify({'error': '安全参数不匹配'})
        
        if not Password().verify_pw(old_password, user.crypto_pw)[0]:
            return jsonify({'error': '旧密码错误'})
        
        user.crypto_pw = Password().hash_pw(new_password)
        user_bp.db.session.commit()
        
        session.pop('captcha_expected', None)

        return jsonify({'success': '密码修改成功'})

    return user_bp.renderTemplate('/base-files/change-password.html')


# ========== UID资料查看 ==========

@user_bp.route('/uid-profile')
def uid_profile():
    """查看UID个人资料页面（公开访问）"""
    target_uid = request.args.get('uid')
    
    if not target_uid:
        current_uid = session.get('current_uid')
        if current_uid:
            target_uid = current_uid
        else:
            return redirect(url_for('user.login'))
    
    try:
        target_uid = int(target_uid)
    except (TypeError, ValueError):
        return user_bp.renderTemplate('/system-files/400.html'), 400
    
    uid_record = user_bp.UIDs.query.get(target_uid)
    if not uid_record or not uid_record.status:
        return user_bp.renderTemplate('/system-files/404.html'), 404
    
    if uid_record.profile_visibility == 'private':
        current_uid = session.get('current_uid')
        if not current_uid or current_uid != target_uid:
            return user_bp.renderTemplate('/system-files/403.html'), 403
    
    posts_count = user_bp.Posts.query.filter_by(author_id=target_uid, is_deleted=False).count()
    articles_count = user_bp.Articles.query.filter_by(author_id=target_uid, is_deleted=False).count()
    uploads_count = user_bp.Uploads.query.filter_by(uid=target_uid, is_deleted=False, is_public=True).count()
    likes_count = user_bp.Likes.query.filter_by(uid=target_uid).count()
    favorites_count = user_bp.Favorites.query.filter_by(uid=target_uid).count()
    
    recent_posts = user_bp.Posts.query.filter_by(
        author_id=target_uid, is_deleted=False
    ).order_by(user_bp.Posts.created_at.desc()).limit(5).all()
    
    recent_articles = user_bp.Articles.query.filter_by(
        author_id=target_uid, is_deleted=False
    ).order_by(user_bp.Articles.time.desc()).limit(5).all()
    
    recent_uploads = user_bp.Uploads.query.filter_by(
        uid=target_uid, is_deleted=False, is_public=True
    ).order_by(user_bp.Uploads.created_at.desc()).limit(5).all()
    
    recent_likes = user_bp.Likes.query.filter_by(
        uid=target_uid
    ).order_by(user_bp.Likes.created_at.desc()).limit(10).all()
    
    recent_favorites = user_bp.Favorites.query.filter_by(
        uid=target_uid
    ).order_by(user_bp.Favorites.created_at.desc()).limit(10).all()
    
    is_following = False
    current_uid = session.get('current_uid')
    if current_uid:
        is_following = user_bp.Follows.query.filter_by(
            follower_uid=current_uid,
            following_uid=target_uid
        ).first() is not None
    
    has_uid_avatar = False
    if uid_record.nickname:
        has_uid_avatar = check_uid_avatar(uid_record.nickname)
    
    return user_bp.renderTemplate(
        '/base-files/uid-profile.html',
        uid=uid_record,
        stats={
            'posts': posts_count,
            'articles': articles_count,
            'uploads': uploads_count,
            'likes': likes_count,
            'favorites': favorites_count,
            'followers': uid_record.followers_count,
            'following': uid_record.following_count
        },
        recent_posts=recent_posts,
        recent_articles=recent_articles,
        recent_uploads=recent_uploads,
        recent_likes=recent_likes,
        recent_favorites=recent_favorites,
        is_following=is_following,
        is_owner=(current_uid == target_uid) if current_uid else False,
        has_uid_avatar=has_uid_avatar
    )


def check_uid_avatar(nickname):
    """检查UID头像是否存在"""
    try:
        from utils.utils import sanitize_filename
        safe_nickname = sanitize_filename(nickname)
        if not safe_nickname:
            return False
            
        static_folder = user_bp.app.static_folder
        avatar_path = os.path.join(
            static_folder, 
            'img', 'upload', 'avatar', 'UIDs', 
            f'{safe_nickname}.png'
        )
        
        expected_dir = os.path.join(static_folder, 'img', 'upload', 'avatar', 'UIDs')
        if not os.path.normpath(avatar_path).startswith(os.path.normpath(expected_dir) + os.sep):
            return False
            
        return os.path.exists(avatar_path)
    except:
        return False


# ========== 致谢系统管理（仅开发者 ID=3） ==========

@user_bp.route('/thanks/admin')
@login_required
@developer_required
def thanks_admin():
    """致谢管理页面（仅开发者可见）"""
    return user_bp.renderTemplate('/base-files/thanks-admin.html')


# ========== 子账户管理 ==========

@user_bp.route('/link-uid', methods=['GET', 'POST'])
@login_required
@require_main_account
@require_verified_email_web
def link_uid():
    """管理子账户"""
    if request.method == 'POST':
        try:
            # 注册新UID（创建子账户）
            if request.args.get('register') == 'true':
                data = request.get_json()
                nickname = data.get('nickname')
                hashed_password = data.get('password')
                bio = data.get('bio', '')
                salt = data.get('salt')
                iterations = data.get('iterations')
                
                if not nickname or not hashed_password:
                    return jsonify({'error': '昵称和密码不能为空'})
                
                if len(nickname) < 2 or len(nickname) > 15:
                    return jsonify({'error': '昵称长度必须在2-15个字符之间'})
                
                if not re.match(r'^[a-zA-Z0-9]{2,15}$', nickname):
                    return jsonify({'error': '昵称只能包含字母和数字'})
                
                existing = user_bp.UIDs.query.filter_by(nickname=nickname).first()
                if existing:
                    return jsonify({'error': '该昵称已被使用'})
                
                new_uid = user_bp.UIDs(
                    crypto_pw=Password().hash_pw(hashed_password),
                    nickname=nickname,
                    level=1,
                    status=True,
                    points=0,
                    id=current_user.id,
                    bio=bio,
                    pbkdf2_salt=salt,
                    pbkdf2_iterations=iterations,
                    created_at=datetime.now(),
                    report_count=0,
                    is_banned=False
                )
                
                user_bp.db.session.add(new_uid)
                user_bp.db.session.commit()
                
                return jsonify({'success': '子账户创建成功'})
            
            # 删除UID
            elif request.args.get('delete') == 'true':
                data = request.get_json()
                uid_to_delete = data.get('uid')
                
                uid_record = user_bp.UIDs.query.filter_by(
                    uid=uid_to_delete,
                    id=current_user.id
                ).first()
                
                if not uid_record:
                    return jsonify({'error': '未找到该子账户记录'})
                
                user_uid_count = user_bp.UIDs.query.filter_by(id=current_user.id).count()
                if user_uid_count <= 1:
                    return jsonify({'error': '至少需要保留一个子账户'})
                
                user_bp.db.session.delete(uid_record)
                user_bp.db.session.commit()
                
                return jsonify({'success': '子账户删除成功'})
            
            # 登录到UID（切换到子账户）
            elif request.args.get('login') == 'true':
                data = request.get_json()
                uid_to_login = data.get('uid')
                
                uid_record = user_bp.UIDs.query.filter_by(
                    uid=uid_to_login,
                    id=current_user.id
                ).first()
                
                if not uid_record:
                    return jsonify({'error': '未找到该子账户记录'})
                
                if not uid_record.status:
                    return jsonify({'error': '该子账户已被禁用'})
                
                session['current_uid'] = uid_record.uid
                session['current_uid_nickname'] = uid_record.nickname
                
                return jsonify({'success': f'已切换到子账户: {uid_record.nickname}'})
            
            else:
                return jsonify({'error': '参数错误'})
                
        except Exception as e:
            user_bp.db.session.rollback()
            print(f"子账户操作失败: {e}")
            return jsonify({'error': '操作失败，请稍后重试'})
    
    user = current_user 
    uids = user.uids
    return user_bp.renderTemplate('/base-files/link-uid.html', uids=uids)


@user_bp.route('/switch-to-main')
@login_required
def switch_to_main():
    """切换回主账户"""
    session.pop('current_uid', None)
    session.pop('current_uid_nickname', None)
    return redirect(url_for('user.profile'))


# ========== 帖子相关路由 ==========

@user_bp.route('/posts', methods=['GET'])
def list_posts():
    """获取帖子列表（API + 页面渲染）"""
    if request.headers.get('X-Requested-With') == 'XMLHttpRequest' or request.args.get('format') == 'json':
        page = request.args.get('page', 1, type=int)
        per_page = request.args.get('per_page', 10, type=int)
        sort = request.args.get('sort', 'latest')
        search = request.args.get('q', '')
        
        query = user_bp.Posts.query.filter_by(is_deleted=False)
        
        if search:
            query = query.filter(
                (user_bp.Posts.title.contains(search)) |
                (user_bp.Posts.content.contains(search))
            )
        
        if sort == 'popular':
            query = query.order_by(user_bp.Posts.views.desc())
        elif sort == 'most_viewed':
            query = query.order_by(user_bp.Posts.views.desc())
        else:
            query = query.order_by(user_bp.Posts.created_at.desc())
        
        posts = query.paginate(page=page, per_page=per_page, error_out=False)
        
        posts_data = []
        for post in posts.items:
            uid = user_bp.UIDs.query.get(post.author_id)
            if uid:
                likes_count = user_bp.Likes.query.filter_by(
                    target_type='post',
                    target_id=post.id
                ).count()
                
                liked = False
                current_uid = session.get('current_uid')
                if current_uid:
                    liked = user_bp.Likes.query.filter_by(
                        uid=current_uid,
                        target_type='post',
                        target_id=post.id
                    ).first() is not None
                
                posts_data.append({
                    'id': post.id,
                    'title': post.title,
                    'content': post.content[:200] + '...' if post.content and len(post.content) > 200 else post.content,
                    'created_at': post.created_at.isoformat(),
                    'views': post.views,
                    'likes': likes_count,
                    'author': {
                        'uid': uid.uid,
                        'nickname': uid.nickname,
                        'level': uid.level,
                        'bio': uid.bio
                    },
                    'liked': liked
                })
        
        return jsonify({
            'success': True,
            'data': posts_data,
            'total': posts.total,
            'page': page,
            'per_page': per_page,
            'has_next': posts.has_next,
            'has_prev': posts.has_prev
        })
    
    return user_bp.renderTemplate('/base-files/posts.html')


@user_bp.route('/api/posts')
def list_posts_api():
    """获取帖子列表（API）"""
    author = request.args.get('author')
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 10, type=int)
    sort = request.args.get('sort', 'latest')
    search = request.args.get('q', '')

    query = user_bp.Posts.query.filter_by(is_deleted=False)
    
    if search:
        query = query.filter(
            (user_bp.Posts.title.contains(search)) |
            (user_bp.Posts.content.contains(search))
        )
    
    if author:
        query = query.filter_by(author_id=author)

    if sort == 'popular':
        query = query.order_by(user_bp.Posts.views.desc())
    elif sort == 'most_viewed':
        query = query.order_by(user_bp.Posts.views.desc())
    else:
        query = query.order_by(user_bp.Posts.created_at.desc())
    
    posts = query.paginate(page=page, per_page=per_page, error_out=False)

    posts_data = []
    for post in posts.items:
        uid = user_bp.UIDs.query.get(post.author_id)
        if uid:
            likes_count = user_bp.Likes.query.filter_by(
                target_type='post',
                target_id=post.id
            ).count()
            
            posts_data.append({
                'id': post.id,
                'title': post.title,
                'content': post.content[:200] + '...' if post.content and len(post.content) > 200 else post.content,
                'created_at': post.created_at.isoformat(),
                'views': post.views,
                'likes': likes_count,
                'author': {
                    'uid': uid.uid,
                    'nickname': uid.nickname,
                    'level': uid.level,
                    'bio': uid.bio
                }
            })
    
    return jsonify({
        'success': True,
        'data': posts_data,
        'total': posts.total,
        'page': page,
        'per_page': per_page,
        'has_next': posts.has_next,
        'has_prev': posts.has_prev,
    })


@user_bp.route('/post/<int:post_id>', methods=['GET'])
def view_post(post_id):
    """查看单个帖子"""
    post = user_bp.Posts.query.filter_by(id=post_id, is_deleted=False).first()
    if not post:
        return user_bp.renderTemplate('/system-files/404.html'), 404
    
    post.views += 1
    user_bp.db.session.commit()
    
    uid = user_bp.UIDs.query.get(post.author_id)
    if not uid:
        return user_bp.renderTemplate('/system-files/404.html'), 404
    
    likes_count = user_bp.Likes.query.filter_by(
        target_type='post',
        target_id=post.id
    ).count()
    
    favorites_count = user_bp.Favorites.query.filter_by(
        target_type='post',
        target_id=post.id
    ).count()
    
    liked = False
    favorited = False
    current_uid = session.get('current_uid')
    if current_uid:
        liked = user_bp.Likes.query.filter_by(
            uid=current_uid,
            target_type='post',
            target_id=post.id
        ).first() is not None
        
        favorited = user_bp.Favorites.query.filter_by(
            uid=current_uid,
            target_type='post',
            target_id=post.id
        ).first() is not None
    
    post_data = {
        'id': post.id,
        'title': post.title,
        'content': post.content,
        'created_at': post.created_at,
        'updated_at': post.updated_at,
        'views': post.views,
        'likes': likes_count,
        'favorites': favorites_count,
        'author': {
            'uid': uid.uid,
            'nickname': uid.nickname,
            'level': uid.level,
            'bio': uid.bio,
            'avatar': None
        },
        'liked': liked,
        'favorited': favorited
    }
    
    return user_bp.renderTemplate('/base-files/post.html', post=post_data)


@user_bp.route('/post/create', methods=['GET', 'POST'])
@login_required
@require_uid_only
@check_ban
def create_post(uid_record):
    """创建新帖子"""
    if request.method == 'GET':
        identity = {
            'type': 'uid',
            'uid': uid_record.uid,
            'nickname': uid_record.nickname,
            'level': uid_record.level
        }
        return user_bp.renderTemplate(
            '/base-files/create-post.html', 
            uid=uid_record,
            identity=identity
        )
    
    try:
        data = request.get_json() if request.is_json else request.form
        title = data.get('title', '').strip()
        content = data.get('content', '').strip()
        
        if not title or not content:
            return jsonify({'error': '标题和内容不能为空'})
        
        if len(title) > 100:
            return jsonify({'error': '标题不能超过100个字符'})
        
        if len(content) > 50000:
            return jsonify({'error': '内容不能超过50000个字符'})
        
        if ContentFilter.contains_js(content):
            print(f"[XSS ATTEMPT] User: {uid_record.uid} 尝试在帖子中注入JS")
            content = ContentFilter.sanitize_post_content(content)
        else:
            content = ContentFilter.sanitize_post_content(content)
        
        title = ContentFilter.sanitize_text_only(title)
        
        new_post = user_bp.Posts(
            author_id=uid_record.uid,
            title=title,
            content=content,
            created_at=datetime.now(),
            updated_at=datetime.now()
        )
        
        user_bp.db.session.add(new_post)
        uid_record.posts_count += 1
        user_bp.db.session.commit()
        
        return jsonify({
            'success': True,
            'message': '帖子发布成功',
            'post_id': new_post.id
        })
        
    except Exception as e:
        user_bp.db.session.rollback()
        print(f"创建帖子失败: {e}")
        return jsonify({'error': '发布失败，请稍后重试'}), 500


@user_bp.route('/post/<int:post_id>/edit', methods=['GET', 'POST'])
@login_required
@require_post_author
def edit_post(post_id, post, uid_record):
    """编辑帖子"""
    if request.method == 'GET':
        return user_bp.renderTemplate('/base-files/edit-post.html', post=post, uid=uid_record)
    
    try:
        data = request.get_json() if request.is_json else request.form
        title = data.get('title', '').strip()
        content = data.get('content', '').strip()
        
        if not title or not content:
            return jsonify({'error': '标题和内容不能为空'})
        
        if ContentFilter.contains_js(content):
            print(f"[XSS ATTEMPT] User: {uid_record.uid} 尝试在编辑帖子时注入JS")
            content = ContentFilter.sanitize_post_content(content)
        else:
            content = ContentFilter.sanitize_post_content(content)
        
        title = ContentFilter.sanitize_text_only(title)
        
        post.title = title
        post.content = content
        post.updated_at = datetime.now()
        
        user_bp.db.session.commit()
        
        return jsonify({
            'success': True,
            'message': '帖子更新成功'
        })
        
    except Exception as e:
        user_bp.db.session.rollback()
        print(f"编辑帖子失败: {e}")
        return jsonify({'error': '更新失败，请稍后重试'}), 500


@user_bp.route('/post/<int:post_id>/delete', methods=['POST'])
@login_required
@require_post_author
def delete_post(post_id, post, uid_record):
    """删除帖子"""
    try:
        post.is_deleted = True
        post.deleted_at = datetime.now()
        
        uid_record.posts_count -= 1
        user_bp.db.session.commit()
        
        return jsonify({
            'success': True,
            'message': '帖子已删除'
        })
        
    except Exception as e:
        user_bp.db.session.rollback()
        print(f"删除帖子失败: {e}")
        return jsonify({'error': '删除失败，请稍后重试'}), 500


# ========== 文章相关路由 ==========

@user_bp.route('/articles', methods=['GET'])
def list_articles():
    """获取文章列表（API + 页面渲染）"""
    if request.headers.get('X-Requested-With') == 'XMLHttpRequest' or request.args.get('format') == 'json':
        page = request.args.get('page', 1, type=int)
        per_page = request.args.get('per_page', 10, type=int)
        sort = request.args.get('sort', 'latest')
        search = request.args.get('q', '')
        
        query = user_bp.Articles.query.filter_by(is_deleted=False)
        
        if search:
            query = query.filter(
                (user_bp.Articles.title.contains(search)) |
                (user_bp.Articles.content.contains(search))
            )
        
        if sort == 'popular':
            query = query.order_by(user_bp.Articles.views.desc())
        elif sort == 'most_viewed':
            query = query.order_by(user_bp.Articles.views.desc())
        else:
            query = query.order_by(user_bp.Articles.time.desc())
        
        articles = query.paginate(page=page, per_page=per_page, error_out=False)
        
        articles_data = []
        for article in articles.items:
            uid = user_bp.UIDs.query.get(article.author_id)
            if uid:
                likes_count = user_bp.Likes.query.filter_by(
                    target_type='article',
                    target_id=article.arid
                ).count()
                
                liked = False
                current_uid = session.get('current_uid')
                if current_uid:
                    liked = user_bp.Likes.query.filter_by(
                        uid=current_uid,
                        target_type='article',
                        target_id=article.arid
                    ).first() is not None
                
                articles_data.append({
                    'arid': article.arid,
                    'title': article.title,
                    'content': article.content[:200] + '...' if article.content and len(article.content) > 200 else article.content,
                    'time': article.time.isoformat(),
                    'views': article.views,
                    'likes': likes_count,
                    'author': {
                        'uid': uid.uid,
                        'nickname': uid.nickname,
                        'level': uid.level,
                        'bio': uid.bio
                    },
                    'comment_count': len([c for c in article.comments if not c.is_deleted]),
                    'liked': liked
                })
        
        return jsonify({
            'success': True,
            'data': articles_data,
            'total': articles.total,
            'page': page,
            'per_page': per_page,
            'has_next': articles.has_next,
            'has_prev': articles.has_prev
        })
    
    return user_bp.renderTemplate('/base-files/articles.html')


@user_bp.route('/api/articles')
def list_articles_api():
    """获取文章列表（API）"""
    author = request.args.get('author')
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 10, type=int)
    sort = request.args.get('sort', 'latest')
    search = request.args.get('q', '')

    query = user_bp.Articles.query.filter_by(is_deleted=False)
    
    if search:
        query = query.filter(
            (user_bp.Articles.title.contains(search)) |
            (user_bp.Articles.content.contains(search))
        )
    
    if author:
        query = query.filter_by(author_id=author)

    if sort == 'popular':
        query = query.order_by(user_bp.Articles.views.desc())
    elif sort == 'most_viewed':
        query = query.order_by(user_bp.Articles.views.desc())
    else:
        query = query.order_by(user_bp.Articles.time.desc())
    
    articles = query.paginate(page=page, per_page=per_page, error_out=False)

    articles_data = []
    for article in articles.items:
        uid = user_bp.UIDs.query.get(article.author_id)
        if uid:
            likes_count = user_bp.Likes.query.filter_by(
                target_type='article',
                target_id=article.arid
            ).count()
            
            articles_data.append({
                'arid': article.arid,
                'title': article.title,
                'content': article.content[:200] + '...' if article.content and len(article.content) > 200 else article.content,
                'time': article.time.isoformat(),
                'views': article.views,
                'likes': likes_count,
                'author': {
                    'uid': uid.uid,
                    'nickname': uid.nickname,
                    'level': uid.level,
                    'bio': uid.bio
                },
                'comment_count': len([c for c in article.comments if not c.is_deleted])
            })
    
    return jsonify({
        'success': True,
        'data': articles_data,
        'total': articles.total,
        'page': page,
        'per_page': per_page,
        'has_next': articles.has_next,
        'has_pre': articles.has_prev,
    })


@user_bp.route('/article/<int:arid>', methods=['GET'])
def view_article(arid):
    """查看文章详情"""
    article = user_bp.Articles.query.filter_by(arid=arid, is_deleted=False).first()
    if not article:
        return user_bp.renderTemplate('/system-files/404.html'), 404
    
    article.views += 1
    user_bp.db.session.commit()
    
    uid = user_bp.UIDs.query.get(article.author_id)
    if not uid:
        return user_bp.renderTemplate('/system-files/404.html'), 404
    
    likes_count = user_bp.Likes.query.filter_by(
        target_type='article',
        target_id=arid
    ).count()
    
    favorites_count = user_bp.Favorites.query.filter_by(
        target_type='article',
        target_id=arid
    ).count()
    
    comments = []
    for comment in article.comments:
        if not comment.is_deleted:
            comment_uid = user_bp.UIDs.query.get(comment.author_id)
            comments.append({
                'id': comment.id,
                'content': comment.content,
                'time': comment.time.strftime('%Y-%m-%d %H:%M'),
                'author': {
                    'uid': comment_uid.uid if comment_uid else None,
                    'nickname': comment_uid.nickname if comment_uid else '已注销',
                    'avatar': None
                }
            })
    
    liked = False
    favorited = False
    current_uid = session.get('current_uid')
    if current_uid:
        liked = user_bp.Likes.query.filter_by(
            uid=current_uid,
            target_type='article',
            target_id=article.arid
        ).first() is not None
        
        favorited = user_bp.Favorites.query.filter_by(
            uid=current_uid,
            target_type='article',
            target_id=article.arid
        ).first() is not None
    
    article_data = {
        'arid': article.arid,
        'title': article.title,
        'content': article.content,
        'time': article.time,
        'views': article.views,
        'likes': likes_count,
        'favorites': favorites_count,
        'author': {
            'uid': uid.uid,
            'nickname': uid.nickname,
            'level': uid.level,
            'bio': uid.bio,
            'avatar': None
        },
        'comments': comments,
        'liked': liked,
        'favorited': favorited
    }
    
    return user_bp.renderTemplate('/base-files/article.html', article=article_data)


@user_bp.route('/article/create', methods=['GET', 'POST'])
@login_required
@require_uid_only
@check_ban
def create_article(uid_record):
    """创建文章"""
    if request.method == 'GET':
        return user_bp.renderTemplate('/base-files/create-article.html', uid=uid_record)
    
    try:
        data = request.get_json() if request.is_json else request.form
        title = data.get('title', '').strip()
        content = data.get('content', '').strip()
        
        if not title or not content:
            return jsonify({'error': '标题和内容不能为空'})
        
        if ContentFilter.contains_js(content):
            print(f"[XSS ATTEMPT] User: {uid_record.uid} 尝试在文章中注入JS")
            content = ContentFilter.sanitize_post_content(content)
        else:
            content = ContentFilter.sanitize_post_content(content)
        
        title = ContentFilter.sanitize_text_only(title)
        
        new_article = user_bp.Articles(
            title=title,
            content=content,
            time=datetime.now(),
            author_id=uid_record.uid
        )
        
        user_bp.db.session.add(new_article)
        uid_record.articles_count += 1
        user_bp.db.session.commit()
        
        return jsonify({
            'success': True,
            'message': '文章发布成功',
            'arid': new_article.arid
        })
        
    except Exception as e:
        user_bp.db.session.rollback()
        print(f"创建文章失败: {e}")
        return jsonify({'error': '发布失败，请稍后重试'}), 500


@user_bp.route('/article/<int:arid>/edit', methods=['GET', 'POST'])
@login_required
@require_article_author
def edit_article(arid, article, uid_record):
    """编辑文章"""
    if request.method == 'GET':
        return user_bp.renderTemplate('/base-files/edit-article.html', article=article, uid=uid_record)
    
    try:
        data = request.get_json() if request.is_json else request.form
        title = data.get('title', '').strip()
        content = data.get('content', '').strip()
        
        if not title or not content:
            return jsonify({'error': '标题和内容不能为空'})
        
        article.title = title
        article.content = content
        article.time = datetime.now()
        
        user_bp.db.session.commit()
        
        return jsonify({
            'success': True,
            'message': '文章更新成功'
        })
        
    except Exception as e:
        user_bp.db.session.rollback()
        print(f"编辑文章失败: {e}")
        return jsonify({'error': '更新失败，请稍后重试'}), 500


@user_bp.route('/article/<int:arid>/delete', methods=['POST'])
@login_required
@require_article_author
def delete_article(arid, article, uid_record):
    """删除文章"""
    try:
        article.is_deleted = True
        
        uid_record.articles_count -= 1
        user_bp.db.session.commit()
        
        return jsonify({
            'success': True,
            'message': '文章已删除'
        })
        
    except Exception as e:
        user_bp.db.session.rollback()
        print(f"删除文章失败: {e}")
        return jsonify({'error': '删除失败，请稍后重试'}), 500


# ========== 评论相关路由 ==========

@user_bp.route('/article/<int:arid>/comment', methods=['POST'])
@login_required
@require_uid_only
@check_ban
def add_comment(arid, uid_record):
    """添加评论"""
    try:
        article = user_bp.Articles.query.filter_by(arid=arid, is_deleted=False).first()
        if not article:
            return jsonify({'error': '文章不存在'}), 404
        
        data = request.get_json() if request.is_json else request.form
        content = data.get('content', '').strip()
        
        if not content:
            return jsonify({'error': '评论内容不能为空'})
        
        if len(content) > 1000:
            return jsonify({'error': '评论不能超过1000个字符'})
        
        content = ContentFilter.sanitize_text_only(content)
        
        new_comment = user_bp.Comments(
            content=content,
            time=datetime.now(),
            author_id=uid_record.uid,
            article_id=arid
        )
        
        user_bp.db.session.add(new_comment)
        user_bp.db.session.commit()
        
        return jsonify({
            'success': True,
            'message': '评论发布成功',
            'comment_id': new_comment.id,
            'comment': {
                'id': new_comment.id,
                'content': new_comment.content,
                'time': new_comment.time.strftime('%Y-%m-%d %H:%M'),
                'author': {
                    'uid': uid_record.uid,
                    'nickname': uid_record.nickname
                }
            }
        })
        
    except Exception as e:
        user_bp.db.session.rollback()
        print(f"添加评论失败: {e}")
        return jsonify({'error': '评论失败，请稍后重试'}), 500


@user_bp.route('/comment/<int:comment_id>/delete', methods=['POST'])
@login_required
@require_uid_only
def delete_comment(comment_id, uid_record):
    """删除评论"""
    try:
        comment = user_bp.Comments.query.get(comment_id)
        if not comment or comment.is_deleted:
            return jsonify({'error': '评论不存在'}), 404
        
        if comment.author_id != uid_record.uid:
            article = user_bp.Articles.query.get(comment.article_id)
            if not article or article.author_id != uid_record.uid:
                return jsonify({'error': '无权删除此评论'}), 403
        
        comment.is_deleted = True
        user_bp.db.session.commit()
        
        return jsonify({
            'success': True,
            'message': '评论已删除'
        })
        
    except Exception as e:
        user_bp.db.session.rollback()
        print(f"删除评论失败: {e}")
        return jsonify({'error': '删除失败'}), 500


# ========== 点赞相关路由 ==========

@user_bp.route('/like', methods=['POST'])
@login_required
@require_uid_only
def toggle_like(uid_record):
    """切换点赞状态"""
    try:
        data = request.get_json()
        target_type = data.get('target_type')
        target_id = data.get('target_id')
        
        if target_type not in ['post', 'article']:
            return jsonify({'error': '无效的目标类型'}), 400
        
        # 验证目标存在
        if target_type == 'post':
            target = user_bp.Posts.query.filter_by(id=target_id, is_deleted=False).first()
        else:
            target = user_bp.Articles.query.filter_by(arid=target_id, is_deleted=False).first()
        
        if not target:
            return jsonify({'error': '目标不存在'}), 404
        
        # 检查是否已点赞
        existing = user_bp.Likes.query.filter_by(
            uid=uid_record.uid,
            target_type=target_type,
            target_id=target_id
        ).first()
        
        if existing:
            # 取消点赞
            user_bp.db.session.delete(existing)
            liked = False
        else:
            # 添加点赞
            new_like = user_bp.Likes(
                uid=uid_record.uid,
                target_type=target_type,
                target_id=target_id,
                created_at=datetime.now()
            )
            user_bp.db.session.add(new_like)
            liked = True
        
        user_bp.db.session.commit()
        
        return jsonify({
            'success': True,
            'liked': liked,
            'message': '点赞成功' if liked else '已取消点赞'
        })
        
    except Exception as e:
        user_bp.db.session.rollback()
        print(f"点赞操作失败: {e}")
        return jsonify({'error': '操作失败'}), 500


@user_bp.route('/likes', methods=['GET'])
@login_required
@require_uid_only
def get_my_likes(uid_record):
    """获取我点赞的内容"""
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 20, type=int)
    target_type = request.args.get('type')  # 可选：post 或 article
    
    query = user_bp.Likes.query.filter_by(uid=uid_record.uid)
    
    if target_type:
        query = query.filter_by(target_type=target_type)
    
    likes = query.order_by(user_bp.Likes.created_at.desc())\
        .paginate(page=page, per_page=per_page, error_out=False)
    
    likes_data = []
    for like in likes.items:
        if like.target_type == 'post':
            post = user_bp.Posts.query.filter_by(id=like.target_id, is_deleted=False).first()
            if post:
                likes_data.append({
                    'id': like.id,
                    'type': 'post',
                    'target_id': post.id,
                    'title': post.title,
                    'content': post.content[:100],
                    'created_at': like.created_at.strftime('%Y-%m-%d %H:%M')
                })
        else:
            article = user_bp.Articles.query.filter_by(arid=like.target_id, is_deleted=False).first()
            if article:
                likes_data.append({
                    'id': like.id,
                    'type': 'article',
                    'target_id': article.arid,
                    'title': article.title,
                    'content': article.content[:100],
                    'created_at': like.created_at.strftime('%Y-%m-%d %H:%M')
                })
    
    return jsonify({
        'success': True,
        'data': likes_data,
        'total': likes.total,
        'page': page,
        'per_page': per_page
    })


# ========== 收藏相关路由 ==========

@user_bp.route('/favorite', methods=['POST'])
@login_required
@require_uid_only
def toggle_favorite(uid_record):
    """切换收藏状态"""
    try:
        data = request.get_json()
        target_type = data.get('target_type')
        target_id = data.get('target_id')
        
        if target_type not in ['post', 'article']:
            return jsonify({'error': '无效的目标类型'}), 400
        
        # 验证目标存在
        if target_type == 'post':
            target = user_bp.Posts.query.filter_by(id=target_id, is_deleted=False).first()
        else:
            target = user_bp.Articles.query.filter_by(arid=target_id, is_deleted=False).first()
        
        if not target:
            return jsonify({'error': '目标不存在'}), 404
        
        # 检查是否已收藏
        existing = user_bp.Favorites.query.filter_by(
            uid=uid_record.uid,
            target_type=target_type,
            target_id=target_id
        ).first()
        
        if existing:
            # 取消收藏
            user_bp.db.session.delete(existing)
            favorited = False
        else:
            # 添加收藏
            new_favorite = user_bp.Favorites(
                uid=uid_record.uid,
                target_type=target_type,
                target_id=target_id,
                created_at=datetime.now()
            )
            user_bp.db.session.add(new_favorite)
            favorited = True
        
        user_bp.db.session.commit()
        
        return jsonify({
            'success': True,
            'favorited': favorited,
            'message': '收藏成功' if favorited else '已取消收藏'
        })
        
    except Exception as e:
        user_bp.db.session.rollback()
        print(f"收藏操作失败: {e}")
        return jsonify({'error': '操作失败'}), 500


@user_bp.route('/favorites', methods=['GET'])
@login_required
@require_uid_only
def get_my_favorites(uid_record):
    """获取我的收藏"""
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 20, type=int)
    target_type = request.args.get('type')
    
    query = user_bp.Favorites.query.filter_by(uid=uid_record.uid)
    
    if target_type:
        query = query.filter_by(target_type=target_type)
    
    favorites = query.order_by(user_bp.Favorites.created_at.desc())\
        .paginate(page=page, per_page=per_page, error_out=False)
    
    favorites_data = []
    for fav in favorites.items:
        if fav.target_type == 'post':
            post = user_bp.Posts.query.filter_by(id=fav.target_id, is_deleted=False).first()
            if post:
                favorites_data.append({
                    'id': fav.id,
                    'type': 'post',
                    'target_id': post.id,
                    'title': post.title,
                    'content': post.content[:100],
                    'created_at': fav.created_at.strftime('%Y-%m-%d %H:%M')
                })
        else:
            article = user_bp.Articles.query.filter_by(arid=fav.target_id, is_deleted=False).first()
            if article:
                favorites_data.append({
                    'id': fav.id,
                    'type': 'article',
                    'target_id': article.arid,
                    'title': article.title,
                    'content': article.content[:100],
                    'created_at': fav.created_at.strftime('%Y-%m-%d %H:%M')
                })
    
    return jsonify({
        'success': True,
        'data': favorites_data,
        'total': favorites.total,
        'page': page,
        'per_page': per_page
    })


# ========== 关注相关路由 ==========

@user_bp.route('/follow', methods=['POST'])
@login_required
@require_uid_only
def follow_user(uid_record):
    """关注/取消关注用户"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': '无效的请求数据'}), 400
        
        target_uid = data.get('uid')
        
        if not target_uid:
            return jsonify({'error': '参数错误'}), 400
        
        if target_uid == uid_record.uid:
            return jsonify({'error': '不能关注自己'}), 400
        
        target_user = user_bp.UIDs.query.get(target_uid)
        if not target_user or not target_user.status:
            return jsonify({'error': '用户不存在或已被禁用'}), 404
        
        # 检查是否已关注
        existing = user_bp.Follows.query.filter_by(
            follower_uid=uid_record.uid,
            following_uid=target_uid
        ).first()
        
        try:
            if existing:
                # 取消关注
                user_bp.db.session.delete(existing)
                uid_record.following_count = max(0, uid_record.following_count - 1)
                target_user.followers_count = max(0, target_user.followers_count - 1)
                following = False
                message = '已取消关注'
            else:
                # 添加关注
                new_follow = user_bp.Follows(
                    follower_uid=uid_record.uid,
                    following_uid=target_uid,
                    created_at=datetime.now()
                )
                user_bp.db.session.add(new_follow)
                uid_record.following_count += 1
                target_user.followers_count += 1
                following = True
                message = '关注成功'
            
            user_bp.db.session.commit()
            
            return jsonify({
                'success': True,
                'following': following,
                'message': message,
                'following_count': uid_record.following_count,
                'followers_count': target_user.followers_count
            })
            
        except Exception as e:
            user_bp.db.session.rollback()
            print(f"关注操作数据库错误: {e}")
            return jsonify({'error': '操作失败，请稍后重试'}), 500
            
    except Exception as e:
        print(f"关注操作错误: {e}")
        return jsonify({'error': '操作失败，请稍后重试'}), 500


@user_bp.route('/followers', methods=['GET'])
@login_required
@require_uid_only
def get_my_followers(uid_record):
    """获取我的粉丝"""
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 20, type=int)
    
    follows = user_bp.Follows.query.filter_by(following_uid=uid_record.uid)\
        .order_by(user_bp.Follows.created_at.desc())\
        .paginate(page=page, per_page=per_page, error_out=False)
    
    followers_data = []
    for follow in follows.items:
        follower = user_bp.UIDs.query.get(follow.follower_uid)
        if follower:
            followers_data.append({
                'uid': follower.uid,
                'nickname': follower.nickname,
                'level': follower.level,
                'bio': follower.bio,
                'followed_at': follow.created_at.strftime('%Y-%m-%d %H:%M'),
                'is_following': user_bp.Follows.query.filter_by(
                    follower_uid=uid_record.uid,
                    following_uid=follower.uid
                ).first() is not None
            })
    
    return jsonify({
        'success': True,
        'data': followers_data,
        'total': follows.total,
        'page': page,
        'per_page': per_page
    })


@user_bp.route('/following', methods=['GET'])
@login_required
@require_uid_only
def get_my_following(uid_record):
    """获取我的关注"""
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 20, type=int)
    
    follows = user_bp.Follows.query.filter_by(follower_uid=uid_record.uid)\
        .order_by(user_bp.Follows.created_at.desc())\
        .paginate(page=page, per_page=per_page, error_out=False)
    
    following_data = []
    for follow in follows.items:
        following = user_bp.UIDs.query.get(follow.following_uid)
        if following:
            following_data.append({
                'uid': following.uid,
                'nickname': following.nickname,
                'level': following.level,
                'bio': following.bio,
                'followed_at': follow.created_at.strftime('%Y-%m-%d %H:%M')
            })
    
    return jsonify({
        'success': True,
        'data': following_data,
        'total': follows.total,
        'page': page,
        'per_page': per_page
    })


@user_bp.route('/user/<int:target_uid>/followers', methods=['GET'])
def get_user_followers(target_uid):
    """获取指定用户的粉丝"""
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 20, type=int)
    
    target_user = user_bp.UIDs.query.get(target_uid)
    if not target_user:
        return jsonify({'error': '用户不存在'}), 404
    
    follows = user_bp.Follows.query.filter_by(following_uid=target_uid)\
        .order_by(user_bp.Follows.created_at.desc())\
        .paginate(page=page, per_page=per_page, error_out=False)
    
    followers_data = []
    current_uid = session.get('current_uid')
    
    for follow in follows.items:
        follower = user_bp.UIDs.query.get(follow.follower_uid)
        if follower:
            is_following = False
            if current_uid:
                is_following = user_bp.Follows.query.filter_by(
                    follower_uid=current_uid,
                    following_uid=follower.uid
                ).first() is not None
            
            followers_data.append({
                'uid': follower.uid,
                'nickname': follower.nickname,
                'level': follower.level,
                'bio': follower.bio,
                'followed_at': follow.created_at.strftime('%Y-%m-%d %H:%M'),
                'is_following': is_following
            })
    
    return jsonify({
        'success': True,
        'data': followers_data,
        'total': follows.total,
        'page': page,
        'per_page': per_page
    })


@user_bp.route('/user/<int:target_uid>/following', methods=['GET'])
def get_user_following(target_uid):
    """获取指定用户的关注"""
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 20, type=int)
    
    target_user = user_bp.UIDs.query.get(target_uid)
    if not target_user:
        return jsonify({'error': '用户不存在'}), 404
    
    follows = user_bp.Follows.query.filter_by(follower_uid=target_uid)\
        .order_by(user_bp.Follows.created_at.desc())\
        .paginate(page=page, per_page=per_page, error_out=False)
    
    following_data = []
    for follow in follows.items:
        following = user_bp.UIDs.query.get(follow.following_uid)
        if following:
            following_data.append({
                'uid': following.uid,
                'nickname': following.nickname,
                'level': following.level,
                'bio': following.bio,
                'followed_at': follow.created_at.strftime('%Y-%m-%d %H:%M')
            })
    
    return jsonify({
        'success': True,
        'data': following_data,
        'total': follows.total,
        'page': page,
        'per_page': per_page
    })


# ========== 私信系统 ==========

@user_bp.route('/messages')
@login_required
@require_uid_only
@check_ban
def messages_page(uid_record):
    """私信中心页面"""
    try:
        conversations = user_bp.Conversations.query.filter_by(
            user_uid=uid_record.uid
        ).order_by(
            user_bp.Conversations.updated_at.desc()
        ).all()
        
        conversation_list = []
        for conv in conversations:
            other = user_bp.UIDs.query.get(conv.other_uid)
            if other and other.status:
                last_msg = None
                if conv.last_message_id:
                    last_msg = user_bp.Messages.query.get(conv.last_message_id)
                
                conversation_list.append({
                    'conversation_id': conv.id,
                    'other_uid': other.uid,
                    'other_nickname': other.nickname,
                    'other_level': other.level,
                    'other_status': other.online_status,
                    'last_message': last_msg.content[:50] + '...' if last_msg and len(last_msg.content) > 50 else (last_msg.content if last_msg else ''),
                    'last_message_time': last_msg.created_at if last_msg else conv.updated_at,
                    'unread_count': conv.unread_count,
                    'is_read': last_msg.is_read if last_msg else True
                })
        
        return user_bp.renderTemplate(
            '/base-files/messages.html',
            uid=uid_record,
            conversations=conversation_list
        )
        
    except Exception as e:
        print(f"加载私信中心失败: {e}")
        return user_bp.renderTemplate('/system-files/500.html'), 500


@user_bp.route('/messages/<int:other_uid>')
@login_required
@require_uid_only
@check_ban
def message_detail(uid_record, other_uid):
    """私信详情页面"""
    try:
        other = user_bp.UIDs.query.get(other_uid)
        if not other or not other.status:
            return user_bp.renderTemplate('/system-files/404.html'), 404
        
        conversation = user_bp.Conversations.query.filter_by(
            user_uid=uid_record.uid,
            other_uid=other_uid
        ).first()
        
        # 标记该会话的所有消息为已读
        unread_messages = user_bp.Messages.query.filter_by(
            to_uid=uid_record.uid,
            from_uid=other_uid,
            is_read=False
        ).all()
        
        for msg in unread_messages:
            msg.is_read = True
            msg.read_at = datetime.now()
        
        if conversation:
            conversation.unread_count = 0
            conversation.updated_at = datetime.now()
        
        user_bp.db.session.commit()
        
        page = request.args.get('page', 1, type=int)
        per_page = 20
        
        messages_query = user_bp.Messages.query.filter(
            ((user_bp.Messages.from_uid == uid_record.uid) & (user_bp.Messages.to_uid == other_uid) & (user_bp.Messages.is_deleted_by_sender == False)) |
            ((user_bp.Messages.from_uid == other_uid) & (user_bp.Messages.to_uid == uid_record.uid) & (user_bp.Messages.is_deleted_by_receiver == False))
        ).order_by(user_bp.Messages.created_at.desc())
        
        pagination = messages_query.paginate(page=page, per_page=per_page, error_out=False)
        
        messages = []
        for msg in pagination.items:
            messages.append({
                'id': msg.id,
                'from_uid': msg.from_uid,
                'to_uid': msg.to_uid,
                'content': msg.content,
                'is_read': msg.is_read,
                'created_at': msg.created_at.strftime('%Y-%m-%d %H:%M:%S'),
                'is_me': msg.from_uid == uid_record.uid
            })
        
        messages.reverse()
        
        return user_bp.renderTemplate(
            '/base-files/message-detail.html',
            uid=uid_record,
            other=other,
            messages=messages,
            pagination=pagination,
            page=page
        )
        
    except Exception as e:
        print(f"加载私信详情失败: {e}")
        return user_bp.renderTemplate('/system-files/500.html'), 500


@user_bp.route('/api/messages/send', methods=['POST'])
@login_required
@require_uid_only
@check_ban
def send_message(uid_record):
    """发送私信（支持好友/悬赏临时会话）"""
    try:
        data = request.get_json()
        to_uid = data.get('to_uid')
        content = data.get('content', '').strip()
        message_type = data.get('message_type', 'normal')  # normal, friend_request, bounty_offer, bounty_deliver, system
        bounty_task_id = data.get('bounty_task_id')
        
        # ========== 参数验证 ==========
        if not to_uid:
            return jsonify({'success': False, 'error': '缺少接收者'}), 400
        
        if not content:
            return jsonify({'success': False, 'error': '消息内容不能为空'}), 400
        
        if len(content) > 2000:
            return jsonify({'success': False, 'error': '消息内容不能超过2000字符'}), 400
        
        # 检查接收者是否存在
        receiver = user_bp.UIDs.query.get(to_uid)
        if not receiver or not receiver.status:
            return jsonify({'success': False, 'error': '接收者不存在'}), 404
        
        # 不能给自己发消息
        if to_uid == uid_record.uid:
            return jsonify({'success': False, 'error': '不能给自己发送私信'}), 400
        
        # ========== 黑名单检查 ==========
        blocked = user_bp.BlockList.query.filter(
            ((user_bp.BlockList.blocker_uid == to_uid) & (user_bp.BlockList.blocked_uid == uid_record.uid))
        ).first()
        
        if blocked:
            return jsonify({'success': False, 'error': '对方已将您拉黑'}), 403
        
        # ========== 好友检查（普通私信需要是好友） ==========
        if message_type == 'normal':
            is_friend = user_bp.Friends.query.filter(
                ((user_bp.Friends.user_uid == uid_record.uid) & (user_bp.Friends.friend_uid == to_uid) & (user_bp.Friends.status == 'accepted')) |
                ((user_bp.Friends.user_uid == to_uid) & (user_bp.Friends.friend_uid == uid_record.uid) & (user_bp.Friends.status == 'accepted'))
            ).first()
            
            if not is_friend:
                return jsonify({'success': False, 'error': '只能给好友发送私信'}), 403
        
        # ========== 悬赏任务检查 ==========
        if bounty_task_id:
            bounty_task = user_bp.BountyTasks.query.get(bounty_task_id)
            if not bounty_task:
                return jsonify({'success': False, 'error': '悬赏任务不存在'}), 404
            # 验证用户是否与此悬赏相关（发布者或接单人）
            if uid_record.uid not in [bounty_task.publisher_uid, bounty_task.assignee_uid]:
                return jsonify({'success': False, 'error': '无权发送悬赏消息'}), 403
        
        # ========== 内容安全过滤 ==========
        if ContentFilter.contains_js(content):
            print(f"[XSS ATTEMPT] User: {uid_record.uid} 尝试在私信中注入JS")
            clean_content = ContentFilter.sanitize_text_only(content)
        else:
            clean_content = ContentFilter.sanitize_message_content(content)
        
        # ========== 创建消息记录 ==========
        message = user_bp.Messages(
            from_uid=uid_record.uid,
            to_uid=to_uid,
            content=clean_content,
            message_type=message_type,
            bounty_task_id=bounty_task_id,
            created_at=datetime.now()
        )
        user_bp.db.session.add(message)
        user_bp.db.session.flush()  # 获取 message.id
        
        # ========== 确定会话类型 ==========
        if bounty_task_id:
            conversation_type = 'bounty_temp'
            is_friend_flag = False
        else:
            # 检查是否是好友关系
            is_friend_rel = user_bp.Friends.query.filter(
                ((user_bp.Friends.user_uid == uid_record.uid) & (user_bp.Friends.friend_uid == to_uid) & (user_bp.Friends.status == 'accepted')) |
                ((user_bp.Friends.user_uid == to_uid) & (user_bp.Friends.friend_uid == uid_record.uid) & (user_bp.Friends.status == 'accepted'))
            ).first()
            conversation_type = 'friend' if is_friend_rel else 'normal'
            is_friend_flag = bool(is_friend_rel)
        
        # ========== 更新或创建发送者的会话 ==========
        sender_conv = user_bp.Conversations.query.filter_by(
            user_uid=uid_record.uid,
            other_uid=to_uid
        ).first()
        
        if sender_conv:
            sender_conv.last_message_id = message.id
            sender_conv.updated_at = datetime.now()
            sender_conv.conversation_type = conversation_type
            sender_conv.is_friend = is_friend_flag
            if bounty_task_id:
                sender_conv.bounty_task_id = bounty_task_id
        else:
            sender_conv = user_bp.Conversations(
                user_uid=uid_record.uid,
                other_uid=to_uid,
                last_message_id=message.id,
                unread_count=0,
                updated_at=datetime.now(),
                conversation_type=conversation_type,
                is_friend=is_friend_flag,
                bounty_task_id=bounty_task_id
            )
            user_bp.db.session.add(sender_conv)
        
        # ========== 更新或创建接收者的会话 ==========
        receiver_conv = user_bp.Conversations.query.filter_by(
            user_uid=to_uid,
            other_uid=uid_record.uid
        ).first()
        
        if receiver_conv:
            receiver_conv.last_message_id = message.id
            receiver_conv.unread_count += 1
            receiver_conv.updated_at = datetime.now()
            receiver_conv.conversation_type = conversation_type
            receiver_conv.is_friend = is_friend_flag
            if bounty_task_id:
                receiver_conv.bounty_task_id = bounty_task_id
        else:
            receiver_conv = user_bp.Conversations(
                user_uid=to_uid,
                other_uid=uid_record.uid,
                last_message_id=message.id,
                unread_count=1,
                updated_at=datetime.now(),
                conversation_type=conversation_type,
                is_friend=is_friend_flag,
                bounty_task_id=bounty_task_id
            )
            user_bp.db.session.add(receiver_conv)
        
        user_bp.db.session.commit()
        
        return jsonify({
            'success': True,
            'message': '发送成功',
            'data': {
                'id': message.id,
                'created_at': message.created_at.strftime('%H:%M'),
                'conversation_type': conversation_type
            }
        })
        
    except Exception as e:
        user_bp.db.session.rollback()
        print(f"发送私信失败: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({'success': False, 'error': f'发送失败: {str(e)}'}), 500


@user_bp.route('/api/messages/<int:message_id>/delete', methods=['POST'])
@login_required
@require_uid_only
def delete_message(uid_record, message_id):
    """删除私信"""
    try:
        message = user_bp.Messages.query.get(message_id)
        if not message:
            return jsonify({'success': False, 'error': '消息不存在'}), 404
        
        if message.from_uid == uid_record.uid:
            message.is_deleted_by_sender = True
        elif message.to_uid == uid_record.uid:
            message.is_deleted_by_receiver = True
        else:
            return jsonify({'success': False, 'error': '无权删除此消息'}), 403
        
        user_bp.db.session.commit()
        
        return jsonify({
            'success': True,
            'message': '删除成功'
        })
        
    except Exception as e:
        user_bp.db.session.rollback()
        print(f"删除私信失败: {e}")
        return jsonify({'success': False, 'error': '删除失败'}), 500


@user_bp.route('/api/messages/unread/count')
@login_required
@require_uid_only
def get_unread_count(uid_record):
    """获取未读消息总数"""
    try:
        total_unread = user_bp.Conversations.query.with_entities(
            user_bp.db.func.sum(user_bp.Conversations.unread_count)
        ).filter_by(
            user_uid=uid_record.uid
        ).scalar() or 0
        
        return jsonify({
            'success': True,
            'unread_count': total_unread
        })
        
    except Exception as e:
        print(f"获取未读计数失败: {e}")
        return jsonify({'success': False, 'error': '获取失败'}), 500


@user_bp.route('/api/messages/conversations')
@login_required
@require_uid_only
def get_conversations(uid_record):
    """获取会话列表API"""
    try:
        conversations = user_bp.Conversations.query.filter_by(
            user_uid=uid_record.uid
        ).order_by(
            user_bp.Conversations.updated_at.desc()
        ).all()
        
        result = []
        for conv in conversations:
            other = user_bp.UIDs.query.get(conv.other_uid)
            if other and other.status:
                last_msg = None
                if conv.last_message_id:
                    last_msg = user_bp.Messages.query.get(conv.last_message_id)
                
                result.append({
                    'conversation_id': conv.id,
                    'other_uid': other.uid,
                    'other_nickname': other.nickname,
                    'other_level': other.level,
                    'other_online': other.online_status,
                    'last_message': last_msg.content[:100] if last_msg else '',
                    'last_message_time': last_msg.created_at.strftime('%Y-%m-%d %H:%M') if last_msg else conv.updated_at.strftime('%Y-%m-%d %H:%M'),
                    'unread_count': conv.unread_count
                })
        
        return jsonify({
            'success': True,
            'data': result
        })
        
    except Exception as e:
        print(f"获取会话列表失败: {e}")
        return jsonify({'success': False, 'error': '获取失败'}), 500


@user_bp.route('/api/messages/history/<int:other_uid>')
@login_required
@require_uid_only
def get_message_history(uid_record, other_uid):
    """获取消息历史API"""
    try:
        page = request.args.get('page', 1, type=int)
        per_page = 20
        
        messages_query = user_bp.Messages.query.filter(
            ((user_bp.Messages.from_uid == uid_record.uid) & (user_bp.Messages.to_uid == other_uid) & (user_bp.Messages.is_deleted_by_sender == False)) |
            ((user_bp.Messages.from_uid == other_uid) & (user_bp.Messages.to_uid == uid_record.uid) & (user_bp.Messages.is_deleted_by_receiver == False))
        ).order_by(user_bp.Messages.created_at.desc())
        
        pagination = messages_query.paginate(page=page, per_page=per_page, error_out=False)
        
        messages = []
        for msg in pagination.items:
            messages.append({
                'id': msg.id,
                'from_uid': msg.from_uid,
                'content': msg.content,
                'is_read': msg.is_read,
                'created_at': msg.created_at.strftime('%Y-%m-%d %H:%M:%S'),
                'is_me': msg.from_uid == uid_record.uid
            })
        
        return jsonify({
            'success': True,
            'data': messages,
            'has_next': pagination.has_next,
            'page': page,
            'total': pagination.total
        })
        
    except Exception as e:
        print(f"获取消息历史失败: {e}")
        return jsonify({'success': False, 'error': '获取失败'}), 500
        

# ========== 积分系统 ==========

@user_bp.route('/points')
@login_required
@require_main_account
@require_verified_email_web
def points_center():
    """积分中心页面"""
    try:
        user = current_user
        
        uids = user_bp.UIDs.query.filter_by(id=user.id, status=True).all()
        
        today = datetime.now().date()
        last_claim = getattr(user, 'last_points_claim', None)
        
        can_claim_today = True
        if last_claim:
            last_claim_date = last_claim.date() if isinstance(last_claim, datetime) else last_claim
            can_claim_today = last_claim_date < today
        
        points_history = get_points_history(user.id)
        
        uid_points = []
        for uid in uids:
            uid_points.append({
                'uid': uid.uid,
                'nickname': uid.nickname,
                'points': uid.points or 0,
                'level': uid.level,
                'report_count': uid.report_count or 0,
                'is_banned': uid.is_banned
            })
        
        return user_bp.renderTemplate(
            '/base-files/points-center.html',
            user=user,
            uids=uids,
            uid_points=uid_points,
            total_points=user.points or 0,
            can_claim_today=can_claim_today,
            points_history=points_history
        )
        
    except Exception as e:
        print(f"加载积分中心失败: {e}")
        return user_bp.renderTemplate('/system-files/500.html'), 500


@user_bp.route('/api/points/claim', methods=['POST'])
@login_required
@require_main_account
def claim_daily_points():
    """领取每日积分"""
    try:
        user = current_user
        today = datetime.now().date()
        
        last_claim = getattr(user, 'last_points_claim', None)
        if last_claim:
            last_claim_date = last_claim.date() if isinstance(last_claim, datetime) else last_claim
            if last_claim_date >= today:
                return jsonify({
                    'success': False,
                    'error': '今天已经领取过了'
                }), 400
        
        if not hasattr(user, 'points') or user.points is None:
            user.points = 0
        user.points = float(user.points or 0) + 10
        user.last_points_claim = datetime.now()
        
        record_points_history(
            user_id=user.id,
            amount=10,
            type='daily_claim',
            description='每日登录奖励'
        )
        
        user_bp.db.session.commit()
        
        return jsonify({
            'success': True,
            'message': '领取成功，获得10积分',
            'total_points': float(user.points)
        })
        
    except Exception as e:
        user_bp.db.session.rollback()
        print(f"领取积分失败: {e}")
        return jsonify({
            'success': False,
            'error': '领取失败，请稍后重试'
        }), 500


@user_bp.route('/api/points/allocate', methods=['POST'])
@login_required
@require_main_account
def allocate_points():
    """分配积分给UID"""
    try:
        data = request.get_json()
        target_uid = data.get('uid')
        points = float(data.get('points', 0))
        
        if not target_uid or points <= 0:
            return jsonify({'success': False, 'error': '参数错误'}), 400
        
        uid_record = user_bp.UIDs.query.filter_by(
            uid=target_uid,
            id=current_user.id,
            status=True
        ).first()
        
        if not uid_record:
            return jsonify({'success': False, 'error': 'UID不存在或不属于你'}), 404
        
        user = current_user
        user_points = float(user.points or 0)
        if user_points < points:
            return jsonify({'success': False, 'error': '积分不足'}), 400
        
        user.points = user_points - points
        
        uid_points = float(uid_record.points or 0)
        uid_record.points = uid_points + points
        
        record_points_history(
            user_id=user.id,
            amount=-points,
            type='allocate',
            description=f'分配给UID {uid_record.nickname}',
            target_uid=target_uid
        )
        
        record_points_history(
            user_id=user.id,
            amount=points,
            type='receive',
            description=f'从主账户接收积分',
            target_uid=target_uid,
            is_uid=True
        )
        
        user_bp.db.session.commit()
        
        return jsonify({
            'success': True,
            'message': f'成功分配 {points} 积分给 {uid_record.nickname}',
            'user_points': float(user.points),
            'uid_points': float(uid_record.points)
        })
        
    except Exception as e:
        user_bp.db.session.rollback()
        print(f"分配积分失败: {e}")
        return jsonify({'success': False, 'error': '分配失败，请稍后重试'}), 500


@user_bp.route('/api/points/history')
@login_required
def get_points_history_api():
    """获取积分历史记录API"""
    try:
        user_id = current_user.id
        page = request.args.get('page', 1, type=int)
        per_page = request.args.get('per_page', 20, type=int)
        
        history_query = user_bp.PointsHistory.query.filter_by(user_id=user_id)
        pagination = history_query.order_by(
            user_bp.PointsHistory.created_at.desc()
        ).paginate(page=page, per_page=per_page, error_out=False)
        
        history_data = []
        for record in pagination.items:
            history_data.append({
                'id': record.id,
                'amount': float(record.amount),
                'type': record.type,
                'description': record.description,
                'target_uid': record.target_uid,
                'is_uid': record.is_uid,
                'created_at': record.created_at.isoformat()
            })
        
        return jsonify({
            'success': True,
            'data': history_data,
            'total': pagination.total,
            'page': page,
            'per_page': per_page,
            'has_next': pagination.has_next
        })
        
    except Exception as e:
        print(f"获取积分历史失败: {e}")
        return jsonify({'success': False, 'error': '获取失败'}), 500


# ========== 积分历史记录辅助函数 ==========

def record_points_history(user_id, amount, type, description, target_uid=None, is_uid=False):
    """记录积分历史"""
    try:
        from decimal import Decimal
        history = user_bp.PointsHistory(
            user_id=user_id,
            amount=Decimal(str(amount)),
            type=type,
            description=description,
            target_uid=target_uid,
            is_uid=is_uid,
            created_at=datetime.now()
        )
        user_bp.db.session.add(history)
    except Exception as e:
        print(f"记录积分历史失败: {e}")


def get_points_history(user_id, limit=50):
    """获取积分历史记录"""
    try:
        history = user_bp.PointsHistory.query.filter_by(
            user_id=user_id
        ).order_by(
            user_bp.PointsHistory.created_at.desc()
        ).limit(limit).all()
        
        return [{
            'id': h.id,
            'amount': float(h.amount),
            'type': h.type,
            'description': h.description,
            'target_uid': h.target_uid,
            'is_uid': h.is_uid,
            'created_at': h.created_at.strftime('%Y-%m-%d %H:%M')
        } for h in history]
    except Exception as e:
        print(f"获取积分历史失败: {e}")
        return []


# ========== 公开文件仓库搜索路由 ==========

@user_bp.route('/public/uploads')
def public_uploads():
    """公开文件仓库搜索页面"""
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 20, type=int)
    search = request.args.get('q', '')
    category = request.args.get('category', 'all')
    sort = request.args.get('sort', 'latest')
    
    query = user_bp.Uploads.query.filter_by(is_deleted=False, is_public=True)
    
    if search:
        query = query.filter(
            (user_bp.Uploads.original_filename.contains(search)) |
            (user_bp.Uploads.description.contains(search))
        )
    
    if category != 'all':
        query = query.filter_by(file_category=category)
    
    if sort == 'downloads':
        query = query.order_by(user_bp.Uploads.downloads.desc())
    elif sort == 'size':
        query = query.order_by(user_bp.Uploads.file_size.desc())
    else:
        query = query.order_by(user_bp.Uploads.created_at.desc())
    
    pagination = query.paginate(page=page, per_page=per_page, error_out=False)
    
    uploads_data = []
    for upload in pagination.items:
        uid = user_bp.UIDs.query.get(upload.uid)
        uploads_data.append({
            'id': upload.id,
            'filename': upload.original_filename,
            'size': upload.file_size,
            'size_formatted': format_file_size(upload.file_size),
            'category': upload.file_category,
            'mime_type': upload.mime_type,
            'downloads': upload.downloads,
            'has_preview': upload.has_preview,
            'created_at': upload.created_at,
            'uploader': {
                'uid': uid.uid if uid else None,
                'nickname': uid.nickname if uid else '未知用户',
                'level': uid.level if uid else 0
            },
            'description': upload.description
        })
    
    if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
        return jsonify({
            'success': True,
            'data': uploads_data,
            'total': pagination.total,
            'page': page,
            'per_page': per_page,
            'has_next': pagination.has_next,
            'has_prev': pagination.has_prev
        })
    
    categories = get_upload_categories()
    
    return user_bp.renderTemplate(
        '/base-files/public-uploads.html',
        uploads=uploads_data,
        pagination=pagination,
        categories=categories,
        search=search,
        category=category,
        sort=sort
    )


@user_bp.route('/api/public/uploads')
def api_public_uploads():
    """公开文件搜索API"""
    uid = request.args.get('uid')
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 20, type=int)
    search = request.args.get('q', '')
    category = request.args.get('category', 'all')
    sort = request.args.get('sort', 'latest')
    
    query = user_bp.Uploads.query.filter_by(is_deleted=False, is_public=True)
    
    if search:
        query = query.filter(
            (user_bp.Uploads.original_filename.contains(search)) |
            (user_bp.Uploads.description.contains(search))
        )
    
    if uid:
        query = query.filter_by(uid=uid)
    
    if category != 'all':
        query = query.filter_by(file_category=category)
    
    if sort == 'downloads':
        query = query.order_by(user_bp.Uploads.downloads.desc())
    elif sort == 'size':
        query = query.order_by(user_bp.Uploads.file_size.desc())
    else:
        query = query.order_by(user_bp.Uploads.created_at.desc())
    
    pagination = query.paginate(page=page, per_page=per_page, error_out=False)
    
    uploads_data = []
    for upload in pagination.items:
        uid = user_bp.UIDs.query.get(upload.uid)
        uploads_data.append({
            'id': upload.id,
            'filename': upload.original_filename,
            'size': upload.file_size,
            'size_formatted': format_file_size(upload.file_size),
            'category': upload.file_category,
            'downloads': upload.downloads,
            'has_preview': upload.has_preview,
            'created_at': upload.created_at.strftime('%Y-%m-%d %H:%M'),
            'uploader': {
                'uid': uid.uid if uid else None,
                'nickname': uid.nickname if uid else '未知用户'
            },
            'description': upload.description[:100] + '...' if upload.description and len(upload.description) > 100 else upload.description
        })
    
    return jsonify({
        'success': True,
        'data': uploads_data,
        'total': pagination.total,
        'page': page,
        'per_page': per_page,
        'has_next': pagination.has_next,
        'has_prev': pagination.has_prev
    })


@user_bp.route('/api/public/uploads/trending')
def api_public_uploads_trending():
    """获取热门下载文件"""
    limit = request.args.get('limit', 10, type=int)
    
    uploads = user_bp.Uploads.query.filter_by(
        is_deleted=False, 
        is_public=True
    ).order_by(
        user_bp.Uploads.downloads.desc()
    ).limit(limit).all()
    
    result = []
    for upload in uploads:
        uid = user_bp.UIDs.query.get(upload.uid)
        result.append({
            'id': upload.id,
            'filename': upload.original_filename,
            'downloads': upload.downloads,
            'size_formatted': format_file_size(upload.file_size),
            'uploader': uid.nickname if uid else '未知用户'
        })
    
    return jsonify({
        'success': True,
        'data': result
    })


# ========== 仓库相关路由 ==========

@user_bp.route('/uploads')
@login_required
@require_uid_only
@check_ban
def list_uploads(uid_record):
    """列出我的文件仓库"""
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 20, type=int)
    category = request.args.get('category')
    search = request.args.get('q', '')
    
    query = user_bp.Uploads.query.filter_by(uid=uid_record.uid, is_deleted=False)
    
    if search:
        query = query.filter(
            (user_bp.Uploads.original_filename.contains(search)) |
            (user_bp.Uploads.description.contains(search))
        )
    
    if category and category != 'all':
        query = query.filter_by(file_category=category)
    
    pagination = query.order_by(user_bp.Uploads.created_at.desc())\
        .paginate(page=page, per_page=per_page, error_out=False)
    
    uploads_data = []
    for upload in pagination.items:
        uploads_data.append({
            'id': upload.id,
            'filename': upload.original_filename,
            'size': upload.file_size,
            'size_formatted': format_file_size(upload.file_size),
            'category': upload.file_category,
            'downloads': upload.downloads,
            'is_public': upload.is_public,
            'has_preview': upload.has_preview,
            'scan_result': upload.scan_result,
            'created_at': upload.created_at.strftime('%Y-%m-%d %H:%M'),
            'description': upload.description
        })
    
    if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
        return jsonify({
            'success': True,
            'data': uploads_data,
            'total': pagination.total,
            'page': page,
            'per_page': per_page,
            'has_next': pagination.has_next,
            'has_prev': pagination.has_prev
        })
    
    return user_bp.renderTemplate(
        '/base-files/uploads.html',
        uploads=uploads_data,
        pagination=pagination,
        categories=get_upload_categories()
    )


@user_bp.route('/upload')
@login_required
@require_uid_only
@check_ban
def upload_page(uid_record):
    """文件上传页面"""
    return user_bp.renderTemplate('/base-files/upload.html', uid=uid_record)


@user_bp.route('/upload/file', methods=['POST'])
@login_required
@require_uid_only
@check_ban
def upload_file(uid_record):
    try:
        if 'file' not in request.files:
            return jsonify({'error': '没有选择文件'}), 400
        
        file = request.files['file']
        if file.filename == '':
            return jsonify({'error': '没有选择文件'}), 400
        
        file.stream.seek(0)
        
        scan_result = file_scanner.scan(file.stream, file.filename)
        
        if not scan_result['safe']:
            if scan_result.get('virus'):
                return jsonify({
                    'error': f'文件包含病毒: {scan_result["virus"]}'
                }), 400
            elif scan_result.get('errors'):
                return jsonify({'error': scan_result['errors'][0]}), 400
        
        description = request.form.get('description', '')
        is_public = request.form.get('isPublic') == 'true'
        
        original_filename = secure_filename(file.filename)
        if not original_filename:
            original_filename = f"upload_{int(time.time())}.bin"
        
        file_hash = hashlib.md5(
            f"{original_filename}{time.time()}{secrets.token_hex(8)}".encode()
        ).hexdigest()[:16]
        
        name_parts = os.path.splitext(original_filename)
        safe_filename = f"{file_hash}{name_parts[1]}"
        
        mime_type = scan_result.get('type_detection', {}).get('mime_type', 'application/octet-stream')
        file_category = get_file_category(mime_type, original_filename)
        
        upload_dir = os.path.join(
            current_app.config['UPLOAD_FOLDER'],
            'files',
            str(uid_record.uid)
        )
        os.makedirs(upload_dir, exist_ok=True)
        
        file.stream.seek(0)
        file_path = os.path.join(upload_dir, safe_filename)
        file.save(file_path)
        
        relative_path = f"files/{uid_record.uid}/{safe_filename}"
        
        preview_info = generate_preview_enhanced(file_path, mime_type, upload_dir, file_hash, original_filename)
        
        new_upload = user_bp.Uploads(
            uid=uid_record.uid,
            filename=safe_filename,
            original_filename=original_filename,
            file_size=os.path.getsize(file_path),
            file_hash=scan_result['file_info']['hash'],
            mime_type=mime_type,
            file_path=relative_path,
            file_category=file_category,
            description=description,
            is_public=is_public,
            scanned=True,
            scan_result='clean' if scan_result['safe'] else 'infected',
            scan_details=scan_result,
            scan_time=datetime.now(),
            has_preview=preview_info['has_preview'],
            preview_path=preview_info.get('path'),
            preview_info=preview_info.get('info')
        )
        
        user_bp.db.session.add(new_upload)
        
        uid_record.uploads_count += 1
        user_bp.db.session.commit()
        
        return jsonify({
            'success': True,
            'message': '文件上传成功',
            'file_id': new_upload.id
        })
        
    except Exception as e:
        user_bp.db.session.rollback()
        print(f"文件上传失败: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({'error': f'上传失败: {str(e)}'}), 500


@user_bp.route('/file/<int:file_id>/preview')
def preview_file(file_id):
    """文件预览页面"""
    upload = user_bp.Uploads.query.get(file_id)
    if not upload or upload.is_deleted:
        return user_bp.renderTemplate('/system-files/404.html'), 404
    
    current_uid = session.get('current_uid')
    if not upload.is_public and (not current_uid or current_uid != upload.uid):
        return user_bp.renderTemplate('/system-files/403.html'), 403
    
    author = user_bp.UIDs.query.get(upload.uid)
    
    return user_bp.renderTemplate(
        '/base-files/file-preview.html',
        file=upload,
        author=author
    )


@user_bp.route('/file/<int:file_id>/view')
def view_file(file_id):
    """查看文件（内联显示）"""
    upload = user_bp.Uploads.query.get(file_id)
    if not upload or upload.is_deleted:
        return user_bp.renderTemplate('/system-files/404.html'), 404
    
    current_uid = session.get('current_uid')
    if not upload.is_public and (not current_uid or current_uid != upload.uid):
        return user_bp.renderTemplate('/system-files/403.html'), 403
    
    file_path = os.path.join(current_app.config['UPLOAD_FOLDER'], upload.file_path)
    
    if not os.path.exists(file_path):
        return user_bp.renderTemplate('/system-files/404.html'), 404
    
    upload.views = getattr(upload, 'views', 0) + 1
    user_bp.db.session.commit()
    
    mime_type = upload.mime_type or 'application/octet-stream'
    
    return send_file(
        file_path,
        mimetype=mime_type,
        as_attachment=False,
        download_name=upload.original_filename
    )


@user_bp.route('/file/<int:file_id>/download')
def download_file(file_id):
    """下载文件"""
    upload = user_bp.Uploads.query.get(file_id)
    if not upload or upload.is_deleted:
        return user_bp.renderTemplate('/system-files/404.html'), 404
    
    current_uid = session.get('current_uid')
    if not upload.is_public and (not current_uid or current_uid != upload.uid):
        return user_bp.renderTemplate('/system-files/403.html'), 403
    
    upload.downloads += 1
    user_bp.db.session.commit()
    
    file_path = os.path.join(current_app.config['UPLOAD_FOLDER'], upload.file_path)
    
    if not os.path.exists(file_path):
        return user_bp.renderTemplate('/system-files/404.html'), 404
    
    return send_file(
        file_path,
        as_attachment=True,
        download_name=upload.original_filename,
        mimetype=upload.mime_type
    )


@user_bp.route('/file/<int:file_id>', methods=['DELETE'])
@login_required
@require_upload_owner
def delete_file(file_id, upload):
    """删除文件"""
    try:
        file_path = os.path.join(current_app.config['UPLOAD_FOLDER'], upload.file_path)
        if os.path.exists(file_path):
            os.remove(file_path)
        
        if upload.preview_path:
            preview_path = os.path.join(current_app.config['UPLOAD_FOLDER'], upload.preview_path)
            if os.path.exists(preview_path):
                os.remove(preview_path)
        
        upload.is_deleted = True
        upload.deleted_at = datetime.now()
        
        uid_record = user_bp.UIDs.query.get(upload.uid)
        if uid_record:
            uid_record.uploads_count -= 1
        
        user_bp.db.session.commit()
        
        return jsonify({'success': True, 'message': '文件已删除'})
        
    except Exception as e:
        user_bp.db.session.rollback()
        print(f"删除文件失败: {e}")
        return jsonify({'error': '删除失败'}), 500


@user_bp.route('/file/<int:file_id>/public', methods=['POST'])
@login_required
@require_upload_owner
def toggle_file_public(file_id, upload):
    """切换文件公开状态"""
    try:
        data = request.get_json()
        is_public = data.get('is_public', not upload.is_public)
        
        upload.is_public = is_public
        user_bp.db.session.commit()
        
        return jsonify({
            'success': True,
            'is_public': upload.is_public,
            'message': '文件已公开' if is_public else '文件已设为私密'
        })
        
    except Exception as e:
        user_bp.db.session.rollback()
        print(f"切换文件状态失败: {e}")
        return jsonify({'error': '操作失败'}), 500


# ========== 举报系统 ==========

@user_bp.route('/api/report/reasons')
def get_report_reasons():
    """获取举报原因列表"""
    try:
        target_type = request.args.get('type', 'post')
        
        reasons = user_bp.ReportReasons.query.filter_by(
            target_type=target_type,
            is_active=True
        ).order_by(user_bp.ReportReasons.sort_order).all()
        
        reasons_data = [{
            'code': r.reason_code,
            'text': r.reason_text,
            'description': r.description
        } for r in reasons]
        
        return jsonify({
            'success': True,
            'data': reasons_data
        })
        
    except Exception as e:
        print(f"获取举报原因失败: {e}")
        return jsonify({'success': False, 'error': '获取失败'}), 500


@user_bp.route('/api/report/submit', methods=['POST'])
@login_required
@require_uid_only
@check_ban
def submit_report(uid_record):
    """提交举报"""
    try:
        data = request.get_json()
        target_type = data.get('target_type')
        target_id = data.get('target_id')
        reason = data.get('reason')
        description = data.get('description', '').strip()
        
        if target_type not in ['post', 'article', 'upload']:
            return jsonify({'success': False, 'error': '无效的举报类型'}), 400
        
        if not target_id:
            return jsonify({'success': False, 'error': '请指定被举报内容'}), 400
        
        if not reason:
            return jsonify({'success': False, 'error': '请选择举报原因'}), 400
        
        if len(description) > 500:
            return jsonify({'success': False, 'error': '描述不能超过500字符'}), 400
        
        target_exists = False
        target_uid = None
        target_id_id = None
        
        if target_type == 'post':
            target = user_bp.Posts.query.filter_by(id=target_id, is_deleted=False).first()
            if target:
                target_exists = True
                target_uid = target.author_id
                uid_obj = user_bp.UIDs.query.get(target_uid)
                if uid_obj:
                    target_id_id = uid_obj.id
        elif target_type == 'article':
            target = user_bp.Articles.query.filter_by(arid=target_id, is_deleted=False).first()
            if target:
                target_exists = True
                target_uid = target.author_id
                uid_obj = user_bp.UIDs.query.get(target_uid)
                if uid_obj:
                    target_id_id = uid_obj.id
        else:
            target = user_bp.Uploads.query.filter_by(id=target_id, is_deleted=False).first()
            if target:
                target_exists = True
                target_uid = target.uid
                uid_obj = user_bp.UIDs.query.get(target_uid)
                if uid_obj:
                    target_id_id = uid_obj.id
        
        if not target_exists:
            return jsonify({'success': False, 'error': '被举报内容不存在或已删除'}), 404
        
        if target_uid == uid_record.uid:
            return jsonify({'success': False, 'error': '不能举报自己的内容'}), 400
        
        existing_report = user_bp.Reports.query.filter_by(
            reporter_uid=uid_record.uid,
            target_type=target_type,
            target_id=target_id,
            status='pending'
        ).first()
        
        if existing_report:
            return jsonify({'success': False, 'error': '您已经举报过该内容，请等待审核'}), 400
        
        report = user_bp.Reports(
            reporter_uid=uid_record.uid,
            target_type=target_type,
            target_id=target_id,
            target_uid=target_uid,
            target_id_id=target_id_id,
            reason=reason,
            description=description,
            status='pending',
            created_at=datetime.now()
        )
        
        user_bp.db.session.add(report)
        user_bp.db.session.commit()
        
        return jsonify({
            'success': True,
            'message': '举报提交成功，感谢您的反馈',
            'report_id': report.id
        })
        
    except Exception as e:
        user_bp.db.session.rollback()
        print(f"提交举报失败: {e}")
        return jsonify({'success': False, 'error': '提交失败，请稍后重试'}), 500


@user_bp.route('/api/report/check/<string:target_type>/<int:target_id>')
@login_required
@require_uid_only
def check_report_status(uid_record, target_type, target_id):
    """检查当前用户是否已举报过某内容"""
    try:
        if target_type not in ['post', 'article', 'upload']:
            return jsonify({'success': False, 'error': '无效的类型'}), 400
        
        report = user_bp.Reports.query.filter_by(
            reporter_uid=uid_record.uid,
            target_type=target_type,
            target_id=target_id,
            status='pending'
        ).first()
        
        return jsonify({
            'success': True,
            'reported': report is not None,
            'report_id': report.id if report else None
        })
        
    except Exception as e:
        print(f"检查举报状态失败: {e}")
        return jsonify({'success': False, 'error': '检查失败'}), 500


@user_bp.route('/api/review-report/<int:report_id>', methods=['POST'])
@login_required
def review_report(report_id):
    """审核举报（管理员功能）"""
    try:
        if current_user.__class__.__name__ not in ['Admins', 'SuperAdmins', 'Owners']:
            return jsonify({'success': False, 'error': '无权操作'}), 403
        
        data = request.get_json()
        action = data.get('action')
        review_comment = data.get('comment', '')
        
        if action not in ['approve', 'reject']:
            return jsonify({'success': False, 'error': '无效的操作'}), 400
        
        report = user_bp.Reports.query.get(report_id)
        if not report or report.status != 'pending':
            return jsonify({'success': False, 'error': '举报不存在或已处理'}), 404
        
        reporter = user_bp.UIDs.query.get(report.reporter_uid)
        target_uid_obj = user_bp.UIDs.query.get(report.target_uid)
        target_id_obj = user_bp.IDs.query.get(report.target_id_id) if report.target_id_id else None
        
        if action == 'approve':
            points_reward = 2
            if reporter:
                reporter.points = float(reporter.points or 0) + points_reward
                
                record_points_history(
                    user_id=reporter.id,
                    amount=points_reward,
                    type='report_reward',
                    description=f'举报奖励（{report.target_type}）',
                    target_uid=reporter.uid,
                    is_uid=True
                )
            
            if target_uid_obj:
                target_uid_obj.report_count = (target_uid_obj.report_count or 0) + 1
                
                if target_uid_obj.report_count >= 3 and not target_uid_obj.is_banned:
                    target_uid_obj.is_banned = True
                    target_uid_obj.banned_at = datetime.now()
                    target_uid_obj.banned_reason = '累计举报达到3次'
                    target_uid_obj.status = False
                    
                    review_comment += f" UID累计举报达3次，已封禁。"
            
            if target_id_obj:
                target_id_obj.report_count = (target_id_obj.report_count or 0) + 1
                
                if target_id_obj.report_count >= 7 and not target_id_obj.is_banned:
                    target_id_obj.is_banned = True
                    target_id_obj.banned_at = datetime.now()
                    target_id_obj.banned_reason = '累计举报达到7次'
                    target_id_obj.status = False
                    
                    for uid in target_id_obj.uids:
                        uid.is_banned = True
                        uid.banned_at = datetime.now()
                        uid.banned_reason = '所属ID被封禁'
                        uid.status = False
                    
                    review_comment += f" ID累计举报达7次，已封禁所有账户。"
                
                if report.target_type == 'post':
                    post = user_bp.Posts.query.get(report.target_id)
                    if post:
                        post.is_deleted = True
                        post.deleted_at = datetime.now()
                elif report.target_type == 'article':
                    article = user_bp.Articles.query.get(report.target_id)
                    if article:
                        article.is_deleted = True
                elif report.target_type == 'upload':
                    upload = user_bp.Uploads.query.get(report.target_id)
                    if upload:
                        upload.is_deleted = True
                        upload.deleted_at = datetime.now()
            
            report.status = 'resolved'
            report.action_taken = 'delete_content'
            report.points_awarded = points_reward
            report.awarded_at = datetime.now()
            
        else:
            report.status = 'rejected'
            report.action_taken = 'ignore'
        
        report.reviewed_by = current_user.id
        report.reviewed_at = datetime.now()
        report.review_comment = review_comment
        
        user_bp.db.session.commit()
        
        return jsonify({
            'success': True,
            'message': '处理成功',
            'report_status': report.status
        })
        
    except Exception as e:
        user_bp.db.session.rollback()
        print(f"处理举报失败: {e}")
        return jsonify({'success': False, 'error': '处理失败'}), 500


@user_bp.route('/api/reports/pending')
@login_required
def get_pending_reports():
    """获取待处理的举报列表（管理员功能）"""
    try:
        if current_user.__class__.__name__ not in ['Admins', 'SuperAdmins', 'Owners']:
            return jsonify({'success': False, 'error': '无权访问'}), 403
        
        page = request.args.get('page', 1, type=int)
        per_page = request.args.get('per_page', 20, type=int)
        
        reports = user_bp.Reports.query.filter_by(status='pending')\
            .order_by(user_bp.Reports.created_at.asc())\
            .paginate(page=page, per_page=per_page, error_out=False)
        
        reports_data = []
        for report in reports.items:
            reporter = user_bp.UIDs.query.get(report.reporter_uid)
            target_author = user_bp.UIDs.query.get(report.target_uid)
            
            content_title = ''
            if report.target_type == 'post':
                post = user_bp.Posts.query.get(report.target_id)
                if post:
                    content_title = post.title
            elif report.target_type == 'article':
                article = user_bp.Articles.query.get(report.target_id)
                if article:
                    content_title = article.title
            elif report.target_type == 'upload':
                upload = user_bp.Uploads.query.get(report.target_id)
                if upload:
                    content_title = upload.original_filename
            
            reports_data.append({
                'id': report.id,
                'target_type': report.target_type,
                'target_id': report.target_id,
                'content_title': content_title,
                'reason': report.reason,
                'description': report.description,
                'created_at': report.created_at.strftime('%Y-%m-%d %H:%M'),
                'reporter': {
                    'uid': reporter.uid if reporter else None,
                    'nickname': reporter.nickname if reporter else '未知'
                },
                'target_author': {
                    'uid': target_author.uid if target_author else None,
                    'nickname': target_author.nickname if target_author else '未知',
                    'report_count': target_author.report_count if target_author else 0,
                    'is_banned': target_author.is_banned if target_author else False
                },
                'target_id_info': {
                    'id': report.target_id_id,
                    'report_count': target_author.user.report_count if target_author and target_author.user else 0,
                    'is_banned': target_author.user.is_banned if target_author and target_author.user else False
                } if target_author and target_author.user else None
            })
        
        return jsonify({
            'success': True,
            'data': reports_data,
            'total': reports.total,
            'page': page,
            'per_page': per_page,
            'has_next': reports.has_next
        })
        
    except Exception as e:
        print(f"获取举报列表失败: {e}")
        return jsonify({'success': False, 'error': '获取失败'}), 500


@user_bp.route('/api/check-ban-status')
@login_required
@require_uid_only
def check_ban_status(uid_record):
    """检查当前UID和所属ID的封禁状态"""
    try:
        result = {
            'uid_banned': uid_record.is_banned,
            'uid_report_count': uid_record.report_count or 0,
            'uid_ban_expires': uid_record.ban_expires_at.strftime('%Y-%m-%d %H:%M') if uid_record.ban_expires_at else None,
            'uid_ban_reason': uid_record.banned_reason
        }
        
        if uid_record.user:
            result.update({
                'id_banned': uid_record.user.is_banned,
                'id_report_count': uid_record.user.report_count or 0,
                'id_ban_expires': uid_record.user.ban_expires_at.strftime('%Y-%m-%d %H:%M') if uid_record.user.ban_expires_at else None,
                'id_ban_reason': uid_record.user.banned_reason
            })
        
        if uid_record.is_banned or (uid_record.user and uid_record.user.is_banned):
            return jsonify({
                'success': False,
                'error': '账户已被封禁',
                'banned': True,
                'details': result
            }), 403
        
        return jsonify({
            'success': True,
            'banned': False,
            'details': result
        })
        
    except Exception as e:
        print(f"检查封禁状态失败: {e}")
        return jsonify({'success': False, 'error': '检查失败'}), 500


# ========== 初始化举报原因数据 ==========

def init_report_reasons():
    """初始化预设的举报原因"""
    try:
        post_reasons = [
            {'code': 'spam', 'text': '垃圾广告', 'description': '包含广告、推广等内容', 'sort': 1},
            {'code': 'porn', 'text': '色情低俗', 'description': '包含色情、低俗内容', 'sort': 2},
            {'code': 'illegal', 'text': '违法信息', 'description': '包含违法信息', 'sort': 3},
            {'code': 'violence', 'text': '暴力血腥', 'description': '包含暴力、血腥内容', 'sort': 4},
            {'code': 'harassment', 'text': '人身攻击', 'description': '包含辱骂、攻击等内容', 'sort': 5},
            {'code': 'misinformation', 'text': '虚假信息', 'description': '包含谣言、虚假信息', 'sort': 6},
            {'code': 'copyright', 'text': '侵犯版权', 'description': '侵犯他人版权', 'sort': 7},
            {'code': 'other', 'text': '其他', 'description': '其他违规内容', 'sort': 99}
        ]
        
        article_reasons = [
            {'code': 'spam', 'text': '垃圾广告', 'description': '包含广告、推广等内容', 'sort': 1},
            {'code': 'porn', 'text': '色情低俗', 'description': '包含色情、低俗内容', 'sort': 2},
            {'code': 'illegal', 'text': '违法信息', 'description': '包含违法信息', 'sort': 3},
            {'code': 'violence', 'text': '暴力血腥', 'description': '包含暴力、血腥内容', 'sort': 4},
            {'code': 'plagiarism', 'text': '抄袭洗稿', 'description': '抄袭、洗稿行为', 'sort': 5},
            {'code': 'misinformation', 'text': '虚假信息', 'description': '包含谣言、虚假信息', 'sort': 6},
            {'code': 'copyright', 'text': '侵犯版权', 'description': '侵犯他人版权', 'sort': 7},
            {'code': 'other', 'text': '其他', 'description': '其他违规内容', 'sort': 99}
        ]
        
        upload_reasons = [
            {'code': 'virus', 'text': '包含病毒', 'description': '文件包含病毒或恶意代码', 'sort': 1},
            {'code': 'porn', 'text': '色情内容', 'description': '文件包含色情内容', 'sort': 2},
            {'code': 'illegal', 'text': '违法内容', 'description': '文件包含违法信息', 'sort': 3},
            {'code': 'copyright', 'text': '侵犯版权', 'description': '侵犯他人版权', 'sort': 4},
            {'code': 'fake', 'text': '虚假文件', 'description': '文件内容与描述不符', 'sort': 5},
            {'code': 'other', 'text': '其他', 'description': '其他违规内容', 'sort': 99}
        ]
        
        for target_type, reasons in [
            ('post', post_reasons),
            ('article', article_reasons),
            ('upload', upload_reasons)
        ]:
            for r in reasons:
                existing = user_bp.ReportReasons.query.filter_by(
                    target_type=target_type,
                    reason_code=r['code']
                ).first()
                
                if not existing:
                    reason = user_bp.ReportReasons(
                        target_type=target_type,
                        reason_code=r['code'],
                        reason_text=r['text'],
                        description=r['description'],
                        sort_order=r['sort'],
                        is_active=True,
                        created_at=datetime.now()
                    )
                    user_bp.db.session.add(reason)
        
        user_bp.db.session.commit()
        print("举报原因初始化完成")
        
    except Exception as e:
        print(f"初始化举报原因失败: {e}")
        user_bp.db.session.rollback()


# ========== 忘记密码/重置密码 ==========

@user_bp.route('/forgot-password', methods=['GET', 'POST'])
@anonymous_required
def forgot_password():
    """忘记密码 - 发送重置邮件"""
    if request.method == 'POST':
        account = request.form.get('account')
        captcha_text = request.form.get('captcha')
        
        expected_captcha = session.get('captcha_expected', '')
        if not expected_captcha or captcha_text.lower() != expected_captcha.lower():
            return jsonify({'error': '验证码错误'})
        
        if not account:
            return jsonify({'error': '请输入昵称或邮箱'})
        
        user = user_bp.IDs.query.filter(
            (user_bp.IDs.nickname == account) | (user_bp.IDs.email == account)
        ).first()
        
        if not user:
            session.pop('captcha_expected', None)
            return jsonify({'success': '如果该账户存在，我们将发送密码重置邮件'})
        
        if not user.email_verified:
            return jsonify({'error': '该邮箱未验证，无法重置密码。请先验证邮箱'})
        
        reset_token = generate_reset_token()
        expires_at = datetime.now() + timedelta(hours=1)
        
        user_bp.PasswordResetTokens.query.filter_by(
            user_id=user.id, used=False
        ).delete()
        
        token_entry = user_bp.PasswordResetTokens(
            user_id=user.id,
            token=reset_token,
            expires_at=expires_at,
            used=False
        )
        
        try:
            user_bp.db.session.add(token_entry)
            user_bp.db.session.commit()
            
            email_sender = EmailSender(user_bp.app, request.host_url, user_bp.url_prefix, user_bp.name)
            success = email_sender.send_password_reset_email(user.email, reset_token, user.id)
            
            if not success:
                print(f"发送重置邮件失败: {user.email}")
                return jsonify({'error': '邮件发送失败，请稍后重试'})
            
            session.pop('captcha_expected', None)
            return jsonify({'success': '密码重置邮件已发送，请查收'})
            
        except Exception as e:
            user_bp.db.session.rollback()
            print(f"创建重置令牌失败: {e}")
            return jsonify({'error': '操作失败，请稍后重试'})
    
    return user_bp.renderTemplate('/base-files/forgot-password.html')


@user_bp.route('/reset-password', methods=['GET', 'POST'])
@anonymous_required
def reset_password():
    """重置密码"""
    if request.method == 'POST':
        token = request.form.get('token')
        user_id = request.form.get('user_id')
        new_password = request.form.get('password')
        confirm_password = request.form.get('confirmPassword')
        captcha_text = request.form.get('captcha')
        
        expected_captcha = session.get('captcha_expected', '')
        if not expected_captcha or captcha_text.lower() != expected_captcha.lower():
            return jsonify({'error': '验证码错误'})
        
        if not token or not user_id or not new_password:
            return jsonify({'error': '参数不完整'})
        
        if new_password != confirm_password:
            return jsonify({'error': '两次输入的密码不一致'})
        
        user = user_bp.IDs.query.get(user_id)
        if not user:
            return jsonify({'error': '用户不存在'})
        
        if not user.email_verified:
            return jsonify({'error': '邮箱未验证，无法重置密码'})
        
        reset_token = user_bp.PasswordResetTokens.query.filter_by(
            token=token,
            user_id=user_id,
            used=False
        ).first()
        
        if not reset_token:
            return jsonify({'error': '无效的重置链接'})
        
        if reset_token.expires_at < datetime.now():
            return jsonify({'error': '重置链接已过期'})
        
        has_upper = bool(re.search(r'[A-Z]', new_password))
        has_lower = bool(re.search(r'[a-z]', new_password))
        has_digit = bool(re.search(r'[0-9]', new_password))
        
        if len(new_password) < 8 or len(new_password) > 30:
            return jsonify({'error': '密码长度必须在8-30个字符之间'})
        
        if not (has_upper and has_lower and has_digit):
            return jsonify({'error': '密码必须包含大小写字母和数字'})
        
        session_key = get_session_key()
        temp_key = f"temp_{session_key}"
        salt, iterations = pbkdf2_security.get_pbkdf2_params_for_new_user(temp_key)
        
        user.crypto_pw = Password().hash_pw(new_password)
        user.pbkdf2_salt = salt
        user.pbkdf2_iterations = iterations
        
        reset_token.used = True
        
        try:
            user_bp.db.session.commit()
            
            try:
                email_sender = EmailSender(user_bp.app, request.host_url, user_bp.url_prefix, user_bp.name)
                email_sender.send_password_change_notification(user.email)
            except Exception as e:
                print(f"发送密码修改通知失败: {e}")
            
            session.pop('captcha_expected', None)
            return jsonify({'success': '密码重置成功，请使用新密码登录'})
            
        except Exception as e:
            user_bp.db.session.rollback()
            print(f"重置密码失败: {e}")
            return jsonify({'error': '操作失败，请稍后重试'})
    
    token = request.args.get('token')
    user_id = request.args.get('user_id')
    
    if not token or not user_id:
        return user_bp.renderTemplate(
            '/base-files/reset-password.html', 
            valid=False,
            error='无效的重置链接'
        )
    
    user = user_bp.IDs.query.get(user_id)
    if not user:
        return user_bp.renderTemplate(
            '/base-files/reset-password.html', 
            valid=False,
            error='用户不存在'
        )
    
    if not user.email_verified:
        return user_bp.renderTemplate(
            '/base-files/reset-password.html', 
            valid=False,
            error='该邮箱尚未验证，无法重置密码。请先完成邮箱验证'
        )
    
    reset_token = user_bp.PasswordResetTokens.query.filter_by(
        token=token,
        user_id=user_id,
        used=False
    ).first()
    
    if not reset_token:
        return user_bp.renderTemplate(
            '/base-files/reset-password.html', 
            valid=False,
            error='无效的重置链接'
        )
    
    if reset_token.expires_at < datetime.now():
        return user_bp.renderTemplate(
            '/base-files/reset-password.html', 
            valid=False,
            error='重置链接已过期'
        )
    
    return user_bp.renderTemplate(
        '/base-files/reset-password.html', 
        valid=True,
        token=token,
        user_id=user_id
    )


# ========== 辅助函数 ==========

def send_verification_email(user):
    """发送验证邮件"""
    verification_token = generate_reset_token()
    expires_at = datetime.now() + timedelta(hours=24)

    user_bp.EmailVerificationTokens.query.filter_by(
        user_id=user.id, 
        used=False
    ).delete()

    token_entry = user_bp.EmailVerificationTokens(
        user_id=user.id,
        token=verification_token,
        email=user.email,
        expires_at=expires_at,
        used=False
    )
    
    try:
        user_bp.db.session.add(token_entry)
        user_bp.db.session.commit()
        
        from flask import request
        email_sender = EmailSender(user_bp.app, request.host_url, user_bp.url_prefix, user_bp.name)
        success = email_sender.send_verification_email(user.email, verification_token, user.id)
        
        if not success:
            print(f"发送验证邮件失败: {user.email}")
            
    except Exception as e:
        user_bp.db.session.rollback()
        print(f"创建验证令牌失败: {e}")


def format_file_size(size):
    """格式化文件大小"""
    if size < 1024:
        return f"{size} B"
    elif size < 1024 * 1024:
        return f"{size/1024:.1f} KB"
    elif size < 1024 * 1024 * 1024:
        return f"{size/(1024*1024):.1f} MB"
    else:
        return f"{size/(1024*1024*1024):.1f} GB"


def get_file_category(mime_type, filename):
    """获取文件分类"""
    if mime_type.startswith('image/'):
        return 'image'
    elif mime_type.startswith('text/'):
        return 'document'
    elif 'font' in mime_type or filename.endswith(('.ttf', '.otf', '.woff', '.hzk')):
        return 'font'
    elif mime_type in ['application/zip', 'application/x-rar-compressed', 
                       'application/x-7z-compressed', 'application/gzip']:
        return 'archive'
    else:
        return 'other'


def get_upload_categories():
    """获取上传分类选项"""
    return [
        {'id': 'all', 'name': '全部'},
        {'id': 'image', 'name': '图片'},
        {'id': 'document', 'name': '文档'},
        {'id': 'font', 'name': '字体'},
        {'id': 'archive', 'name': '压缩包'},
        {'id': 'other', 'name': '其他'}
    ]


def generate_preview_enhanced(file_path, mime_type, upload_dir, file_hash, original_filename):
    """增强版文件预览生成器 - 支持更多格式"""
    result = {'has_preview': False, 'path': None, 'info': None}
    
    try:
        if mime_type and mime_type.startswith('image/'):
            from PIL import Image
            
            try:
                img = Image.open(file_path)
                
                img_format = img.format or 'Unknown'
                img_mode = img.mode
                img_width, img_height = img.size
                
                thumb_filename = f"{file_hash}_thumb.jpg"
                thumb_path = os.path.join(upload_dir, thumb_filename)
                
                img_copy = img.copy()
                img_copy.thumbnail((800, 800), Image.Resampling.LANCZOS)
                
                if img_copy.mode in ('RGBA', 'LA', 'P'):
                    background = Image.new('RGB', img_copy.size, (255, 255, 255))
                    if img_copy.mode == 'RGBA':
                        background.paste(img_copy, mask=img_copy.split()[-1])
                    else:
                        background.paste(img_copy)
                    img_copy = background
                elif img_copy.mode != 'RGB':
                    img_copy = img_copy.convert('RGB')
                
                img_copy.save(thumb_path, 'JPEG', quality=85, optimize=True)
                
                result['has_preview'] = True
                result['path'] = os.path.join('files', str(upload_dir).split('/')[-1], thumb_filename)
                result['info'] = {
                    'width': img_width,
                    'height': img_height,
                    'format': img_format,
                    'mode': img_mode,
                    'thumb_width': img_copy.width,
                    'thumb_height': img_copy.height,
                    'is_animated': getattr(img, 'is_animated', False),
                    'n_frames': getattr(img, 'n_frames', 1) if hasattr(img, 'n_frames') else 1
                }
                
                img.close()
                
            except Exception as e:
                print(f"图片预览生成失败: {e}")
        
        elif mime_type and (mime_type.startswith('text/') or 
                           mime_type in ['application/json', 'application/xml', 'application/javascript',
                                        'application/x-yaml', 'application/x-sh', 'application/x-python']):
            try:
                import chardet
                with open(file_path, 'rb') as f:
                    raw_data = f.read(10000)
                    encoding_result = chardet.detect(raw_data)
                    encoding = encoding_result.get('encoding', 'utf-8') or 'utf-8'
                
                with open(file_path, 'r', encoding=encoding, errors='replace') as f:
                    content = f.read(50000)
                    
                ext = os.path.splitext(original_filename)[1].lower()
                language_map = {
                    '.py': 'python', '.js': 'javascript', '.html': 'html',
                    '.htm': 'html', '.css': 'css', '.json': 'json',
                    '.xml': 'xml', '.yaml': 'yaml', '.yml': 'yaml',
                    '.sh': 'bash', '.bash': 'bash', '.md': 'markdown',
                    '.txt': 'text'
                }
                language = language_map.get(ext, 'text')
                
                result['has_preview'] = True
                result['info'] = {
                    'preview': content[:10000],
                    'truncated': len(content) >= 50000,
                    'total_length': len(content),
                    'encoding': encoding,
                    'language': language,
                    'line_count': len(content.split('\n'))
                }
                
            except Exception as e:
                print(f"文本预览生成失败: {e}")
        
        elif mime_type == 'application/pdf' or original_filename.lower().endswith('.pdf'):
            try:
                result['has_preview'] = True
                result['info'] = {'type': 'pdf', 'page_count': 1}
            except Exception as e:
                print(f"PDF预览生成失败: {e}")
        
        elif mime_type in ['application/zip', 'application/x-rar-compressed', 
                          'application/x-7z-compressed', 'application/gzip',
                          'application/x-tar'] or file_path.endswith(('.zip', '.rar', '.7z', '.tar', '.gz')):
            try:
                file_list = []
                total_size = 0
                total_files = 0
                
                if file_path.endswith('.zip'):
                    import zipfile
                    with zipfile.ZipFile(file_path, 'r') as zf:
                        for i, info in enumerate(zf.infolist()):
                            if i >= 100:
                                break
                            if not info.filename.startswith('__MACOSX/'):
                                file_list.append({
                                    'name': info.filename,
                                    'size': info.file_size,
                                    'compressed': info.compress_size,
                                    'is_dir': info.filename.endswith('/')
                                })
                            total_files += 1
                            total_size += info.file_size
                
                elif file_path.endswith('.tar') or file_path.endswith('.tar.gz') or file_path.endswith('.tgz'):
                    import tarfile
                    with tarfile.open(file_path, 'r:*') as tf:
                        for i, member in enumerate(tf.getmembers()):
                            if i >= 100:
                                break
                            file_list.append({
                                'name': member.name,
                                'size': member.size,
                                'is_dir': member.isdir()
                            })
                            total_files += 1
                            total_size += member.size
                
                result['has_preview'] = True
                result['info'] = {
                    'files': file_list,
                    'total_files': total_files,
                    'total_size': total_size,
                    'truncated': total_files > 100
                }
                
            except Exception as e:
                print(f"压缩包预览生成失败: {e}")
        
        elif 'font' in mime_type or original_filename.endswith(('.ttf', '.otf', '.woff', '.woff2', '.eot', '.hzk')):
            try:
                result['has_preview'] = True
                result['info'] = {'type': 'font', 'format': mime_type}
            except Exception as e:
                print(f"字体预览生成失败: {e}")
    
    except Exception as e:
        print(f"预览生成失败: {e}")
    
    return result


# ========== 获取文件信息 API ==========

@user_bp.route('/api/file/<int:file_id>/info')
def file_info(file_id):
    """获取文件信息（API）"""
    upload = user_bp.Uploads.query.get(file_id)
    if not upload or upload.is_deleted:
        return jsonify({'error': '文件不存在'}), 404
    
    current_uid = session.get('current_uid')
    if not upload.is_public and (not current_uid or current_uid != upload.uid):
        return jsonify({'error': '无权访问'}), 403
    
    file_path = os.path.join(current_app.config['UPLOAD_FOLDER'], upload.file_path)
    
    file_info_data = {
        'id': upload.id,
        'name': upload.original_filename,
        'size': upload.file_size,
        'size_formatted': format_file_size(upload.file_size),
        'mime_type': upload.mime_type,
        'category': upload.file_category,
        'created_at': upload.created_at.isoformat(),
        'downloads': upload.downloads,
        'description': upload.description,
        'has_preview': upload.has_preview,
        'preview_info': upload.preview_info,
        'is_public': upload.is_public
    }
    
    if os.path.exists(file_path):
        stat = os.stat(file_path)
        file_info_data['exists'] = True
        file_info_data['modified'] = datetime.fromtimestamp(stat.st_mtime).isoformat()
    else:
        file_info_data['exists'] = False
    
    return jsonify({
        'success': True,
        'data': file_info_data
    })


# ========== 点赞列表 API（修复版） ==========

@user_bp.route('/api/<int:uid>/likes')
def api_get_user_likes(uid):
    """修复版：获取指定用户的点赞列表（API）"""
    try:
        target_user = user_bp.UIDs.query.filter_by(uid=uid, status=True).first()
        if not target_user:
            return jsonify({'success': False, 'error': '用户不存在'}), 404

        current_uid = get_current_uid()
        if target_user.profile_visibility == 'private' and current_uid != uid:
            return jsonify({'success': False, 'error': '用户隐私设置不允许访问'}), 403

        page = request.args.get('page', 1, type=int)
        per_page = request.args.get('per_page', 10, type=int)

        likes_query = user_bp.Likes.query.filter_by(uid=uid)
        
        likes = likes_query.order_by(user_bp.Likes.created_at.desc())\
            .paginate(page=page, per_page=per_page, error_out=False)
        
        likes_data = []
        for like in likes.items:
            item_data = None
            target_type = like.target_type
            target_id = like.target_id
            
            if target_type == 'post':
                post = user_bp.Posts.query.get(target_id)
                if post and not post.is_deleted:
                    item_data = {
                        'type': 'post',
                        'target_id': post.id,
                        'title': post.title,
                        'url': f'/user/post/{post.id}'
                    }
            elif target_type == 'article':
                article = user_bp.Articles.query.get(target_id)
                if article and not article.is_deleted:
                    item_data = {
                        'type': 'article',
                        'target_id': article.arid,
                        'title': article.title,
                        'url': f'/user/article/{article.arid}'
                    }
            
            if item_data:
                likes_data.append({
                    'type': like.target_type,
                    'target_id': like.target_id,
                    'created_at': like.created_at.isoformat(),
                    'item': item_data
                })
        
        return jsonify({
            'success': True,
            'data': likes_data,
            'total': likes.total,
            'page': page,
            'per_page': per_page,
            'has_next': likes.has_next
        })
        
    except Exception as e:
        print(f"获取点赞列表失败: {e}")
        return jsonify({'success': False, 'error': '服务器内部错误'}), 500


# ========== 收藏列表 API（修复版） ==========

@user_bp.route('/api/<int:uid>/favorites')
def api_get_user_favorites(uid):
    """修复版：获取指定用户的收藏列表（API）"""
    try:
        target_user = user_bp.UIDs.query.filter_by(uid=uid, status=True).first()
        if not target_user:
            return jsonify({'success': False, 'error': '用户不存在'}), 404

        current_uid = get_current_uid()
        if target_user.profile_visibility == 'private' and current_uid != uid:
            return jsonify({'success': False, 'error': '用户隐私设置不允许访问'}), 403

        page = request.args.get('page', 1, type=int)
        per_page = request.args.get('per_page', 10, type=int)

        favorites_query = user_bp.Favorites.query.filter_by(uid=uid)
        
        favorites = favorites_query.order_by(user_bp.Favorites.created_at.desc())\
            .paginate(page=page, per_page=per_page, error_out=False)
        
        favorites_data = []
        for fav in favorites.items:
            item_data = None
            target_type = fav.target_type
            target_id = fav.target_id
            
            if target_type == 'post':
                post = user_bp.Posts.query.get(target_id)
                if post and not post.is_deleted:
                    item_data = {
                        'type': 'post',
                        'target_id': post.id,
                        'title': post.title,
                        'url': f'/user/post/{post.id}'
                    }
            elif target_type == 'article':
                article = user_bp.Articles.query.get(target_id)
                if article and not article.is_deleted:
                    item_data = {
                        'type': 'article',
                        'target_id': article.arid,
                        'title': article.title,
                        'url': f'/user/article/{article.arid}'
                    }
            
            if item_data:
                favorites_data.append({
                    'type': fav.target_type,
                    'target_id': fav.target_id,
                    'created_at': fav.created_at.isoformat(),
                    'item': item_data
                })
        
        return jsonify({
            'success': True,
            'data': favorites_data,
            'total': favorites.total,
            'page': page,
            'per_page': per_page,
            'has_next': favorites.has_next
        })
        
    except Exception as e:
        print(f"获取收藏列表失败: {e}")
        return jsonify({'success': False, 'error': '服务器内部错误'}), 500


# ========== UID 列表 API ==========

@user_bp.route('/api/uids')
def api_list_uids():
    """获取UID列表API（公开）"""
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 10, type=int)
    search = request.args.get('search', '')
    
    query = user_bp.UIDs.query.filter_by(status=True)
    
    if search:
        query = query.filter(user_bp.UIDs.nickname.contains(search))
    
    uids = query.order_by(user_bp.UIDs.created_at.desc())\
        .paginate(page=page, per_page=per_page, error_out=False)
    
    uids_data = []
    for uid in uids.items:
        uids_data.append({
            'uid': uid.uid,
            'nickname': uid.nickname,
            'level': uid.level,
            'bio': uid.bio[:100] + '...' if uid.bio and len(uid.bio) > 100 else uid.bio,
            'posts_count': uid.posts_count,
            'articles_count': uid.articles_count,
            'followers_count': uid.followers_count,
            'created_at': uid.created_at.strftime('%Y-%m-%d') if uid.created_at else None
        })
    
    return jsonify({
        'success': True,
        'data': uids_data,
        'total': uids.total,
        'page': page,
        'per_page': per_page,
        'has_next': uids.has_next,
        'has_prev': uids.has_prev
    })


# ========== 关注列表 API（公开） ==========

@user_bp.route('/api/following')
def api_get_user_following():
    """获取指定用户的关注列表（API）"""
    target_uid = request.args.get('uid')
    
    if not target_uid:
        return jsonify({'error': '缺少UID参数'}), 400
    
    try:
        target_uid = int(target_uid)
    except (TypeError, ValueError):
        return jsonify({'error': '无效的UID'}), 400
    
    target_user = user_bp.UIDs.query.get(target_uid)
    if not target_user:
        return jsonify({'error': '用户不存在'}), 404
    
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 20, type=int)
    
    follows = user_bp.Follows.query.filter_by(follower_uid=target_uid)\
        .order_by(user_bp.Follows.created_at.desc())\
        .paginate(page=page, per_page=per_page, error_out=False)
    
    following_data = []
    current_uid = session.get('current_uid')
    
    for follow in follows.items:
        following = user_bp.UIDs.query.get(follow.following_uid)
        if following and following.status:
            is_followed_by_current = False
            if current_uid:
                is_followed_by_current = user_bp.Follows.query.filter_by(
                    follower_uid=current_uid,
                    following_uid=following.uid
                ).first() is not None
            
            following_data.append({
                'uid': following.uid,
                'nickname': following.nickname,
                'level': following.level,
                'bio': following.bio[:100] + '...' if following.bio and len(following.bio) > 100 else following.bio,
                'avatar': None,
                'followed_at': follow.created_at.strftime('%Y-%m-%d %H:%M') if follow.created_at else None,
                'is_followed_by_current': is_followed_by_current
            })
    
    return jsonify({
        'success': True,
        'data': following_data,
        'total': follows.total,
        'page': page,
        'per_page': per_page,
        'has_next': follows.has_next,
        'has_prev': follows.has_prev
    })


@user_bp.route('/api/followers')
def api_get_user_followers():
    """获取指定用户的粉丝列表（API）"""
    target_uid = request.args.get('uid')
    
    if not target_uid:
        return jsonify({'error': '缺少UID参数'}), 400
    
    try:
        target_uid = int(target_uid)
    except (TypeError, ValueError):
        return jsonify({'error': '无效的UID'}), 400
    
    target_user = user_bp.UIDs.query.get(target_uid)
    if not target_user:
        return jsonify({'error': '用户不存在'}), 404
    
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 20, type=int)
    
    follows = user_bp.Follows.query.filter_by(following_uid=target_uid)\
        .order_by(user_bp.Follows.created_at.desc())\
        .paginate(page=page, per_page=per_page, error_out=False)
    
    followers_data = []
    current_uid = session.get('current_uid')
    
    for follow in follows.items:
        follower = user_bp.UIDs.query.get(follow.follower_uid)
        if follower and follower.status:
            is_followed_by_current = False
            if current_uid:
                is_followed_by_current = user_bp.Follows.query.filter_by(
                    follower_uid=current_uid,
                    following_uid=follower.uid
                ).first() is not None
            
            followers_data.append({
                'uid': follower.uid,
                'nickname': follower.nickname,
                'level': follower.level,
                'bio': follower.bio[:100] + '...' if follower.bio and len(follower.bio) > 100 else follower.bio,
                'avatar': None,
                'followed_at': follow.created_at.strftime('%Y-%m-%d %H:%M') if follow.created_at else None,
                'is_followed_by_current': is_followed_by_current
            })
    
    return jsonify({
        'success': True,
        'data': followers_data,
        'total': follows.total,
        'page': page,
        'per_page': per_page,
        'has_next': follows.has_next,
        'has_prev': follows.has_prev
    })

# ========== 悬赏接单系统 ==========

# ========== 辅助函数 ==========

def get_status_text(status):
    """获取状态文本"""
    status_map = {
        'pending': '待接单',
        'in_progress': '进行中',
        'completed': '待确认',
        'finalized': '已完成',
        'cancelled': '已取消',
        'disputed': '争议中'
    }
    return status_map.get(status, '未知')


# ========== 新悬赏系统 API（赏金池模式） ==========

from decimal import Decimal, getcontext
getcontext().prec = 10  # 设置Decimal精度

# ========== 辅助函数 ==========

def calculate_bounty_pools(total_points):
    """计算静态池和动态池（四六开）"""
    total = Decimal(str(total_points))
    static_pool = (total * Decimal('0.6')).quantize(Decimal('0.0'))
    dynamic_pool = (total * Decimal('0.4')).quantize(Decimal('0.0'))
    # 处理四舍五入导致的误差
    if static_pool + dynamic_pool != total:
        diff = total - (static_pool + dynamic_pool)
        static_pool += diff
    return static_pool, dynamic_pool


def is_privileged_uploader(bounty_id, uploader_uid):
    """检查是否是前三名上传者（特权）"""
    BountyUploads = user_bp.BountyUploads
    count = BountyUploads.query.filter_by(bounty_id=bounty_id).count()
    return count < 3  # 前三名有特权


def log_bounty_reward(bounty_id, upload_id, target_uid, reward_type, amount, snapshot_dynamic=None, snapshot_static=None):
    """记录奖励日志"""
    BountyRewardLogs = user_bp.BountyRewardLogs
    log = BountyRewardLogs(
        bounty_id=bounty_id,
        upload_id=upload_id,
        target_uid=target_uid,
        reward_type=reward_type,
        amount=Decimal(str(amount)),
        snapshot_dynamic_pool=Decimal(str(snapshot_dynamic)) if snapshot_dynamic else None,
        snapshot_static_pool=Decimal(str(snapshot_static)) if snapshot_static else None
    )
    user_bp.db.session.add(log)


# ========== 页面路由 ==========

@user_bp.route('/bounty')
def bounty_index():
    """悬赏系统首页"""
    return user_bp.renderTemplate('/base-files/bounty/index.html')


@user_bp.route('/bounty/create')
@login_required
@require_uid_only
@require_verified_email_web
def bounty_create_page(uid_record):
    """发布悬赏页面"""
    return user_bp.renderTemplate('/base-files/bounty/create.html', uid_record=uid_record)


@user_bp.route('/bounty/detail/<int:bounty_id>')
def bounty_detail_page(bounty_id):
    """悬赏详情页面"""
    return user_bp.renderTemplate('/base-files/bounty/detail.html', bounty_id=bounty_id)


@user_bp.route('/bounty/my')
@login_required
@require_uid_only
def bounty_my_page(uid_record):
    """我的悬赏页面"""
    return user_bp.renderTemplate('/base-files/bounty/my.html')


@user_bp.route('/bounty/my-uploads')
@login_required
@require_uid_only
def bounty_my_uploads_page(uid_record):
    """我上传的作品页面"""
    return user_bp.renderTemplate('/base-files/bounty/my-uploads.html', uid=uid_record)


# ========== API 路由 ==========

@user_bp.route('/api/bounty/create', methods=['POST'])
@login_required
@require_uid_only
@require_verified_email
def api_bounty_create(uid_record):
    """发布悬赏（支持 multipart/form-data + JSON 混合）"""
    try:
        # 检测 Content-Type，支持 JSON 和 FormData
        if request.content_type and 'application/json' in request.content_type:
            data = request.get_json()
            title = data.get('title', '').strip()
            description = data.get('description', '').strip()
            total_points = data.get('total_points', 0)
            constraint_type = data.get('constraint_type', 'max_uploaders')
            constraint_value = data.get('constraint_value', 0)
            no_deal_action = data.get('no_deal_action', 'refund')
            attachment_urls = data.get('attachments', [])
        else:
            # FormData 模式
            title = request.form.get('title', '').strip()
            description = request.form.get('description', '').strip()
            total_points = float(request.form.get('total_points', 0))
            constraint_type = request.form.get('constraint_type', 'max_uploaders')
            constraint_value = int(request.form.get('constraint_value', 0) or 0)
            no_deal_action = request.form.get('no_deal_action', 'refund')
            
            # 处理文件上传
            files = request.files.getlist('files')
            attachment_urls = []
            for file in files:
                if file and file.filename:
                    # 保存文件到临时目录
                    ext = os.path.splitext(file.filename)[1]
                    filename = f"{secrets.token_hex(16)}{ext}"
                    temp_dir = os.path.join(current_app.config['UPLOAD_FOLDER'], 'temp', str(current_user.id))
                    os.makedirs(temp_dir, exist_ok=True)
                    file_path = os.path.join(temp_dir, filename)
                    file.save(file_path)
                    attachment_urls.append(f"/uploads/temp/{current_user.id}/{filename}")
        
        # ========== 验证 ==========
        if not title or not description:
            return jsonify({'success': False, 'error': '请填写标题和描述'}), 400
        
        if len(title) > 200:
            return jsonify({'success': False, 'error': '标题不能超过200个字符'}), 400
        
        if len(description) > 5000:
            return jsonify({'success': False, 'error': '描述不能超过5000个字符'}), 400
        
        if total_points < 50:
            return jsonify({'success': False, 'error': '悬赏总积分至少为50'}), 400
        
        if total_points > 100000:
            return jsonify({'success': False, 'error': '悬赏总积分不能超过100000'}), 400
        
        # 检查积分是否足够
        if float(uid_record.points or 0) < total_points:
            return jsonify({'success': False, 'error': f'积分不足，当前仅有 {float(uid_record.points or 0)} 积分'}), 400
        
        # 验证约束类型
        if constraint_type not in ['max_uploaders', 'min_total_points']:
            constraint_type = 'max_uploaders'
        
        if constraint_type == 'max_uploaders' and constraint_value <= 0:
            constraint_value = 10
        elif constraint_type == 'min_total_points' and constraint_value <= 0:
            constraint_value = 100
        
        # ========== 计算赏金池 ==========
        total_dec = Decimal(str(total_points))
        static_pool = (total_dec * Decimal('0.6')).quantize(Decimal('0.0'))
        dynamic_pool = (total_dec * Decimal('0.4')).quantize(Decimal('0.0'))
        if static_pool + dynamic_pool != total_dec:
            diff = total_dec - (static_pool + dynamic_pool)
            static_pool += diff
        
        # ========== 创建悬赏 ==========
        BountyTasks = user_bp.BountyTasks
        new_bounty = BountyTasks(
            title=title,
            description=description,
            publisher_uid=uid_record.uid,
            total_points=float(total_dec),
            static_pool=float(static_pool),
            dynamic_pool=float(dynamic_pool),
            max_uploaders=constraint_value if constraint_type == 'max_uploaders' else 0,
            min_total_points=constraint_value if constraint_type == 'min_total_points' else 0,
            no_deal_action=no_deal_action,
            status='open',
            attachments=json.dumps(attachment_urls, ensure_ascii=False),
            created_at=datetime.now(),
            updated_at=datetime.now()
        )
        
        user_bp.db.session.add(new_bounty)
        
        # 扣除积分（托管）
        uid_record.points = float(uid_record.points or 0) - total_points
        
        # 记录积分历史
        record_points_history(
            user_id=current_user.id,
            amount=-total_points,
            type='bounty_publish',
            description=f'发布悬赏：{title[:50]}',
            target_uid=uid_record.uid,
            is_uid=True
        )
        
        user_bp.db.session.commit()
        
        return jsonify({
            'success': True,
            'message': '悬赏发布成功',
            'bounty_id': new_bounty.id,
            'url': url_for('user.bounty_detail_page', bounty_id=new_bounty.id)
        })
        
    except Exception as e:
        user_bp.db.session.rollback()
        print(f"发布悬赏失败: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({'success': False, 'error': str(e)}), 500


@user_bp.route('/api/bounty/<int:bounty_id>/upload', methods=['POST'])
@login_required
@require_uid_only
@require_verified_email
def api_bounty_upload(uid_record, bounty_id):
    """上传作品"""
    try:
        BountyTasks = user_bp.BountyTasks
        BountyUploads = user_bp.BountyUploads
        
        bounty = BountyTasks.query.get(bounty_id)
        if not bounty:
            return jsonify({'success': False, 'error': '悬赏不存在'}), 404
        
        if bounty.status != 'open':
            return jsonify({'success': False, 'error': '悬赏已结束，无法上传'}), 400
        
        # 检查最大上传人数限制
        if bounty.max_uploaders > 0:
            current_uploads = BountyUploads.query.filter_by(bounty_id=bounty_id).count()
            if current_uploads >= bounty.max_uploaders:
                return jsonify({'success': False, 'error': '已达最大上传人数限制'}), 400
        
        # 检查是否已经上传过
        existing = BountyUploads.query.filter_by(
            bounty_id=bounty_id,
            uploader_uid=uid_record.uid
        ).first()
        if existing:
            return jsonify({'success': False, 'error': '您已经上传过作品'}), 400
        
        # 获取上传文件
        if 'file' not in request.files:
            return jsonify({'success': False, 'error': '请选择文件'}), 400
        
        file = request.files['file']
        if file.filename == '':
            return jsonify({'success': False, 'error': '请选择文件'}), 400
        
        title = request.form.get('title', '').strip()
        description = request.form.get('description', '').strip()
        
        # 保存文件
        original_filename = secure_filename(file.filename)
        if not original_filename:
            original_filename = f"upload_{int(time.time())}.bin"
        
        file_hash = hashlib.md5(
            f"{original_filename}{time.time()}{secrets.token_hex(8)}".encode()
        ).hexdigest()[:16]
        
        name_parts = os.path.splitext(original_filename)
        safe_filename = f"{file_hash}{name_parts[1]}"
        
        upload_dir = os.path.join(
            current_app.config['UPLOAD_FOLDER'],
            'bounty',
            str(bounty_id)
        )
        os.makedirs(upload_dir, exist_ok=True)
        
        file_path = os.path.join(upload_dir, safe_filename)
        file.save(file_path)
        
        relative_path = f"bounty/{bounty_id}/{safe_filename}"
        file_size = os.path.getsize(file_path)
        
        # 计算上传奖励
        is_privileged = is_privileged_uploader(bounty_id, uid_record.uid)
        current_dynamic_pool = Decimal(str(bounty.dynamic_pool))
        
        if is_privileged:
            # 前三名：按总动态池的5%计算
            upload_reward = (Decimal(str(bounty.total_points)) * Decimal('0.4') * Decimal('0.05')).quantize(Decimal('0.00'))
        else:
            # 第四名及以后：按当前动态池的5%计算
            upload_reward = (current_dynamic_pool * Decimal('0.05')).quantize(Decimal('0.00'))
        
        # 从动态池扣除上传奖励
        bounty.dynamic_pool = float(current_dynamic_pool - upload_reward)
        
        # 创建上传记录
        new_upload = BountyUploads(
            bounty_id=bounty_id,
            uploader_uid=uid_record.uid,
            title=title or original_filename,
            description=description,
            file_path=relative_path,
            file_size=file_size,
            upload_reward=float(upload_reward),
            total_reward=float(upload_reward),
            is_privileged=is_privileged,
            status='pending',
            created_at=datetime.now()
        )
        
        user_bp.db.session.add(new_upload)
        user_bp.db.session.flush()
        
        # 记录奖励日志
        log_bounty_reward(
            bounty_id=bounty_id,
            upload_id=new_upload.id,
            target_uid=uid_record.uid,
            reward_type='upload',
            amount=upload_reward,
            snapshot_dynamic=bounty.dynamic_pool + float(upload_reward)
        )
        
        # 转账上传奖励给上传者
        uid_record.points = float(uid_record.points or 0) + float(upload_reward)
        
        # 记录积分历史
        record_points_history(
            user_id=current_user.id,
            amount=upload_reward,
            type='bounty_upload',
            description=f'上传作品到悬赏：{bounty.title[:30]}',
            target_uid=uid_record.uid,
            is_uid=True
        )
        
        # 如果达到最大人数，设置过期时间（3天后）
        if bounty.max_uploaders > 0:
            current_count = BountyUploads.query.filter_by(bounty_id=bounty_id).count()
            if current_count >= bounty.max_uploaders and not bounty.expired_at:
                bounty.expired_at = datetime.now() + timedelta(days=3)
        
        user_bp.db.session.commit()
        
        return jsonify({
            'success': True,
            'message': '作品上传成功',
            'upload_id': new_upload.id,
            'upload_reward': float(upload_reward)
        })
        
    except Exception as e:
        user_bp.db.session.rollback()
        print(f"上传作品失败: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({'success': False, 'error': str(e)}), 500


@user_bp.route('/api/bounty/<int:bounty_id>/view/<int:upload_id>', methods=['POST'])
@login_required
@require_uid_only
@require_verified_email
def api_bounty_view(uid_record, bounty_id, upload_id):
    """悬赏者查看作品（支付查看费）"""
    try:
        BountyTasks = user_bp.BountyTasks
        BountyUploads = user_bp.BountyUploads
        
        bounty = BountyTasks.query.get(bounty_id)
        if not bounty:
            return jsonify({'success': False, 'error': '悬赏不存在'}), 404
        
        # 验证当前用户是悬赏者
        if bounty.publisher_uid != uid_record.uid:
            return jsonify({'success': False, 'error': '只有发布者可以查看作品'}), 403
        
        if bounty.status != 'open':
            return jsonify({'success': False, 'error': '悬赏已结束'}), 400
        
        upload = BountyUploads.query.get(upload_id)
        if not upload or upload.bounty_id != bounty_id:
            return jsonify({'success': False, 'error': '作品不存在'}), 404
        
        if upload.is_viewed:
            return jsonify({'success': False, 'error': '已经查看过该作品'}), 400
        
        # 计算查看奖励
        current_dynamic_pool = Decimal(str(bounty.dynamic_pool))
        view_reward = (current_dynamic_pool * Decimal('0.2')).quantize(Decimal('0.00'))
        
        upload_reward = Decimal(str(upload.upload_reward))
        
        if view_reward > upload_reward:
            # 补差额
            extra_reward = view_reward - upload_reward
            upload.view_reward = float(extra_reward)
            upload.total_reward = float(view_reward)
        else:
            # 查看费小于已给上传奖，不补（已给的不退）
            extra_reward = Decimal('0')
            upload.view_reward = float(Decimal('0'))
            upload.total_reward = float(upload_reward)
        
        # 从动态池扣除查看奖励
        bounty.dynamic_pool = float(current_dynamic_pool - view_reward)
        
        # 更新上传记录
        upload.is_viewed = True
        upload.viewed_at = datetime.now()
        
        # 获取当前查看顺序
        view_count = BountyUploads.query.filter_by(
            bounty_id=bounty_id,
            is_viewed=True
        ).count()
        upload.view_order = view_count
        
        if extra_reward > 0:
            # 转账额外奖励给上传者
            uploader = user_bp.UIDs.query.get(upload.uploader_uid)
            if uploader:
                uploader.points = float(uploader.points or 0) + float(extra_reward)
                
                # 记录积分历史
                record_points_history(
                    user_id=uploader.id,
                    amount=extra_reward,
                    type='bounty_view',
                    description=f'作品被查看奖励（悬赏：{bounty.title[:30]}）',
                    target_uid=uploader.uid,
                    is_uid=True
                )
        
        # 记录奖励日志
        log_bounty_reward(
            bounty_id=bounty_id,
            upload_id=upload_id,
            target_uid=upload.uploader_uid,
            reward_type='view',
            amount=view_reward,
            snapshot_dynamic=bounty.dynamic_pool + float(view_reward)
        )
        
        user_bp.db.session.commit()
        
        return jsonify({
            'success': True,
            'message': '查看成功',
            'view_reward': float(view_reward),
            'extra_reward': float(extra_reward),
            'remaining_dynamic_pool': bounty.dynamic_pool
        })
        
    except Exception as e:
        user_bp.db.session.rollback()
        print(f"查看作品失败: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({'success': False, 'error': str(e)}), 500


@user_bp.route('/api/bounty/<int:bounty_id>/select/<int:upload_id>', methods=['POST'])
@login_required
@require_uid_only
@require_verified_email
def api_bounty_select(uid_record, bounty_id, upload_id):
    """选择成交者（结束悬赏）"""
    try:
        BountyTasks = user_bp.BountyTasks
        BountyUploads = user_bp.BountyUploads
        
        bounty = BountyTasks.query.get(bounty_id)
        if not bounty:
            return jsonify({'success': False, 'error': '悬赏不存在'}), 404
        
        # 验证当前用户是悬赏者
        if bounty.publisher_uid != uid_record.uid:
            return jsonify({'success': False, 'error': '只有发布者可以选择成交者'}), 403
        
        if bounty.status != 'open':
            return jsonify({'success': False, 'error': '悬赏已结束'}), 400
        
        upload = BountyUploads.query.get(upload_id)
        if not upload or upload.bounty_id != bounty_id:
            return jsonify({'success': False, 'error': '作品不存在'}), 404
        
        # 计算成交者所得 = 静态池 + 动态池剩余
        winner_reward = Decimal(str(bounty.static_pool)) + Decimal(str(bounty.dynamic_pool))
        
        # 转账给成交者
        winner = user_bp.UIDs.query.get(upload.uploader_uid)
        if winner:
            winner.points = float(winner.points or 0) + float(winner_reward)
            
            # 记录积分历史
            record_points_history(
                user_id=winner.id,
                amount=winner_reward,
                type='bounty_win',
                description=f'赢得悬赏：{bounty.title[:30]}',
                target_uid=winner.uid,
                is_uid=True
            )
        
        # 计算平台手续费
        total_paid = Decimal('0')
        all_uploads = BountyUploads.query.filter_by(bounty_id=bounty_id).all()
        for u in all_uploads:
            total_paid += Decimal(str(u.total_reward))
        total_paid += winner_reward
        
        platform_fee = Decimal(str(bounty.total_points)) - total_paid
        
        # 更新悬赏状态
        bounty.winner_uid = upload.uploader_uid
        bounty.completed_at = datetime.now()
        bounty.status = 'closed'
        
        # 更新上传记录状态
        upload.status = 'selected'
        
        # 标记其他作品为未选中
        BountyUploads.query.filter_by(bounty_id=bounty_id).filter(
            BountyUploads.id != upload_id
        ).update({'status': 'rejected'})
        
        # 记录成交日志
        log_bounty_reward(
            bounty_id=bounty_id,
            upload_id=upload_id,
            target_uid=upload.uploader_uid,
            reward_type='win',
            amount=winner_reward,
            snapshot_dynamic=bounty.dynamic_pool,
            snapshot_static=bounty.static_pool
        )
        
        # 如果有平台手续费，记录（归平台）
        if platform_fee > 0:
            # 可以记录到系统账户或日志
            print(f"平台手续费: {platform_fee} (悬赏 {bounty_id})")
        
        user_bp.db.session.commit()
        
        return jsonify({
            'success': True,
            'message': f'已选择 {winner.nickname if winner else "用户"} 作为成交者',
            'winner_reward': float(winner_reward),
            'platform_fee': float(platform_fee)
        })
        
    except Exception as e:
        user_bp.db.session.rollback()
        print(f"选择成交者失败: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({'success': False, 'error': str(e)}), 500


@user_bp.route('/api/bounty/<int:bounty_id>/append', methods=['POST'])
@login_required
@require_uid_only
@require_verified_email
def api_bounty_append(uid_record, bounty_id):
    """追加静态池"""
    try:
        data = request.get_json()
        add_points = data.get('add_points', 0)
        
        if add_points <= 0:
            return jsonify({'success': False, 'error': '追加积分必须大于0'}), 400
        
        if add_points > 100000:
            return jsonify({'success': False, 'error': '单次追加不能超过100000积分'}), 400
        
        BountyTasks = user_bp.BountyTasks
        BountyAppendLogs = user_bp.BountyAppendLogs
        
        bounty = BountyTasks.query.get(bounty_id)
        if not bounty:
            return jsonify({'success': False, 'error': '悬赏不存在'}), 404
        
        # 验证当前用户是悬赏者
        if bounty.publisher_uid != uid_record.uid:
            return jsonify({'success': False, 'error': '只有发布者可以追加赏金'}), 403
        
        if bounty.status != 'open':
            return jsonify({'success': False, 'error': '悬赏已结束，无法追加'}), 400
        
        # 检查积分是否足够
        if float(uid_record.points or 0) < add_points:
            return jsonify({'success': False, 'error': f'积分不足，当前仅有 {float(uid_record.points or 0)} 积分'}), 400
        
        # 追加积分
        add_dec = Decimal(str(add_points))
        
        # 追加的积分按四六开分配
        new_static = Decimal(str(bounty.static_pool)) + (add_dec * Decimal('0.6'))
        new_total = Decimal(str(bounty.total_points)) + add_dec
        
        bounty.static_pool = float(new_static)
        bounty.total_points = float(new_total)
        
        # 扣除用户积分
        uid_record.points = float(uid_record.points or 0) - add_points
        
        # 记录追加日志
        append_log = BountyAppendLogs(
            bounty_id=bounty_id,
            added_points=add_points,
            new_static_pool=bounty.static_pool,
            new_total_points=bounty.total_points,
            append_uid=uid_record.uid
        )
        user_bp.db.session.add(append_log)
        
        # 记录积分历史
        record_points_history(
            user_id=uid_record.id,
            amount=-add_points,
            type='bounty_append',
            description=f'追加悬赏赏金：{bounty.title[:30]}',
            target_uid=uid_record.uid,
            is_uid=True
        )
        
        user_bp.db.session.commit()
        
        return jsonify({
            'success': True,
            'message': f'成功追加 {add_points} 积分',
            'new_total_points': bounty.total_points,
            'new_static_pool': bounty.static_pool
        })
        
    except Exception as e:
        user_bp.db.session.rollback()
        print(f"追加赏金失败: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@user_bp.route('/api/bounty/<int:bounty_id>/close', methods=['POST'])
@login_required
@require_uid_only
def api_bounty_close(uid_record, bounty_id):
    """关闭悬赏（无人成交处理）"""
    try:
        data = request.get_json()
        action = data.get('action')  # 'refund' 或 'distribute'
        
        BountyTasks = user_bp.BountyTasks
        BountyUploads = user_bp.BountyUploads
        
        bounty = BountyTasks.query.get(bounty_id)
        if not bounty:
            return jsonify({'success': False, 'error': '悬赏不存在'}), 404
        
        # 验证当前用户是悬赏者
        if bounty.publisher_uid != uid_record.uid:
            return jsonify({'success': False, 'error': '只有发布者可以关闭悬赏'}), 403
        
        if bounty.status != 'open':
            return jsonify({'success': False, 'error': '悬赏已结束'}), 400
        
        uploads = BountyUploads.query.filter_by(bounty_id=bounty_id).all()
        total_uploads = len(uploads)
        
        if total_uploads == 0:
            # 无人上传，全额退还
            publisher = user_bp.UIDs.query.get(bounty.publisher_uid)
            if publisher:
                publisher.points = float(publisher.points or 0) + float(bounty.total_points)
                
                record_points_history(
                    user_id=publisher.id,
                    amount=bounty.total_points,
                    type='bounty_refund',
                    description=f'悬赏无人上传，全额退还：{bounty.title[:30]}',
                    target_uid=bounty.publisher_uid,
                    is_uid=True
                )
            
            bounty.status = 'cancelled'
            user_bp.db.session.commit()
            
            return jsonify({'success': True, 'message': '悬赏已取消，积分已全额退还'})
        
        if action == 'refund':
            # 扣除5%后返还给悬赏者
            refund_rate = Decimal('0.95')
            refund_amount = Decimal(str(bounty.total_points)) * refund_rate
            
            publisher = user_bp.UIDs.query.get(bounty.publisher_uid)
            if publisher:
                publisher.points = float(publisher.points or 0) + float(refund_amount)
                
                record_points_history(
                    user_id=publisher.id,
                    amount=refund_amount,
                    type='bounty_refund',
                    description=f'悬赏无人成交，退还95%：{bounty.title[:30]}',
                    target_uid=bounty.publisher_uid,
                    is_uid=True
                )
            
            bounty.status = 'expired'
            
        elif action == 'distribute':
            # 扣除5%分配给所有上传者
            distribute_rate = Decimal('0.05')
            distribute_amount = Decimal(str(bounty.total_points)) * distribute_rate
            
            if total_uploads > 0:
                per_uploader = distribute_amount / Decimal(str(total_uploads))
                
                for upload in uploads:
                    uploader = user_bp.UIDs.query.get(upload.uploader_uid)
                    if uploader:
                        uploader.points = float(uploader.points or 0) + float(per_uploader)
                        
                        record_points_history(
                            user_id=uploader.id,
                            amount=per_uploader,
                            type='bounty_distribute',
                            description=f'悬赏无人成交，分配补偿：{bounty.title[:30]}',
                            target_uid=uploader.uid,
                            is_uid=True
                        )
            
            # 剩余积分退还悬赏者
            remaining = Decimal(str(bounty.total_points)) - distribute_amount
            publisher = user_bp.UIDs.query.get(bounty.publisher_uid)
            if publisher:
                publisher.points = float(publisher.points or 0) + float(remaining)
            
            bounty.status = 'expired'
        
        else:
            return jsonify({'success': False, 'error': '无效的操作'}), 400
        
        user_bp.db.session.commit()
        
        return jsonify({'success': True, 'message': '悬赏已处理'})
        
    except Exception as e:
        user_bp.db.session.rollback()
        print(f"关闭悬赏失败: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@user_bp.route('/api/bounty/list', methods=['GET'])
def api_bounty_list_new():
    """获取悬赏列表（新版）"""
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 12, type=int)
    status = request.args.get('status', 'open')
    sort = request.args.get('sort', 'latest')
    search = request.args.get('search', '').strip()
    
    BountyTasks = user_bp.BountyTasks
    BountyUploads = user_bp.BountyUploads
    
    query = BountyTasks.query
    
    if status == 'open':
        query = query.filter(BountyTasks.status == 'open')
    elif status == 'closed':
        query = query.filter(BountyTasks.status == 'closed')
    elif status == 'expired':
        query = query.filter(BountyTasks.status == 'expired')
    elif status == 'cancelled':
        query = query.filter(BountyTasks.status == 'cancelled')
    elif status == 'all':
        pass
    else:
        query = query.filter(BountyTasks.status == 'open')
    
    if search:
        query = query.filter(
            (BountyTasks.title.contains(search)) |
            (BountyTasks.description.contains(search))
        )
    
    if sort == 'hot':
        query = query.order_by(BountyTasks.total_points.desc())
    elif sort == 'deadline':
        query = query.order_by(BountyTasks.expired_at.asc())
    else:
        query = query.order_by(BountyTasks.created_at.desc())
    
    pagination = query.paginate(page=page, per_page=per_page, error_out=False)
    
    tasks_data = []
    for task in pagination.items:
        publisher = user_bp.UIDs.query.get(task.publisher_uid)
        upload_count = BountyUploads.query.filter_by(bounty_id=task.id).count()
        
        tasks_data.append({
            'id': task.id,
            'title': task.title,
            'description': task.description[:150] + '...' if len(task.description) > 150 else task.description,
            'total_points': float(task.total_points),
            'static_pool': float(task.static_pool),
            'dynamic_pool': float(task.dynamic_pool),
            'status': task.status,
            'max_uploaders': task.max_uploaders,
            'upload_count': upload_count,
            'created_at': task.created_at.strftime('%Y-%m-%d %H:%M'),
            'expired_at': task.expired_at.strftime('%Y-%m-%d %H:%M') if task.expired_at else None,
            'publisher': {
                'uid': publisher.uid if publisher else None,
                'nickname': publisher.nickname if publisher else '已注销',
                'level': publisher.level if publisher else 0
            } if publisher else None
        })
    
    return jsonify({
        'success': True,
        'data': tasks_data,
        'total': pagination.total,
        'page': page,
        'per_page': per_page,
        'total_pages': pagination.pages,
        'has_next': pagination.has_next,
        'has_prev': pagination.has_prev
    })


@user_bp.route('/api/bounty/<int:bounty_id>/detail', methods=['GET'])
def api_bounty_detail_new(bounty_id):
    """获取悬赏详情（新版）"""
    BountyTasks = user_bp.BountyTasks
    BountyUploads = user_bp.BountyUploads
    
    bounty = BountyTasks.query.get(bounty_id)
    if not bounty:
        return jsonify({'success': False, 'error': '悬赏不存在'}), 404
    
    publisher = user_bp.UIDs.query.get(bounty.publisher_uid)
    winner = user_bp.UIDs.query.get(bounty.winner_uid) if bounty.winner_uid else None
    
    # 获取作品列表
    uploads = BountyUploads.query.filter_by(bounty_id=bounty_id).order_by(
        BountyUploads.created_at.asc()
    ).all()
    
    current_uid = session.get('current_uid')
    is_publisher = current_uid == bounty.publisher_uid
    
    uploads_data = []
    for upload in uploads:
        uploader = user_bp.UIDs.query.get(upload.uploader_uid)
        
        # 非发布者只能看到已查看的作品的基本信息
        can_view_detail = is_publisher or upload.is_viewed
        
        uploads_data.append({
            'id': upload.id,
            'title': upload.title,
            'description': upload.description,
            'file_path': upload.file_path if can_view_detail else None,
            'file_size': upload.file_size,
            'upload_reward': float(upload.upload_reward),
            'view_reward': float(upload.view_reward),
            'total_reward': float(upload.total_reward),
            'is_viewed': upload.is_viewed,
            'view_order': upload.view_order,
            'status': upload.status,
            'is_privileged': upload.is_privileged,
            'created_at': upload.created_at.strftime('%Y-%m-%d %H:%M'),
            'uploader': {
                'uid': uploader.uid if uploader else None,
                'nickname': uploader.nickname if uploader else '已注销',
                'level': uploader.level if uploader else 0
            } if can_view_detail else None
        })
    
    return jsonify({
        'success': True,
        'data': {
            'id': bounty.id,
            'title': bounty.title,
            'description': bounty.description,
            'total_points': float(bounty.total_points),
            'static_pool': float(bounty.static_pool),
            'dynamic_pool': float(bounty.dynamic_pool),
            'status': bounty.status,
            'max_uploaders': bounty.max_uploaders,
            'min_total_points': float(bounty.min_total_points) if bounty.min_total_points else None,
            'no_deal_action': bounty.no_deal_action,
            'created_at': bounty.created_at.strftime('%Y-%m-%d %H:%M'),
            'updated_at': bounty.updated_at.strftime('%Y-%m-%d %H:%M') if bounty.updated_at else None,
            'expired_at': bounty.expired_at.strftime('%Y-%m-%d %H:%M') if bounty.expired_at else None,
            'completed_at': bounty.completed_at.strftime('%Y-%m-%d %H:%M') if bounty.completed_at else None,
            'attachments': json.loads(bounty.attachments) if bounty.attachments else [],
            'publisher': {
                'uid': publisher.uid if publisher else None,
                'nickname': publisher.nickname if publisher else '已注销',
                'level': publisher.level if publisher else 0,
                'bio': publisher.bio if publisher else None
            } if publisher else None,
            'winner': {
                'uid': winner.uid if winner else None,
                'nickname': winner.nickname if winner else None
            } if winner else None,
            'uploads': uploads_data,
            'is_publisher': is_publisher,
            'can_upload': not is_publisher and bounty.status == 'open'
        }
    })


@user_bp.route('/api/bounty/my/published', methods=['GET'])
@login_required
@require_uid_only
def api_bounty_my_published_new(uid_record):
    """我发布的悬赏（新版）"""
    BountyTasks = user_bp.BountyTasks
    BountyUploads = user_bp.BountyUploads
    
    tasks = BountyTasks.query.filter_by(publisher_uid=uid_record.uid)\
        .order_by(BountyTasks.created_at.desc()).all()
    
    tasks_data = []
    for task in tasks:
        upload_count = BountyUploads.query.filter_by(bounty_id=task.id).count()
        tasks_data.append({
            'id': task.id,
            'title': task.title,
            'total_points': float(task.total_points),
            'static_pool': float(task.static_pool),
            'dynamic_pool': float(task.dynamic_pool),
            'status': task.status,
            'upload_count': upload_count,
            'max_uploaders': task.max_uploaders,
            'created_at': task.created_at.strftime('%Y-%m-%d %H:%M'),
            'expired_at': task.expired_at.strftime('%Y-%m-%d %H:%M') if task.expired_at else None,
            'winner_uid': task.winner_uid
        })
    
    return jsonify({
        'success': True,
        'data': tasks_data
    })


@user_bp.route('/api/bounty/my/uploads', methods=['GET'])
@login_required
@require_uid_only
def api_bounty_my_uploads(uid_record):
    """我上传的作品列表"""
    BountyUploads = user_bp.BountyUploads
    
    uploads = BountyUploads.query.filter_by(uploader_uid=uid_record.uid)\
        .order_by(BountyUploads.created_at.desc()).all()
    
    uploads_data = []
    for upload in uploads:
        bounty = user_bp.BountyTasks.query.get(upload.bounty_id)
        uploads_data.append({
            'id': upload.id,
            'bounty_id': upload.bounty_id,
            'bounty_title': bounty.title if bounty else '悬赏已删除',
            'bounty_status': bounty.status if bounty else 'unknown',
            'title': upload.title,
            'description': upload.description,
            'upload_reward': float(upload.upload_reward),
            'view_reward': float(upload.view_reward),
            'total_reward': float(upload.total_reward),
            'is_viewed': upload.is_viewed,
            'status': upload.status,
            'created_at': upload.created_at.strftime('%Y-%m-%d %H:%M')
        })
    
    return jsonify({
        'success': True,
        'data': uploads_data
    })


@user_bp.route('/api/bounty/<int:bounty_id>/uploads/<int:upload_id>/download')
@login_required
@require_uid_only
def api_bounty_download_file(uid_record, bounty_id, upload_id):
    """下载悬赏作品文件"""
    BountyTasks = user_bp.BountyTasks
    BountyUploads = user_bp.BountyUploads
    
    bounty = BountyTasks.query.get(bounty_id)
    if not bounty:
        return jsonify({'error': '悬赏不存在'}), 404
    
    upload = BountyUploads.query.get(upload_id)
    if not upload or upload.bounty_id != bounty_id:
        return jsonify({'error': '文件不存在'}), 404
    
    # 只有悬赏者或作品上传者可以下载
    if uid_record.uid != bounty.publisher_uid and uid_record.uid != upload.uploader_uid:
        return jsonify({'error': '无权下载'}), 403
    
    # 如果是上传者自己下载，不需要查看过
    # 如果是悬赏者下载，需要已经查看过该作品
    if uid_record.uid == bounty.publisher_uid and not upload.is_viewed:
        return jsonify({'error': '请先查看作品后再下载'}), 403
    
    file_path = os.path.join(current_app.config['UPLOAD_FOLDER'], upload.file_path)
    
    if not os.path.exists(file_path):
        return jsonify({'error': '文件不存在'}), 404
    
    return send_file(
        file_path,
        as_attachment=True,
        download_name=upload.title or 'download'
    )


@user_bp.route('/api/upload/temp', methods=['POST'])
@login_required
@require_uid_only
def api_temp_upload(uid_record):
    """临时上传文件（用于发布悬赏时的附件）"""
    try:
        if 'file' not in request.files:
            return jsonify({'success': False, 'error': '没有文件'}), 400
        
        file = request.files['file']
        if file.filename == '':
            return jsonify({'success': False, 'error': '没有选择文件'}), 400
        
        # 生成唯一文件名
        ext = os.path.splitext(file.filename)[1]
        filename = f"{secrets.token_hex(16)}{ext}"
        
        # 保存到临时目录
        temp_dir = os.path.join(current_app.config['UPLOAD_FOLDER'], 'temp', str(current_user.id))
        os.makedirs(temp_dir, exist_ok=True)
        
        file_path = os.path.join(temp_dir, filename)
        file.save(file_path)
        
        # 返回可访问的URL
        url = f"/uploads/temp/{current_user.id}/{filename}"
        
        return jsonify({
            'success': True,
            'url': url,
            'filename': filename
        })
        
    except Exception as e:
        print(f"临时上传失败: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


# ========== 好友系统 ==========

@user_bp.route('/api/friends/request', methods=['POST'])
@login_required
@require_uid_only
def send_friend_request(uid_record):
    """发送好友申请"""
    try:
        data = request.get_json()
        to_uid = data.get('to_uid')
        message = data.get('message', '').strip()[:200]
        
        if not to_uid:
            return jsonify({'success': False, 'error': '缺少接收者'}), 400
        
        if to_uid == uid_record.uid:
            return jsonify({'success': False, 'error': '不能添加自己为好友'}), 400
        
        target = user_bp.UIDs.query.get(to_uid)
        if not target or not target.status:
            return jsonify({'success': False, 'error': '用户不存在'}), 404
        
        # 检查是否已经是好友
        existing_friend = user_bp.Friends.query.filter(
            ((user_bp.Friends.user_uid == uid_record.uid) & (user_bp.Friends.friend_uid == to_uid)) |
            ((user_bp.Friends.user_uid == to_uid) & (user_bp.Friends.friend_uid == uid_record.uid))
        ).first()
        
        if existing_friend:
            if existing_friend.status == 'accepted':
                return jsonify({'success': False, 'error': '已经是好友关系'}), 400
            elif existing_friend.status == 'pending':
                return jsonify({'success': False, 'error': '已有待处理的好友申请'}), 400
        
        # 检查是否在黑名单中
        blocked = user_bp.BlockList.query.filter(
            ((user_bp.BlockList.blocker_uid == to_uid) & (user_bp.BlockList.blocked_uid == uid_record.uid))
        ).first()
        
        if blocked:
            return jsonify({'success': False, 'error': '对方已将您拉黑'}), 403
        
        # 创建好友申请
        friend_request = user_bp.FriendRequests(
            from_uid=uid_record.uid,
            to_uid=to_uid,
            message=message,
            status='pending',
            created_at=datetime.now()
        )
        user_bp.db.session.add(friend_request)
        
        # 创建好友关系（pending 状态）
        friendship = user_bp.Friends(
            user_uid=uid_record.uid,
            friend_uid=to_uid,
            status='pending',
            created_at=datetime.now()
        )
        user_bp.db.session.add(friendship)
        
        # 发送系统私信通知（使用扩展后的 Messages 表）
        system_msg = user_bp.Messages(
            from_uid=uid_record.uid,
            to_uid=to_uid,
            content=f'📨 用户 {uid_record.nickname} 向您发送了好友申请{"：" + message if message else ""}',
            is_system=True,
            message_type='friend_request',
            created_at=datetime.now()
        )
        user_bp.db.session.add(system_msg)
        user_bp.db.session.flush()
        
        # 更新会话
        conv = user_bp.Conversations.query.filter_by(
            user_uid=to_uid,
            other_uid=uid_record.uid
        ).first()
        
        if not conv:
            conv = user_bp.Conversations(
                user_uid=to_uid,
                other_uid=uid_record.uid,
                last_message_id=system_msg.id,
                unread_count=1,
                updated_at=datetime.now(),
                conversation_type='normal'
            )
            user_bp.db.session.add(conv)
        
        user_bp.db.session.commit()
        
        return jsonify({'success': True, 'message': '好友申请已发送'})
        
    except Exception as e:
        user_bp.db.session.rollback()
        print(f"发送好友申请失败: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@user_bp.route('/api/friends/requests', methods=['GET'])
@login_required
@require_uid_only
def get_friend_requests(uid_record):
    """获取好友申请列表"""
    try:
        pending_requests = user_bp.FriendRequests.query.filter_by(
            to_uid=uid_record.uid,
            status='pending'
        ).order_by(user_bp.FriendRequests.created_at.desc()).all()
        
        pending_data = []
        for req in pending_requests:
            from_user = user_bp.UIDs.query.get(req.from_uid)
            if from_user:
                pending_data.append({
                    'id': req.id,
                    'from_uid': from_user.uid,
                    'nickname': from_user.nickname,
                    'level': from_user.level,
                    'message': req.message,
                    'created_at': req.created_at.strftime('%Y-%m-%d %H:%M')
                })
        
        return jsonify({'success': True, 'data': pending_data})
        
    except Exception as e:
        print(f"获取好友申请失败: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@user_bp.route('/api/friends/request/<int:request_id>/<string:action>', methods=['POST'])
@login_required
@require_uid_only
def handle_friend_request(uid_record, request_id, action):
    """处理好友申请（accept/reject）"""
    try:
        if action not in ['accept', 'reject']:
            return jsonify({'success': False, 'error': '无效的操作'}), 400
        
        friend_request = user_bp.FriendRequests.query.get(request_id)
        if not friend_request:
            return jsonify({'success': False, 'error': '申请不存在'}), 404
        
        if friend_request.to_uid != uid_record.uid:
            return jsonify({'success': False, 'error': '无权操作'}), 403
        
        if friend_request.status != 'pending':
            return jsonify({'success': False, 'error': '申请已处理'}), 400
        
        friend_request.status = 'accepted' if action == 'accept' else 'rejected'
        friend_request.responded_at = datetime.now()
        
        # 更新好友关系
        friendship = user_bp.Friends.query.filter_by(
            user_uid=friend_request.from_uid,
            friend_uid=friend_request.to_uid
        ).first()
        
        if friendship:
            friendship.status = 'accepted' if action == 'accept' else 'rejected'
            friendship.updated_at = datetime.now()
        
        if action == 'accept':
            # 创建反向好友关系
            friendship_reverse = user_bp.Friends(
                user_uid=friend_request.to_uid,
                friend_uid=friend_request.from_uid,
                status='accepted',
                created_at=datetime.now()
            )
            user_bp.db.session.add(friendship_reverse)
            
            # 更新会话为好友会话
            conv1 = user_bp.Conversations.query.filter_by(
                user_uid=friend_request.from_uid,
                other_uid=friend_request.to_uid
            ).first()
            if conv1:
                conv1.conversation_type = 'friend'
                conv1.is_friend = True
            
            conv2 = user_bp.Conversations.query.filter_by(
                user_uid=friend_request.to_uid,
                other_uid=friend_request.from_uid
            ).first()
            if conv2:
                conv2.conversation_type = 'friend'
                conv2.is_friend = True
            
            # 发送系统通知
            system_msg = user_bp.Messages(
                from_uid=uid_record.uid,
                to_uid=friend_request.from_uid,
                content=f'✅ 用户 {uid_record.nickname} 接受了您的好友申请',
                is_system=True,
                message_type='friend_request',
                created_at=datetime.now()
            )
            user_bp.db.session.add(system_msg)
        
        user_bp.db.session.commit()
        
        return jsonify({'success': True, 'message': f'已{action == "accept" and "接受" or "拒绝"}好友申请'})
        
    except Exception as e:
        user_bp.db.session.rollback()
        print(f"处理好友申请失败: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@user_bp.route('/api/friends/list', methods=['GET'])
@login_required
@require_uid_only
def get_friends_list(uid_record):
    """获取好友列表"""
    try:
        friendships = user_bp.Friends.query.filter_by(
            user_uid=uid_record.uid,
            status='accepted'
        ).order_by(user_bp.Friends.created_at.desc()).all()
        
        friends_data = []
        for friendship in friendships:
            friend = user_bp.UIDs.query.get(friendship.friend_uid)
            if friend and friend.status:
                conv = user_bp.Conversations.query.filter_by(
                    user_uid=uid_record.uid,
                    other_uid=friend.uid
                ).first()
                
                friends_data.append({
                    'uid': friend.uid,
                    'nickname': friend.nickname,
                    'level': friend.level,
                    'bio': friend.bio,
                    'online_status': friend.online_status,
                    'last_message': conv.last_message.content[:50] if conv and conv.last_message else None,
                    'last_message_time': conv.updated_at.strftime('%Y-%m-%d %H:%M') if conv else None,
                    'unread_count': conv.unread_count if conv else 0
                })
        
        return jsonify({'success': True, 'data': friends_data})
        
    except Exception as e:
        print(f"获取好友列表失败: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@user_bp.route('/api/friends/delete', methods=['POST'])
@login_required
@require_uid_only
def delete_friend(uid_record):
    """删除好友"""
    try:
        data = request.get_json()
        friend_uid = data.get('uid')
        
        if not friend_uid:
            return jsonify({'success': False, 'error': '缺少参数'}), 400
        
        # 删除双向好友关系
        user_bp.Friends.query.filter(
            ((user_bp.Friends.user_uid == uid_record.uid) & (user_bp.Friends.friend_uid == friend_uid)) |
            ((user_bp.Friends.user_uid == friend_uid) & (user_bp.Friends.friend_uid == uid_record.uid))
        ).delete()
        
        user_bp.db.session.commit()
        
        return jsonify({'success': True, 'message': '已删除好友'})
        
    except Exception as e:
        user_bp.db.session.rollback()
        print(f"删除好友失败: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


# ========== 黑名单系统 ==========

@user_bp.route('/api/block/add', methods=['POST'])
@login_required
@require_uid_only
def add_block(uid_record):
    """拉黑用户"""
    try:
        data = request.get_json()
        blocked_uid = data.get('uid')
        reason = data.get('reason', '').strip()[:200]
        
        if not blocked_uid:
            return jsonify({'success': False, 'error': '缺少参数'}), 400
        
        if blocked_uid == uid_record.uid:
            return jsonify({'success': False, 'error': '不能拉黑自己'}), 400
        
        target = user_bp.UIDs.query.get(blocked_uid)
        if not target:
            return jsonify({'success': False, 'error': '用户不存在'}), 404
        
        existing = user_bp.BlockList.query.filter_by(
            blocker_uid=uid_record.uid,
            blocked_uid=blocked_uid
        ).first()
        
        if existing:
            return jsonify({'success': False, 'error': '已拉黑该用户'}), 400
        
        block = user_bp.BlockList(
            blocker_uid=uid_record.uid,
            blocked_uid=blocked_uid,
            reason=reason,
            created_at=datetime.now()
        )
        user_bp.db.session.add(block)
        
        # 删除好友关系
        user_bp.Friends.query.filter(
            ((user_bp.Friends.user_uid == uid_record.uid) & (user_bp.Friends.friend_uid == blocked_uid)) |
            ((user_bp.Friends.user_uid == blocked_uid) & (user_bp.Friends.friend_uid == uid_record.uid))
        ).delete()
        
        user_bp.db.session.commit()
        
        return jsonify({'success': True, 'message': '已拉黑该用户'})
        
    except Exception as e:
        user_bp.db.session.rollback()
        print(f"拉黑用户失败: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@user_bp.route('/api/block/remove', methods=['POST'])
@login_required
@require_uid_only
def remove_block(uid_record):
    """取消拉黑"""
    try:
        data = request.get_json()
        blocked_uid = data.get('uid')
        
        if not blocked_uid:
            return jsonify({'success': False, 'error': '缺少参数'}), 400
        
        user_bp.BlockList.query.filter_by(
            blocker_uid=uid_record.uid,
            blocked_uid=blocked_uid
        ).delete()
        
        user_bp.db.session.commit()
        
        return jsonify({'success': True, 'message': '已取消拉黑'})
        
    except Exception as e:
        user_bp.db.session.rollback()
        print(f"取消拉黑失败: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@user_bp.route('/api/block/list', methods=['GET'])
@login_required
@require_uid_only
def get_block_list(uid_record):
    """获取黑名单列表"""
    try:
        blocks = user_bp.BlockList.query.filter_by(
            blocker_uid=uid_record.uid
        ).order_by(user_bp.BlockList.created_at.desc()).all()
        
        block_data = []
        for block in blocks:
            blocked = user_bp.UIDs.query.get(block.blocked_uid)
            if blocked:
                block_data.append({
                    'uid': blocked.uid,
                    'nickname': blocked.nickname,
                    'level': blocked.level,
                    'reason': block.reason,
                    'created_at': block.created_at.strftime('%Y-%m-%d %H:%M')
                })
        
        return jsonify({'success': True, 'data': block_data})
        
    except Exception as e:
        print(f"获取黑名单失败: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


# ========== 积分转账 ==========

@user_bp.route('/api/points/transfer', methods=['POST'])
@login_required
@require_uid_only
@check_ban
def transfer_points(uid_record):
    """向好友转账积分"""
    try:
        data = request.get_json()
        to_uid = data.get('to_uid')
        amount = float(data.get('amount', 0))
        message = data.get('message', '').strip()[:500]
        
        if not to_uid:
            return jsonify({'success': False, 'error': '缺少接收者'}), 400
        
        if to_uid == uid_record.uid:
            return jsonify({'success': False, 'error': '不能给自己转账'}), 400
        
        if amount <= 0:
            return jsonify({'success': False, 'error': '转账金额必须大于0'}), 400
        
        if amount > 1000:
            return jsonify({'success': False, 'error': '单次转账不能超过1000积分'}), 400
        
        # 检查是否是好友
        is_friend = user_bp.Friends.query.filter(
            ((user_bp.Friends.user_uid == uid_record.uid) & (user_bp.Friends.friend_uid == to_uid) & (user_bp.Friends.status == 'accepted')) |
            ((user_bp.Friends.user_uid == to_uid) & (user_bp.Friends.friend_uid == uid_record.uid) & (user_bp.Friends.status == 'accepted'))
        ).first()
        
        if not is_friend:
            return jsonify({'success': False, 'error': '只能给好友转账'}), 403
        
        receiver = user_bp.UIDs.query.get(to_uid)
        if not receiver or not receiver.status:
            return jsonify({'success': False, 'error': '接收者不存在'}), 404
        
        if float(uid_record.points or 0) < amount:
            return jsonify({'success': False, 'error': f'积分不足，当前仅有 {float(uid_record.points or 0)} 积分'}), 400
        
        # 执行转账
        uid_record.points = float(uid_record.points or 0) - amount
        receiver.points = float(receiver.points or 0) + amount
        
        # 记录转账
        transfer = user_bp.PointsTransfers(
            from_uid=uid_record.uid,
            to_uid=to_uid,
            amount=amount,
            message=message,
            status='completed',
            created_at=datetime.now(),
            completed_at=datetime.now()
        )
        user_bp.db.session.add(transfer)
        
        # 发送私信通知
        notify_msg = user_bp.Messages(
            from_uid=uid_record.uid,
            to_uid=to_uid,
            content=f'💰 用户 {uid_record.nickname} 向您转账 {amount} 积分' + (f'\n\n附言：{message}' if message else ''),
            is_system=True,
            message_type='system',
            amount=amount,
            created_at=datetime.now()
        )
        user_bp.db.session.add(notify_msg)
        user_bp.db.session.flush()
        
        # 更新会话
        conv = user_bp.Conversations.query.filter_by(
            user_uid=to_uid,
            other_uid=uid_record.uid
        ).first()
        
        if conv:
            conv.last_message_id = notify_msg.id
            conv.unread_count += 1
            conv.updated_at = datetime.now()
        
        user_bp.db.session.commit()
        
        return jsonify({
            'success': True,
            'message': f'成功转账 {amount} 积分给 {receiver.nickname}',
            'new_balance': float(uid_record.points)
        })
        
    except Exception as e:
        user_bp.db.session.rollback()
        print(f"积分转账失败: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


# ========== 好友页面路由 ==========

@user_bp.route('/friends')
@login_required
@require_uid_only
def friends_page(uid_record):
    """好友管理页面"""
    return user_bp.renderTemplate('/base-files/friends.html')
