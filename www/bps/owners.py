from flask import Blueprint, render_template, request, jsonify, redirect, url_for, session, send_file, make_response
from flask_login import login_user, logout_user, login_required, current_user
from utils.password_checker import Password
from utils.email_sender import EmailSender, generate_reset_token
from utils.pbkdf2_security import PBKDF2Security
from utils.utils import RenderTemplate, anonymous_required, require_csrf
from utils.file_scanner import FileScanner
import os
import re
import secrets
import string
from datetime import datetime, timedelta
from PIL import Image
from werkzeug.utils import secure_filename
from functools import wraps

owner_bp = Blueprint('owner', __name__)

# 初始化 PBKDF2 安全模块
pbkdf2_security = PBKDF2Security()

# 初始化文件扫描器
file_scanner = FileScanner()

# 需要在主app中初始化db后传入
def init_owner_bp(app, db, Owners, OwnerLogs, InviteCodes, InviteCodeUses,
                  IDs, UIDs, Admins, SuperAdmins, Posts, Articles, Uploads,
                  Comments, AdminLogs, SuperAdminLogs,
                  OwnerAnnouncements, OwnerAnnouncementReads):
    """初始化Owner蓝图"""
    random_url_prefix = secrets.token_urlsafe(secrets.randbelow(4) + 8)
    owner_bp.url_prefix = f"/{random_url_prefix}"
    app.config['OWNER_PREFIX'] = random_url_prefix
    print(f"Owner URL Prefix: /{random_url_prefix} (每次服务器重启会随机生成新的前缀)")
    
    # 存储数据库相关对象
    owner_bp.db = db
    owner_bp.Owners = Owners
    owner_bp.OwnerLogs = OwnerLogs
    owner_bp.InviteCodes = InviteCodes
    owner_bp.InviteCodeUses = InviteCodeUses
    owner_bp.IDs = IDs
    owner_bp.UIDs = UIDs
    owner_bp.Admins = Admins
    owner_bp.SuperAdmins = SuperAdmins
    owner_bp.Posts = Posts
    owner_bp.Articles = Articles
    owner_bp.Uploads = Uploads
    owner_bp.Comments = Comments
    owner_bp.AdminLogs = AdminLogs
    owner_bp.SuperAdminLogs = SuperAdminLogs
    owner_bp.OwnerAnnouncements = OwnerAnnouncements
    owner_bp.OwnerAnnouncementReads = OwnerAnnouncementReads
    owner_bp.app = app
    
    # 创建蓝图特定的模型字典
    owner_models = {
        'Owners': Owners,
        'Admins': Admins,
        'SuperAdmins': SuperAdmins,
        'IDs': IDs,
        'UIDs': UIDs
    }
    
    # 初始化蓝图特定的渲染实例
    owner_bp.renderTemplate = RenderTemplate(
        db, 
        models=owner_models, 
        global_context={'basic_url': owner_bp.url_prefix[1:]}
    ).renderTemplate
    
    return owner_bp


# ========== 辅助函数 ==========

def get_current_identity():
    """获取当前身份信息"""
    try:
        if current_user.is_authenticated:
            user_class = current_user.__class__.__name__
            
            if user_class == 'Owners':
                return {
                    'type': 'owner',
                    'id': current_user.id,
                    'nickname': current_user.nickname,
                    'email': current_user.email,
                    'email_verified': current_user.email_verified,
                    'object': current_user
                }
        return None
    except:
        return None


def get_session_key():
    """生成唯一的会话标识符"""
    if 'session_key' not in session:
        session['session_key'] = secrets.token_hex(16)
    return session['session_key']


def generate_invite_code(length=32):
    """生成邀请码"""
    alphabet = string.ascii_letters + string.digits
    return 'INVITE_' + ''.join(secrets.choice(alphabet) for _ in range(length))


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


def get_user_by_id(user_id):
    """根据ID获取用户信息（辅助模板函数）"""
    try:
        return owner_bp.IDs.query.get(user_id)
    except:
        return None


def get_uid_by_id(uid):
    """根据UID获取UID信息（辅助模板函数）"""
    try:
        return owner_bp.UIDs.query.get(uid)
    except:
        return None


def get_category_color(category):
    """获取公告分类颜色（辅助模板函数）"""
    colors = {
        'info': '#4361ee',
        'warning': '#facc15',
        'danger': '#f87171',
        'success': '#4ade80',
        'maintenance': '#fb923c'
    }
    return colors.get(category, '#6c757d')


# ========== 权限装饰器 ==========

def owner_required(f):
    """只允许Owner访问的装饰器"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated:
            return redirect(url_for('owner.login'))
        
        if current_user.__class__.__name__ != 'Owners':
            return jsonify({'error': '需要所有者权限'}), 403
        
        return f(*args, **kwargs)
    return decorated_function


def log_owner_action(action, target_type=None, target_id=None, content=None):
    """记录Owner操作日志的装饰器"""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            result = f(*args, **kwargs)
            
            try:
                log_entry = owner_bp.OwnerLogs(
                    owner_id=current_user.id,
                    action=action,
                    target_type=target_type,
                    target_id=target_id,
                    content=content or f'执行操作: {action}',
                    ip_address=request.remote_addr,
                    time=datetime.now()
                )
                owner_bp.db.session.add(log_entry)
                owner_bp.db.session.commit()
            except Exception as e:
                print(f"记录日志失败: {e}")
            
            return result
        return decorated_function
    return decorator


# ========== 认证路由 ==========

@owner_bp.route('/api/pbkdf2-salt')
def get_owner_pbkdf2_salt():
    """获取PBKDF2参数"""
    try:
        owner_id = session.get('owner_id')
        
        if owner_id:
            owner = owner_bp.Owners.query.get(owner_id)
            if owner:
                salt, iterations = pbkdf2_security.get_pbkdf2_params_for_existing_user(owner)
                owner_bp.db.session.commit()
                return jsonify({
                    'success': True,
                    'salt': salt,
                    'iterations': iterations,
                    'is_owner_specific': True
                })
        
        session_key = get_session_key()
        temp_key = f"temp_{session_key}"
        salt, iterations = pbkdf2_security.get_pbkdf2_params_for_new_user(temp_key)
        return jsonify({
            'success': True,
            'salt': salt,
            'iterations': iterations,
            'is_owner_specific': False
        })
            
    except Exception as e:
        print(f"获取PBKDF2参数失败: {e}")
        return jsonify({'success': False, 'error': '服务器错误'}), 500


@owner_bp.route('/api/owner-pbkdf2-params')
def get_owner_specific_pbkdf2_params():
    """获取所有者特定的PBKDF2参数"""
    try:
        account = request.args.get('account')
        
        if not account:
            return jsonify({'success': False, 'error': '账号参数缺失'})
        
        owner = owner_bp.Owners.query.filter_by(nickname=account).first()
        
        if owner:
            if not owner.pbkdf2_salt or not owner.pbkdf2_iterations:
                owner.pbkdf2_salt, owner.pbkdf2_iterations = pbkdf2_security.get_pbkdf2_params_for_new_user()
                owner_bp.db.session.commit()
            
            return jsonify({
                'success': True,
                'salt': owner.pbkdf2_salt,
                'iterations': owner.pbkdf2_iterations,
                'is_owner_specific': True
            })
        else:
            session_key = get_session_key()
            temp_key = f"temp_{session_key}"
            salt, iterations = pbkdf2_security.get_pbkdf2_params_for_new_user(temp_key)
            
            return jsonify({
                'success': True,
                'salt': salt,
                'iterations': iterations,
                'is_owner_specific': False
            })
            
    except Exception as e:
        print(f"获取所有者PBKDF2参数失败: {e}")
        return jsonify({'success': False, 'error': '服务器错误'}), 500


@owner_bp.route('/login', methods=['GET', 'POST'])
@anonymous_required
@require_csrf
def login():
    """Owner登录"""
    if request.method == 'POST':
        account = request.form.get('account')
        client_hashed_pw = request.form.get('password')
        salt = request.form.get('salt')
        iterations = request.form.get('iterations')
        captcha_text = request.form.get('captcha')
        
        if captcha_text.lower() != session.get('captcha_expected', '').lower():
            return jsonify({'error': '验证码错误'})
        
        if account and client_hashed_pw and salt and iterations:
            owner = owner_bp.Owners.query.filter_by(nickname=account).first()

            if owner:
                if not owner.pbkdf2_salt or not owner.pbkdf2_iterations:
                    owner.pbkdf2_salt, owner.pbkdf2_iterations = pbkdf2_security.get_pbkdf2_params_for_new_user()
                    owner_bp.db.session.commit()
                    return jsonify({'error': '账户安全升级，请刷新页面重新登录'})
                
                if owner.pbkdf2_salt != salt or owner.pbkdf2_iterations != int(iterations):
                    return jsonify({'error': '安全参数不匹配，请刷新页面重试'})
                
                if Password().verify_pw(client_hashed_pw, owner.crypto_pw)[0]:
                    # 清空旧session
                    session.clear()
                    
                    # 设置新的session
                    session['owner_id'] = owner.id
                    session['nickname'] = owner.nickname
                    session['role'] = 'owner'
                    session['logged-in'] = True
                    
                    login_user(owner)
                    
                    owner.last_login = datetime.now()
                    owner_bp.db.session.commit()
                    
                    # 记录登录日志
                    log_entry = owner_bp.OwnerLogs(
                        owner_id=owner.id,
                        action='login',
                        content='Owner登录',
                        ip_address=request.remote_addr,
                        time=datetime.now()
                    )
                    owner_bp.db.session.add(log_entry)
                    owner_bp.db.session.commit()
                    
                    return jsonify({'success': '登录成功'})
                else:
                    return jsonify({'error': '密码错误'})
            else:
                return jsonify({'error': 'Owner不存在'})
        else:
            return jsonify({'error': '请填写完整信息'})
            
    return owner_bp.renderTemplate('/base-files/login.html')


@owner_bp.route('/register', methods=['GET', 'POST'])
@anonymous_required
@require_csrf
def register():
    """所有者注册（需要邀请码和特殊的 Cookie 令牌）"""
    if request.method == 'POST':
        nickname = request.form.get('nickname')
        email = request.form.get('email')
        client_hashed_pw = request.form.get('password')
        invite_code = request.form.get('invite_code')
        salt = request.form.get('salt')
        iterations = request.form.get('iterations')
        captcha_text = request.form.get('captcha')
        token = request.form.get('token') or request.cookies.get('token')
        
        # 验证验证码
        expected_captcha = session.get('captcha_expected', '')
        if not expected_captcha or captcha_text.lower() != expected_captcha.lower():
            return jsonify({'error': '验证码错误'})
        
        if not nickname or not email or not client_hashed_pw or not invite_code:
            return jsonify({'error': '请填写完整信息'})
        
        # 验证邀请码
        if invite_code != 'FR33HUB-0WN3R-2O26':
            return jsonify({'error': '无效的邀请码'})
        
        # 验证 Cookie 令牌
        expected_token = session.get('owner_reg_token', '')
        if not token or token != expected_token:
            return jsonify({'error': '无效的注册令牌，请按 F12 添加正确的 Cookie'})
        
        # 验证昵称格式
        if not re.match(r'^[a-zA-Z0-9]{4,20}$', nickname):
            return jsonify({'error': '昵称只能包含字母和数字，长度4-20个字符'})
        
        # 验证邮箱格式
        if not re.match(r'^[^\s@]+@[^\s@]+\.[^\s@]+$', email):
            return jsonify({'error': '邮箱格式不正确'})
        
        # 检查是否已存在
        if owner_bp.Owners.query.filter_by(nickname=nickname).first():
            return jsonify({'error': '昵称已存在'})
        
        if owner_bp.Owners.query.filter_by(email=email).first():
            return jsonify({'error': '邮箱已被注册'})
        
        # 验证安全参数
        session_key = get_session_key()
        temp_key = f"temp_{session_key}"
        if not pbkdf2_security.verify_temp_params(temp_key, salt, int(iterations)):
            return jsonify({'error': '安全参数无效，请刷新页面重试'})
        
        # 创建所有者 - 根据更新的 Owners 模型（包含 email 字段）
        new_owner = owner_bp.Owners(
            nickname=nickname,
            email=email,
            crypto_pw=Password().hash_pw(client_hashed_pw),
            pbkdf2_salt=salt,
            pbkdf2_iterations=int(iterations),
            email_verified=True,  # Owner 自动验证邮箱
            profile_visibility='private',
            online_status=True,
            can_post_announcement=True,
            created_at=datetime.now()
        )
        
        owner_bp.db.session.add(new_owner)
        owner_bp.db.session.commit()
        
        # 清除 Cookie 令牌
        session.pop('owner_reg_token', None)
        session.pop('captcha_expected', None)
        
        response = jsonify({'success': '注册成功，请登录'})
        response.set_cookie('token', '', expires=0)  # 删除 Cookie
        
        return response
    
    # GET 请求 - 生成随机令牌并设置到 Session 和 Cookie
    random_token = secrets.token_urlsafe(32)
    session['owner_reg_token'] = random_token
    
    # 渲染模板
    response = make_response(owner_bp.renderTemplate('/base-files/register.html'))
    response.set_cookie('token', random_token, max_age=3600, httponly=True)  # 1小时有效
    
    return response


@owner_bp.route('/logout')
@login_required
@owner_required
def logout():
    """Owner登出"""
    # 记录登出日志
    log_entry = owner_bp.OwnerLogs(
        owner_id=current_user.id,
        action='logout',
        content='Owner登出',
        ip_address=request.remote_addr,
        time=datetime.now()
    )
    owner_bp.db.session.add(log_entry)
    owner_bp.db.session.commit()
    
    logout_user()
    session.clear()
    session['logged-in'] = False
    return redirect(url_for('index'))


# ========== 仪表盘 ==========

@owner_bp.route('/')
@owner_bp.route('/dashboard')
@login_required
@owner_required
def dashboard():
    """Owner仪表盘"""
    identity = get_current_identity()
    
    # 获取统计数据
    stats = {
        'users': {
            'total': owner_bp.IDs.query.count(),
            'active_24h': owner_bp.IDs.query.filter(
                owner_bp.IDs.last_login >= datetime.now() - timedelta(hours=24)
            ).count(),
            'total_uids': owner_bp.UIDs.query.count(),
            'email_verified': owner_bp.IDs.query.filter_by(email_verified=True).count()
        },
        'admins': {
            'total': owner_bp.Admins.query.count(),
            'active': owner_bp.Admins.query.filter_by(status=True).count(),
            'email_verified': owner_bp.Admins.query.filter_by(email_verified=True).count()
        },
        'superadmins': {
            'total': owner_bp.SuperAdmins.query.count(),
            'active': owner_bp.SuperAdmins.query.filter_by(status=True).count(),
            'email_verified': owner_bp.SuperAdmins.query.filter_by(email_verified=True).count()
        },
        'content': {
            'posts': owner_bp.Posts.query.filter_by(is_deleted=False).count(),
            'articles': owner_bp.Articles.query.filter_by(is_deleted=False).count(),
            'uploads': owner_bp.Uploads.query.filter_by(is_deleted=False).count(),
            'comments': owner_bp.Comments.query.filter_by(is_deleted=False).count(),
            'total_size': owner_bp.db.session.query(
                owner_bp.db.func.sum(owner_bp.Uploads.file_size)
            ).scalar() or 0
        },
        'invites': {
            'total': owner_bp.InviteCodes.query.count(),
            'used': owner_bp.InviteCodes.query.filter(
                owner_bp.InviteCodes.used_count >= owner_bp.InviteCodes.max_uses
            ).count(),
            'active': owner_bp.InviteCodes.query.filter_by(is_active=True).count()
        }
    }
    
    return owner_bp.renderTemplate(
        '/base-files/dashboard.html',
        stats=stats,
        identity=identity
    )


@owner_bp.route('/api/stats')
@login_required
@owner_required
def api_stats():
    """获取统计数据API"""
    stats = {
        'users': {
            'total': owner_bp.IDs.query.count(),
            'active_24h': owner_bp.IDs.query.filter(
                owner_bp.IDs.last_login >= datetime.now() - timedelta(hours=24)
            ).count(),
            'total_uids': owner_bp.UIDs.query.count()
        },
        'admins': {
            'total': owner_bp.Admins.query.count(),
            'active': owner_bp.Admins.query.filter_by(status=True).count()
        },
        'superadmins': {
            'total': owner_bp.SuperAdmins.query.count(),
            'active': owner_bp.SuperAdmins.query.filter_by(status=True).count()
        },
        'content': {
            'posts': owner_bp.Posts.query.filter_by(is_deleted=False).count(),
            'articles': owner_bp.Articles.query.filter_by(is_deleted=False).count(),
            'uploads': owner_bp.Uploads.query.filter_by(is_deleted=False).count(),
            'total_size': owner_bp.db.session.query(
                owner_bp.db.func.sum(owner_bp.Uploads.file_size)
            ).scalar() or 0
        }
    }
    return jsonify({'success': True, 'data': stats})


# ========== 邀请码管理 ==========

@owner_bp.route('/invite-codes')
@login_required
@owner_required
def invite_codes():
    """邀请码管理页面"""
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 20, type=int)
    
    codes = owner_bp.InviteCodes.query.order_by(
        owner_bp.InviteCodes.created_at.desc()
    ).paginate(page=page, per_page=per_page, error_out=False)
    
    # 获取统计数据
    stats = {
        'total': owner_bp.InviteCodes.query.count(),
        'used': owner_bp.InviteCodes.query.filter(
            owner_bp.InviteCodes.used_count >= owner_bp.InviteCodes.max_uses
        ).count(),
        'active': owner_bp.InviteCodes.query.filter_by(is_active=True).count()
    }
    
    return owner_bp.renderTemplate(
        '/base-files/invite-codes.html',
        codes=codes.items,
        pagination=codes,
        stats=stats
    )


@owner_bp.route('/invite-code/create', methods=['POST'])
@login_required
@owner_required
@log_owner_action('create_invite', 'invite_code')
def create_invite_code():
    """创建邀请码"""
    try:
        data = request.get_json()
        code_type = data.get('code_type', 'temporary')  # temporary, permanent
        target_role = data.get('target_role', 'admin')  # admin, superadmin
        max_uses = data.get('max_uses', 1)
        expires_in = data.get('expires_in')  # 小时，None表示永久
        
        # 生成唯一邀请码
        while True:
            code = generate_invite_code()
            existing = owner_bp.InviteCodes.query.filter_by(code=code).first()
            if not existing:
                break
        
        expires_at = None
        if expires_in:
            expires_at = datetime.now() + timedelta(hours=int(expires_in))
        
        invite_code = owner_bp.InviteCodes(
            code=code,
            code_type=code_type,
            target_role=target_role,
            max_uses=max_uses,
            used_count=0,
            expires_at=expires_at,
            is_active=True,
            created_at=datetime.now(),
            created_by_id=current_user.id
        )
        
        owner_bp.db.session.add(invite_code)
        owner_bp.db.session.commit()
        
        return jsonify({
            'success': True,
            'message': '邀请码创建成功',
            'code': code,
            'id': invite_code.id
        })
        
    except Exception as e:
        owner_bp.db.session.rollback()
        print(f"创建邀请码失败: {e}")
        return jsonify({'error': '创建失败'}), 500


@owner_bp.route('/invite-code/<int:code_id>/toggle', methods=['POST'])
@login_required
@owner_required
@log_owner_action('toggle_invite', 'invite_code')
def toggle_invite_code(code_id):
    """启用/禁用邀请码"""
    invite = owner_bp.InviteCodes.query.get(code_id)
    if not invite:
        return jsonify({'error': '邀请码不存在'}), 404
    
    invite.is_active = not invite.is_active
    owner_bp.db.session.commit()
    
    return jsonify({
        'success': True,
        'is_active': invite.is_active,
        'message': '已启用' if invite.is_active else '已禁用'
    })


@owner_bp.route('/invite-code/<int:code_id>/delete', methods=['POST'])
@login_required
@owner_required
@log_owner_action('delete_invite', 'invite_code')
def delete_invite_code(code_id):
    """删除邀请码"""
    invite = owner_bp.InviteCodes.query.get(code_id)
    if not invite:
        return jsonify({'error': '邀请码不存在'}), 404
    
    try:
        owner_bp.db.session.delete(invite)
        owner_bp.db.session.commit()
        return jsonify({'success': True, 'message': '邀请码已删除'})
    except Exception as e:
        owner_bp.db.session.rollback()
        print(f"删除邀请码失败: {e}")
        return jsonify({'error': '删除失败'}), 500


@owner_bp.route('/api/invite-codes')
@login_required
@owner_required
def api_invite_codes():
    """获取邀请码列表API"""
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 20, type=int)
    
    codes = owner_bp.InviteCodes.query.order_by(
        owner_bp.InviteCodes.created_at.desc()
    ).paginate(page=page, per_page=per_page, error_out=False)
    
    codes_data = []
    for code in codes.items:
        codes_data.append({
            'id': code.id,
            'code': code.code,
            'type': code.code_type,
            'target_role': code.target_role,
            'max_uses': code.max_uses,
            'used_count': code.used_count,
            'is_active': code.is_active,
            'expires_at': code.expires_at.isoformat() if code.expires_at else None,
            'created_at': code.created_at.isoformat()
        })
    
    return jsonify({
        'success': True,
        'data': codes_data,
        'total': codes.total,
        'page': page,
        'per_page': per_page
    })


@owner_bp.route('/api/invite-code/validate', methods=['POST'])
def validate_invite_code():
    """验证邀请码（用于注册）"""
    try:
        data = request.get_json()
        code = data.get('code')
        role = data.get('role', 'admin')
        
        if not code:
            return jsonify({'error': '邀请码不能为空'}), 400
        
        invite = owner_bp.InviteCodes.query.filter_by(
            code=code,
            is_active=True
        ).first()
        
        if not invite:
            return jsonify({'valid': False, 'error': '无效的邀请码'})
        
        if invite.target_role != role:
            return jsonify({'valid': False, 'error': f'邀请码不适用于{role}角色'})
        
        if invite.expires_at and invite.expires_at < datetime.now():
            return jsonify({'valid': False, 'error': '邀请码已过期'})
        
        if invite.used_count >= invite.max_uses:
            return jsonify({'valid': False, 'error': '邀请码已达到最大使用次数'})
        
        return jsonify({
            'valid': True,
            'invite_id': invite.id,
            'target_role': invite.target_role,
            'code_type': invite.code_type
        })
        
    except Exception as e:
        print(f"验证邀请码失败: {e}")
        return jsonify({'error': '验证失败'}), 500


# ========== 用户管理 ==========

@owner_bp.route('/users')
@login_required
@owner_required
def users():
    """用户管理页面（IDs）"""
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 20, type=int)
    search = request.args.get('search', '')
    
    query = owner_bp.IDs.query
    
    if search:
        query = query.filter(
            (owner_bp.IDs.nickname.contains(search)) |
            (owner_bp.IDs.email.contains(search))
        )
    
    users = query.order_by(owner_bp.IDs.created_at.desc())\
        .paginate(page=page, per_page=per_page, error_out=False)
    
    return owner_bp.renderTemplate(
        '/base-files/users.html',
        users=users.items,
        pagination=users,
        search=search
    )


@owner_bp.route('/api/users')
@login_required
@owner_required
def api_users():
    """获取用户列表API（包含邮箱）"""
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 20, type=int)
    search = request.args.get('search', '')
    
    query = owner_bp.IDs.query
    
    if search:
        query = query.filter(
            (owner_bp.IDs.nickname.contains(search)) |
            (owner_bp.IDs.email.contains(search))
        )
    
    users = query.order_by(owner_bp.IDs.created_at.desc())\
        .paginate(page=page, per_page=per_page, error_out=False)
    
    users_data = []
    for user in users.items:
        uids = owner_bp.UIDs.query.filter_by(id=user.id).all()
        users_data.append({
            'id': user.id,
            'nickname': user.nickname,
            'email': user.email,  # Owner可以看到邮箱
            'email_verified': user.email_verified,
            'status': user.status,
            'level': user.level,
            'all_points': user.all_points,
            'last_points': user.last_points,
            'uids_count': len(uids),
            'created_at': user.created_at.isoformat() if user.created_at else None,
            'last_login': user.last_login.isoformat() if user.last_login else None
        })
    
    return jsonify({
        'success': True,
        'data': users_data,
        'total': users.total,
        'page': page,
        'per_page': per_page
    })


@owner_bp.route('/user/<int:user_id>')
@login_required
@owner_required
def user_detail(user_id):
    """用户详情页面"""
    user = owner_bp.IDs.query.get(user_id)
    if not user:
        return jsonify({'error': '用户不存在'}), 404
    
    uids = owner_bp.UIDs.query.filter_by(id=user.id).all()
    
    # 获取所有UID的内容
    uid_ids = [uid.uid for uid in uids]
    posts = owner_bp.Posts.query.filter(
        owner_bp.Posts.author_id.in_(uid_ids)
    ).order_by(owner_bp.Posts.created_at.desc()).limit(50).all()
    
    articles = owner_bp.Articles.query.filter(
        owner_bp.Articles.author_id.in_(uid_ids)
    ).order_by(owner_bp.Articles.time.desc()).limit(50).all()
    
    uploads = owner_bp.Uploads.query.filter(
        owner_bp.Uploads.uid.in_(uid_ids)
    ).order_by(owner_bp.Uploads.created_at.desc()).limit(50).all()
    
    return owner_bp.renderTemplate(
        '/base-files/user-detail.html',
        user=user,
        uids=uids,
        recent_posts=posts,
        recent_articles=articles,
        recent_uploads=uploads
    )


@owner_bp.route('/user/<int:user_id>/toggle-status', methods=['POST'])
@login_required
@owner_required
@log_owner_action('toggle_user_status', 'user')
def toggle_user_status(user_id):
    """切换用户状态"""
    user = owner_bp.IDs.query.get(user_id)
    if not user:
        return jsonify({'error': '用户不存在'}), 404
    
    user.status = not user.status
    
    # 同时禁用/启用所有子账户
    uids = owner_bp.UIDs.query.filter_by(id=user_id).all()
    for uid in uids:
        uid.status = user.status
    
    owner_bp.db.session.commit()
    
    return jsonify({
        'success': True,
        'status': user.status,
        'message': '用户已启用' if user.status else '用户已禁用'
    })


@owner_bp.route('/user/<int:user_id>/reset-password', methods=['POST'])
@login_required
@owner_required
@log_owner_action('reset_user_password', 'user')
def reset_user_password(user_id):
    """重置用户密码"""
    user = owner_bp.IDs.query.get(user_id)
    if not user:
        return jsonify({'error': '用户不存在'}), 404
    
    temp_password = secrets.token_urlsafe(12)
    user.crypto_pw = Password().hash_pw(temp_password)
    owner_bp.db.session.commit()
    
    # TODO: 发送邮件通知用户
    
    return jsonify({
        'success': True,
        'message': '密码已重置',
        'temp_password': temp_password  # 仅开发环境使用
    })


@owner_bp.route('/user/<int:user_id>/points', methods=['POST'])
@login_required
@owner_required
@log_owner_action('adjust_user_points', 'user')
def adjust_user_points(user_id):
    """调整用户积分"""
    try:
        data = request.get_json()
        points = data.get('points', 0)
        operation = data.get('operation', 'add')  # add, set
        
        user = owner_bp.IDs.query.get(user_id)
        if not user:
            return jsonify({'error': '用户不存在'}), 404
        
        if operation == 'add':
            user.all_points += points
            user.last_points += points
        elif operation == 'set':
            user.all_points = points
            user.last_points = points
        
        owner_bp.db.session.commit()
        
        return jsonify({
            'success': True,
            'message': '积分已更新',
            'all_points': user.all_points,
            'last_points': user.last_points
        })
        
    except Exception as e:
        owner_bp.db.session.rollback()
        print(f"调整积分失败: {e}")
        return jsonify({'error': '操作失败'}), 500


# ========== 管理员管理 ==========

@owner_bp.route('/admins')
@login_required
@owner_required
def admins():
    """管理员管理页面"""
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 20, type=int)
    role = request.args.get('role', 'all')  # all, admin, superadmin
    
    admins_data = []
    superadmins_data = []
    admins_pagination = None
    superadmins_pagination = None
    
    if role in ['all', 'admin']:
        admins_pagination = owner_bp.Admins.query.order_by(
            owner_bp.Admins.created_at.desc()
        ).paginate(page=page, per_page=per_page, error_out=False)
        admins_data = admins_pagination.items
    
    if role in ['all', 'superadmin']:
        superadmins_pagination = owner_bp.SuperAdmins.query.order_by(
            owner_bp.SuperAdmins.created_at.desc()
        ).paginate(page=page, per_page=per_page, error_out=False)
        superadmins_data = superadmins_pagination.items
    
    return owner_bp.renderTemplate(
        '/base-files/admins.html',
        admins=admins_data,
        superadmins=superadmins_data,
        pagination_admins=admins_pagination,
        pagination_superadmins=superadmins_pagination,
        role=role
    )


@owner_bp.route('/api/admins')
@login_required
@owner_required
def api_admins():
    """获取管理员列表API"""
    role = request.args.get('role', 'all')
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 20, type=int)
    
    result = []
    
    if role in ['all', 'admin']:
        admins = owner_bp.Admins.query.order_by(
            owner_bp.Admins.created_at.desc()
        ).paginate(page=page, per_page=per_page, error_out=False)
        
        for admin in admins.items:
            result.append({
                'id': admin.id,
                'nickname': admin.nickname,
                'email': admin.email,
                'email_verified': admin.email_verified,
                'status': admin.status,
                'level': admin.level,
                'role': 'admin',
                'invite_code': admin.invite_code,
                'invite_code_used': admin.invite_code_used,
                'invited_by': admin.invited_by,
                'created_at': admin.created_at.isoformat() if admin.created_at else None,
                'last_login': admin.last_login.isoformat() if admin.last_login else None
            })
    
    if role in ['all', 'superadmin']:
        superadmins = owner_bp.SuperAdmins.query.order_by(
            owner_bp.SuperAdmins.created_at.desc()
        ).paginate(page=page, per_page=per_page, error_out=False)
        
        for sa in superadmins.items:
            result.append({
                'id': sa.id,
                'nickname': sa.nickname,
                'email': sa.email,
                'email_verified': sa.email_verified,
                'status': sa.status,
                'level': sa.level,
                'role': 'superadmin',
                'invite_code': sa.invite_code,
                'invite_code_used': sa.invite_code_used,
                'invited_by': sa.invited_by,
                'created_at': sa.created_at.isoformat() if sa.created_at else None,
                'last_login': sa.last_login.isoformat() if sa.last_login else None
            })
    
    return jsonify({
        'success': True,
        'data': result,
        'total': len(result)
    })


@owner_bp.route('/admin/create', methods=['POST'])
@login_required
@owner_required
@log_owner_action('create_admin', 'admin')
def create_admin():
    """创建管理员"""
    try:
        data = request.get_json()
        nickname = data.get('nickname')
        email = data.get('email')
        role = data.get('role', 'admin')  # admin, superadmin
        
        if not nickname or not email:
            return jsonify({'error': '请填写完整信息'}), 400
        
        # 检查是否已存在
        if role == 'admin':
            if owner_bp.Admins.query.filter_by(nickname=nickname).first():
                return jsonify({'error': '昵称已存在'}), 400
            if owner_bp.Admins.query.filter_by(email=email).first():
                return jsonify({'error': '邮箱已被注册'}), 400
        else:
            if owner_bp.SuperAdmins.query.filter_by(nickname=nickname).first():
                return jsonify({'error': '昵称已存在'}), 400
            if owner_bp.SuperAdmins.query.filter_by(email=email).first():
                return jsonify({'error': '邮箱已被注册'}), 400
        
        # 生成临时密码
        temp_password = secrets.token_urlsafe(12)
        hashed_pw = Password().hash_pw(temp_password)
        
        if role == 'admin':
            new_admin = owner_bp.Admins(
                nickname=nickname,
                email=email,
                crypto_pw=hashed_pw,
                level=1,
                status=True,
                email_verified=False,
                invited_by=current_user.id,
                created_at=datetime.now(),
                can_manage_users=True,
                can_manage_admins=False,
                can_post_announcement=True
            )
            owner_bp.db.session.add(new_admin)
        else:
            new_sa = owner_bp.SuperAdmins(
                nickname=nickname,
                email=email,
                crypto_pw=hashed_pw,
                level=1,
                status=True,
                email_verified=False,
                invited_by=current_user.id,
                created_at=datetime.now(),
                can_manage_admins=True,
                can_manage_superadmins=False,
                can_post_announcement=True
            )
            owner_bp.db.session.add(new_sa)
        
        owner_bp.db.session.commit()
        
        # TODO: 发送邮件通知管理员，包含临时密码
        
        return jsonify({
            'success': True,
            'message': f'{role}创建成功',
            'temp_password': temp_password  # 仅开发环境使用
        })
        
    except Exception as e:
        owner_bp.db.session.rollback()
        print(f"创建管理员失败: {e}")
        return jsonify({'error': '创建失败'}), 500


@owner_bp.route('/admin/<int:admin_id>/toggle-status', methods=['POST'])
@login_required
@owner_required
@log_owner_action('toggle_admin_status', 'admin')
def toggle_admin_status(admin_id):
    """切换管理员状态"""
    data = request.get_json()
    role = data.get('role', 'admin')
    
    if role == 'admin':
        admin = owner_bp.Admins.query.get(admin_id)
    else:
        admin = owner_bp.SuperAdmins.query.get(admin_id)
    
    if not admin:
        return jsonify({'error': '管理员不存在'}), 404
    
    admin.status = not admin.status
    owner_bp.db.session.commit()
    
    return jsonify({
        'success': True,
        'status': admin.status,
        'message': '已启用' if admin.status else '已禁用'
    })


@owner_bp.route('/admin/<int:admin_id>/reset-password', methods=['POST'])
@login_required
@owner_required
@log_owner_action('reset_admin_password', 'admin')
def reset_admin_password(admin_id):
    """重置管理员密码"""
    data = request.get_json()
    role = data.get('role', 'admin')
    
    if role == 'admin':
        admin = owner_bp.Admins.query.get(admin_id)
    else:
        admin = owner_bp.SuperAdmins.query.get(admin_id)
    
    if not admin:
        return jsonify({'error': '管理员不存在'}), 404
    
    temp_password = secrets.token_urlsafe(12)
    admin.crypto_pw = Password().hash_pw(temp_password)
    owner_bp.db.session.commit()
    
    # TODO: 发送邮件通知管理员
    
    return jsonify({
        'success': True,
        'message': '密码已重置',
        'temp_password': temp_password  # 仅开发环境使用
    })


@owner_bp.route('/admin/<int:admin_id>/delete', methods=['POST'])
@login_required
@owner_required
@log_owner_action('delete_admin', 'admin')
def delete_admin(admin_id):
    """删除管理员"""
    data = request.get_json()
    role = data.get('role', 'admin')
    
    if role == 'admin':
        admin = owner_bp.Admins.query.get(admin_id)
    else:
        admin = owner_bp.SuperAdmins.query.get(admin_id)
    
    if not admin:
        return jsonify({'error': '管理员不存在'}), 404
    
    try:
        owner_bp.db.session.delete(admin)
        owner_bp.db.session.commit()
        return jsonify({'success': True, 'message': '管理员已删除'})
    except Exception as e:
        owner_bp.db.session.rollback()
        print(f"删除管理员失败: {e}")
        return jsonify({'error': '删除失败'}), 500


# ========== UID管理 ==========

@owner_bp.route('/uids')
@login_required
@owner_required
def uids():
    """UID管理页面"""
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 20, type=int)
    search = request.args.get('search', '')
    status = request.args.get('status', 'all')
    
    query = owner_bp.UIDs.query
    
    if search:
        query = query.filter(owner_bp.UIDs.nickname.contains(search))
    
    if status != 'all':
        query = query.filter_by(status=(status == 'active'))
    
    uids = query.order_by(owner_bp.UIDs.created_at.desc())\
        .paginate(page=page, per_page=per_page, error_out=False)
    
    return owner_bp.renderTemplate(
        '/base-files/uids.html',
        uids=uids.items,
        pagination=uids,
        search=search,
        status=status
    )


@owner_bp.route('/api/uids')
@login_required
@owner_required
def api_uids():
    """获取UID列表API"""
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 20, type=int)
    search = request.args.get('search', '')
    status = request.args.get('status', 'all')
    
    query = owner_bp.UIDs.query
    
    if search:
        query = query.filter(owner_bp.UIDs.nickname.contains(search))
    
    if status != 'all':
        query = query.filter_by(status=(status == 'active'))
    
    uids = query.order_by(owner_bp.UIDs.created_at.desc())\
        .paginate(page=page, per_page=per_page, error_out=False)
    
    uids_data = []
    for uid in uids.items:
        user = owner_bp.IDs.query.get(uid.id)
        uids_data.append({
            'uid': uid.uid,
            'nickname': uid.nickname,
            'level': uid.level,
            'points': uid.points,
            'status': uid.status,
            'posts_count': uid.posts_count,
            'articles_count': uid.articles_count,
            'uploads_count': uid.uploads_count,
            'created_at': uid.created_at.isoformat() if uid.created_at else None,
            'last_active': uid.last_active.isoformat() if uid.last_active else None,
            'user': {
                'id': user.id if user else None,
                'nickname': user.nickname if user else None,
                'email': user.email if user else None,  # Owner可以看到邮箱
                'level': user.level if user else None
            } if user else None
        })
    
    return jsonify({
        'success': True,
        'data': uids_data,
        'total': uids.total,
        'page': page,
        'per_page': per_page
    })


@owner_bp.route('/uid/<int:uid>')
@login_required
@owner_required
def uid_detail(uid):
    """UID详情页面"""
    uid_record = owner_bp.UIDs.query.get(uid)
    if not uid_record:
        return jsonify({'error': 'UID不存在'}), 404
    
    user = owner_bp.IDs.query.get(uid_record.id)
    
    posts = owner_bp.Posts.query.filter_by(
        author_id=uid, is_deleted=False
    ).order_by(owner_bp.Posts.created_at.desc()).limit(50).all()
    
    articles = owner_bp.Articles.query.filter_by(
        author_id=uid, is_deleted=False
    ).order_by(owner_bp.Articles.time.desc()).limit(50).all()
    
    uploads = owner_bp.Uploads.query.filter_by(
        uid=uid, is_deleted=False
    ).order_by(owner_bp.Uploads.created_at.desc()).limit(50).all()
    
    return owner_bp.renderTemplate(
        '/base-files/uid-detail.html',
        uid=uid_record,
        user=user,
        posts=posts,
        articles=articles,
        uploads=uploads
    )


@owner_bp.route('/uid/<int:uid>/toggle-status', methods=['POST'])
@login_required
@owner_required
@log_owner_action('toggle_uid_status', 'uid')
def toggle_uid_status(uid):
    """切换UID状态"""
    uid_record = owner_bp.UIDs.query.get(uid)
    if not uid_record:
        return jsonify({'error': 'UID不存在'}), 404
    
    uid_record.status = not uid_record.status
    owner_bp.db.session.commit()
    
    return jsonify({
        'success': True,
        'status': uid_record.status,
        'message': 'UID已启用' if uid_record.status else 'UID已禁用'
    })


# ========== 内容管理 ==========

@owner_bp.route('/posts')
@login_required
@owner_required
def posts():
    """帖子管理页面"""
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 20, type=int)
    search = request.args.get('search', '')
    
    query = owner_bp.Posts.query.filter_by(is_deleted=False)
    
    if search:
        query = query.filter(
            (owner_bp.Posts.title.contains(search)) |
            (owner_bp.Posts.content.contains(search))
        )
    
    posts = query.order_by(owner_bp.Posts.created_at.desc())\
        .paginate(page=page, per_page=per_page, error_out=False)
    
    return owner_bp.renderTemplate(
        '/base-files/posts.html',
        posts=posts.items,
        pagination=posts,
        search=search
    )


@owner_bp.route('/articles')
@login_required
@owner_required
def articles():
    """文章管理页面"""
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 20, type=int)
    search = request.args.get('search', '')
    
    query = owner_bp.Articles.query.filter_by(is_deleted=False)
    
    if search:
        query = query.filter(
            (owner_bp.Articles.title.contains(search)) |
            (owner_bp.Articles.content.contains(search))
        )
    
    articles = query.order_by(owner_bp.Articles.time.desc())\
        .paginate(page=page, per_page=per_page, error_out=False)
    
    return owner_bp.renderTemplate(
        '/base-files/articles.html',
        articles=articles.items,
        pagination=articles,
        search=search
    )


@owner_bp.route('/uploads')
@login_required
@owner_required
def uploads():
    """文件管理页面"""
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 20, type=int)
    search = request.args.get('search', '')
    
    query = owner_bp.Uploads.query.filter_by(is_deleted=False)
    
    if search:
        query = query.filter(
            (owner_bp.Uploads.original_filename.contains(search)) |
            (owner_bp.Uploads.description.contains(search))
        )
    
    uploads = query.order_by(owner_bp.Uploads.created_at.desc())\
        .paginate(page=page, per_page=per_page, error_out=False)
    
    return owner_bp.renderTemplate(
        '/base-files/uploads.html',
        uploads=uploads.items,
        pagination=uploads,
        search=search
    )


# ========== 公告管理 ==========

@owner_bp.route('/announcements')
@login_required
@owner_required
def announcements():
    """公告列表页面"""
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 10, type=int)
    
    announcements = owner_bp.OwnerAnnouncements.query.filter_by(
        is_deleted=False
    ).order_by(
        owner_bp.OwnerAnnouncements.is_pinned.desc(),
        owner_bp.OwnerAnnouncements.created_at.desc()
    ).paginate(page=page, per_page=per_page, error_out=False)
    
    return owner_bp.renderTemplate(
        '/base-files/announcements.html',
        announcements=announcements.items,
        pagination=announcements
    )


@owner_bp.route('/announcement/create', methods=['GET', 'POST'])
@login_required
@owner_required
def create_announcement():
    """创建公告"""
    owner = current_user
    
    if request.method == 'GET':
        return owner_bp.renderTemplate('/base-files/announcement-form.html')
    
    try:
        data = request.get_json() if request.is_json else request.form
        title = data.get('title', '').strip()
        content = data.get('content', '').strip()
        category = data.get('category', 'info')
        target_role = data.get('target_role', 'all')
        is_pinned = data.get('is_pinned', False)
        end_at = data.get('end_at')
        
        if not title or not content:
            return jsonify({'error': '标题和内容不能为空'})
        
        announcement = owner_bp.OwnerAnnouncements(
            title=title,
            content=content,
            category=category,
            target_role=target_role,
            is_pinned=is_pinned,
            end_at=datetime.fromisoformat(end_at) if end_at else None,
            author_id=owner.id,
            author_name=owner.nickname,
            created_at=datetime.now()
        )
        
        owner_bp.db.session.add(announcement)
        owner_bp.db.session.commit()
        
        # 记录日志
        log_entry = owner_bp.OwnerLogs(
            owner_id=owner.id,
            action='create_announcement',
            target_type='announcement',
            target_id=announcement.id,
            content=f'创建公告: {title}',
            ip_address=request.remote_addr
        )
        owner_bp.db.session.add(log_entry)
        owner_bp.db.session.commit()
        
        return jsonify({
            'success': True,
            'message': '公告发布成功',
            'announcement_id': announcement.id
        })
        
    except Exception as e:
        owner_bp.db.session.rollback()
        print(f"创建公告失败: {e}")
        return jsonify({'error': '发布失败'}), 500


@owner_bp.route('/announcement/<int:announcement_id>/edit', methods=['GET', 'POST'])
@login_required
@owner_required
def edit_announcement(announcement_id):
    """编辑公告"""
    owner = current_user
    
    announcement = owner_bp.OwnerAnnouncements.query.get(announcement_id)
    if not announcement or announcement.is_deleted:
        return jsonify({'error': '公告不存在'}), 404
    
    if request.method == 'GET':
        return owner_bp.renderTemplate(
            '/base-files/announcement-form.html',
            announcement=announcement
        )
    
    try:
        data = request.get_json() if request.is_json else request.form
        title = data.get('title', '').strip()
        content = data.get('content', '').strip()
        category = data.get('category', 'info')
        target_role = data.get('target_role', 'all')
        is_pinned = data.get('is_pinned', False)
        end_at = data.get('end_at')
        
        if not title or not content:
            return jsonify({'error': '标题和内容不能为空'})
        
        announcement.title = title
        announcement.content = content
        announcement.category = category
        announcement.target_role = target_role
        announcement.is_pinned = is_pinned
        announcement.end_at = datetime.fromisoformat(end_at) if end_at else None
        announcement.updated_at = datetime.now()
        
        owner_bp.db.session.commit()
        
        # 记录日志
        log_entry = owner_bp.OwnerLogs(
            owner_id=owner.id,
            action='edit_announcement',
            target_type='announcement',
            target_id=announcement.id,
            content=f'编辑公告: {title}',
            ip_address=request.remote_addr
        )
        owner_bp.db.session.add(log_entry)
        owner_bp.db.session.commit()
        
        return jsonify({
            'success': True,
            'message': '公告更新成功'
        })
        
    except Exception as e:
        owner_bp.db.session.rollback()
        print(f"更新公告失败: {e}")
        return jsonify({'error': '更新失败'}), 500


@owner_bp.route('/announcement/<int:announcement_id>/delete', methods=['POST'])
@login_required
@owner_required
def delete_announcement(announcement_id):
    """删除公告"""
    owner = current_user
    
    announcement = owner_bp.OwnerAnnouncements.query.get(announcement_id)
    if not announcement or announcement.is_deleted:
        return jsonify({'error': '公告不存在'}), 404
    
    try:
        announcement.is_deleted = True
        owner_bp.db.session.commit()
        
        # 记录日志
        log_entry = owner_bp.OwnerLogs(
            owner_id=owner.id,
            action='delete_announcement',
            target_type='announcement',
            target_id=announcement.id,
            content=f'删除公告: {announcement.title}',
            ip_address=request.remote_addr
        )
        owner_bp.db.session.add(log_entry)
        owner_bp.db.session.commit()
        
        return jsonify({'success': True, 'message': '公告已删除'})
        
    except Exception as e:
        owner_bp.db.session.rollback()
        print(f"删除公告失败: {e}")
        return jsonify({'error': '删除失败'}), 500


@owner_bp.route('/announcement/<int:announcement_id>/toggle-pin', methods=['POST'])
@login_required
@owner_required
def toggle_announcement_pin(announcement_id):
    """切换公告置顶状态"""
    announcement = owner_bp.OwnerAnnouncements.query.get(announcement_id)
    if not announcement or announcement.is_deleted:
        return jsonify({'error': '公告不存在'}), 404
    
    try:
        announcement.is_pinned = not announcement.is_pinned
        owner_bp.db.session.commit()
        
        return jsonify({
            'success': True,
            'is_pinned': announcement.is_pinned,
            'message': '已置顶' if announcement.is_pinned else '已取消置顶'
        })
        
    except Exception as e:
        owner_bp.db.session.rollback()
        print(f"切换置顶失败: {e}")
        return jsonify({'error': '操作失败'}), 500


@owner_bp.route('/api/announcements')
def get_announcements():
    """获取公告列表（API）"""
    role = session.get('role', 'user')
    
    all_announcements = []
    
    # 获取管理员公告
    admin_announcements = owner_bp.Announcements.query.filter(
        owner_bp.Announcements.is_deleted == False,
        owner_bp.Announcements.is_active == True,
        owner_bp.Announcements.start_at <= datetime.now(),
        (owner_bp.Announcements.end_at >= datetime.now()) | (owner_bp.Announcements.end_at == None),
        (owner_bp.Announcements.target_role == 'all') | (owner_bp.Announcements.target_role == role)
    ).all()
    
    # 获取超级管理员公告
    superadmin_announcements = owner_bp.SuperAdminAnnouncements.query.filter(
        owner_bp.SuperAdminAnnouncements.is_deleted == False,
        owner_bp.SuperAdminAnnouncements.is_active == True,
        owner_bp.SuperAdminAnnouncements.start_at <= datetime.now(),
        (owner_bp.SuperAdminAnnouncements.end_at >= datetime.now()) | (owner_bp.SuperAdminAnnouncements.end_at == None),
        (owner_bp.SuperAdminAnnouncements.target_role == 'all') | (owner_bp.SuperAdminAnnouncements.target_role == role)
    ).all()
    
    # 获取所有者公告
    owner_announcements = owner_bp.OwnerAnnouncements.query.filter(
        owner_bp.OwnerAnnouncements.is_deleted == False,
        owner_bp.OwnerAnnouncements.is_active == True,
        owner_bp.OwnerAnnouncements.start_at <= datetime.now(),
        (owner_bp.OwnerAnnouncements.end_at >= datetime.now()) | (owner_bp.OwnerAnnouncements.end_at == None),
        (owner_bp.OwnerAnnouncements.target_role == 'all') | (owner_bp.OwnerAnnouncements.target_role == role)
    ).all()
    
    # 合并
    for ann in admin_announcements:
        all_announcements.append({
            'id': ann.id,
            'title': ann.title,
            'content': ann.content,
            'category': ann.category,
            'is_pinned': ann.is_pinned,
            'author_name': ann.author_name,
            'author_role': 'admin',
            'created_at': ann.created_at.strftime('%Y-%m-%d %H:%M')
        })
    
    for ann in superadmin_announcements:
        all_announcements.append({
            'id': ann.id,
            'title': ann.title,
            'content': ann.content,
            'category': ann.category,
            'is_pinned': ann.is_pinned,
            'author_name': ann.author_name,
            'author_role': 'superadmin',
            'created_at': ann.created_at.strftime('%Y-%m-%d %H:%M')
        })
    
    for ann in owner_announcements:
        all_announcements.append({
            'id': ann.id,
            'title': ann.title,
            'content': ann.content,
            'category': ann.category,
            'is_pinned': ann.is_pinned,
            'author_name': ann.author_name,
            'author_role': 'owner',
            'created_at': ann.created_at.strftime('%Y-%m-%d %H:%M')
        })
    
    # 按置顶和时间排序
    all_announcements.sort(key=lambda x: (not x['is_pinned'], x['created_at']), reverse=True)
    
    return jsonify({
        'success': True,
        'data': all_announcements[:20]
    })


@owner_bp.route('/api/announcement/<int:announcement_id>/read', methods=['POST'])
@login_required
def mark_announcement_read(announcement_id):
    """标记公告为已读"""
    role = session.get('role')
    user_id = session.get(f'{role}_id')
    
    if not user_id:
        return jsonify({'error': '未登录'}), 401
    
    # 确定是哪个公告表
    from_where = request.args.get('from', 'owner')
    
    if from_where == 'admin':
        announcement = owner_bp.Announcements.query.get(announcement_id)
        read_model = owner_bp.AnnouncementReads
    elif from_where == 'superadmin':
        announcement = owner_bp.SuperAdminAnnouncements.query.get(announcement_id)
        read_model = owner_bp.SuperAdminAnnouncementReads
    else:
        announcement = owner_bp.OwnerAnnouncements.query.get(announcement_id)
        read_model = owner_bp.OwnerAnnouncementReads
    
    if not announcement or announcement.is_deleted:
        return jsonify({'error': '公告不存在'}), 404
    
    # 检查是否已读
    existing = read_model.query.filter_by(
        announcement_id=announcement_id,
        user_id=user_id,
        user_role=role
    ).first()
    
    if not existing:
        read_record = read_model(
            announcement_id=announcement_id,
            user_id=user_id,
            user_role=role,
            read_at=datetime.now()
        )
        owner_bp.db.session.add(read_record)
        announcement.views += 1
        owner_bp.db.session.commit()
    
    return jsonify({'success': True})


# ========== 日志查看 ==========

@owner_bp.route('/logs')
@login_required
@owner_required
def logs():
    """日志查看页面"""
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 50, type=int)
    log_type = request.args.get('type', 'all')  # all, admin, superadmin, owner
    action = request.args.get('action')
    
    if log_type == 'admin':
        query = owner_bp.AdminLogs.query
        model_name = 'AdminLogs'
    elif log_type == 'superadmin':
        query = owner_bp.SuperAdminLogs.query
        model_name = 'SuperAdminLogs'
    elif log_type == 'owner':
        query = owner_bp.OwnerLogs.query
        model_name = 'OwnerLogs'
    else:
        # 简化：只显示owner日志
        query = owner_bp.OwnerLogs.query
        model_name = 'OwnerLogs'
    
    if action:
        query = query.filter_by(action=action)
    
    logs = query.order_by(owner_bp.OwnerLogs.time.desc())\
        .paginate(page=page, per_page=per_page, error_out=False)
    
    return owner_bp.renderTemplate(
        '/base-files/logs.html',
        logs=logs.items,
        pagination=logs,
        log_type=log_type,
        action=action,
        model_name=model_name
    )


@owner_bp.route('/api/logs')
@login_required
@owner_required
def api_logs():
    """获取日志API"""
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 50, type=int)
    log_type = request.args.get('type', 'owner')
    action = request.args.get('action')
    
    if log_type == 'admin':
        query = owner_bp.AdminLogs.query
    elif log_type == 'superadmin':
        query = owner_bp.SuperAdminLogs.query
    else:
        query = owner_bp.OwnerLogs.query
    
    if action:
        query = query.filter_by(action=action)
    
    logs = query.order_by(owner_bp.OwnerLogs.time.desc())\
        .paginate(page=page, per_page=per_page, error_out=False)
    
    logs_data = []
    for log in logs.items:
        log_data = {
            'id': log.id,
            'time': log.time.isoformat(),
            'action': log.action,
            'target_type': log.target_type,
            'target_id': log.target_id,
            'content': log.content,
            'ip_address': log.ip_address
        }
        
        if log_type == 'admin':
            log_data['admin_id'] = log.admin_id
        elif log_type == 'superadmin':
            log_data['super_admin_id'] = log.super_admin_id
        else:
            log_data['owner_id'] = log.owner_id
        
        logs_data.append(log_data)
    
    return jsonify({
        'success': True,
        'data': logs_data,
        'total': logs.total,
        'page': page,
        'per_page': per_page
    })


# ========== 系统设置 ==========

@owner_bp.route('/settings')
@login_required
@owner_required
def settings():
    """系统设置页面"""
    return owner_bp.renderTemplate('/base-files/settings.html', user=current_user)


@owner_bp.route('/api/settings', methods=['GET', 'POST'])
@login_required
@owner_required
def api_settings():
    """获取/更新系统设置"""
    if request.method == 'GET':
        # 从配置文件或数据库读取设置
        settings = {
            'site_name': 'FreeHub',
            'site_description': '一个自由的社区',
            'allow_register': True,
            'require_email_verify': True,
            'max_upload_size': 100,
            'allowed_file_types': ['image', 'document', 'font', 'archive'],
            'maintenance_mode': False,
            'invite_code_auto_enable': True,
            'invite_code_threshold': 300,
            'user_admin_ratio': 2
        }
        return jsonify({'success': True, 'data': settings})
    
    else:
        data = request.get_json()
        # TODO: 保存设置到配置文件或数据库
        return jsonify({'success': True, 'message': '设置已保存'})


# ========== 个人资料 ==========

@owner_bp.route('/profile')
@login_required
@owner_required
def profile():
    """Owner个人资料"""
    owner = current_user
    return owner_bp.renderTemplate('/base-files/profile.html', user=owner)


@owner_bp.route('/change-password', methods=['GET', 'POST'])
@login_required
@owner_required
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
        
        owner = current_user
        
        if not owner.pbkdf2_salt or not owner.pbkdf2_iterations:
            return jsonify({'error': '用户安全参数异常'})
        
        if owner.pbkdf2_salt != salt or owner.pbkdf2_iterations != int(iterations):
            return jsonify({'error': '安全参数不匹配'})
        
        if not Password().verify_pw(old_password, owner.crypto_pw)[0]:
            return jsonify({'error': '旧密码错误'})
        
        owner.crypto_pw = Password().hash_pw(new_password)
        owner_bp.db.session.commit()
        
        session.pop('captcha_expected', None)

        return jsonify({'success': '密码修改成功'})

    return owner_bp.renderTemplate('/base-files/change-password.html')


@owner_bp.route('/upload-avatar', methods=['GET', 'POST'])
@login_required
@owner_required
def upload_avatar():
    """上传头像"""
    if request.method == 'POST':
        try:
            if 'avatar' not in request.files:
                return jsonify({'success': False, 'error': '没有选择文件'})
        
            file = request.files['avatar']
            if file.filename == '':
                return jsonify({'success': False, 'error': '没有选择文件'})
        
            allowed_extensions = {'jpg', 'jpeg', 'png', 'webp'}
            if not ('.' in file.filename and 
                    file.filename.rsplit('.', 1)[1].lower() in allowed_extensions):
                return jsonify({'success': False, 'error': '不支持的文件格式'})
        
            file.seek(0, 2)
            file_size = file.tell()
            file.seek(0)
            if file_size > 5 * 1024 * 1024:
                return jsonify({'success': False, 'error': '文件大小不能超过5MB'})
        
            owner = current_user
        
            upload_dir = os.path.join(owner_bp.app.static_folder, 'img', 'upload', 'avatar')
            os.makedirs(upload_dir, exist_ok=True)
        
            filename = f"{owner.nickname}.png"
            filepath = os.path.join(upload_dir, 'Owners', filename)
            os.makedirs(os.path.dirname(filepath), exist_ok=True)
        
            try:
                image = Image.open(file.stream)
            
                if image.mode in ('RGBA', 'LA'):
                    background = Image.new('RGB', image.size, (255, 255, 255))
                    if image.mode == 'RGBA':
                        background.paste(image, mask=image.split()[-1])
                    else:
                        background.paste(image)
                    image = background
                elif image.mode != 'RGB':
                    image = image.convert('RGB')
            
                size = min(image.size)
                left = (image.size[0] - size) // 2
                top = (image.size[1] - size) // 2
                right = left + size
                bottom = top + size
            
                image = image.crop((left, top, right, bottom))
                image.save(filepath, 'PNG', quality=95)
            
                return jsonify({
                    'success': True, 
                    'message': '头像上传成功',
                    'avatar_url': f"/static/img/upload/avatar/Owners/{filename}"
                })
            
            except Exception as e:
                print(f"图片处理错误: {e}")
                return jsonify({'success': False, 'error': '图片处理失败'})
            
        except Exception as e:
            print(f"上传错误: {e}")
            return jsonify({'success': False, 'error': '上传失败'})
        
    else:
        return owner_bp.renderTemplate('/base-files/upload-avatar.html')
    