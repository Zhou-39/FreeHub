from flask import Blueprint, render_template, request, session, jsonify, redirect, url_for, make_response
from flask_login import login_user, logout_user, login_required, current_user
from utils.password_checker import Password
from utils.email_sender import EmailSender, generate_reset_token
from utils.pbkdf2_security import PBKDF2Security
from utils.utils import RenderTemplate, anonymous_required, require_csrf
from utils.file_scanner import FileScanner
import os
import re
import secrets
from datetime import datetime, timedelta
from PIL import Image
from functools import wraps

superadmin_bp = Blueprint('superadmin', __name__)

# 初始化 PBKDF2 安全模块
pbkdf2_security = PBKDF2Security()

# 初始化文件扫描器
file_scanner = FileScanner()

# 需要在主app中初始化db后传入
def init_superadmin_bp(app, db, SuperAdmins, EmailVerificationTokens, PasswordResetTokens,
                       Admins, IDs, UIDs, Posts, Articles, Uploads, Comments, 
                       SuperAdminLogs, SuperAdminAnnouncements, SuperAdminAnnouncementReads,
                       AdminLogs):
    """初始化超级管理员蓝图"""
    random_url_prefix = secrets.token_urlsafe(secrets.randbelow(4) + 8)
    superadmin_bp.url_prefix = f"/{random_url_prefix}"
    app.config['SUPERADMIN_PREFIX'] = random_url_prefix
    print(f"SuperAdmin URL Prefix: /{random_url_prefix} (每次服务器重启会随机生成新的前缀)")
    
    # 存储数据库相关对象
    superadmin_bp.db = db
    superadmin_bp.SuperAdmins = SuperAdmins
    superadmin_bp.EmailVerificationTokens = EmailVerificationTokens
    superadmin_bp.PasswordResetTokens = PasswordResetTokens
    superadmin_bp.Admins = Admins
    superadmin_bp.IDs = IDs
    superadmin_bp.UIDs = UIDs
    superadmin_bp.Posts = Posts
    superadmin_bp.Articles = Articles
    superadmin_bp.Uploads = Uploads
    superadmin_bp.Comments = Comments
    superadmin_bp.SuperAdminLogs = SuperAdminLogs
    superadmin_bp.SuperAdminAnnouncements = SuperAdminAnnouncements
    superadmin_bp.SuperAdminAnnouncementReads = SuperAdminAnnouncementReads
    superadmin_bp.AdminLogs = AdminLogs
    superadmin_bp.app = app
    
    # 创建蓝图特定的模型字典
    superadmin_models = {
        'SuperAdmins': SuperAdmins,
        'Admins': Admins,
        'IDs': IDs,
        'UIDs': UIDs
    }

    # 初始化蓝图特定的渲染实例
    superadmin_bp.renderTemplate = RenderTemplate(
        db, 
        models=superadmin_models, 
        global_context={'basic_url': superadmin_bp.url_prefix[1:]}
    ).renderTemplate
    
    return superadmin_bp


# ========== 辅助函数 ==========

def get_current_identity():
    """获取当前身份信息"""
    try:
        if current_user.is_authenticated:
            user_class = current_user.__class__.__name__
            
            if user_class == 'SuperAdmins':
                return {
                    'type': 'superadmin',
                    'id': current_user.id,
                    'nickname': current_user.nickname,
                    'email': current_user.email,
                    'email_verified': current_user.email_verified,
                    'object': current_user,
                    'level': current_user.level
                }
        return None
    except:
        return None


def get_session_key():
    """生成唯一的会话标识符"""
    if 'session_key' not in session:
        session['session_key'] = secrets.token_hex(16)
    return session['session_key']


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
        return superadmin_bp.IDs.query.get(user_id)
    except:
        return None


def get_uid_by_id(uid):
    """根据UID获取UID信息（辅助模板函数）"""
    try:
        return superadmin_bp.UIDs.query.get(uid)
    except:
        return None


def get_post_by_id(post_id):
    """根据帖子ID获取帖子信息（辅助模板函数）"""
    try:
        return superadmin_bp.Posts.query.get(post_id)
    except:
        return None


def get_article_by_id(arid):
    """根据文章ID获取文章信息（辅助模板函数）"""
    try:
        return superadmin_bp.Articles.query.get(arid)
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

def superadmin_required(f):
    """只允许超级管理员访问的装饰器"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated:
            return redirect(url_for('superadmin.login'))
        
        if current_user.__class__.__name__ != 'SuperAdmins':
            return jsonify({'error': '需要超级管理员权限'}), 403
        
        return f(*args, **kwargs)
    return decorated_function


def log_superadmin_action(action, target_type=None, target_id=None, content=None):
    """记录超级管理员操作日志的装饰器"""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            result = f(*args, **kwargs)
            
            try:
                log_entry = superadmin_bp.SuperAdminLogs(
                    super_admin_id=current_user.id,
                    action=action,
                    target_type=target_type,
                    target_id=target_id,
                    content=content or f'执行操作: {action}',
                    ip_address=request.remote_addr,
                    time=datetime.now()
                )
                superadmin_bp.db.session.add(log_entry)
                superadmin_bp.db.session.commit()
            except Exception as e:
                print(f"记录日志失败: {e}")
            
            return result
        return decorated_function
    return decorator


# ========== 认证路由 ==========

@superadmin_bp.route('/api/pbkdf2-salt')
def get_superadmin_pbkdf2_salt():
    """获取PBKDF2参数"""
    try:
        superadmin_id = session.get('superadmin_id')
        
        if superadmin_id:
            superadmin = superadmin_bp.SuperAdmins.query.get(superadmin_id)
            if superadmin:
                salt, iterations = pbkdf2_security.get_pbkdf2_params_for_existing_user(superadmin)
                superadmin_bp.db.session.commit()
                return jsonify({
                    'success': True,
                    'salt': salt,
                    'iterations': iterations,
                    'is_superadmin_specific': True
                })
            else:
                return jsonify({'success': False, 'error': '超级管理员不存在'}), 404
        else:
            session_key = get_session_key()
            temp_key = f"temp_{session_key}"
            salt, iterations = pbkdf2_security.get_pbkdf2_params_for_new_user(temp_key)
            return jsonify({
                'success': True,
                'salt': salt,
                'iterations': iterations,
                'is_superadmin_specific': False
            })
            
    except Exception as e:
        print(f"获取PBKDF2参数失败: {e}")
        return jsonify({'success': False, 'error': '服务器错误'}), 500


@superadmin_bp.route('/api/superadmin-pbkdf2-params')
def get_superadmin_specific_pbkdf2_params():
    """获取超级管理员特定的PBKDF2参数"""
    try:
        account = request.args.get('account')
        
        if not account:
            return jsonify({'success': False, 'error': '账号参数缺失'})
        
        superadmin = superadmin_bp.SuperAdmins.query.filter(
            (superadmin_bp.SuperAdmins.nickname == account) | (superadmin_bp.SuperAdmins.email == account)
        ).first()
        
        if superadmin:
            if not superadmin.pbkdf2_salt or not superadmin.pbkdf2_iterations:
                superadmin.pbkdf2_salt, superadmin.pbkdf2_iterations = pbkdf2_security.get_pbkdf2_params_for_new_user()
                superadmin_bp.db.session.commit()
            
            return jsonify({
                'success': True,
                'salt': superadmin.pbkdf2_salt,
                'iterations': superadmin.pbkdf2_iterations,
                'is_superadmin_specific': True
            })
        else:
            session_key = get_session_key()
            temp_key = f"temp_{session_key}"
            salt, iterations = pbkdf2_security.get_pbkdf2_params_for_new_user(temp_key)
            
            return jsonify({
                'success': True,
                'salt': salt,
                'iterations': iterations,
                'is_superadmin_specific': False
            })
            
    except Exception as e:
        print(f"获取超级管理员PBKDF2参数失败: {e}")
        return jsonify({'success': False, 'error': '服务器错误'}), 500


@superadmin_bp.route('/login', methods=['GET', 'POST'])
@anonymous_required
@require_csrf
def login():
    """超级管理员登录"""
    if request.method == 'POST':
        account = request.form.get('account')
        client_hashed_pw = request.form.get('password')
        salt = request.form.get('salt')
        iterations = request.form.get('iterations')
        captcha_text = request.form.get('captcha')
        
        # 验证验证码
        expected_captcha = session.get('captcha_expected', '')
        if not expected_captcha or captcha_text.lower() != expected_captcha.lower():
            return jsonify({'error': '验证码错误'})
        
        if account and client_hashed_pw and salt and iterations:
            superadmin = superadmin_bp.SuperAdmins.query.filter(
                (superadmin_bp.SuperAdmins.nickname == account) | (superadmin_bp.SuperAdmins.email == account)
            ).first()

            if superadmin:
                if not superadmin.pbkdf2_salt or not superadmin.pbkdf2_iterations:
                    superadmin.pbkdf2_salt, superadmin.pbkdf2_iterations = pbkdf2_security.get_pbkdf2_params_for_new_user()
                    superadmin_bp.db.session.commit()
                    return jsonify({'error': '账户安全升级，请刷新页面重新登录'})
                
                if superadmin.pbkdf2_salt != salt or superadmin.pbkdf2_iterations != int(iterations):
                    return jsonify({'error': '安全参数不匹配，请刷新页面重试'})
                
                if Password().verify_pw(client_hashed_pw, superadmin.crypto_pw)[0]:
                    session.clear()
                    session['superadmin_id'] = superadmin.id
                    session['nickname'] = superadmin.nickname
                    session['role'] = 'superadmin'
                    session['logged-in'] = True
                    login_user(superadmin)
                    
                    superadmin.last_login = datetime.now()
                    superadmin_bp.db.session.commit()
                    
                    # 记录登录日志
                    log_entry = superadmin_bp.SuperAdminLogs(
                        super_admin_id=superadmin.id,
                        action='login',
                        content='超级管理员登录',
                        ip_address=request.remote_addr,
                        time=datetime.now()
                    )
                    superadmin_bp.db.session.add(log_entry)
                    superadmin_bp.db.session.commit()
                    
                    session.pop('captcha_expected', None)

                    if not superadmin.email_verified:
                        return jsonify({'warning': '邮箱未验证，部分功能可能受限'})
                    
                    return jsonify({'success': '登录成功'})
                else:
                    return jsonify({'error': '用户名或密码错误'})
            else:
                return jsonify({'error': '超级管理员不存在'})
        else:
            return jsonify({'error': '请填写完整信息'})
            
    return superadmin_bp.renderTemplate('/base-files/login.html')


@superadmin_bp.route('/register', methods=['GET', 'POST'])
@anonymous_required
@require_csrf
def register():
    """超级管理员注册（需要邀请码）"""
    if request.method == 'POST':
        nickname = request.form.get('nickname')
        email = request.form.get('email')
        client_hashed_pw = request.form.get('password')
        invite_code = request.form.get('invite_code')
        salt = request.form.get('salt')
        iterations = request.form.get('iterations')
        captcha_text = request.form.get('captcha')
        
        # 验证验证码
        expected_captcha = session.get('captcha_expected', '')
        if not expected_captcha or captcha_text.lower() != expected_captcha.lower():
            return jsonify({'error': '验证码错误'})
        
        if not nickname or not email or not client_hashed_pw or not invite_code:
            return jsonify({'error': '请填写完整信息'})
        
        # 验证邀请码
        if invite_code != 'FR33HUB-SUP3RADMlN-2O26':
            return jsonify({'error': '无效的邀请码'})
        
        # 验证昵称格式
        if not re.match(r'^[a-zA-Z0-9]{4,20}$', nickname):
            return jsonify({'error': '昵称只能包含字母和数字，长度4-20个字符'})
        
        # 验证邮箱格式
        if not re.match(r'^[^\s@]+@[^\s@]+\.[^\s@]+$', email):
            return jsonify({'error': '邮箱格式不正确'})
        
        # 检查是否已存在
        if superadmin_bp.SuperAdmins.query.filter_by(nickname=nickname).first():
            return jsonify({'error': '昵称已存在'})
        
        if superadmin_bp.SuperAdmins.query.filter_by(email=email).first():
            return jsonify({'error': '邮箱已被注册'})
        
        # 验证安全参数
        session_key = get_session_key()
        temp_key = f"temp_{session_key}"
        if not pbkdf2_security.verify_temp_params(temp_key, salt, int(iterations)):
            return jsonify({'error': '安全参数无效，请刷新页面重试'})
        
        # 创建超级管理员
        new_superadmin = superadmin_bp.SuperAdmins(
            nickname=nickname,
            email=email,
            crypto_pw=Password().hash_pw(client_hashed_pw),
            pbkdf2_salt=salt,
            pbkdf2_iterations=int(iterations),
            level=1,
            status=True,
            email_verified=False,
            invite_code=invite_code,
            invite_code_used=True,
            invite_code_created_at=datetime.now(),
            created_at=datetime.now(),
            can_manage_admins=True,
            can_manage_superadmins=False,
            can_post_announcement=True
        )
        
        superadmin_bp.db.session.add(new_superadmin)
        superadmin_bp.db.session.commit()
        
        # 发送验证邮件
        send_verification_email(new_superadmin)
        
        session.pop('captcha_expected', None)
        
        return jsonify({'success': '注册成功，请查收验证邮件完成邮箱验证'})
    
    # GET 请求
    return superadmin_bp.renderTemplate('/base-files/register.html')


@superadmin_bp.route('/logout')
@login_required
@superadmin_required
def logout():
    """超级管理员登出"""
    # 记录登出日志
    log_entry = superadmin_bp.SuperAdminLogs(
        super_admin_id=current_user.id,
        action='logout',
        content='超级管理员登出',
        ip_address=request.remote_addr,
        time=datetime.now()
    )
    superadmin_bp.db.session.add(log_entry)
    superadmin_bp.db.session.commit()
    
    logout_user()
    session.clear()
    session['logged-in'] = False
    return redirect(url_for('index'))


def send_verification_email(superadmin):
    """发送验证邮件"""
    verification_token = generate_reset_token()
    expires_at = datetime.now() + timedelta(hours=24)

    superadmin_bp.EmailVerificationTokens.query.filter_by(
        superadmin_id=superadmin.id, 
        used=False
    ).delete()

    token_entry = superadmin_bp.EmailVerificationTokens(
        superadmin_id=superadmin.id,
        token=verification_token,
        email=superadmin.email,
        expires_at=expires_at,
        used=False
    )
    
    try:
        superadmin_bp.db.session.add(token_entry)
        superadmin_bp.db.session.commit()
        
        from flask import request
        email_sender = EmailSender(superadmin_bp.app, request.host_url, superadmin_bp.url_prefix[1:], 'superadmin')
        success = email_sender.send_verification_email(superadmin.email, verification_token, superadmin.id)
        
        if not success:
            print(f"发送验证邮件失败: {superadmin.email}")
            
    except Exception as e:
        superadmin_bp.db.session.rollback()
        print(f"创建验证令牌失败: {e}")


# ========== 仪表盘 ==========

@superadmin_bp.route('/')
@superadmin_bp.route('/dashboard')
@login_required
@superadmin_required
def dashboard():
    """超级管理员仪表盘"""
    identity = get_current_identity()
    
    # 获取统计数据
    stats = {
        'users': {
            'total': superadmin_bp.IDs.query.count(),
            'active_24h': superadmin_bp.IDs.query.filter(
                superadmin_bp.IDs.last_login >= datetime.now() - timedelta(hours=24)
            ).count(),
            'total_uids': superadmin_bp.UIDs.query.count(),
            'email_verified': superadmin_bp.IDs.query.filter_by(email_verified=True).count()
        },
        'admins': {
            'total': superadmin_bp.Admins.query.count(),
            'active': superadmin_bp.Admins.query.filter_by(status=True).count(),
            'email_verified': superadmin_bp.Admins.query.filter_by(email_verified=True).count()
        },
        'superadmins': {
            'total': superadmin_bp.SuperAdmins.query.count(),
            'active': superadmin_bp.SuperAdmins.query.filter_by(status=True).count()
        },
        'content': {
            'posts': superadmin_bp.Posts.query.filter_by(is_deleted=False).count(),
            'articles': superadmin_bp.Articles.query.filter_by(is_deleted=False).count(),
            'uploads': superadmin_bp.Uploads.query.filter_by(is_deleted=False).count(),
            'comments': superadmin_bp.Comments.query.filter_by(is_deleted=False).count(),
            'total_size': superadmin_bp.db.session.query(
                superadmin_bp.db.func.sum(superadmin_bp.Uploads.file_size)
            ).scalar() or 0
        }
    }
    
    # 获取最近活动
    recent_activities = []
    
    # 最近的管理员操作
    recent_logs = superadmin_bp.AdminLogs.query.order_by(
        superadmin_bp.AdminLogs.time.desc()
    ).limit(5).all()
    for log in recent_logs:
        admin = superadmin_bp.Admins.query.get(log.admin_id)
        recent_activities.append({
            'type': 'admin_action',
            'content': f'管理员 {admin.nickname if admin else "未知"} 执行了 {log.action}',
            'time': log.time,
            'icon': 'user-cog',
            'color': 'warning'
        })
    
    # 最近的帖子
    recent_posts = superadmin_bp.Posts.query.filter_by(is_deleted=False).order_by(
        superadmin_bp.Posts.created_at.desc()
    ).limit(5).all()
    for post in recent_posts:
        uid = superadmin_bp.UIDs.query.get(post.author_id)
        recent_activities.append({
            'type': 'post_create',
            'content': f'新帖子: "{post.title}" 由 {uid.nickname if uid else "未知用户"} 发布',
            'time': post.created_at,
            'icon': 'file-alt',
            'color': 'info'
        })
    
    # 按时间排序
    recent_activities.sort(key=lambda x: x['time'], reverse=True)
    recent_activities = recent_activities[:10]
    
    return superadmin_bp.renderTemplate(
        '/base-files/dashboard.html',
        stats=stats,
        recent_activities=recent_activities,
        identity=identity,
        user=current_user
    )


@superadmin_bp.route('/api/stats')
@login_required
@superadmin_required
def api_stats():
    """获取统计数据API"""
    stats = {
        'users': {
            'total': superadmin_bp.IDs.query.count(),
            'active_24h': superadmin_bp.IDs.query.filter(
                superadmin_bp.IDs.last_login >= datetime.now() - timedelta(hours=24)
            ).count(),
            'total_uids': superadmin_bp.UIDs.query.count()
        },
        'admins': {
            'total': superadmin_bp.Admins.query.count(),
            'active': superadmin_bp.Admins.query.filter_by(status=True).count()
        },
        'superadmins': {
            'total': superadmin_bp.SuperAdmins.query.count(),
            'active': superadmin_bp.SuperAdmins.query.filter_by(status=True).count()
        },
        'content': {
            'posts': superadmin_bp.Posts.query.filter_by(is_deleted=False).count(),
            'articles': superadmin_bp.Articles.query.filter_by(is_deleted=False).count(),
            'uploads': superadmin_bp.Uploads.query.filter_by(is_deleted=False).count(),
            'total_size': superadmin_bp.db.session.query(
                superadmin_bp.db.func.sum(superadmin_bp.Uploads.file_size)
            ).scalar() or 0
        }
    }
    return jsonify({'success': True, 'data': stats})


# ========== 管理员管理 ==========

@superadmin_bp.route('/admins')
@login_required
@superadmin_required
def admins():
    """管理员管理页面"""
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 20, type=int)
    search = request.args.get('search', '')
    status = request.args.get('status', 'all')
    
    query = superadmin_bp.Admins.query
    
    if search:
        query = query.filter(
            (superadmin_bp.Admins.nickname.contains(search)) |
            (superadmin_bp.Admins.email.contains(search))
        )
    
    if status != 'all':
        query = query.filter_by(status=(status == 'active'))
    
    admins = query.order_by(superadmin_bp.Admins.created_at.desc())\
        .paginate(page=page, per_page=per_page, error_out=False)
    
    return superadmin_bp.renderTemplate(
        '/base-files/admins.html',
        admins=admins.items,
        pagination=admins,
        search=search,
        status=status
    )


@superadmin_bp.route('/api/admins')
@login_required
@superadmin_required
def api_admins():
    """获取管理员列表API"""
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 20, type=int)
    search = request.args.get('search', '')
    status = request.args.get('status', 'all')
    
    query = superadmin_bp.Admins.query
    
    if search:
        query = query.filter(
            (superadmin_bp.Admins.nickname.contains(search)) |
            (superadmin_bp.Admins.email.contains(search))
        )
    
    if status != 'all':
        query = query.filter_by(status=(status == 'active'))
    
    admins = query.order_by(superadmin_bp.Admins.created_at.desc())\
        .paginate(page=page, per_page=per_page, error_out=False)
    
    admins_data = []
    for admin in admins.items:
        admins_data.append({
            'id': admin.id,
            'nickname': admin.nickname,
            'email': admin.email,
            'email_verified': admin.email_verified,
            'status': admin.status,
            'level': admin.level,
            'invite_code': admin.invite_code,
            'invite_code_used': admin.invite_code_used,
            'created_at': admin.created_at.isoformat() if admin.created_at else None,
            'last_login': admin.last_login.isoformat() if admin.last_login else None,
            'can_manage_users': admin.can_manage_users,
            'can_manage_admins': admin.can_manage_admins
        })
    
    return jsonify({
        'success': True,
        'data': admins_data,
        'total': admins.total,
        'page': page,
        'per_page': per_page,
        'has_next': admins.has_next,
        'has_prev': admins.has_prev
    })


@superadmin_bp.route('/admin/<int:admin_id>/toggle-status', methods=['POST'])
@login_required
@superadmin_required
@log_superadmin_action('toggle_admin_status', 'admin')
def toggle_admin_status(admin_id):
    """切换管理员状态"""
    admin = superadmin_bp.Admins.query.get(admin_id)
    if not admin:
        return jsonify({'error': '管理员不存在'}), 404
    
    # 不能禁用自己
    if admin.id == current_user.id:
        return jsonify({'error': '不能禁用自己'}), 400
    
    admin.status = not admin.status
    superadmin_bp.db.session.commit()
    
    return jsonify({
        'success': True,
        'status': admin.status,
        'message': '管理员已启用' if admin.status else '管理员已禁用'
    })


@superadmin_bp.route('/admin/<int:admin_id>/reset-password', methods=['POST'])
@login_required
@superadmin_required
@log_superadmin_action('reset_admin_password', 'admin')
def reset_admin_password(admin_id):
    """重置管理员密码"""
    admin = superadmin_bp.Admins.query.get(admin_id)
    if not admin:
        return jsonify({'error': '管理员不存在'}), 404
    
    # 生成临时密码
    temp_password = secrets.token_urlsafe(12)
    
    # 更新密码
    admin.crypto_pw = Password().hash_pw(temp_password)
    superadmin_bp.db.session.commit()
    
    # TODO: 发送邮件通知管理员
    
    return jsonify({
        'success': True,
        'message': '密码已重置',
        'temp_password': temp_password  # 仅开发环境使用
    })


@superadmin_bp.route('/admin/create', methods=['POST'])
@login_required
@superadmin_required
@log_superadmin_action('create_admin', 'admin')
def create_admin():
    """创建新管理员"""
    try:
        data = request.get_json()
        nickname = data.get('nickname')
        email = data.get('email')
        
        if not nickname or not email:
            return jsonify({'error': '昵称和邮箱不能为空'}), 400
        
        # 检查是否已存在
        if superadmin_bp.Admins.query.filter_by(nickname=nickname).first():
            return jsonify({'error': '昵称已存在'}), 400
        
        if superadmin_bp.Admins.query.filter_by(email=email).first():
            return jsonify({'error': '邮箱已被注册'}), 400
        
        # 生成临时密码
        temp_password = secrets.token_urlsafe(12)
        hashed_pw = Password().hash_pw(temp_password)
        
        # 创建管理员
        new_admin = superadmin_bp.Admins(
            nickname=nickname,
            email=email,
            crypto_pw=hashed_pw,
            level=1,
            status=True,
            email_verified=False,
            created_at=datetime.now(),
            can_manage_users=True,
            can_manage_admins=False,
            can_post_announcement=True
        )
        
        superadmin_bp.db.session.add(new_admin)
        superadmin_bp.db.session.commit()
        
        # TODO: 发送邮件通知管理员，包含临时密码
        
        return jsonify({
            'success': True,
            'message': '管理员创建成功',
            'temp_password': temp_password  # 仅开发环境使用
        })
        
    except Exception as e:
        superadmin_bp.db.session.rollback()
        print(f"创建管理员失败: {e}")
        return jsonify({'error': '创建失败'}), 500


# ========== 用户管理（可以看到关联的ID）==========

@superadmin_bp.route('/users')
@login_required
@superadmin_required
def users():
    """用户管理页面（IDs）"""
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 20, type=int)
    search = request.args.get('search', '')
    
    query = superadmin_bp.IDs.query
    
    if search:
        query = query.filter(
            (superadmin_bp.IDs.nickname.contains(search)) |
            (superadmin_bp.IDs.email.contains(search))
        )
    
    users = query.order_by(superadmin_bp.IDs.created_at.desc())\
        .paginate(page=page, per_page=per_page, error_out=False)
    
    return superadmin_bp.renderTemplate(
        '/base-files/users.html',
        users=users.items,
        pagination=users,
        search=search
    )


@superadmin_bp.route('/api/users')
@login_required
@superadmin_required
def api_users():
    """获取用户列表API"""
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 20, type=int)
    search = request.args.get('search', '')
    
    query = superadmin_bp.IDs.query
    
    if search:
        query = query.filter(
            (superadmin_bp.IDs.nickname.contains(search)) |
            (superadmin_bp.IDs.email.contains(search))
        )
    
    users = query.order_by(superadmin_bp.IDs.created_at.desc())\
        .paginate(page=page, per_page=per_page, error_out=False)
    
    users_data = []
    for user in users.items:
        uids = superadmin_bp.UIDs.query.filter_by(id=user.id).all()
        users_data.append({
            'id': user.id,
            'nickname': user.nickname,
            'email': user.email,
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


@superadmin_bp.route('/user/<int:user_id>')
@login_required
@superadmin_required
def user_detail(user_id):
    """用户详情页面"""
    user = superadmin_bp.IDs.query.get(user_id)
    if not user:
        return jsonify({'error': '用户不存在'}), 404
    
    uids = superadmin_bp.UIDs.query.filter_by(id=user.id).all()
    
    return superadmin_bp.renderTemplate(
        '/base-files/user-detail.html',
        user=user,
        uids=uids
    )


@superadmin_bp.route('/user/<int:user_id>/toggle-status', methods=['POST'])
@login_required
@superadmin_required
@log_superadmin_action('toggle_user_status', 'user')
def toggle_user_status(user_id):
    """切换用户状态"""
    user = superadmin_bp.IDs.query.get(user_id)
    if not user:
        return jsonify({'error': '用户不存在'}), 404
    
    user.status = not user.status
    
    # 同时禁用/启用所有子账户
    uids = superadmin_bp.UIDs.query.filter_by(id=user_id).all()
    for uid in uids:
        uid.status = user.status
    
    superadmin_bp.db.session.commit()
    
    return jsonify({
        'success': True,
        'status': user.status,
        'message': '用户已启用' if user.status else '用户已禁用'
    })


# ========== UID管理（可以看到关联的ID）==========

@superadmin_bp.route('/uids')
@login_required
@superadmin_required
def uids():
    """UID管理页面（可以看到关联的ID）"""
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 20, type=int)
    search = request.args.get('search', '')
    status = request.args.get('status', 'all')
    
    query = superadmin_bp.UIDs.query
    
    if search:
        query = query.filter(superadmin_bp.UIDs.nickname.contains(search))
    
    if status != 'all':
        query = query.filter_by(status=(status == 'active'))
    
    uids = query.order_by(superadmin_bp.UIDs.created_at.desc())\
        .paginate(page=page, per_page=per_page, error_out=False)
    
    return superadmin_bp.renderTemplate(
        '/base-files/users.html',
        uids=uids.items,
        pagination=uids,
        search=search,
        status=status
    )


@superadmin_bp.route('/api/uids')
@login_required
@superadmin_required
def api_uids():
    """获取UID列表API（包含关联的ID信息，但无邮箱）"""
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 20, type=int)
    search = request.args.get('search', '')
    status = request.args.get('status', 'all')
    
    query = superadmin_bp.UIDs.query
    
    if search:
        query = query.filter(superadmin_bp.UIDs.nickname.contains(search))
    
    if status != 'all':
        query = query.filter_by(status=(status == 'active'))
    
    uids = query.order_by(superadmin_bp.UIDs.created_at.desc())\
        .paginate(page=page, per_page=per_page, error_out=False)
    
    uids_data = []
    for uid in uids.items:
        user = superadmin_bp.IDs.query.get(uid.id)
        uids_data.append({
            'uid': uid.uid,
            'nickname': uid.nickname,
            'level': uid.level,
            'points': uid.points,
            'status': uid.status,
            'posts_count': uid.posts_count,
            'articles_count': uid.articles_count,
            'uploads_count': uid.uploads_count,
            'followers_count': uid.followers_count,
            'following_count': uid.following_count,
            'created_at': uid.created_at.isoformat() if uid.created_at else None,
            'last_active': uid.last_active.isoformat() if uid.last_active else None,
            'user': {
                'id': user.id if user else None,
                'nickname': user.nickname if user else None,
                'level': user.level if user else None,
                'status': user.status if user else None
            } if user else None
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


@superadmin_bp.route('/uid/<int:uid>')
@login_required
@superadmin_required
def uid_detail(uid):
    """UID详情页面（可以看到关联的ID信息）"""
    uid_record = superadmin_bp.UIDs.query.get(uid)
    if not uid_record:
        return jsonify({'error': 'UID不存在'}), 404
    
    user = superadmin_bp.IDs.query.get(uid_record.id)
    
    # 获取UID的内容
    posts = superadmin_bp.Posts.query.filter_by(
        author_id=uid, is_deleted=False
    ).order_by(superadmin_bp.Posts.created_at.desc()).limit(20).all()
    
    articles = superadmin_bp.Articles.query.filter_by(
        author_id=uid, is_deleted=False
    ).order_by(superadmin_bp.Articles.time.desc()).limit(20).all()
    
    # 超级管理员可以看到所有文件（包括私密）
    uploads = superadmin_bp.Uploads.query.filter_by(
        uid=uid, is_deleted=False
    ).order_by(superadmin_bp.Uploads.created_at.desc()).limit(20).all()
    
    return superadmin_bp.renderTemplate(
        '/base-files/uid-detail.html',
        uid=uid_record,
        user=user,
        posts=posts,
        articles=articles,
        uploads=uploads
    )


@superadmin_bp.route('/uid/<int:uid>/toggle-status', methods=['POST'])
@login_required
@superadmin_required
@log_superadmin_action('toggle_uid_status', 'uid')
def toggle_uid_status(uid):
    """切换UID状态"""
    uid_record = superadmin_bp.UIDs.query.get(uid)
    if not uid_record:
        return jsonify({'error': 'UID不存在'}), 404
    
    uid_record.status = not uid_record.status
    superadmin_bp.db.session.commit()
    
    return jsonify({
        'success': True,
        'status': uid_record.status,
        'message': 'UID已启用' if uid_record.status else 'UID已禁用'
    })


# ========== 帖子管理 ==========

@superadmin_bp.route('/posts')
@login_required
@superadmin_required
def posts():
    """帖子管理页面"""
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 20, type=int)
    search = request.args.get('search', '')
    author = request.args.get('author', '')
    
    query = superadmin_bp.Posts.query.filter_by(is_deleted=False)
    
    if search:
        query = query.filter(
            (superadmin_bp.Posts.title.contains(search)) |
            (superadmin_bp.Posts.content.contains(search))
        )
    
    if author:
        uid_records = superadmin_bp.UIDs.query.filter(
            superadmin_bp.UIDs.nickname.contains(author)
        ).all()
        uid_ids = [uid.uid for uid in uid_records]
        query = query.filter(superadmin_bp.Posts.author_id.in_(uid_ids))
    
    posts = query.order_by(superadmin_bp.Posts.created_at.desc())\
        .paginate(page=page, per_page=per_page, error_out=False)
    
    posts_data = []
    for post in posts.items:
        uid = superadmin_bp.UIDs.query.get(post.author_id)
        posts_data.append({
            'id': post.id,
            'title': post.title,
            'content': post.content[:200] + '...' if post.content and len(post.content) > 200 else post.content,
            'author_nickname': uid.nickname if uid else '已删除用户',
            'author_uid': uid.uid if uid else None,
            'views': post.views,
            'created_at': post.created_at,
            'is_deleted': post.is_deleted
        })
    
    return superadmin_bp.renderTemplate(
        '/base-files/posts.html',
        posts=posts_data,
        pagination=posts,
        search=search,
        author=author
    )


@superadmin_bp.route('/api/posts')
@login_required
@superadmin_required
def api_posts():
    """获取帖子列表API"""
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 20, type=int)
    search = request.args.get('search', '')
    author = request.args.get('author', '')
    
    query = superadmin_bp.Posts.query.filter_by(is_deleted=False)
    
    if search:
        query = query.filter(
            (superadmin_bp.Posts.title.contains(search)) |
            (superadmin_bp.Posts.content.contains(search))
        )
    
    if author:
        uid_records = superadmin_bp.UIDs.query.filter(
            superadmin_bp.UIDs.nickname.contains(author)
        ).all()
        uid_ids = [uid.uid for uid in uid_records]
        query = query.filter(superadmin_bp.Posts.author_id.in_(uid_ids))
    
    posts = query.order_by(superadmin_bp.Posts.created_at.desc())\
        .paginate(page=page, per_page=per_page, error_out=False)
    
    posts_data = []
    for post in posts.items:
        uid = superadmin_bp.UIDs.query.get(post.author_id)
        posts_data.append({
            'id': post.id,
            'title': post.title,
            'content': post.content[:200] + '...' if post.content and len(post.content) > 200 else post.content,
            'author_nickname': uid.nickname if uid else '已删除用户',
            'author_uid': uid.uid if uid else None,
            'views': post.views,
            'created_at': post.created_at.isoformat(),
            'is_deleted': post.is_deleted
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


@superadmin_bp.route('/post/<int:post_id>/delete', methods=['POST'])
@login_required
@superadmin_required
@log_superadmin_action('delete_post', 'post')
def delete_post(post_id):
    """删除帖子"""
    post = superadmin_bp.Posts.query.get(post_id)
    if not post:
        return jsonify({'error': '帖子不存在'}), 404
    
    post.is_deleted = True
    post.deleted_at = datetime.now()
    
    uid = superadmin_bp.UIDs.query.get(post.author_id)
    if uid:
        uid.posts_count = max(0, uid.posts_count - 1)
    
    superadmin_bp.db.session.commit()
    
    return jsonify({'success': True, 'message': '帖子已删除'})


@superadmin_bp.route('/post/<int:post_id>/restore', methods=['POST'])
@login_required
@superadmin_required
@log_superadmin_action('restore_post', 'post')
def restore_post(post_id):
    """恢复帖子"""
    post = superadmin_bp.Posts.query.get(post_id)
    if not post:
        return jsonify({'error': '帖子不存在'}), 404
    
    post.is_deleted = False
    post.deleted_at = None
    
    uid = superadmin_bp.UIDs.query.get(post.author_id)
    if uid:
        uid.posts_count += 1
    
    superadmin_bp.db.session.commit()
    
    return jsonify({'success': True, 'message': '帖子已恢复'})


# ========== 文章管理 ==========

@superadmin_bp.route('/articles')
@login_required
@superadmin_required
def articles():
    """文章管理页面"""
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 20, type=int)
    search = request.args.get('search', '')
    author = request.args.get('author', '')
    
    query = superadmin_bp.Articles.query.filter_by(is_deleted=False)
    
    if search:
        query = query.filter(
            (superadmin_bp.Articles.title.contains(search)) |
            (superadmin_bp.Articles.content.contains(search))
        )
    
    if author:
        uid_records = superadmin_bp.UIDs.query.filter(
            superadmin_bp.UIDs.nickname.contains(author)
        ).all()
        uid_ids = [uid.uid for uid in uid_records]
        query = query.filter(superadmin_bp.Articles.author_id.in_(uid_ids))
    
    articles = query.order_by(superadmin_bp.Articles.time.desc())\
        .paginate(page=page, per_page=per_page, error_out=False)
    
    articles_data = []
    for article in articles.items:
        uid = superadmin_bp.UIDs.query.get(article.author_id)
        articles_data.append({
            'arid': article.arid,
            'title': article.title,
            'content': article.content[:200] + '...' if article.content and len(article.content) > 200 else article.content,
            'author_nickname': uid.nickname if uid else '已删除用户',
            'author_uid': uid.uid if uid else None,
            'views': article.views,
            'time': article.time,
            'is_deleted': article.is_deleted
        })
    
    return superadmin_bp.renderTemplate(
        '/base-files/articles.html',
        articles=articles_data,
        pagination=articles,
        search=search,
        author=author
    )


@superadmin_bp.route('/api/articles')
@login_required
@superadmin_required
def api_articles():
    """获取文章列表API"""
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 20, type=int)
    search = request.args.get('search', '')
    author = request.args.get('author', '')
    
    query = superadmin_bp.Articles.query.filter_by(is_deleted=False)
    
    if search:
        query = query.filter(
            (superadmin_bp.Articles.title.contains(search)) |
            (superadmin_bp.Articles.content.contains(search))
        )
    
    if author:
        uid_records = superadmin_bp.UIDs.query.filter(
            superadmin_bp.UIDs.nickname.contains(author)
        ).all()
        uid_ids = [uid.uid for uid in uid_records]
        query = query.filter(superadmin_bp.Articles.author_id.in_(uid_ids))
    
    articles = query.order_by(superadmin_bp.Articles.time.desc())\
        .paginate(page=page, per_page=per_page, error_out=False)
    
    articles_data = []
    for article in articles.items:
        uid = superadmin_bp.UIDs.query.get(article.author_id)
        articles_data.append({
            'arid': article.arid,
            'title': article.title,
            'content': article.content[:200] + '...' if article.content and len(article.content) > 200 else article.content,
            'author_nickname': uid.nickname if uid else '已删除用户',
            'author_uid': uid.uid if uid else None,
            'views': article.views,
            'time': article.time.isoformat(),
            'is_deleted': article.is_deleted
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


@superadmin_bp.route('/article/<int:arid>/delete', methods=['POST'])
@login_required
@superadmin_required
@log_superadmin_action('delete_article', 'article')
def delete_article(arid):
    """删除文章"""
    article = superadmin_bp.Articles.query.get(arid)
    if not article:
        return jsonify({'error': '文章不存在'}), 404
    
    article.is_deleted = True
    
    uid = superadmin_bp.UIDs.query.get(article.author_id)
    if uid:
        uid.articles_count = max(0, uid.articles_count - 1)
    
    superadmin_bp.db.session.commit()
    
    return jsonify({'success': True, 'message': '文章已删除'})


@superadmin_bp.route('/article/<int:arid>/restore', methods=['POST'])
@login_required
@superadmin_required
@log_superadmin_action('restore_article', 'article')
def restore_article(arid):
    """恢复文章"""
    article = superadmin_bp.Articles.query.get(arid)
    if not article:
        return jsonify({'error': '文章不存在'}), 404
    
    article.is_deleted = False
    
    uid = superadmin_bp.UIDs.query.get(article.author_id)
    if uid:
        uid.articles_count += 1
    
    superadmin_bp.db.session.commit()
    
    return jsonify({'success': True, 'message': '文章已恢复'})


# ========== 文件管理 ==========

@superadmin_bp.route('/uploads')
@login_required
@superadmin_required
def uploads():
    """文件管理页面（可以看到所有文件，包括私密）"""
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 20, type=int)
    search = request.args.get('search', '')
    category = request.args.get('category', 'all')
    scan_status = request.args.get('scan_status', 'all')
    
    query = superadmin_bp.Uploads.query.filter_by(is_deleted=False)
    
    if search:
        query = query.filter(
            (superadmin_bp.Uploads.original_filename.contains(search)) |
            (superadmin_bp.Uploads.description.contains(search))
        )
    
    if category != 'all':
        query = query.filter_by(file_category=category)
    
    if scan_status != 'all':
        query = query.filter_by(scan_result=scan_status)
    
    uploads = query.order_by(superadmin_bp.Uploads.created_at.desc())\
        .paginate(page=page, per_page=per_page, error_out=False)
    
    uploads_data = []
    for upload in uploads.items:
        uid = superadmin_bp.UIDs.query.get(upload.uid)
        uploads_data.append({
            'id': upload.id,
            'filename': upload.original_filename,
            'size': upload.file_size,
            'size_formatted': format_file_size(upload.file_size),
            'category': upload.file_category,
            'mime_type': upload.mime_type,
            'downloads': upload.downloads,
            'is_public': upload.is_public,
            'has_preview': upload.has_preview,
            'scan_result': upload.scan_result,
            'created_at': upload.created_at,
            'uploader_nickname': uid.nickname if uid else '未知用户',
            'uploader_uid': uid.uid if uid else None
        })
    
    # 获取分类统计
    categories = [
        {'id': 'all', 'name': '全部'},
        {'id': 'image', 'name': '图片'},
        {'id': 'document', 'name': '文档'},
        {'id': 'font', 'name': '字体'},
        {'id': 'archive', 'name': '压缩包'},
        {'id': 'other', 'name': '其他'}
    ]
    
    return superadmin_bp.renderTemplate(
        '/base-files/uploads.html',
        uploads=uploads_data,
        pagination=uploads,
        categories=categories,
        search=search,
        category=category,
        scan_status=scan_status
    )


@superadmin_bp.route('/api/uploads')
@login_required
@superadmin_required
def api_uploads():
    """获取文件列表API（包括私密文件）"""
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 20, type=int)
    search = request.args.get('search', '')
    category = request.args.get('category', 'all')
    scan_status = request.args.get('scan_status', 'all')
    
    query = superadmin_bp.Uploads.query.filter_by(is_deleted=False)
    
    if search:
        query = query.filter(
            (superadmin_bp.Uploads.original_filename.contains(search)) |
            (superadmin_bp.Uploads.description.contains(search))
        )
    
    if category != 'all':
        query = query.filter_by(file_category=category)
    
    if scan_status != 'all':
        query = query.filter_by(scan_result=scan_status)
    
    uploads = query.order_by(superadmin_bp.Uploads.created_at.desc())\
        .paginate(page=page, per_page=per_page, error_out=False)
    
    uploads_data = []
    for upload in uploads.items:
        uid = superadmin_bp.UIDs.query.get(upload.uid)
        uploads_data.append({
            'id': upload.id,
            'filename': upload.original_filename,
            'size': upload.file_size,
            'size_formatted': format_file_size(upload.file_size),
            'category': upload.file_category,
            'mime_type': upload.mime_type,
            'downloads': upload.downloads,
            'is_public': upload.is_public,
            'has_preview': upload.has_preview,
            'scan_result': upload.scan_result,
            'created_at': upload.created_at.isoformat(),
            'uploader_nickname': uid.nickname if uid else '未知用户',
            'uploader_uid': uid.uid if uid else None,
            'file_path': upload.file_path
        })
    
    return jsonify({
        'success': True,
        'data': uploads_data,
        'total': uploads.total,
        'page': page,
        'per_page': per_page,
        'has_next': uploads.has_next,
        'has_prev': uploads.has_prev
    })


@superadmin_bp.route('/upload/<int:upload_id>/delete', methods=['POST'])
@login_required
@superadmin_required
@log_superadmin_action('delete_upload', 'upload')
def delete_upload(upload_id):
    """删除文件（包括私密文件）"""
    upload = superadmin_bp.Uploads.query.get(upload_id)
    if not upload:
        return jsonify({'error': '文件不存在'}), 404
    
    # 删除物理文件
    file_path = os.path.join(superadmin_bp.app.static_folder, upload.file_path)
    if os.path.exists(file_path):
        os.remove(file_path)
    
    # 删除预览文件
    if upload.preview_path:
        preview_path = os.path.join(superadmin_bp.app.static_folder, upload.preview_path)
        if os.path.exists(preview_path):
            os.remove(preview_path)
    
    upload.is_deleted = True
    upload.deleted_at = datetime.now()
    
    uid = superadmin_bp.UIDs.query.get(upload.uid)
    if uid:
        uid.uploads_count = max(0, uid.uploads_count - 1)
    
    superadmin_bp.db.session.commit()
    
    return jsonify({'success': True, 'message': '文件已删除'})


@superadmin_bp.route('/upload/<int:upload_id>/restore', methods=['POST'])
@login_required
@superadmin_required
@log_superadmin_action('restore_upload', 'upload')
def restore_upload(upload_id):
    """恢复文件"""
    upload = superadmin_bp.Uploads.query.get(upload_id)
    if not upload:
        return jsonify({'error': '文件不存在'}), 404
    
    upload.is_deleted = False
    upload.deleted_at = None
    
    uid = superadmin_bp.UIDs.query.get(upload.uid)
    if uid:
        uid.uploads_count += 1
    
    superadmin_bp.db.session.commit()
    
    return jsonify({'success': True, 'message': '文件已恢复'})


@superadmin_bp.route('/upload/<int:upload_id>/scan', methods=['POST'])
@login_required
@superadmin_required
@log_superadmin_action('scan_upload', 'upload')
def scan_upload(upload_id):
    """重新扫描文件病毒"""
    upload = superadmin_bp.Uploads.query.get(upload_id)
    if not upload:
        return jsonify({'error': '文件不存在'}), 404
    
    file_path = os.path.join(superadmin_bp.app.static_folder, upload.file_path)
    if not os.path.exists(file_path):
        return jsonify({'error': '文件不存在'}), 404
    
    result = file_scanner.scan(file_path)
    
    upload.scanned = True
    upload.scan_result = 'clean' if result['safe'] else 'infected'
    upload.scan_details = result
    upload.scan_time = datetime.now()
    
    superadmin_bp.db.session.commit()
    
    return jsonify({
        'success': True,
        'scan_result': upload.scan_result,
        'message': '扫描完成'
    })


# ========== 评论管理 ==========

@superadmin_bp.route('/comments')
@login_required
@superadmin_required
def comments():
    """评论管理页面"""
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 30, type=int)
    search = request.args.get('search', '')
    
    query = superadmin_bp.Comments.query.filter_by(is_deleted=False)
    
    if search:
        query = query.filter(superadmin_bp.Comments.content.contains(search))
    
    comments = query.order_by(superadmin_bp.Comments.time.desc())\
        .paginate(page=page, per_page=per_page, error_out=False)
    
    comments_data = []
    for comment in comments.items:
        uid = superadmin_bp.UIDs.query.get(comment.author_id)
        article = superadmin_bp.Articles.query.get(comment.article_id)
        comments_data.append({
            'id': comment.id,
            'content': comment.content[:100] + '...' if comment.content and len(comment.content) > 100 else comment.content,
            'author_nickname': uid.nickname if uid else '已删除用户',
            'author_uid': uid.uid if uid else None,
            'article_title': article.title if article else '已删除文章',
            'article_id': comment.article_id,
            'time': comment.time,
            'is_deleted': comment.is_deleted
        })
    
    return superadmin_bp.renderTemplate(
        '/base-files/comments.html',
        comments=comments_data,
        pagination=comments,
        search=search
    )


@superadmin_bp.route('/comment/<int:comment_id>/delete', methods=['POST'])
@login_required
@superadmin_required
@log_superadmin_action('delete_comment', 'comment')
def delete_comment(comment_id):
    """删除评论"""
    comment = superadmin_bp.Comments.query.get(comment_id)
    if not comment:
        return jsonify({'error': '评论不存在'}), 404
    
    comment.is_deleted = True
    superadmin_bp.db.session.commit()
    
    return jsonify({'success': True, 'message': '评论已删除'})


@superadmin_bp.route('/comment/<int:comment_id>/restore', methods=['POST'])
@login_required
@superadmin_required
@log_superadmin_action('restore_comment', 'comment')
def restore_comment(comment_id):
    """恢复评论"""
    comment = superadmin_bp.Comments.query.get(comment_id)
    if not comment:
        return jsonify({'error': '评论不存在'}), 404
    
    comment.is_deleted = False
    superadmin_bp.db.session.commit()
    
    return jsonify({'success': True, 'message': '评论已恢复'})


# ========== 公告管理 ==========

@superadmin_bp.route('/announcements')
@login_required
@superadmin_required
def announcements():
    """公告列表页面"""
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 10, type=int)
    
    announcements = superadmin_bp.SuperAdminAnnouncements.query.filter_by(
        is_deleted=False
    ).order_by(
        superadmin_bp.SuperAdminAnnouncements.is_pinned.desc(),
        superadmin_bp.SuperAdminAnnouncements.created_at.desc()
    ).paginate(page=page, per_page=per_page, error_out=False)
    
    return superadmin_bp.renderTemplate(
        '/base-files/announcements.html',
        announcements=announcements.items,
        pagination=announcements
    )


@superadmin_bp.route('/announcement/create', methods=['GET', 'POST'])
@login_required
@superadmin_required
def create_announcement():
    """创建公告"""
    superadmin = current_user
    
    if request.method == 'GET':
        return superadmin_bp.renderTemplate('/base-files/announcement-form.html')
    
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
        
        announcement = superadmin_bp.SuperAdminAnnouncements(
            title=title,
            content=content,
            category=category,
            target_role=target_role,
            is_pinned=is_pinned,
            end_at=datetime.fromisoformat(end_at) if end_at else None,
            author_id=superadmin.id,
            author_name=superadmin.nickname,
            created_at=datetime.now()
        )
        
        superadmin_bp.db.session.add(announcement)
        superadmin_bp.db.session.commit()
        
        # 记录日志
        log_entry = superadmin_bp.SuperAdminLogs(
            super_admin_id=superadmin.id,
            action='create_announcement',
            target_type='announcement',
            target_id=announcement.id,
            content=f'创建公告: {title}',
            ip_address=request.remote_addr
        )
        superadmin_bp.db.session.add(log_entry)
        superadmin_bp.db.session.commit()
        
        return jsonify({
            'success': True,
            'message': '公告发布成功',
            'announcement_id': announcement.id
        })
        
    except Exception as e:
        superadmin_bp.db.session.rollback()
        print(f"创建公告失败: {e}")
        return jsonify({'error': '发布失败'}), 500


@superadmin_bp.route('/announcement/<int:announcement_id>/edit', methods=['GET', 'POST'])
@login_required
@superadmin_required
def edit_announcement(announcement_id):
    """编辑公告"""
    superadmin = current_user
    
    announcement = superadmin_bp.SuperAdminAnnouncements.query.get(announcement_id)
    if not announcement or announcement.is_deleted:
        return jsonify({'error': '公告不存在'}), 404
    
    if request.method == 'GET':
        return superadmin_bp.renderTemplate(
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
        
        superadmin_bp.db.session.commit()
        
        # 记录日志
        log_entry = superadmin_bp.SuperAdminLogs(
            super_admin_id=superadmin.id,
            action='edit_announcement',
            target_type='announcement',
            target_id=announcement.id,
            content=f'编辑公告: {title}',
            ip_address=request.remote_addr
        )
        superadmin_bp.db.session.add(log_entry)
        superadmin_bp.db.session.commit()
        
        return jsonify({
            'success': True,
            'message': '公告更新成功'
        })
        
    except Exception as e:
        superadmin_bp.db.session.rollback()
        print(f"更新公告失败: {e}")
        return jsonify({'error': '更新失败'}), 500


@superadmin_bp.route('/announcement/<int:announcement_id>/delete', methods=['POST'])
@login_required
@superadmin_required
def delete_announcement(announcement_id):
    """删除公告"""
    superadmin = current_user
    
    announcement = superadmin_bp.SuperAdminAnnouncements.query.get(announcement_id)
    if not announcement or announcement.is_deleted:
        return jsonify({'error': '公告不存在'}), 404
    
    try:
        announcement.is_deleted = True
        superadmin_bp.db.session.commit()
        
        # 记录日志
        log_entry = superadmin_bp.SuperAdminLogs(
            super_admin_id=superadmin.id,
            action='delete_announcement',
            target_type='announcement',
            target_id=announcement.id,
            content=f'删除公告: {announcement.title}',
            ip_address=request.remote_addr
        )
        superadmin_bp.db.session.add(log_entry)
        superadmin_bp.db.session.commit()
        
        return jsonify({'success': True, 'message': '公告已删除'})
        
    except Exception as e:
        superadmin_bp.db.session.rollback()
        print(f"删除公告失败: {e}")
        return jsonify({'error': '删除失败'}), 500


@superadmin_bp.route('/announcement/<int:announcement_id>/toggle-pin', methods=['POST'])
@login_required
@superadmin_required
def toggle_announcement_pin(announcement_id):
    """切换公告置顶状态"""
    announcement = superadmin_bp.SuperAdminAnnouncements.query.get(announcement_id)
    if not announcement or announcement.is_deleted:
        return jsonify({'error': '公告不存在'}), 404
    
    try:
        announcement.is_pinned = not announcement.is_pinned
        superadmin_bp.db.session.commit()
        
        return jsonify({
            'success': True,
            'is_pinned': announcement.is_pinned,
            'message': '已置顶' if announcement.is_pinned else '已取消置顶'
        })
        
    except Exception as e:
        superadmin_bp.db.session.rollback()
        print(f"切换置顶失败: {e}")
        return jsonify({'error': '操作失败'}), 500


@superadmin_bp.route('/api/announcements')
def get_announcements():
    """获取公告列表（API）"""
    role = session.get('role', 'user')
    
    announcements = superadmin_bp.SuperAdminAnnouncements.query.filter(
        superadmin_bp.SuperAdminAnnouncements.is_deleted == False,
        superadmin_bp.SuperAdminAnnouncements.is_active == True,
        superadmin_bp.SuperAdminAnnouncements.start_at <= datetime.now(),
        (superadmin_bp.SuperAdminAnnouncements.end_at >= datetime.now()) | (superadmin_bp.SuperAdminAnnouncements.end_at == None),
        (superadmin_bp.SuperAdminAnnouncements.target_role == 'all') | (superadmin_bp.SuperAdminAnnouncements.target_role == role)
    ).order_by(
        superadmin_bp.SuperAdminAnnouncements.is_pinned.desc(),
        superadmin_bp.SuperAdminAnnouncements.created_at.desc()
    ).limit(20).all()
    
    announcements_data = []
    for ann in announcements:
        announcements_data.append({
            'id': ann.id,
            'title': ann.title,
            'content': ann.content,
            'category': ann.category,
            'is_pinned': ann.is_pinned,
            'author_name': ann.author_name,
            'created_at': ann.created_at.strftime('%Y-%m-%d %H:%M')
        })
    
    return jsonify({
        'success': True,
        'data': announcements_data
    })


@superadmin_bp.route('/api/announcement/<int:announcement_id>/read', methods=['POST'])
@login_required
def mark_announcement_read(announcement_id):
    """标记公告为已读"""
    role = session.get('role')
    user_id = session.get(f'{role}_id')
    
    if not user_id:
        return jsonify({'error': '未登录'}), 401
    
    announcement = superadmin_bp.SuperAdminAnnouncements.query.get(announcement_id)
    if not announcement or announcement.is_deleted:
        return jsonify({'error': '公告不存在'}), 404
    
    existing = superadmin_bp.SuperAdminAnnouncementReads.query.filter_by(
        announcement_id=announcement_id,
        user_id=user_id,
        user_role=role
    ).first()
    
    if not existing:
        read_record = superadmin_bp.SuperAdminAnnouncementReads(
            announcement_id=announcement_id,
            user_id=user_id,
            user_role=role,
            read_at=datetime.now()
        )
        superadmin_bp.db.session.add(read_record)
        announcement.views += 1
        superadmin_bp.db.session.commit()
    
    return jsonify({'success': True})


# ========== 系统日志 ==========

@superadmin_bp.route('/logs')
@login_required
@superadmin_required
def logs():
    """操作日志页面"""
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 50, type=int)
    log_type = request.args.get('type', 'all')
    action = request.args.get('action')
    
    if log_type == 'admin':
        query = superadmin_bp.AdminLogs.query
    elif log_type == 'superadmin':
        query = superadmin_bp.SuperAdminLogs.query
    else:
        query = superadmin_bp.SuperAdminLogs.query
    
    if action:
        query = query.filter_by(action=action)
    
    logs = query.order_by(superadmin_bp.SuperAdminLogs.time.desc())\
        .paginate(page=page, per_page=per_page, error_out=False)
    
    return superadmin_bp.renderTemplate(
        '/base-files/logs.html',
        logs=logs.items,
        pagination=logs,
        log_type=log_type,
        action=action
    )


@superadmin_bp.route('/api/logs')
@login_required
@superadmin_required
def api_logs():
    """获取日志API"""
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 50, type=int)
    log_type = request.args.get('type', 'superadmin')
    action = request.args.get('action')
    
    if log_type == 'admin':
        query = superadmin_bp.AdminLogs.query
    else:
        query = superadmin_bp.SuperAdminLogs.query
    
    if action:
        query = query.filter_by(action=action)
    
    logs = query.order_by(superadmin_bp.SuperAdminLogs.time.desc())\
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
        else:
            log_data['super_admin_id'] = log.super_admin_id
        
        logs_data.append(log_data)
    
    return jsonify({
        'success': True,
        'data': logs_data,
        'total': logs.total,
        'page': page,
        'per_page': per_page
    })


# ========== 个人资料 ==========

@superadmin_bp.route('/profile')
@login_required
@superadmin_required
def profile():
    """超级管理员个人资料"""
    superadmin = current_user
    return superadmin_bp.renderTemplate('/base-files/profile.html', user=superadmin)


@superadmin_bp.route('/settings', methods=['GET', 'POST'])
@login_required
@superadmin_required
def settings():
    """超级管理员设置"""
    if request.method == 'POST':
        try:
            superadmin = current_user
            
            if request.is_json:
                data = request.get_json()
                
                if 'nickname' in data and data['nickname'] != superadmin.nickname:
                    if superadmin_bp.SuperAdmins.query.filter_by(nickname=data['nickname']).first():
                        return jsonify({'success': False, 'error': '昵称已存在'})
                    superadmin.nickname = data['nickname']
                
                if 'bio' in data:
                    superadmin.bio = data['bio']
                
                if 'profile_visibility' in data:
                    superadmin.profile_visibility = data['profileVisibility']
                if 'online_status' in data:
                    superadmin.online_status = bool(data['onlineStatus'])
                
                superadmin_bp.db.session.commit()
                session['nickname'] = superadmin.nickname
                
                return jsonify({'success': True, 'message': '设置已保存'})
            
        except Exception as e:
            superadmin_bp.db.session.rollback()
            return jsonify({'success': False, 'error': f'保存失败: {str(e)}'})
    
    # GET请求 - 获取当前设置
    superadmin = current_user
    settings_data = {
        'nickname': superadmin.nickname or '',
        'email': superadmin.email or '',
        'bio': superadmin.bio or '',
        'profile_visibility': superadmin.profile_visibility or 'public',
        'online_status': superadmin.online_status if hasattr(superadmin, 'online_status') else True
    }
    
    return superadmin_bp.renderTemplate('/base-files/settings.html', user=superadmin, settings=settings_data)


@superadmin_bp.route('/change-password', methods=['GET', 'POST'])
@login_required
@superadmin_required
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
        
        superadmin = current_user
        
        if not superadmin.pbkdf2_salt or not superadmin.pbkdf2_iterations:
            return jsonify({'error': '用户安全参数异常'})
        
        if superadmin.pbkdf2_salt != salt or superadmin.pbkdf2_iterations != int(iterations):
            return jsonify({'error': '安全参数不匹配'})
        
        if not Password().verify_pw(old_password, superadmin.crypto_pw)[0]:
            return jsonify({'error': '旧密码错误'})
        
        superadmin.crypto_pw = Password().hash_pw(new_password)
        superadmin_bp.db.session.commit()
        
        session.pop('captcha_expected', None)

        return jsonify({'success': '密码修改成功'})

    return superadmin_bp.renderTemplate('/base-files/change-password.html')


@superadmin_bp.route('/upload-avatar', methods=['GET', 'POST'])
@login_required
@superadmin_required
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
        
            superadmin = current_user
        
            upload_dir = os.path.join(superadmin_bp.app.static_folder, 'img', 'upload', 'avatar')
            os.makedirs(upload_dir, exist_ok=True)
        
            filename = f"{superadmin.nickname}.png"
            filepath = os.path.join(upload_dir, 'SuperAdmins', filename)
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
                    'avatar_url': f"/static/img/upload/avatar/SuperAdmins/{filename}"
                })
            
            except Exception as e:
                print(f"图片处理错误: {e}")
                return jsonify({'success': False, 'error': '图片处理失败'})
            
        except Exception as e:
            print(f"上传错误: {e}")
            return jsonify({'success': False, 'error': '上传失败'})
        
    else:
        return superadmin_bp.renderTemplate('/base-files/upload-avatar.html')
    