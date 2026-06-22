from flask import Flask, render_template, request, session, make_response, redirect, url_for, jsonify, send_from_directory
from flask_sqlalchemy import SQLAlchemy
# from flask_migrate import Migrate  # 已注释，使用手动 SQL 管理数据库
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from utils.database_creator import DatabaseCreator
from utils.password_checker import Password
from utils.utils import RenderTemplate, anonymous_required, require_csrf
from utils.file_scanner import FileScanner
from utils.content_filter import ContentFilter
import os, sys, string, secrets, io, re, smtplib
from datetime import datetime, timedelta
from werkzeug.utils import secure_filename
from PIL import Image
from whitenoise import WhiteNoise
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.header import Header
from functools import wraps

# 在 app.py 的导入部分添加
from utils.pbkdf2_security import PBKDF2Security

# 初始化（可选，主要用于清理过期salt）
pbkdf2_security = PBKDF2Security()
pbkdf2_security.cleanup_expired_temp_params()

# 加载环境变量
from dotenv import load_dotenv
load_dotenv()

app = Flask(__name__)
# 设置 JSON 不进行 ASCII 编码
app.config['JSON_AS_ASCII'] = False

# 配置WhiteNoise
app.wsgi_app = WhiteNoise(
    app.wsgi_app,
    root='static/',           # 静态文件目录
    prefix='static/',         # URL前缀
    index_file=True,          # 支持索引文件
    max_age=3600,            # 缓存时间（秒）
    allow_all_origins=False,
    charset='utf-8'
)

# 设置数据库路径
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:////var/website/www/DBs/Users/users.db'
app.config['SQLALCHEMY_BINDS'] = {
    'users': 'sqlite:////var/website/www/DBs/Users/users.db',
    'admins': 'sqlite:////var/website/www/DBs/Admins/admins.db'
}

def generate_random_string(length=12):
    characters = string.ascii_letters + string.digits + string.punctuation
    random_string = ''.join(secrets.choice(characters) for i in range(length))
    return random_string

app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.secret_key = generate_random_string(100)

# 会话配置
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=6)
app.config['SESSION_REFRESH_EACH_REQUEST'] = True
app.config['SESSION_COOKIE_SECURE'] = True
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'

login_manager = LoginManager()
login_manager.init_app(app)

# 在 app 初始化后添加
from flask_caching import Cache

# 配置缓存（使用简单内存缓存）
app.config['CACHE_TYPE'] = 'SimpleCache'
app.config['CACHE_DEFAULT_TIMEOUT'] = 300  # 5分钟
cache = Cache(app)

# 在 app.py 中添加配置
app.config['UPLOAD_FOLDER'] = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'uploads')
app.config['MAX_CONTENT_LENGTH'] = 100 * 1024 * 1024  # 100MB

# ========== SMTP 配置 ==========
SMTP_CONFIG = {
    "host": "smtp.qq.com",
    "port": 587,
    "user": os.getenv("EMAIL_BOX", ""),
    "password": os.getenv("EMAIL_PASSWORD", ""),
    "to_email": os.getenv("TO_EMAIL", "")
}

# 初始化数据库
DBCreator = DatabaseCreator(app)
db = DBCreator.db
# migrate = Migrate(app, db)  # 已注释

DBCreator.user_tables()
IDs = DBCreator.ids
UIDs = DBCreator.uids
Likes = DBCreator.likes
Posts = DBCreator.posts
Follows = DBCreator.follows
Reports = DBCreator.reports
Uploads = DBCreator.uploads
Articles = DBCreator.articles
Comments = DBCreator.comments
Messages = DBCreator.messages
Favorites = DBCreator.favorites
Conversations = DBCreator.conversations
PointsHistory = DBCreator.points_history
ReportReasons = DBCreator.report_reasons
PasswordResetTokens = DBCreator.password_reset_tokens
EmailVerificationTokens = DBCreator.email_verification_tokens
BountyTasks = DBCreator.bounty_tasks
PointsEarnings = DBCreator.points_earnings
Thanks = DBCreator.thanks
EmailRecoveryRequests = DBCreator.email_recovery_requests
Friends = DBCreator.friends
FriendRequests = DBCreator.friend_requests
PointsTransfers = DBCreator.points_transfers
BlockList = DBCreator.block_list
BountySubTasks = DBCreator.bounty_sub_tasks
BountyUploads = DBCreator.bounty_uploads
BountyRewardLogs = DBCreator.bounty_reward_logs
BountyAppendLogs = DBCreator.bounty_append_logs

DBCreator.admin_tables()
Admins = DBCreator.admins
AdminLogs = DBCreator.admin_logs
AdminPosts = DBCreator.admin_posts
Announcements = DBCreator.announcements
AdminArticles = DBCreator.admin_articles
AdminComments = DBCreator.admin_comments
AnnouncementReads = DBCreator.announcement_reads
AdminPasswordResetTokens = DBCreator.admin_password_reset_tokens
AdminEmailVerificationTokens = DBCreator.admin_email_verification_tokens

DBCreator.super_admin_tables()
SuperAdmins = DBCreator.super_admins
SuperAdminLogs = DBCreator.super_admin_logs
SuperAdminPosts = DBCreator.super_admin_posts
SuperAdminArticles = DBCreator.super_admin_articles
SuperAdminComments = DBCreator.super_admin_comments
SuperAdminAnnouncements = DBCreator.super_admin_announcements
SuperAdminAnnouncementReads = DBCreator.super_admin_announcement_reads
SuperAdminPasswordResetTokens = DBCreator.super_admin_password_reset_tokens
SuperAdminEmailVerificationTokens = DBCreator.super_admin_email_verification_tokens

DBCreator.owner_tables()
Owners = DBCreator.owners
OwnerLogs = DBCreator.owner_logs
OwnerPosts = DBCreator.owner_posts
InviteCodes = DBCreator.invite_codes
OwnerArticles = DBCreator.owner_articles
OwnerComments = DBCreator.owner_comments
InviteCodeUses = DBCreator.invite_code_uses
OwnerAnnouncements = DBCreator.owner_announcements
OwnerAnnouncementReads = DBCreator.owner_announcement_reads

# 创建所有表（表已存在时不会重复创建）
with app.app_context():
    db.create_all()

# 创建主应用的渲染实例
models = {
    'IDs': IDs,
    'Admins': Admins,
    'UIDs': UIDs
}
main_render = RenderTemplate(db, models=models)

# 导入并注册蓝图
from bps.users import init_user_bp
user_bp = init_user_bp(app, db, cache, IDs, UIDs, EmailVerificationTokens, PasswordResetTokens, Posts, Articles, Comments, Likes, Favorites, Follows, Uploads, PointsHistory, Messages, Conversations, Reports, ReportReasons, BountyTasks, PointsEarnings, EmailRecoveryRequests, Friends, FriendRequests, PointsTransfers, BlockList, BountySubTasks)
app.register_blueprint(user_bp)

from bps.admins import init_admin_bp
admin_bp = init_admin_bp(app, db, Admins, AdminEmailVerificationTokens, AdminPasswordResetTokens, IDs, UIDs, Posts, Articles, Uploads, Comments, Announcements, AnnouncementReads, AdminLogs)
app.register_blueprint(admin_bp)

from bps.superadmins import init_superadmin_bp
superadmin_bp = init_superadmin_bp(app, db, SuperAdmins, SuperAdminEmailVerificationTokens, SuperAdminPasswordResetTokens, Admins, IDs, UIDs, Posts, Articles, Uploads, Comments, SuperAdminLogs, SuperAdminAnnouncements, SuperAdminAnnouncementReads, AdminLogs)
app.register_blueprint(superadmin_bp)

from bps.owners import init_owner_bp
owner_bp = init_owner_bp(app, db, Owners, OwnerLogs, InviteCodes, InviteCodeUses, IDs, UIDs, Admins, SuperAdmins, Posts, Articles, Uploads, Comments, AdminLogs, SuperAdminLogs, OwnerAnnouncements, OwnerAnnouncementReads)
app.register_blueprint(owner_bp)

from bps.api import api_bp
app.register_blueprint(api_bp)

# 设置登录视图为蓝图路由
login_manager.login_view = 'user.login'

@login_manager.user_loader
def load_user(user_id):
    try:
        id = int(user_id)
    except (TypeError, ValueError):
        return None

    user_role = session.get('role')
    
    if user_role == 'admin':
        try:
            user = db.session.get(Admins, id)
            if user:
                return user
        except Exception:
            pass
    elif user_role == 'superadmin':
        try:
            user = db.session.get(SuperAdmins, id)
            if user:
                return user
        except Exception:
            pass
    elif user_role == 'owner':
        try:
            user = db.session.get(Owners, id)
            if user:
                return user
        except Exception:
            pass
    elif user_role == 'user':
        try:
            user = db.session.get(IDs, id)
            if user:
                return user
        except Exception:
            pass
    
    return None

# 初始化举报原因
with app.app_context():
    from bps.users import init_report_reasons
    init_report_reasons()

@app.before_request
def generate_nonce():
    """为每个请求生成唯一的nonce"""
    request.nonce = secrets.token_urlsafe(16)

@app.after_request
def add_security_headers(response):
    """添加安全响应头，包括CSP和nonce"""
    if not hasattr(request, 'nonce'):
        request.nonce = secrets.token_urlsafe(16)
    
    csp = [
        "default-src 'self'",
        f"script-src 'self' 'nonce-{request.nonce}'",
        f"style-src 'self' 'nonce-{request.nonce}'",
        "img-src 'self' data:",
        "font-src 'self'",
        "connect-src 'self'",
        "frame-ancestors 'none'",
        "base-uri 'self'",
        "form-action 'self'",
        "object-src 'none'",
        "upgrade-insecure-requests"
    ]
    
    response.headers['Content-Security-Policy'] = '; '.join(csp)
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    response.headers['Permissions-Policy'] = 'geolocation=(), microphone=(), camera=()'
    
    return response

# ========== 页面路由 ==========

@app.route('/')
def index():
    return main_render.renderTemplate('/system-files/home.html')

@app.route('/theme', methods=['POST'])
def set_theme():
    try:
        data = request.get_json()
        theme = data.get('theme', 'system')
        
        if theme not in ['system', 'light', 'dark']:
            return jsonify({'success': False, 'error': '无效的主题'})
        
        session['theme'] = theme
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/captcha')
def captcha():
    from utils.captcha_maker import generate_captcha
    captcha_text, captcha_image = generate_captcha()
    session['captcha_expected'] = captcha_text
    response = make_response(captcha_image.getvalue())
    response.headers['Content-Type'] = 'image/png'
    return response

@app.route('/about')
def about():
    user_rights = [IDs, Admins]
    total_users = sum([db.session.query(model).count() for model in user_rights])
    return main_render.renderTemplate('/system-files/about.html', total_users=total_users)

@app.route('/contact')
def contact():
    return main_render.renderTemplate('/system-files/contact.html')

@app.route('/share/<int:id>')
def share(id):
    return main_render.renderTemplate(f'/system-files/share/{id}.html')

@app.route('/uploads/temp/<int:user_id>/<filename>')
def temp_upload_file(user_id, filename):
    """访问临时上传的文件"""
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], 'temp', str(user_id), filename)
    if not os.path.exists(file_path):
        return jsonify({'error': '文件不存在'}), 404
    return send_file(file_path)

@app.route('/favicon.ico')
def favicon():
    return send_from_directory(
        os.path.join(app.static_folder, 'img', 'system'),
        'favicon.ico',
        mimetype='image/vnd.microsoft.icon'
    )

@app.route('/donate-image')
def donate_image():
    return send_from_directory(
        os.path.join(app.static_folder, 'img', 'system'),
        'donate.png',
        mimetype='image/png'
    )

@app.route('/donate')
def donate():
    return main_render.renderTemplate('/system-files/donate.html')

# ========== 联系表单 API ==========

@app.route('/api/contact/send', methods=['POST'])
def api_contact_send():
    """处理联系表单，通过 SMTP 发送邮件"""
    try:
        data = request.get_json()
        name = data.get('name', '').strip()
        email = data.get('email', '').strip()
        subject = data.get('subject', '').strip()
        message = data.get('message', '').strip()
        captcha = data.get('captcha', '').strip()
        
        # 验证必填字段
        if not all([name, email, subject, message, captcha]):
            return jsonify({'success': False, 'error': '请填写所有字段'}), 400
        
        # 验证邮箱格式
        if not re.match(r'^[^@]+@[^@]+\.[^@]+$', email):
            return jsonify({'success': False, 'error': '邮箱格式无效'}), 400
        
        # 验证验证码
        expected_captcha = session.get('captcha_expected', '')
        if not expected_captcha or captcha.upper() != expected_captcha.upper():
            return jsonify({'success': False, 'error': '验证码错误'}), 400
        
        # 清除验证码
        session.pop('captcha_expected', None)
        
        # 主题映射
        subject_map = {
            'bug': '🐛 漏洞报告',
            'suggestion': '💡 功能建议',
            'question': '❓ 使用问题',
            'cooperation': '🤝 合作咨询'
        }
        display_subject = subject_map.get(subject, subject)
        
        # 构建邮件内容
        email_content = f"""
来自 FreeHub 联系表单

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

【用户信息】
姓名/昵称：{name}
邮箱：{email}
主题：{display_subject}
IP地址：{request.remote_addr}
User-Agent：{request.headers.get('User-Agent', '未知')}

【消息内容】
{message}

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
发送时间：{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
        """
        
        # 发送邮件
        msg = MIMEMultipart()
        msg['From'] = SMTP_CONFIG['user']
        msg['To'] = SMTP_CONFIG['to_email']
        msg['Subject'] = Header(f'[FreeHub反馈] {name} - {display_subject}', 'utf-8')
        
        msg.attach(MIMEText(email_content, 'plain', 'utf-8'))
        
        try:
            server = smtplib.SMTP(SMTP_CONFIG['host'], SMTP_CONFIG['port'])
            server.starttls()
            server.login(SMTP_CONFIG['user'], SMTP_CONFIG['password'])
            server.send_message(msg)
            server.quit()
        except Exception as e:
            print(f"SMTP 发送失败: {e}")
            return jsonify({'success': False, 'error': '邮件发送失败，请稍后重试'}), 500
        
        # 发送自动回复
        try:
            auto_reply = MIMEText(f"""
感谢您的来信！

我是 FreeHub 的开发者（一个初三学生）。您的反馈已收到，我会认真阅读并尽快回复您。

━━━━━━━━━━━━━━━━━━━━━━━━
FreeHub - 一个初三生的技术乌托邦
https://free-hub.cn

您反馈的内容：
{message[:200]}{'...' if len(message) > 200 else ''}
            """, 'plain', 'utf-8')
            auto_reply['Subject'] = Header('FreeHub 已收到您的反馈', 'utf-8')
            auto_reply['From'] = SMTP_CONFIG['user']
            auto_reply['To'] = email
            
            server = smtplib.SMTP(SMTP_CONFIG['host'], SMTP_CONFIG['port'])
            server.starttls()
            server.login(SMTP_CONFIG['user'], SMTP_CONFIG['password'])
            server.send_message(auto_reply)
            server.quit()
        except Exception as e:
            print(f"自动回复发送失败: {e}")
        
        return jsonify({'success': True, 'message': '发送成功'})
        
    except Exception as e:
        print(f"联系表单处理错误: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({'success': False, 'error': str(e)}), 500


# ========== 致谢系统（数据库版） ==========

def developer_required(f):
    """仅开发者（主账户 ID=3）可访问的装饰器"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated:
            return redirect(url_for('user.login'))
        
        # 检查是否是主账户且 ID=3
        if current_user.__class__.__name__ == 'IDs' and current_user.id == 3:
            return f(*args, **kwargs)
        
        return main_render.renderTemplate('/system-files/403.html'), 403
    return decorated_function


@app.route('/thanks')
def thanks_page():
    """公开致谢列表页面"""
    return main_render.renderTemplate('/system-files/thanks.html')


@app.route('/thank-detail/<int:id>')
def thank_detail_page(id):
    """致谢详情页面"""
    thanks = Thanks.query.filter_by(id=id, is_visible=True).first()
    if not thanks:
        return main_render.renderTemplate('/system-files/404.html'), 404
    return main_render.renderTemplate('/system-files/thank-detail.html', thanks=thanks)


@app.route('/thanks/manage')
@developer_required
def thanks_manage():
    """致谢管理页面（仅开发者可见）"""
    return main_render.renderTemplate('/base-files/thanks-admin.html')


# ========== 致谢 API ==========

@app.route('/thanks/api/list', methods=['GET'])
def thanks_api_list():
    """获取致谢列表（公开）"""
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 12, type=int)
    sort = request.args.get('sort', 'default')
    
    query = Thanks.query.filter_by(is_visible=True)
    
    if sort == 'date':
        query = query.order_by(Thanks.achievement_date.desc(), Thanks.created_at.desc())
    else:
        query = query.order_by(Thanks.sort_order.desc(), Thanks.created_at.desc())
    
    pagination = query.paginate(page=page, per_page=per_page, error_out=False)
    
    thanks_list = []
    for t in pagination.items:
        thanks_list.append({
            'id': t.id,
            'name': t.name,
            'contact_masked': t.masked_contact(),
            'achievement': t.achievement,
            'avatar_id': t.avatar_id,
            'achievement_date': t.achievement_date.strftime('%Y-%m-%d') if t.achievement_date else None,
            'created_at': t.created_at.strftime('%Y-%m-%d %H:%M:%S')
        })
    
    return jsonify({
        'success': True,
        'data': thanks_list,
        'total': pagination.total,
        'page': page,
        'per_page': per_page,
        'total_pages': pagination.pages,
        'has_next': pagination.has_next,
        'has_prev': pagination.has_prev
    })


@app.route('/thanks/api/all', methods=['GET'])
@developer_required
def thanks_api_all():
    """获取所有致谢（管理用，包含未显示）"""
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 50, type=int)
    show_hidden = request.args.get('show_hidden', 'false') == 'true'
    
    query = Thanks.query
    if not show_hidden:
        query = query.filter_by(is_visible=True)
    
    query = query.order_by(Thanks.sort_order.desc(), Thanks.created_at.desc())
    pagination = query.paginate(page=page, per_page=per_page, error_out=False)
    
    thanks_list = []
    for t in pagination.items:
        thanks_list.append({
            'id': t.id,
            'name': t.name,
            'contact': t.contact,
            'contact_masked': t.masked_contact(),
            'achievement': t.achievement,
            'avatar_id': t.avatar_id,
            'achievement_date': t.achievement_date.strftime('%Y-%m-%d') if t.achievement_date else None,
            'sort_order': t.sort_order,
            'is_visible': t.is_visible,
            'created_at': t.created_at.strftime('%Y-%m-%d %H:%M:%S')
        })
    
    return jsonify({
        'success': True,
        'data': thanks_list,
        'total': pagination.total,
        'page': page,
        'per_page': per_page,
        'total_pages': pagination.pages,
        'has_next': pagination.has_next,
        'has_prev': pagination.has_prev
    })


@app.route('/thanks/api/create', methods=['POST'])
@developer_required
def thanks_api_create():
    """创建致谢记录"""
    data = request.get_json()
    
    name = data.get('name', '').strip()
    contact = data.get('contact', '').strip()
    achievement = data.get('achievement', '').strip()
    avatar_id = data.get('avatar_id', 0)
    achievement_date = data.get('achievement_date', None)
    sort_order = data.get('sort_order', 0)
    is_visible = data.get('is_visible', True)
    
    if not name or not achievement:
        return jsonify({'error': '姓名和贡献描述不能为空'}), 400
    
    date_obj = None
    if achievement_date:
        try:
            date_obj = datetime.strptime(achievement_date, '%Y-%m-%d').date()
        except ValueError:
            return jsonify({'error': '日期格式错误，请使用 YYYY-MM-DD'}), 400
    
    new_thanks = Thanks(
        name=name,
        contact=contact,
        achievement=achievement,
        avatar_id=avatar_id,
        achievement_date=date_obj,
        sort_order=sort_order,
        is_visible=is_visible,
        created_by=current_user.id
    )
    
    db.session.add(new_thanks)
    db.session.commit()
    
    return jsonify({'success': True, 'message': '致谢记录已添加', 'id': new_thanks.id})


@app.route('/thanks/api/<int:thanks_id>/update', methods=['PUT'])
@developer_required
def thanks_api_update(thanks_id):
    """更新致谢记录"""
    thanks = Thanks.query.get(thanks_id)
    if not thanks:
        return jsonify({'error': '记录不存在'}), 404
    
    data = request.get_json()
    
    if 'name' in data:
        thanks.name = data['name'].strip()
    if 'contact' in data:
        thanks.contact = data['contact'].strip()
    if 'achievement' in data:
        thanks.achievement = data['achievement'].strip()
    if 'avatar_id' in data:
        thanks.avatar_id = data['avatar_id']
    if 'achievement_date' in data:
        if data['achievement_date']:
            thanks.achievement_date = datetime.strptime(data['achievement_date'], '%Y-%m-%d').date()
        else:
            thanks.achievement_date = None
    if 'sort_order' in data:
        thanks.sort_order = data['sort_order']
    if 'is_visible' in data:
        thanks.is_visible = data['is_visible']
    
    thanks.updated_at = datetime.now()
    db.session.commit()
    
    return jsonify({'success': True, 'message': '更新成功'})


@app.route('/thanks/api/<int:thanks_id>/delete', methods=['DELETE'])
@developer_required
def thanks_api_delete(thanks_id):
    """删除致谢记录"""
    thanks = Thanks.query.get(thanks_id)
    if not thanks:
        return jsonify({'error': '记录不存在'}), 404
    
    db.session.delete(thanks)
    db.session.commit()
    
    return jsonify({'success': True, 'message': '删除成功'})


@app.route('/thanks/api/<int:thanks_id>/toggle', methods=['POST'])
@developer_required
def thanks_api_toggle(thanks_id):
    """切换显示/隐藏"""
    thanks = Thanks.query.get(thanks_id)
    if not thanks:
        return jsonify({'error': '记录不存在'}), 404
    
    thanks.is_visible = not thanks.is_visible
    thanks.updated_at = datetime.now()
    db.session.commit()
    
    return jsonify({
        'success': True,
        'is_visible': thanks.is_visible,
        'message': '已显示' if thanks.is_visible else '已隐藏'
    })


# ========== 接单系统 API（基础） ==========

def require_verified_email(f):
    """强制要求邮箱已验证"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated:
            return jsonify({'error': '未登录', 'login_required': True}), 401
        
        if current_user.__class__.__name__ == 'IDs':
            if not current_user.email_verified:
                return jsonify({
                    'error': '请先验证邮箱后再使用此功能',
                    'need_verify': True,
                    'verify_url': url_for('user.verify_reminder')
                }), 403
        
        return f(*args, **kwargs)
    return decorated_function


@app.route('/api/bounty/list', methods=['GET'])
def api_bounty_list():
    """获取悬赏列表（公开）"""
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 20, type=int)
    status = request.args.get('status', 'pending')
    
    query = BountyTasks.query.filter_by(status=status)
    tasks = query.order_by(BountyTasks.created_at.desc()).paginate(page=page, per_page=per_page, error_out=False)
    
    tasks_data = []
    for task in tasks.items:
        publisher = UIDs.query.get(task.publisher_uid)
        assignee = UIDs.query.get(task.assignee_uid) if task.assignee_uid else None
        
        tasks_data.append({
            'id': task.id,
            'title': task.title,
            'description': task.description[:200],
            'bounty_points': float(task.bounty_points),
            'status': task.status,
            'created_at': task.created_at.isoformat(),
            'publisher': {
                'uid': publisher.uid if publisher else None,
                'nickname': publisher.nickname if publisher else '已注销'
            },
            'assignee': {
                'uid': assignee.uid if assignee else None,
                'nickname': assignee.nickname if assignee else None
            } if assignee else None
        })
    
    return jsonify({
        'success': True,
        'data': tasks_data,
        'total': tasks.total,
        'page': page,
        'per_page': per_page
    })


# ========== 错误页面 ==========

@app.errorhandler(403)
def forbidden(e):
    return main_render.renderTemplate('/system-files/403.html'), 403

@app.errorhandler(404)
def page_not_found(e):
    return main_render.renderTemplate('/system-files/404.html'), 404

@app.errorhandler(429)
def too_many_requests(e):
    return main_render.renderTemplate('/system-files/429.html'), 429

@app.errorhandler(500)
def internal_server_error(e):
    return main_render.renderTemplate('/system-files/500.html'), 500


# ========== 启动 ==========

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=443, debug=True, ssl_context=('/var/website/www/127.0.0.1+2.pem', '/var/website/www/127.0.0.1+2-key.pem'))
