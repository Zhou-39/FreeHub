from functools import wraps
from flask import redirect, url_for, request, session, render_template, current_app, abort
from flask_login import current_user
import os
import re
import hashlib
import secrets
import html
from werkzeug.utils import secure_filename
from urllib.parse import urlparse

def anonymous_required(f):
    """
    只允许未登录用户访问的装饰器
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if current_user.is_authenticated:
            # 用户已登录，重定向到首页或其他页面
            return redirect(url_for('index'))
        return f(*args, **kwargs)
    return decorated_function

def validate_user_id(user_id):
    """
    验证用户ID是否为有效的正整数
    
    Args:
        user_id: 用户ID字符串或数字
        
    Returns:
        有效的整数ID或None
    """
    try:
        if user_id is None:
            return None
            
        user_id_str = str(user_id).strip()
        if not user_id_str.isdigit():
            return None
            
        user_id_int = int(user_id_str)
        if user_id_int <= 0:
            return None
            
        return user_id_int
    except (ValueError, TypeError, AttributeError):
        return None

def validate_role(role):
    """
    验证角色是否为有效值
    
    Args:
        role: 角色字符串
        
    Returns:
        有效的角色字符串
    """
    VALID_ROLES = {'user', 'admin', 'superadmin', 'owner'}
    if role in VALID_ROLES:
        return role
    return 'user'

def sanitize_filename(filename):
    """
    清理文件名，防止路径遍历攻击
    
    Args:
        filename: 原始文件名
        
    Returns:
        安全的文件名
    """
    if not filename:
        return ""
    
    # 使用secure_filename清理文件名
    safe_name = secure_filename(filename)
    
    # 额外的安全检查：防止路径遍历
    if '..' in safe_name or safe_name.startswith('/') or safe_name.startswith('\\'):
        return ""
    
    # 限制文件扩展名（不允许的扩展应被拒绝）
    allowed_extensions = {'.png', '.jpg', '.jpeg', '.gif', '.bmp', '.webp'}
    _, ext = os.path.splitext(safe_name)
    if ext:
        if ext.lower() not in allowed_extensions:
            # 返回空字符串表示无效/不被接受的文件名
            return ""

    return safe_name

def validate_nickname(nickname):
    """
    验证昵称是否安全
    
    Args:
        nickname: 昵称字符串
        
    Returns:
        布尔值，表示昵称是否安全
    """
    if not nickname:
        return False
    
    # 检查长度限制
    if len(nickname) < 4 or len(nickname) > 20:
        return False
    
    # 检查是否只包含允许的字符
    if not re.match(r'^[a-zA-Z0-9]+$', nickname):
        return False
    
    return True

def validate_email(email):
    """
    验证邮箱格式
    
    Args:
        email: 邮箱地址
        
    Returns:
        布尔值，表示邮箱是否有效
    """
    if not email:
        return False
    
    email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return bool(re.match(email_pattern, email))

def validate_password(password):
    """
    验证密码强度
    
    Args:
        password: 密码字符串
        
    Returns:
        布尔值，表示密码是否足够强
    """
    if not password:
        return False
    
    # 长度要求
    if len(password) < 8 or len(password) > 30:
        return False
    
    # 复杂度要求
    has_upper = bool(re.search(r'[A-Z]', password))
    has_lower = bool(re.search(r'[a-z]', password))
    has_digit = bool(re.search(r'[0-9]', password))
    
    return has_upper and has_lower and has_digit

def sanitize_html(input_str):
    """
    清理HTML输入，防止XSS攻击
    
    Args:
        input_str: 输入字符串
        
    Returns:
        安全的字符串
    """
    if not input_str:
        return ""

    # 使用标准库的 html.escape 进行安全转义，避免手写替换产生双重转义问题
    safe = html.escape(input_str, quote=True)

    # 额外转义少数非HTML实体但仍可能被滥用的字符
    safe = safe.replace('(', '&#40;').replace(')', '&#41;').replace('`', '&#96;')
    return safe

def validate_url(url):
    """
    验证URL是否安全
    
    Args:
        url: URL字符串
        
    Returns:
        布尔值，表示URL是否安全
    """
    if not url:
        return False
    
    try:
        result = urlparse(url)
        
        # 检查协议
        if result.scheme not in ['http', 'https', '']:
            return False
        
        # 检查域名
        if not result.netloc:
            return False
        
        # 防止JavaScript协议
        if 'javascript:' in url.lower():
            return False
        
        return True
    except:
        return False

def generate_csrf_token():
    """
    生成CSRF令牌
    """
    return secrets.token_hex(32)

def verify_csrf_token(token):
    """
    验证CSRF令牌
    """
    if 'csrf_token' not in session:
        return False
    return secrets.compare_digest(session['csrf_token'], token)

class RenderTemplate:
    def __init__(self, db=None, models=None, **global_context):
        """
        初始化渲染模板类
        
        Args:
            db: SQLAlchemy数据库实例
            models: 包含各种模型的字典
            global_context: 全局模板上下文
        """
        self.db = db
        self.models = models or {}
        self.global_context = global_context

    def renderTemplate(self, template_name_or_list, **context):
        """
        渲染模板，自动添加用户信息、角色等上下文
        """
        from flask import request
        
        # 合并所有上下文
        merged_context = {}
        merged_context.update(self.global_context)
        merged_context.update(context)
        
        # 从请求路径判断是用户还是管理员
        path = request.path
        if path.startswith('/'+current_app.config['OWNER_PREFIX']):
            basic_url = current_app.config['OWNER_PREFIX']
            role_name = 'Owners'
            user_id_key = 'owner_id'
            user_model_key = 'Owners'
        elif path.startswith('/'+current_app.config['SUPERADMIN_PREFIX']):
            basic_url = current_app.config['SUPERADMIN_PREFIX']
            role_name = 'SuperAdmins'
            user_id_key = 'superadmin_id'
            user_model_key = 'SuperAdmins'
        elif path.startswith('/admin'):
            basic_url = 'admin'
            role_name = 'Admins'
            user_id_key = 'admin_id'
            user_model_key = 'Admins'
        else:
            basic_url = 'user'
            role_name = 'Users'
            user_id_key = 'user_id'
            user_model_key = 'IDs'
        
        # 获取用户信息
        user_info = self._get_user_info(basic_url, role_name, user_id_key, user_model_key)
        merged_context.update(user_info)
        
        # 获取主题
        theme = session.get('theme', 'system')
        merged_context['theme'] = theme
        
        # 添加CSRF令牌
        if 'csrf_token' not in session:
            session['csrf_token'] = generate_csrf_token()
        merged_context['csrf_token'] = session['csrf_token']
        
        # 渲染模板
        return render_template(template_name_or_list, **merged_context)
    
    def _get_user_info(self, basic_url, role_name, user_id_key, user_model_key):
        """获取当前用户信息，包含安全验证"""
        try:
            from flask_login import current_user
            
            # 获取session角色
            session_role = session.get('role')
            
            # 如果用户已登录，直接使用 current_user
            if current_user and current_user.is_authenticated:
                # 获取用户对象
                user = current_user
                user_class = user.__class__.__name__
                
                # 根据用户类确定角色信息
                if user_class == 'SuperAdmins':
                    role_name = 'SuperAdmins'
                    basic_url = current_app.config.get('SUPERADMIN_PREFIX', 'superadmin')
                elif user_class == 'Admins':
                    role_name = 'Admins'
                    basic_url = 'admin'
                elif user_class == 'Owners':
                    role_name = 'Owners'
                    basic_url = current_app.config.get('OWNER_PREFIX', 'owner')
                else:  # IDs
                    role_name = 'Users'
                    basic_url = 'user'
                
                # 检查头像
                has_avatar = False
                if user.nickname:
                    has_avatar = self._check_avatar(user.nickname, role_name)
                
                return {
                    'role': [role_name, user],
                    'has_avatar': has_avatar,
                    'basic_url': basic_url,
                    'current_user': user
                }
            
            # 未登录用户，返回默认值
            # 根据路径判断 basic_url（用于未登录时的导航）
            path = request.path
            if path.startswith('/admin'):
                basic_url = 'admin'
            elif path.startswith('/'+current_app.config.get('SUPERADMIN_PREFIX', 'superadmin')):
                basic_url = current_app.config.get('SUPERADMIN_PREFIX', 'superadmin')
            elif path.startswith('/'+current_app.config.get('OWNER_PREFIX', 'owner')):
                basic_url = current_app.config.get('OWNER_PREFIX', 'owner')
            else:
                basic_url = 'user'
            
            return {
                'role': [role_name, None],
                'has_avatar': False,
                'basic_url': basic_url
            }
            
        except Exception as e:
            current_app.logger.error(f"获取用户信息失败: {type(e).__name__}")
            return {
                'role': [role_name, None],
                'has_avatar': False,
                'basic_url': basic_url
            }

    def _check_avatar(self, nickname, role_name):
        """检查用户头像是否存在"""
        try:
            safe_nickname = sanitize_filename(nickname)
            if not safe_nickname:
                return False
                
            static_folder = current_app.static_folder
            avatar_path = os.path.join(
                static_folder, 
                'img', 'upload', 'avatar', role_name, 
                f'{safe_nickname}.png'
            )
            
            expected_dir = os.path.join(static_folder, 'img', 'upload', 'avatar', role_name)
            if not os.path.normpath(avatar_path).startswith(os.path.normpath(expected_dir) + os.sep):
                return False
                
            return os.path.exists(avatar_path)
        except:
            return False

# 安全中间件装饰器
def require_csrf(f):
    """要求CSRF令牌的装饰器"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if request.method in ['POST', 'PUT', 'DELETE', 'PATCH']:
            token = request.form.get('csrf_token') or request.headers.get('X-CSRF-Token')
            if not token or not verify_csrf_token(token):
                abort(403, description='CSRF token missing or invalid')
        return f(*args, **kwargs)
    return decorated_function

def rate_limit(max_per_minute=60):
    """速率限制装饰器"""
    from datetime import datetime, timedelta
    from collections import defaultdict
    import time
    
    requests = defaultdict(list)
    
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            # 获取客户端标识
            client_ip = request.remote_addr
            user_agent = request.headers.get('User-Agent', '')
            client_id = hashlib.sha256(f"{client_ip}{user_agent}".encode()).hexdigest()
            
            # 清理过期的请求记录
            current_time = time.time()
            requests[client_id] = [req_time for req_time in requests[client_id] 
                                  if current_time - req_time < 60]
            
            # 检查速率限制
            if len(requests[client_id]) >= max_per_minute:
                abort(429, description='请求过于频繁，请稍后再试')
            
            # 记录请求时间
            requests[client_id].append(current_time)
            
            return f(*args, **kwargs)
        return decorated_function
    return decorator

def sanitize_form_data(data):
    """清理表单数据"""
    if isinstance(data, dict):
        return {k: sanitize_html(v) if isinstance(v, str) else v for k, v in data.items()}
    elif isinstance(data, list):
        return [sanitize_html(item) if isinstance(item, str) else item for item in data]
    elif isinstance(data, str):
        return sanitize_html(data)
    else:
        return data

import os
import io
import re
import pickle
import urllib.request
import urllib.parse
from typing import Tuple

import torch
import torch.nn as nn
from torchvision import transforms, models
from PIL import Image

from sklearn.feature_extraction.text import TfidfVectorizer

MODEL_FILE = "moderation_model.pth"
VECT_FILE = "vectorizer.pkl"

# 扩展的安全网址白名单
SAFE_DOMAINS = [
    # 国内主流网站
    "baidu.com", "www.baidu.com", "map.baidu.com", "tieba.baidu.com",
    "qq.com", "www.qq.com", "mail.qq.com", "game.qq.com", "v.qq.com",
    "taobao.com", "www.taobao.com", "world.taobao.com",
    "tmall.com", "www.tmall.com",
    "jd.com", "www.jd.com", "book.jd.com",
    "163.com", "www.163.com", "mail.163.com", "news.163.com",
    "sina.com.cn", "www.sina.com.cn", "news.sina.com.cn",
    "sohu.com", "www.sohu.com", "news.sohu.com",
    "csdn.net", "www.csdn.net", "blog.csdn.net", "download.csdn.net",
    "zhihu.com", "www.zhihu.com", "zhuanlan.zhihu.com",
    "bilibili.com", "www.bilibili.com", "space.bilibili.com",
    "douyin.com", "www.douyin.com",
    "kuaishou.com", "www.kuaishou.com",
    "weibo.com", "www.weibo.com",
    "xiaohongshu.com", "www.xiaohongshu.com",
    "meituan.com", "www.meituan.com",
    "dianping.com", "www.dianping.com",
    "ele.me", "www.ele.me",
    "didiglobal.com", "www.didiglobal.com",
    
    # 云服务商
    "aliyun.com", "www.aliyun.com", "help.aliyun.com", "market.aliyun.com",
    "tencentcloud.com", "cloud.tencent.com",
    "huaweicloud.com", "www.huaweicloud.com",
    "qcloud.com", "www.qcloud.com",
    "baidubce.com", "www.baidubce.com",
    
    # 科技公司
    "microsoft.com", "www.microsoft.com", "learn.microsoft.com", "docs.microsoft.com",
    "apple.com", "www.apple.com", "developer.apple.com",
    "google.com", "www.google.com", "developers.google.com", "cloud.google.com",
    "github.com", "www.github.com", "gist.github.com",
    "gitlab.com", "www.gitlab.com",
    "stackoverflow.com", "www.stackoverflow.com",
    "medium.com", "www.medium.com",
    "wikipedia.org", "www.wikipedia.org", "zh.wikipedia.org",
    "youtube.com", "www.youtube.com",
    "twitter.com", "www.twitter.com",
    "facebook.com", "www.facebook.com",
    "instagram.com", "www.instagram.com",
    "telegram.org", "www.telegram.org",
    
    # 教育资源
    "icourse163.org", "www.icourse163.org",
    "xuetangx.com", "www.xuetangx.com",
    "coursera.org", "www.coursera.org",
    "udemy.com", "www.udemy.com",
    "khanacademy.org", "www.khanacademy.org",
    "acm.org", "www.acm.org",
    "ieee.org", "www.ieee.org",
    
    # 政府机构
    "gov.cn", "www.gov.cn", "*.gov.cn",
    "edu.cn", "www.edu.cn", "*.edu.cn",
    "12377.cn", "www.12377.cn",
    
    # 新闻媒体
    "people.com.cn", "www.people.com.cn",
    "xinhuanet.com", "www.xinhuanet.com",
    "cctv.com", "www.cctv.com",
    "chinadaily.com.cn", "www.chinadaily.com.cn",
    "thepaper.cn", "www.thepaper.cn",
    "jiemian.com", "www.jiemian.com",
    
    # 开发者社区
    "jianshu.com", "www.jianshu.com",
    "segmentfault.com", "www.segmentfault.com",
    "v2ex.com", "www.v2ex.com",
    "ruanyifeng.com", "www.ruanyifeng.com",
    "liaoxuefeng.com", "www.liaoxuefeng.com",
    "runoob.com", "www.runoob.com",
    "w3school.com.cn", "www.w3school.com.cn",
    
    # 设计/创意
    "zcool.com.cn", "www.zcool.com.cn",
    "huaban.com", "www.huaban.com",
    "pinterest.com", "www.pinterest.com",
    "behance.net", "www.behance.net",
    "dribbble.com", "www.dribbble.com",
    
    # 办公/协作
    "feishu.cn", "www.feishu.cn",
    "larksuite.com", "www.larksuite.com",
    "dingtalk.com", "www.dingtalk.com",
    "weixin.qq.com", "work.weixin.qq.com",
    "teams.microsoft.com",
    "zoom.us", "www.zoom.us",
    
    # 支付/金融
    "alipay.com", "www.alipay.com",
    "wechatpay.com", "www.wechatpay.com",
    "paypal.com", "www.paypal.com",
    "icbc.com.cn", "www.icbc.com.cn",
    "cmbchina.com", "www.cmbchina.com",
    
    # 开源镜像站
    "mirrors.aliyun.com",
    "mirrors.tuna.tsinghua.edu.cn",
    "mirrors.ustc.edu.cn",
    "mirrors.huaweicloud.com",
    "mirrors.cloud.tencent.com",
    
    # 其他常用
    "ip138.com", "www.ip138.com",
    "weather.com.cn", "www.weather.com.cn",
    "12306.cn", "www.12306.cn",
    "ctrip.com", "www.ctrip.com",
    "qunar.com", "www.qunar.com",
    "fliggy.com", "www.fliggy.com",
]

# 扩展敏感词库
EXTENDED_SENSITIVE_WORDS = []  # 自行扩展

# ImageNet mean/std
IMAGENET_MEAN = [0.485, 0.456, 0.406]
IMAGENET_STD = [0.229, 0.224, 0.225]


class SimpleModerationModel(nn.Module):
    """联合图像+文本的小型分类器。
    image_backbone: 使用 ResNet18（可选择预训练权重）提取图像 embedding
    text_fc: 文本特征 MLP
    classifier: 组合后的二分类器
    """
    def __init__(self, text_dim=500, image_emb=512, hidden=None, pretrained_image=True):
        super().__init__()
        # 尝试加载预训练权重（可能会从网络下载）
        try:
            # torchvision 早期/新版 API 兼容处理
            try:
                # 新版 torchvision
                backbone = models.resnet18(weights=models.ResNet18_Weights.DEFAULT if hasattr(models, 'ResNet18_Weights') else None)
            except Exception:
                backbone = models.resnet18(pretrained=pretrained_image)
        except Exception:
            backbone = models.resnet18(pretrained=False)

        # 替换最后一层以获得固定大小 embedding
        backbone.fc = nn.Linear(backbone.fc.in_features, image_emb)
        self.image_backbone = backbone

        # 如果未指定 hidden，则根据 text_dim 自适应
        if hidden is None:
            # 保证 hidden 有合理范围，避免过小或过大
            hidden = max(128, min(512, text_dim // 2))

        self.text_fc = nn.Sequential(
            nn.Linear(text_dim, hidden),
            nn.ReLU(),
            nn.Linear(hidden, max(64, hidden // 2)),
            nn.ReLU(),
        )

        self.classifier = nn.Sequential(
            nn.Linear(image_emb + (hidden // 2), hidden),
            nn.ReLU(),
            nn.Linear(hidden, 1),
        )

    def forward(self, img_tensor, text_vec):
        img_emb = self.image_backbone(img_tensor)
        txt_feat = self.text_fc(text_vec)
        combined = torch.cat([img_emb, txt_feat], dim=1)
        logit = self.classifier(combined).squeeze(1)
        return logit


def is_whitelisted_domain(host):
    """检查域名是否在白名单中"""
    if not host:
        return False
    
    # 完全匹配
    if host in SAFE_DOMAINS:
        return True
    
    # 子域名匹配（例如：*.baidu.com）
    for safe_domain in SAFE_DOMAINS:
        if safe_domain.startswith('*.'):
            # 处理通配符域名，如 *.gov.cn
            domain_part = safe_domain[2:]  # 去掉 *.
            if host.endswith('.' + domain_part) or host == domain_part:
                return True
        elif host.endswith('.' + safe_domain):
            # 匹配子域名，如 map.baidu.com 匹配 baidu.com
            return True
    
    return False


def is_direct_media(url: str) -> Tuple[bool, str]:
    """判断 URL 是否直接指向图片/媒体，返回 (is_media, media_type)"""
    url_l = url.lower()
    for ext in ('.jpg', '.jpeg', '.png', '.gif', '.bmp', '.webp', '.svg', '.ico'):
        if url_l.endswith(ext):
            return True, 'image'
    # 尝试 HEAD 请求 看 Content-Type
    try:
        req = urllib.request.Request(url, method='HEAD')
        with urllib.request.urlopen(req, timeout=6) as r:
            ctype = r.headers.get('Content-Type', '')
            if ctype.startswith('image/'):
                return True, 'image'
            if ctype.startswith('video/'):
                return True, 'video'
    except Exception:
        pass
    return False, ''


def http_get(url, timeout=8):
    """通用抓取 HTML（支持 http/https），简单返回文本内容或 None。"""
    try:
        req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.read().decode(errors='ignore')
    except Exception:
        return None


def extract_images_and_text(html, base_url=None):
    img_srcs = re.findall(r'<img[^>]+src=["\']([^"\']+)["\']', html, flags=re.IGNORECASE)
    no_script = re.sub(r'<(script|style)[\s\S]*?>[\s\S]*?<\/\1>', ' ', html, flags=re.IGNORECASE)
    text = re.sub(r'<[^>]+>', ' ', no_script)
    text = re.sub(r'\s+', ' ', text).strip()
    full_img_urls = []
    for src in img_srcs:
        if src.startswith('data:'):
            full_img_urls.append(src)
            continue
        full = urllib.parse.urljoin(base_url, src) if base_url else src
        full_img_urls.append(full)
    return full_img_urls, text


def fetch_image_bytes(url, timeout=8):
    if url.startswith('data:'):
        m = re.match(r'data:(.*?);base64,(.*)', url)
        if not m:
            return None
        import base64
        return base64.b64decode(m.group(2))
    try:
        req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.read()
    except Exception:
        return None


# 预处理（包括 ImageNet 归一化，适配预训练模型）
preprocess = transforms.Compose([
    transforms.Resize((224, 224)),
    transforms.ToTensor(),
    transforms.Normalize(mean=IMAGENET_MEAN, std=IMAGENET_STD),
])


def compute_text_sensitive_score(text: str) -> float:
    """
    基于敏感词简单打分，返回 0..1。
    修复版：更准确地检测敏感词，提高敏感度
    """
    if not text or not text.strip():
        return 0.0
    
    lower = text.lower()
    
    # 计算匹配的敏感词数量（去重）
    matched_words = set()
    for word in EXTENDED_SENSITIVE_WORDS:
        if word in lower:
            matched_words.add(word)
    
    # 计算敏感词出现次数（包括重复）
    total_occurrences = 0
    for word in EXTENDED_SENSITIVE_WORDS:
        try:
            total_occurrences += len(re.findall(re.escape(word.lower()), lower))
        except Exception:
            if word.lower() in lower:
                total_occurrences += 1
    
    # 文本长度因子：短文本更容易被判定为敏感
    text_length = len(text)
    length_factor = min(1.0, 300 / max(text_length, 30))  # 提高短文本权重
    
    # 敏感词密度
    word_count = len(text.split())
    if word_count > 0:
        density = total_occurrences / word_count
    else:
        density = 0
    
    # 综合评分 - 大幅提高权重，让分数更容易达到阈值
    # 基础分：匹配的独特敏感词数量
    base_score = min(1.0, len(matched_words) / 1.5)  # 每1.5个独特词就得1分
    
    # 密度分
    density_score = min(1.0, density * 2.0)  # 密度达到0.5就得满分
    
    # 频率分
    frequency_score = min(1.0, total_occurrences / 2)  # 每2次出现就得1分
    
    # 加权组合 - 大幅提高密度和频率的权重
    score = (
        base_score * 0.3 +      # 独特词数量权重
        density_score * 0.4 +    # 密度权重
        frequency_score * 0.2 +   # 频率权重
        length_factor * 0.1       # 长度因子权重
    ) * 1.2  # 整体放大20%，让分数更容易超过阈值
    
    # 确保分数在0-1之间
    score = min(1.0, max(0.0, score))
    
    # 调试信息
    # print(f"文本分析: 长度={text_length}, 独特词={len(matched_words)}, "
    #       f"总出现={total_occurrences}, 密度={density:.2f}, 得分={score:.2f}")
    # if matched_words:
    #     print(f"匹配到的词: {matched_words}")
    
    return float(score)


def ensure_model(text_dim=500, device='cpu'):
    """加载或训练模型与向量器，训练时使用合成样本（教学示例）。"""
    vectorizer = None
    if os.path.exists(VECT_FILE):
        with open(VECT_FILE, 'rb') as f:
            vectorizer = pickle.load(f)

    if os.path.exists(MODEL_FILE) and vectorizer is not None:
        try:
            text_dim_load = 0
            try:
                text_dim_load = len(vectorizer.get_feature_names_out())
            except Exception:
                text_dim_load = getattr(vectorizer, 'max_features', 500) or 500
            model = SimpleModerationModel(text_dim=text_dim_load, pretrained_image=True)
            model.load_state_dict(torch.load(MODEL_FILE, map_location=device))
            model.to(device)
            model.eval()
            return model, vectorizer
        except Exception:
            print('加载已有模型失败，重新训练')

    # 训练一个示例模型（合成数据）
    print('开始合成训练（示例）... 训练后会保存为', MODEL_FILE)
    # 使用基于字符的 n-gram 分词以兼容中文（char_wb），更适合无分词器环境
    vectorizer = TfidfVectorizer(max_features=text_dim, analyzer='char_wb', ngram_range=(2,4))
    
    # 创建更多样化的训练数据
    safe_texts = [
        '这是一个关于旅行和烹饪的无害帖子。',
        '今天天气真好，我们去公园散步吧。',
        '如何制作美味的意大利面，分享美食教程。',
        '最新科技新闻：人工智能的发展与应用',
        '学习编程的10个建议，从入门到精通',
        '健康饮食指南：每天应该吃什么？',
        '摄影技巧分享：如何拍出好看的照片',
        '旅游攻略：云南大理自由行推荐',
        '育儿经验分享：如何培养孩子的兴趣',
        '运动健身：每天30分钟的有氧运动',
        'Python编程入门教程，适合零基础学习',
        '机器学习基础概念讲解',
        '如何提高工作效率的5个方法',
        '读书笔记：《思考，快与慢》读后感',
        '周末去郊游，感受大自然的美好'
    ] * 20
        
    unsafe_texts = [] * 20  # 自行扩展
    
    texts = safe_texts + unsafe_texts
    labels = [0] * len(safe_texts) + [1] * len(unsafe_texts)

    X_text = vectorizer.fit_transform(texts).toarray().astype('float32')
    actual_text_dim = X_text.shape[1]

    # 合成图像张量
    def make_image_tensor(is_unsafe: int):
        import numpy as np
        a = np.random.rand(3, 224, 224).astype('float32')
        if is_unsafe:
            a = (a * 2.0) % 1.0
        return torch.from_numpy(a)

    device = torch.device(device)
    model = SimpleModerationModel(text_dim=actual_text_dim, pretrained_image=True)
    model.to(device)
    opt = torch.optim.Adam(model.parameters(), lr=1e-3)
    loss_fn = nn.BCEWithLogitsLoss()

    epochs = 10
    batch_size = 32
    import numpy as np
    N = len(labels)
    idx = np.arange(N)
    for ep in range(epochs):
        np.random.shuffle(idx)
        running_loss = 0.0
        for i in range(0, N, batch_size):
            batch_idx = idx[i:i+batch_size]
            tb = torch.from_numpy(X_text[batch_idx])
            imgs = torch.stack([make_image_tensor(labels[j]) for j in batch_idx], dim=0)
            lbs = torch.tensor([labels[j] for j in batch_idx], dtype=torch.float32)

            imgs = imgs.to(device)
            tb = tb.to(device)
            lbs = lbs.to(device)

            opt.zero_grad()
            logits = model(imgs, tb)
            loss = loss_fn(logits, lbs)
            loss.backward()
            opt.step()
            running_loss += loss.item() * len(batch_idx)
        print(f'Epoch {ep+1}/{epochs} loss={running_loss/N:.4f}')

    torch.save(model.state_dict(), MODEL_FILE)
    with open(VECT_FILE, 'wb') as f:
        pickle.dump(vectorizer, f)
    model.eval()
    return model, vectorizer


def predict_url(url: str, model, vectorizer, device='cpu'):
    parsed = urllib.parse.urlparse(url)
    host = parsed.hostname or ''

    # 白名单直接返回安全（跳过所有检测）
    if is_whitelisted_domain(host):
        print(f"域名 {host} 在白名单中，直接判定为安全")
        return {
            'url': url, 
            'host': host, 
            'safe': True, 
            'probability': 0.05,  # 5%
            'reason': 'whitelisted',
            'image_prob': 0.05,
            'text_score': 0.0,
            'matched_words': []
        }

    # 先判断是否为媒体文件
    is_media, media_type = is_direct_media(url)
    html = None
    imgs = []
    text = ''

    if is_media and media_type == 'image':
        # 直接下载图片
        b = fetch_image_bytes(url)
        if not b:
            return {
                'url': url, 
                'host': host, 
                'safe': False, 
                'probability': 0.30, 
                'reason': 'fetch_failed',
                'image_prob': 0.30,
                'text_score': 0.0,
                'matched_words': []
            }
        try:
            im = Image.open(io.BytesIO(b)).convert('RGB')
            t = preprocess(im)
            img_tensors = [t]
            text = ''
        except Exception:
            return {
                'url': url, 
                'host': host, 
                'safe': False, 
                'probability': 0.30, 
                'reason': 'image_decode_failed',
                'image_prob': 0.30,
                'text_score': 0.0,
                'matched_words': []
            }
    else:
        html = http_get(url)
        if not html:
            return {
                'url': url, 
                'host': host, 
                'safe': False, 
                'probability': 0.30, 
                'reason': 'fetch_failed',
                'image_prob': 0.30,
                'text_score': 0.0,
                'matched_words': []
            }
        imgs, text = extract_images_and_text(html, base_url=url)
        
        # 打印提取的文本用于调试
        print(f"提取的文本长度: {len(text)}")
        if text:
            print(f"文本预览: {text[:200]}")
        
        img_tensors = []
        for src in imgs[:5]:
            b = fetch_image_bytes(src)
            if not b:
                continue
            try:
                im = Image.open(io.BytesIO(b)).convert('RGB')
                t = preprocess(im)
                img_tensors.append(t)
            except Exception:
                continue
        if len(img_tensors) == 0:
            # 填充一个空白张量
            img_tensors = [torch.zeros(3, 224, 224)]

    # 文本向量化
    try:
        if text and text.strip():
            txt_vec = vectorizer.transform([text]).toarray().astype('float32')
        else:
            txt_vec = vectorizer.transform(['']).toarray().astype('float32')
    except Exception as e:
        print(f"文本向量化失败: {e}")
        txt_vec = vectorizer.transform(['']).toarray().astype('float32')

    imgs_batch = torch.stack(img_tensors, dim=0).to(device)
    txt_batch = torch.from_numpy(txt_vec.repeat(len(img_tensors), axis=0)).to(device)

    with torch.no_grad():
        logits = model(imgs_batch, txt_batch)
        probs = torch.sigmoid(logits)
        image_prob = float(probs.mean().item())  # 保持为小数 (0-1)

    # 计算文本敏感词得分（返回小数）
    text_score = compute_text_sensitive_score(text)
    
    print(f"图片概率: {image_prob:.2%}, 文本得分: {text_score:.2%}")

    # 获取匹配到的敏感词
    lower_text = text.lower()
    matched_words = []
    for word in EXTENDED_SENSITIVE_WORDS:
        if word in lower_text and word not in matched_words:
            matched_words.append(word)
            if len(matched_words) >= 10:
                break
    
    # 高风险关键词快速检测
    high_risk_keywords = ['91av', 'av', '成人', '色情', 'porn', 'sex', '成人视频', 'av电影', 'av视频']
    for keyword in high_risk_keywords:
        if keyword in host.lower() or keyword in lower_text:
            print(f"检测到高风险关键词: {keyword}")
            return {
                'url': url,
                'host': host,
                'safe': False,
                'probability': 0.85,  # 85%
                'image_prob': image_prob,
                'text_score': text_score,
                'imgs_checked': len(img_tensors),
                'text_snippet': (text[:400] + '...') if len(text) > 400 else text,
                'matched_words': [keyword] + matched_words[:5],
                'reason': 'high_risk_keyword',
                'threshold': 0.30
            }

    # 判断是否有实际图片
    has_real_images = len(img_tensors) > 1 or (len(img_tensors) == 1 and not torch.all(img_tensors[0] == 0))
    
    # 根据内容类型调整权重和阈值
    if has_real_images:
        if text and text.strip() and len(text) > 50:
            # 图文并茂 - 提高文本权重
            combined_prob = 0.4 * image_prob + 0.6 * text_score
            threshold = 0.25  # 25% 阈值
        elif text and text.strip():
            # 少量文字 - 图片权重稍高
            combined_prob = 0.6 * image_prob + 0.4 * text_score
            threshold = 0.28
        else:
            # 只有图片
            combined_prob = 0.8 * image_prob + 0.2 * text_score
            threshold = 0.30
    else:
        # 没有图片，只有文字
        combined_prob = 0.1 * image_prob + 0.9 * text_score
        threshold = 0.20  # 20% 阈值
    
    # 特殊规则：如果文本得分较高（>15%），降低阈值
    if text_score > 0.15:
        threshold = threshold * 0.8  # 阈值降低20%
        print(f"文本得分较高，阈值降至: {threshold:.1%}")
    
    safe = combined_prob < threshold
    
    # 确定风险原因
    if not safe:
        if text_score > threshold * 0.7:
            reason = 'high_text_risk'
        elif image_prob > threshold * 0.7:
            reason = 'high_image_risk'
        else:
            reason = 'combined_risk_exceeded'
    else:
        reason = 'normal'

    return {
        'url': url,
        'host': host,
        'safe': bool(safe),
        'probability': combined_prob,
        'image_prob': image_prob,
        'text_score': text_score,
        'imgs_checked': len(img_tensors),
        'text_snippet': (text[:400] + '...') if len(text) > 400 else text,
        'matched_words': matched_words[:10],
        'reason': reason,
        'threshold': threshold
    }


def test_text_analysis():
    """测试文本分析功能"""
    test_texts = []  # 自行扩展
    
    print("\n===== 文本分析测试 =====")
    results = []
    for text in test_texts:
        score = compute_text_sensitive_score(text)
        results.append((text[:30], score))
        print(f"文本: {text[:30]}... 得分: {score:.2f}")
    
    return results


def test_whitelist():
    """测试白名单功能"""
    print("\n===== 白名单测试 =====")
    test_domains = [
        "aliyun.com",
        "www.aliyun.com",
        "help.aliyun.com",
        "baidu.com",
        "map.baidu.com",
        "gov.cn",
        "www.gov.cn",
        "xxx.xxx.gov.cn",
        "edu.cn",
        "tsinghua.edu.cn",
        "pku.edu.cn"
    ]
    
    for domain in test_domains:
        result = is_whitelisted_domain(domain)
        print(f"域名: {domain:20} 在白名单中: {result}")


_MODEL = None
_VECT = None
_DEVICE = 'cuda' if torch.cuda.is_available() else 'cpu'

if not (os.path.exists(MODEL_FILE) and os.path.exists(VECT_FILE)):
    print('未找到模型文件，开始训练（示例合成训练）...')
    _MODEL, _VECT = ensure_model(text_dim=500, device=_DEVICE)
else:
    _MODEL, _VECT = ensure_model(text_dim=500, device=_DEVICE)

# 如果直接运行此文件，执行测试
if __name__ == "__main__":
    test_whitelist()
    test_text_analysis()
