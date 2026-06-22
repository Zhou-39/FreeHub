import re
import html
import bleach
from bleach.css_sanitizer import CSSSanitizer
from urllib.parse import urlparse

class ContentFilter:
    """内容过滤工具类"""
    
    # ===== 帖子/文章允许的HTML标签（较宽松） =====
    POST_ALLOWED_TAGS = [
        'p', 'br', 'strong', 'b', 'em', 'i', 'u', 's', 'mark',
        'h1', 'h2', 'h3', 'h4', 'h5', 'h6',
        'ul', 'ol', 'li',
        'blockquote', 'pre', 'code',
        'span', 'div',
        'img',
        'a',
        'table', 'thead', 'tbody', 'tr', 'th', 'td',
        'hr',
        'font'
    ]
    
    POST_ALLOWED_ATTRIBUTES = {
        '*': ['class', 'id', 'style', 'title'],
        'a': ['href', 'target', 'rel'],
        'img': ['src', 'alt', 'width', 'height', 'title'],
        'span': ['style'],
        'div': ['style'],
        'p': ['style'],
        'font': ['color', 'size', 'face']
    }
    
    # ===== 私信允许的标签（非常严格，基本不允许HTML） =====
    MESSAGE_ALLOWED_TAGS = [
        'p', 'br', 'strong', 'em', 'u'  # 只允许最基本的文本格式
    ]
    
    MESSAGE_ALLOWED_ATTRIBUTES = {}  # 不允许任何属性
    
    # 允许的CSS属性
    ALLOWED_CSS_PROPERTIES = [
        'color', 'background-color', 'font-size', 'font-family',
        'text-align', 'font-weight', 'font-style', 'text-decoration',
        'margin', 'padding', 'border', 'border-radius'
    ]
    
    # 允许的URL协议
    ALLOWED_PROTOCOLS = ['http', 'https', 'mailto', 'tel']
    
    @classmethod
    def sanitize_post_content(cls, content):
        """
        清理帖子/文章内容（允许HTML，但过滤）
        """
        if not content:
            return ""
        
        # 创建CSS清理器
        css_sanitizer = CSSSanitizer(allowed_css_properties=cls.ALLOWED_CSS_PROPERTIES)
        
        # 清理HTML
        cleaned = bleach.clean(
            content,
            tags=cls.POST_ALLOWED_TAGS,
            attributes=cls.POST_ALLOWED_ATTRIBUTES,
            css_sanitizer=css_sanitizer,
            protocols=cls.ALLOWED_PROTOCOLS,
            strip=True,
            strip_comments=True
        )
        
        # 额外清理：移除危险的on*事件属性
        cleaned = cls._remove_event_handlers(cleaned)
        
        # 验证链接安全性
        cleaned = cls._validate_links(cleaned)
        
        return cleaned
    
    @classmethod
    def sanitize_message_content(cls, content):
        """
        清理私信内容（纯文本，不允许HTML）
        """
        if not content:
            return ""
        
        # 先HTML转义，再处理换行
        escaped = html.escape(content)
        
        # 允许基本格式：将特定的转义转换回HTML标签（受控的）
        # 例如：允许用户输入 **text** 转换为 <strong>text</strong>
        # 这里实现一个简单的标记语言转换
        formatted = cls._apply_simple_markup(escaped)
        
        # 再次使用bleach确保安全（只允许极少数标签）
        cleaned = bleach.clean(
            formatted,
            tags=cls.MESSAGE_ALLOWED_TAGS,
            attributes=cls.MESSAGE_ALLOWED_ATTRIBUTES,
            strip=True
        )
        
        # 将换行符转换为<br>
        cleaned = cleaned.replace('\n', '<br>')
        
        return cleaned
    
    @classmethod
    def sanitize_text_only(cls, content):
        """
        纯文本清理（完全转义，无任何格式）
        """
        if not content:
            return ""
        return html.escape(content)
    
    @classmethod
    def _apply_simple_markup(cls, text):
        """
        应用简单的标记语言转换
        例如：*text* -> <em>text</em>, **text** -> <strong>text</strong>
        """
        # 粗体：**text**
        text = re.sub(r'\*\*(.*?)\*\*', r'<strong>\1</strong>', text)
        
        # 斜体：*text*
        text = re.sub(r'\*(.*?)\*', r'<em>\1</em>', text)
        
        # 下划线：__text__
        text = re.sub(r'__(.*?)__', r'<u>\1</u>', text)
        
        return text
    
    @classmethod
    def _remove_event_handlers(cls, content):
        """移除JavaScript事件处理器"""
        event_patterns = [
            r'on\w+\s*=\s*["\'][^"\']*["\']',
            r'javascript:',
            r'vbscript:',
            r'data:',
            r'expression\('
        ]
        
        for pattern in event_patterns:
            content = re.sub(pattern, '', content, flags=re.IGNORECASE)
        
        return content
    
    @classmethod
    def _validate_links(cls, content):
        """验证链接安全性"""
        def replace_link(match):
            url = match.group(1)
            try:
                parsed = urlparse(url)
                
                # 检查协议
                if parsed.scheme and parsed.scheme not in cls.ALLOWED_PROTOCOLS:
                    return '#'
                
                # 添加安全属性
                return f'href="{url}" target="_blank" rel="noopener noreferrer"'
            except:
                return '#'
        
        # 替换所有链接
        content = re.sub(r'href="([^"]+)"', replace_link, content)
        return content
    
    @classmethod
    def contains_js(cls, content):
        """检查是否包含JavaScript代码"""
        js_patterns = [
            r'<script',
            r'javascript:',
            r'onload\s*=',
            r'onclick\s*=',
            r'onmouseover\s*=',
            r'expression\(',
            r'eval\(',
            r'alert\(',
            r'document\.cookie',
            r'window\.location'
        ]
        
        content_lower = content.lower()
        for pattern in js_patterns:
            if re.search(pattern, content_lower):
                return True
        return False
    