import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import os
import secrets
from email.utils import formataddr

class EmailSender:
    def __init__(self, app, url, basic_url, group):
        self.app = app
        self.url = url
        self.basic_url = basic_url
        self.group = group
        
        # QQ邮箱配置 - 465端口使用SSL，不需要starttls()
        self.smtp_server = "smtp.qq.com"
        self.smtp_port = 465  # SSL端口
        self.sender_email = os.getenv("EMAIL_BOX", "")  # 完整QQ邮箱，如：123456@qq.com
        self.sender_password = os.getenv("EMAIL_PASSWORD", "")  # 16位授权码，不是QQ密码！
        self.sender_name = "FreeHub网站"  # 发件人名称

    def _connect_smtp(self):
        """连接SMTP服务器 - 使用SSL连接"""
        try:
            # 465端口使用SMTP_SSL，不是普通SMTP
            server = smtplib.SMTP_SSL(self.smtp_server, self.smtp_port, timeout=30)
            server.login(self.sender_email, self.sender_password)
            return server
        except Exception as e:
            print(f"SMTP连接失败: {e}")
            raise

    def send_password_reset_email(self, user_email, reset_token, user_id):
        try:
            # 创建重置链接
            reset_link = f"{self.url}{self.basic_url}/reset-password?token={reset_token}&{self.group}_id={user_id}"

            # 创建邮件内容
            msg = MIMEMultipart()
            msg['From'] = formataddr((self.sender_name, self.sender_email))
            msg['To'] = user_email
            msg['Subject'] = "FreeHub - 密码重置请求"

            body = f"""
            <html>
            <body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333;">
                <div style="max-width: 600px; margin: 0 auto; padding: 20px; border: 1px solid #e0e0e0; border-radius: 5px;">
                    <h2 style="color: #4361ee;">密码重置请求</h2>
                    <p>您请求重置密码，请点击下面的链接：</p>
                    <div style="margin: 30px 0;">
                        <a href="{reset_link}" style="display: inline-block; padding: 12px 24px; background-color: #4361ee; color: white; text-decoration: none; border-radius: 5px; font-weight: bold;">重置密码</a>
                    </div>
                    <p>如果按钮无法点击，请复制以下链接到浏览器：</p>
                    <p style="background-color: #f5f5f5; padding: 10px; border-radius: 3px; word-break: break-all;">
                        {reset_link}
                    </p>
                    <p style="color: #666; font-size: 0.9em; margin-top: 30px;">
                        <strong>注意：</strong><br>
                        1. 此链接有效期为1小时<br>
                        2. 如果您没有请求重置密码，请忽略此邮件<br>
                        3. 请勿将此链接分享给他人
                    </p>
                    <hr style="border: none; border-top: 1px solid #e0e0e0; margin: 30px 0;">
                    <p style="color: #999; font-size: 0.8em;">
                        这是系统自动发送的邮件，请勿回复。<br>
                        FreeHub团队
                    </p>
                </div>
            </body>
            </html>
            """

            msg.attach(MIMEText(body, 'html'))

            # 发送邮件
            server = self._connect_smtp()
            server.send_message(msg)
            server.quit()
            
            print(f"密码重置邮件已发送到: {user_email}")
            return True
            
        except Exception as e:
            print(f"发送邮件失败: {e}")
            return False

    def send_verification_email(self, user_email, verification_token, user_id):
        try:
            # 创建验证链接
            verify_link = f"{self.url}{self.basic_url}/verify-email?token={verification_token}&{self.group}_id={user_id}"

            msg = MIMEMultipart()
            msg['From'] = formataddr((self.sender_name, self.sender_email))
            msg['To'] = user_email
            msg['Subject'] = "FreeHub - 邮箱验证请求"

            body = f"""
            <html>
            <body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333;">
                <div style="max-width: 600px; margin: 0 auto; padding: 20px; border: 1px solid #e0e0e0; border-radius: 5px;">
                    <h2 style="color: #4361ee;">邮箱验证</h2>
                    <p>感谢您注册FreeHub！请点击下面的链接验证您的邮箱：</p>
                    <div style="margin: 30px 0;">
                        <a href="{verify_link}" style="display: inline-block; padding: 12px 24px; background-color: #4CAF50; color: white; text-decoration: none; border-radius: 5px; font-weight: bold;">验证邮箱</a>
                    </div>
                    <p>如果按钮无法点击，请复制以下链接到浏览器：</p>
                    <p style="background-color: #f5f5f5; padding: 10px; border-radius: 3px; word-break: break-all;">
                        {verify_link}
                    </p>
                    <p style="color: #666; font-size: 0.9em; margin-top: 30px;">
                        <strong>重要提示：</strong><br>
                        1. 此链接有效期为24小时<br>
                        2. 验证后您将可以使用网站所有功能<br>
                        3. 如果您没有注册FreeHub，请忽略此邮件
                    </p>
                    <hr style="border: none; border-top: 1px solid #e0e0e0; margin: 30px 0;">
                    <p style="color: #999; font-size: 0.8em;">
                        欢迎加入FreeHub社区！<br>
                        FreeHub团队
                    </p>
                </div>
            </body>
            </html>
            """

            msg.attach(MIMEText(body, 'html'))

            # 发送邮件
            server = self._connect_smtp()
            server.send_message(msg)
            server.quit()
            
            print(f"验证邮件已发送到: {user_email}")
            return True
            
        except Exception as e:
            print(f"发送验证邮件失败: {e}")
            return False

    def send_password_change_notification(self, user_email):
        try:
            msg = MIMEMultipart()
            msg['From'] = formataddr((self.sender_name, self.sender_email))
            msg['To'] = user_email
            msg['Subject'] = "FreeHub - 密码修改通知"

            body = f"""
            <html>
            <body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333;">
                <div style="max-width: 600px; margin: 0 auto; padding: 20px; border: 1px solid #e0e0e0; border-radius: 5px;">
                    <h2 style="color: #4361ee;">密码修改成功</h2>
                    <p>您的FreeHub账户密码已成功修改。</p>
                    <div style="background-color: #f0f9ff; padding: 15px; border-radius: 5px; border-left: 4px solid #4361ee; margin: 20px 0;">
                        <p style="margin: 0;"><strong>安全提示：</strong></p>
                        <ul style="margin: 10px 0 0 20px;">
                            <li>请妥善保管您的新密码</li>
                            <li>建议定期更换密码</li>
                            <li>不要在多个网站使用相同密码</li>
                        </ul>
                    </div>
                    <p style="color: #d32f2f; font-weight: bold;">
                        如果这不是您本人操作，请立即：
                        <a href="{self.url}{self.basic_url}/forgot-password" style="color: #d32f2f; text-decoration: underline;">点击这里重置密码</a>
                    </p>
                    <hr style="border: none; border-top: 1px solid #e0e0e0; margin: 30px 0;">
                    <p style="color: #999; font-size: 0.8em;">
                        这是系统自动发送的安全通知邮件。<br>
                        FreeHub团队
                    </p>
                </div>
            </body>
            </html>
            """

            msg.attach(MIMEText(body, 'html'))

            # 发送邮件
            server = self._connect_smtp()
            server.send_message(msg)
            server.quit()
            
            print(f"密码修改通知已发送到: {user_email}")
            return True
            
        except Exception as e:
            print(f"发送密码修改通知邮件失败: {e}")
            return False
    
    def send_verification_code(self, to_email, code, purpose='recover'):
        """发送6位数字验证码"""
        subject_map = {
            'recover': '账号恢复验证码',
            'verify': '邮箱验证码'
        }
        subject = f"FreeHub - {subject_map.get(purpose, '验证码')}"
        
        body = f"""
        <html>
        <body style="font-family: Arial, sans-serif; padding: 20px;">
            <h2 style="color: #4361ee;">您的验证码是：{code}</h2>
            <p>该验证码 <strong>5分钟内有效</strong>，请勿泄露给他人。</p>
            <p>如果您没有进行此操作，请忽略本邮件。</p>
            <hr style="margin: 20px 0;">
            <p style="color: #999; font-size: 12px;">FreeHub 团队</p>
        </body>
        </html>
        """
        self._send_email(to_email, subject, body)


    def send_email_change_notification(self, to_email, new_email):
        """发送邮箱变更通知"""
        subject = "FreeHub - 账号邮箱已被更改"
        body = f"""
        <html>
        <body style="font-family: Arial, sans-serif; padding: 20px;">
            <h2 style="color: #f87171;">⚠️ 账号邮箱已被更改</h2>
            <p>您的账号邮箱已被更改为：<strong>{new_email}</strong></p>
            <p>如果这是您本人的操作，请忽略本邮件。</p>
            <p>如果这不是您本人的操作，请立即联系管理员：<a href="https://free-hub.cn/contact">联系我们</a></p>
            <hr style="margin: 20px 0;">
            <p style="color: #999; font-size: 12px;">FreeHub 安全团队</p>
        </body>
        </html>
        """
        self._send_email(to_email, subject, body)


    def _send_email(self, to_email, subject, html_body):
        """内部邮件发送方法"""
        import smtplib
        from email.mime.text import MIMEText
        from email.mime.multipart import MIMEMultipart
        
        msg = MIMEMultipart()
        msg['From'] = self.sender_email
        msg['To'] = to_email
        msg['Subject'] = subject
        msg.attach(MIMEText(html_body, 'html'))
        
        with smtplib.SMTP_SSL(self.smtp_server, self.smtp_port) as server:
            server.login(self.sender_email, self.sender_password)
            server.send_message(msg)

# 密码重置令牌生成器
def generate_reset_token():
    return secrets.token_urlsafe(32)
    