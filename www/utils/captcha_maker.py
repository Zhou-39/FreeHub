import random
import string
import secrets
from PIL import Image, ImageDraw, ImageFont
from io import BytesIO

def generate_captcha(num=6, width=190, height=60, if_uppercase=False):
    # 生成6位随机字符（字母+数字）
    chars = string.ascii_letters + string.digits
    captcha_text = ''.join(secrets.choice(chars) for _ in range(num))
    expected = captcha_text if if_uppercase else captcha_text.lower()  # 存储小写形式

    # 创建图片
    width, height = width, height
    image = Image.new('RGB', (width, height), color=(240, 240, 240))
    draw = ImageDraw.Draw(image)

    # 使用系统字体或备用字体
    try:
        font = ImageFont.truetype('/var/website/www/static/fonts/font.ttf', size=30)
    except:
        font = ImageFont.load_default()

    # 绘制干扰线和噪点
    for _ in range(5):
        x1 = random.randint(0, width)
        y1 = random.randint(0, height)
        x2 = random.randint(0, width)
        y2 = random.randint(0, height)
        draw.line((x1, y1, x2, y2), fill=(random.randint(50, 200), random.randint(50, 200), random.randint(50, 200)))

    for _ in range(100):
        x = random.randint(0, width)
        y = random.randint(0, height)
        draw.point((x, y), fill=(random.randint(0, 255), random.randint(0, 255), random.randint(0, 255)))

    # 绘制验证码文本（每个字符随机位置和颜色）
    x = 10
    for ch in captcha_text:
        y = random.randint(5, 15)
        draw.text((x, y), ch, fill=(random.randint(0, 100), random.randint(0, 100), random.randint(0, 100)), font=font)
        x += 30

    # 返回图片二进制流
    img_io = BytesIO()
    image.save(img_io, 'PNG')
    img_io.seek(0)

    return expected, img_io
