import os
import hashlib
import json
import logging
import tempfile
import subprocess
from datetime import datetime
from pathlib import Path
from typing import Dict, Union, Optional, List, Tuple
import magic

# 尝试导入 clamd
try:
    import clamd
    CLAMD_AVAILABLE = True
except ImportError:
    CLAMD_AVAILABLE = False
    print("警告: python-clamd 未安装，将使用命令行模式")

class ChineseFontDetector:
    """
    中文字体检测器
    支持 HZK12, HZK14, HZK16, HZK24, HZK32 等多种点阵字体
    """
    
    # 点阵字体规格
    FONT_SPECS = {
        'hzk12': {
            'name': 'HZK12',
            'description': '12x12 点阵汉字库',
            'bytes_per_char': 24,
            'chars_count': 8192,
            'common_sizes': [196608, 200704],
            'width': 12,
            'height': 12,
            'encoding': 'GB2312'
        },
        'hzk14': {
            'name': 'HZK14',
            'description': '14x14 点阵汉字库',
            'bytes_per_char': 28,
            'chars_count': 8192,
            'common_sizes': [229376, 233472],
            'width': 14,
            'height': 14,
            'encoding': 'GB2312'
        },
        'hzk16': {
            'name': 'HZK16',
            'description': '16x16 点阵汉字库（最常用）',
            'bytes_per_char': 32,
            'chars_count': 8192,
            'common_sizes': [262144, 266240],
            'width': 16,
            'height': 16,
            'encoding': 'GB2312'
        },
        'hzk24': {
            'name': 'HZK24',
            'description': '24x24 点阵汉字库',
            'bytes_per_char': 72,
            'chars_count': 8192,
            'common_sizes': [589824, 598016],
            'width': 24,
            'height': 24,
            'encoding': 'GB2312'
        },
        'hzk32': {
            'name': 'HZK32',
            'description': '32x32 点阵汉字库',
            'bytes_per_char': 128,
            'chars_count': 8192,
            'common_sizes': [1048576, 1056768],
            'width': 32,
            'height': 32,
            'encoding': 'GB2312'
        },
        'hzk40': {
            'name': 'HZK40',
            'description': '40x40 点阵汉字库',
            'bytes_per_char': 200,
            'chars_count': 8192,
            'common_sizes': [1638400, 1654784],
            'width': 40,
            'height': 40,
            'encoding': 'GB2312'
        },
        'hzk48': {
            'name': 'HZK48',
            'description': '48x48 点阵汉字库',
            'bytes_per_char': 288,
            'chars_count': 8192,
            'common_sizes': [2359296, 2383872],
            'width': 48,
            'height': 48,
            'encoding': 'GB2312'
        },
        'hzk16t': {  # 注意这里需要逗号，并且要正确缩进
            'name': 'HZK16T',
            'description': '16x16 繁体汉字库',
            'bytes_per_char': 32,
            'chars_count': 13060,               # BIG5 编码的汉字数
            'common_sizes': [417920, 425984],
            'width': 16,
            'height': 16,
            'encoding': 'BIG5'
        }
    }
    
    # 点阵数据特征（用于验证）
    PATTERN_FEATURES = {
        'hzk12': {
            'row_bytes': 2,
            'typical_pattern': [0x00, 0x00, 0x3F, 0xFC, 0x3F, 0xFC, 0x00, 0x00],
            'density_range': (0.3, 0.7)
        },
        'hzk16': {
            'row_bytes': 2,
            'typical_pattern': [0x00, 0x00, 0x7F, 0xFE, 0x7F, 0xFE, 0x00, 0x00],
            'density_range': (0.3, 0.6)
        },
        'hzk24': {
            'row_bytes': 3,
            'typical_pattern': [0x00, 0x00, 0x00, 0x7F, 0xFF, 0xFE, 0x00, 0x00, 0x00],
            'density_range': (0.25, 0.55)
        }
    }
    
    @classmethod
    def detect(cls, file_path: str, filename: Optional[str] = None) -> Dict:
        """
        检测是否为中文字体文件
        
        Args:
            file_path: 文件路径
            filename: 原始文件名
        
        Returns:
            检测结果
        """
        result = {
            'is_chinese_font': False,
            'font_type': None,
            'font_spec': None,
            'confidence': 0.0,
            'encoding': None,
            'details': {}
        }
        
        try:
            file_size = os.path.getsize(file_path)
            
            # 1. 通过文件名判断
            if filename:
                name_lower = filename.lower()
                for font_key, spec in cls.FONT_SPECS.items():
                    if font_key in name_lower or spec['name'].lower() in name_lower:
                        # 检查文件大小是否匹配
                        if file_size in spec['common_sizes']:
                            result['is_chinese_font'] = True
                            result['font_type'] = font_key
                            result['font_spec'] = spec
                            result['encoding'] = spec['encoding']
                            result['confidence'] = 0.7
                            result['details']['match_method'] = 'filename_and_size'
                            break
            
            # 2. 通过文件大小和数据结构判断
            for font_key, spec in cls.FONT_SPECS.items():
                if file_size in spec['common_sizes']:
                    # 读取文件内容验证
                    content_valid = cls._validate_font_content(
                        file_path, 
                        spec['bytes_per_char'],
                        font_key
                    )
                    
                    if content_valid['valid']:
                        result['is_chinese_font'] = True
                        result['font_type'] = font_key
                        result['font_spec'] = spec
                        result['encoding'] = spec['encoding']
                        result['confidence'] = content_valid['confidence']
                        result['details'] = content_valid['details']
                        break
            
            # 3. 如果文件名包含 hzk 但大小不匹配，可能是变体
            if not result['is_chinese_font'] and filename:
                if 'hzk' in filename.lower():
                    result['is_chinese_font'] = True
                    result['font_type'] = 'unknown_hzk'
                    result['confidence'] = 0.3
                    result['details'] = {
                        'match_method': 'filename_only',
                        'warning': '文件名包含 HZK 但大小不匹配标准规格'
                    }
            
        except Exception as e:
            result['details']['error'] = str(e)
        
        return result
    
    @classmethod
    def _validate_font_content(cls, file_path: str, bytes_per_char: int, font_key: str) -> Dict:
        """
        验证字体文件内容
        
        点阵字体的特征：
        1. 每个字符的数据不是全0或全1
        2. 点阵数据有一定的随机性
        3. 相邻字符之间可能有连续性
        """
        result = {
            'valid': False,
            'confidence': 0.0,
            'details': {}
        }
        
        try:
            with open(file_path, 'rb') as f:
                # 读取前几个字符
                sample_count = min(10, 8192)  # 最多读取10个字符
                sample_data = []
                
                for i in range(sample_count):
                    char_data = f.read(bytes_per_char)
                    if len(char_data) != bytes_per_char:
                        break
                    sample_data.append(char_data)
                
                if len(sample_data) < 3:
                    return result
                
                # 检查每个字符的数据是否合理
                valid_chars = 0
                total_points = 0
                zero_chars = 0
                pattern_matches = 0
                
                for i, char_data in enumerate(sample_data):
                    # 转换为点阵密度
                    bits = 0
                    zeros = 0
                    for byte in char_data:
                        bits += bin(byte).count('1')
                        if byte == 0:
                            zeros += 1
                    
                    density = bits / (bytes_per_char * 8)
                    
                    # 检查是否全零（空白字符）
                    if zeros == bytes_per_char:
                        zero_chars += 1
                        continue
                    
                    # 密度应该在合理范围内
                    font_features = cls.PATTERN_FEATURES.get(font_key, {})
                    density_range = font_features.get('density_range', (0.2, 0.8))
                    
                    if density_range[0] < density < density_range[1]:
                        valid_chars += 1
                    
                    total_points += bits
                    
                    # 检查相邻字符的连续性（点阵字体相邻字符通常不相关）
                    if i > 0:
                        prev_data = sample_data[i-1]
                        difference = sum(
                            1 for a, b in zip(char_data, prev_data) if a != b
                        )
                        if difference > bytes_per_char * 0.3:  # 至少30%不同
                            pattern_matches += 1
                
                # 计算置信度
                if valid_chars >= sample_count * 0.6:  # 60%以上的字符有效
                    avg_density = total_points / (len(sample_data) * bytes_per_char * 8)
                    
                    # 平均密度应该在合理范围
                    if 0.2 < avg_density < 0.6:
                        result['valid'] = True
                        result['confidence'] = 0.6 + (valid_chars / sample_count) * 0.3
                        
                        # 加上连续性检查
                        if pattern_matches >= (sample_count - zero_chars) * 0.5:
                            result['confidence'] += 0.1
                        
                        result['details'] = {
                            'valid_chars': valid_chars,
                            'zero_chars': zero_chars,
                            'avg_density': avg_density,
                            'pattern_matches': pattern_matches
                        }
        
        except Exception as e:
            result['details']['error'] = str(e)
        
        return result


class FileTypeDetector:
    """
    文件类型检测器
    通过文件头签名识别文件类型，不依赖扩展名
    """
    
    # 常见文件的魔数签名
    MAGIC_SIGNATURES = {
        # 图片
        b'\xFF\xD8\xFF': 'image/jpeg',
        b'\x89PNG\r\n\x1a\n': 'image/png',
        b'GIF87a': 'image/gif',
        b'GIF89a': 'image/gif',
        b'RIFF....WEBP': 'image/webp',
        b'\x00\x00\x01\x00': 'image/ico',
        b'BM': 'image/bmp',
        
        # 文档
        b'%PDF': 'application/pdf',
        b'PK\x03\x04': 'application/zip',  # Office 文档也是 ZIP
        b'\xD0\xCF\x11\xE0': 'application/msword',
        b'{\rtf': 'text/rtf',
        
        # 压缩文件
        b'PK\x03\x04': 'application/zip',
        b'Rar!\x1a\x07': 'application/x-rar-compressed',
        b'7z\xbc\xaf\x27\x1c': 'application/x-7z-compressed',
        b'\x1F\x8B': 'application/gzip',
        b'BZh': 'application/x-bzip2',
        b'ustar': 'application/x-tar',
        
        # 字体文件
        b'\x00\x01\x00\x00\x00': 'font/ttf',      # TrueType
        b'OTTO': 'font/otf',                       # OpenType
        b'\x00\x00\x00\x0C': 'font/woff',          # WOFF
        b'wOFF': 'font/woff2',                      # WOFF2
        b'true': 'font/ttf',                        # TrueType (另一种签名)
        b'typ1': 'font/type1',                      # Type1
    }
    
    def __init__(self):
        self.mime = magic.Magic(mime=True)
        self.font_detector = ChineseFontDetector()
    
    def detect(self, file_path: str, filename: Optional[str] = None) -> Dict:
        """
        检测文件类型，支持无扩展名文件
        """
        result = {
            'mime_type': None,
            'extension': None,
            'description': None,
            'confidence': 0.0,
            'method': 'unknown',
            'is_chinese_font': False,
            'font_info': None
        }
        
        # 1. 检查是否是中文字体
        font_result = self.font_detector.detect(file_path, filename)
        if font_result['is_chinese_font']:
            result['is_chinese_font'] = True
            result['font_info'] = font_result
            result['mime_type'] = f"font/{font_result['font_type']}"
            result['extension'] = f".{font_result['font_type']}"
            result['description'] = font_result['font_spec']['description'] if font_result['font_spec'] else '中文字体'
            result['confidence'] = font_result['confidence']
            result['method'] = 'chinese_font_detector'
            return result
        
        # 2. 使用 python-magic 检测
        try:
            mime_type = self.mime.from_file(file_path)
            if mime_type and mime_type != 'application/octet-stream':
                result['mime_type'] = mime_type
                result['method'] = 'libmagic'
                result['confidence'] = 0.9
                
                ext = self._mime_to_extension(mime_type)
                if ext:
                    result['extension'] = ext
        except:
            pass
        
        # 3. 如果 libmagic 失败，使用魔数检测
        if not result['mime_type'] or result['mime_type'] == 'application/octet-stream':
            magic_result = self._detect_by_magic(file_path)
            if magic_result['mime_type']:
                result.update(magic_result)
                result['method'] = 'magic_bytes'
                result['confidence'] = 0.8
        
        # 4. 如果所有检测都失败，但提供了文件名
        if not result['mime_type'] and filename:
            ext = Path(filename).suffix.lower()
            if ext:
                result['extension'] = ext
                result['mime_type'] = self._extension_to_mime(ext)
                result['confidence'] = 0.5
                result['method'] = 'extension_fallback'
                result['warning'] = '基于扩展名推测，可能不准确'
        
        return result
    
    def _detect_by_magic(self, file_path: str) -> Dict:
        """通过魔数签名检测"""
        result = {'mime_type': None, 'extension': None, 'description': None}
        
        try:
            with open(file_path, 'rb') as f:
                header = f.read(12)
                
                for magic_bytes, mime_type in self.MAGIC_SIGNATURES.items():
                    if header.startswith(magic_bytes):
                        result['mime_type'] = mime_type
                        result['extension'] = self._mime_to_extension(mime_type)
                        break
                
                # 特殊处理 PKZIP 文件
                if header.startswith(b'PK\x03\x04'):
                    f.seek(0)
                    content = f.read(1024)
                    if b'word/' in content:
                        result['mime_type'] = 'application/vnd.openxmlformats-officedocument.wordprocessingml.document'
                    elif b'xl/' in content:
                        result['mime_type'] = 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
                    elif b'ppt/' in content:
                        result['mime_type'] = 'application/vnd.openxmlformats-officedocument.presentationml.presentation'
        
        except Exception as e:
            print(f"魔数检测失败: {e}")
        
        return result
    
    def _mime_to_extension(self, mime_type: str) -> Optional[str]:
        """MIME 类型转扩展名"""
        mime_to_ext = {
            'image/jpeg': '.jpg',
            'image/png': '.png',
            'image/gif': '.gif',
            'image/webp': '.webp',
            'image/bmp': '.bmp',
            'image/svg+xml': '.svg',
            'image/x-icon': '.ico',
            'application/pdf': '.pdf',
            'text/plain': '.txt',
            'application/zip': '.zip',
            'font/ttf': '.ttf',
            'font/otf': '.otf',
            'font/woff': '.woff',
            'font/woff2': '.woff2',
        }
        
        # 添加中文字体
        for size in [12, 14, 16, 24, 32, 40, 48]:
            mime_to_ext[f'font/hzk{size}'] = f'.hzk{size}'
        
        return mime_to_ext.get(mime_type)
    
    def _extension_to_mime(self, ext: str) -> Optional[str]:
        """扩展名转 MIME 类型"""
        ext_to_mime = {
            '.jpg': 'image/jpeg',
            '.jpeg': 'image/jpeg',
            '.png': 'image/png',
            '.gif': 'image/gif',
            '.webp': 'image/webp',
            '.pdf': 'application/pdf',
            '.txt': 'text/plain',
            '.zip': 'application/zip',
            '.ttf': 'font/ttf',
            '.otf': 'font/otf',
        }
        
        # 添加中文字体
        if ext.startswith('.hzk'):
            ext_to_mime[ext] = f'font/{ext[1:]}'
        
        return ext_to_mime.get(ext.lower())


class FileScanner:
    """
    文件安全扫描器
    支持病毒扫描、文件类型验证、哈希计算等功能
    """
    
    def __init__(self, config: Optional[Dict] = None):
        """初始化文件扫描器"""
        
        # 默认配置
        self.config = {
            'clamav_host': '127.0.0.1',
            'clamav_port': 3310,
            'clamav_timeout': 30,
            'max_file_size': 100 * 1024 * 1024,
            'quarantine_dir': '/var/quarantine',
            'scan_archives': True,
            'check_file_type': True,
            'allowed_extensions': None,
            'allowed_mime_types': None,
            'enable_cache': True,
            'cache_ttl': 3600,
            'use_clamd': CLAMD_AVAILABLE,
            'clamscan_path': '/usr/bin/clamscan',
            'log_file': '/var/log/file_scanner.log',
            'allow_no_extension': True,
            'special_files': ['font/hzk12', 'font/hzk14', 'font/hzk16', 
                            'font/hzk24', 'font/hzk32', 'font/hzk40', 'font/hzk48']
        }
        
        if config:
            self.config.update(config)
        
        self._setup_logging()
        os.makedirs(self.config['quarantine_dir'], exist_ok=True)
        
        self.type_detector = FileTypeDetector()
        self.scan_cache = {}
        
        # 初始化 ClamAV
        self.clamd_client = None
        if self.config['use_clamd'] and CLAMD_AVAILABLE:
            try:
                self.clamd_client = clamd.ClamdNetworkSocket(
                    self.config['clamav_host'],
                    self.config['clamav_port'],
                    self.config['clamav_timeout']
                )
                self.clamd_client.ping()
                self.logger.info("ClamAV 服务连接成功")
            except Exception as e:
                self.logger.warning(f"ClamAV 服务连接失败: {e}")
                self.config['use_clamd'] = False
        
        # 允许的 MIME 类型
        self.allowed_mime_types = self.config['allowed_mime_types'] or {
            'image/jpeg', 'image/png', 'image/gif', 'image/webp',
            'text/plain', 'application/pdf',
            'application/zip', 'application/x-rar-compressed',
            'font/ttf', 'font/otf', 'font/woff', 'font/woff2',
        }
        
        # 添加所有中文字体
        if self.config['allow_no_extension']:
            for font_type in self.config['special_files']:
                self.allowed_mime_types.add(font_type)
    
    def _setup_logging(self):
        """设置日志"""
        self.logger = logging.getLogger('FileScanner')
        self.logger.setLevel(logging.INFO)
        
        try:
            fh = logging.FileHandler(self.config['log_file'])
            fh.setLevel(logging.INFO)
            formatter = logging.Formatter(
                '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
            )
            fh.setFormatter(formatter)
            self.logger.addHandler(fh)
        except:
            pass
        
        ch = logging.StreamHandler()
        ch.setLevel(logging.WARNING)
        self.logger.addHandler(ch)
    
    def scan(self, file_input: Union[str, bytes, object], filename: Optional[str] = None) -> Dict:
        """扫描文件"""
        start_time = datetime.now()
        
        result = {
            'safe': False,
            'scanned': True,
            'timestamp': datetime.now().isoformat(),
            'file_info': {},
            'virus': None,
            'warnings': [],
            'errors': [],
            'scan_time': 0,
            'type_detection': None
        }
        
        try:
            # 处理不同类型的输入
            if isinstance(file_input, str):
                if not os.path.exists(file_input):
                    result['errors'].append('文件不存在')
                    return result
                
                file_path = file_input
                result['file_info'] = self._get_file_info(file_path, filename)
                
                # 文件类型检测
                type_info = self.type_detector.detect(file_path, filename)
                result['type_detection'] = type_info
                result['file_info']['detected_mime'] = type_info['mime_type']
                result['file_info']['detected_method'] = type_info['method']
                
                # 检查文件大小
                if result['file_info']['size'] > self.config['max_file_size']:
                    result['errors'].append(f'文件过大（最大 {self.config["max_file_size"]} 字节）')
                    return result
                
                # 检查缓存
                if self.config['enable_cache']:
                    cached = self._check_cache(result['file_info']['hash'])
                    if cached:
                        result.update(cached)
                        result['cached'] = True
                        result['scan_time'] = (datetime.now() - start_time).total_seconds()
                        return result
                
                # 文件类型验证
                if self.config['check_file_type']:
                    type_valid = self._validate_file_type(type_info)
                    if not type_valid['valid']:
                        result['safe'] = False
                        result['errors'].extend(type_valid['errors'])
                        return result
                
                # 病毒扫描
                scan_result = self._scan_file_path(file_path)
                result.update(scan_result)
                
            elif isinstance(file_input, bytes):
                # 处理字节数据
                if not filename:
                    result['errors'].append('字节数据需要提供文件名')
                    return result
                
                with tempfile.NamedTemporaryFile(delete=False) as tmp:
                    tmp.write(file_input)
                    tmp_path = tmp.name
                
                try:
                    result['file_info'] = self._get_file_info(tmp_path, filename)
                    type_info = self.type_detector.detect(tmp_path, filename)
                    result['type_detection'] = type_info
                    
                    if self.config['check_file_type']:
                        type_valid = self._validate_file_type(type_info)
                        if not type_valid['valid']:
                            result['errors'].extend(type_valid['errors'])
                            return result
                    
                    scan_result = self._scan_file_path(tmp_path)
                    result.update(scan_result)
                finally:
                    if os.path.exists(tmp_path):
                        os.unlink(tmp_path)
            
            elif hasattr(file_input, 'read'):
                # 处理文件对象
                if not filename:
                    result['errors'].append('文件对象需要提供文件名')
                    return result
                
                with tempfile.NamedTemporaryFile(delete=False) as tmp:
                    tmp.write(file_input.read())
                    tmp_path = tmp.name
                
                try:
                    result['file_info'] = self._get_file_info(tmp_path, filename)
                    type_info = self.type_detector.detect(tmp_path, filename)
                    result['type_detection'] = type_info
                    
                    if self.config['check_file_type']:
                        type_valid = self._validate_file_type(type_info)
                        if not type_valid['valid']:
                            result['errors'].extend(type_valid['errors'])
                            return result
                    
                    scan_result = self._scan_file_path(tmp_path)
                    result.update(scan_result)
                finally:
                    if os.path.exists(tmp_path):
                        os.unlink(tmp_path)
            
            else:
                result['errors'].append('不支持的文件输入类型')
                return result
            
            # 缓存结果
            if self.config['enable_cache'] and result['safe']:
                self._add_to_cache(result['file_info']['hash'], result)
            
            self._log_scan(result)
            
        except Exception as e:
            self.logger.error(f"扫描过程出错: {e}")
            result['errors'].append(f'扫描出错: {str(e)}')
        
        result['scan_time'] = (datetime.now() - start_time).total_seconds()
        return result
    
    def _validate_file_type(self, type_info: Dict) -> Dict:
        """验证文件类型是否允许"""
        result = {'valid': True, 'errors': []}
        
        mime_type = type_info.get('mime_type')
        
        if not mime_type:
            if self.config['allow_no_extension']:
                return result
            result['valid'] = False
            result['errors'].append('无法检测文件类型')
            return result
        
        # 中文字体自动允许
        if type_info.get('is_chinese_font'):
            return result
        
        if mime_type not in self.allowed_mime_types:
            if mime_type.startswith('text/') and 'text/plain' in self.allowed_mime_types:
                return result
            result['valid'] = False
            result['errors'].append(f'不允许的文件类型: {mime_type}')
        
        return result
    
    def _scan_file_path(self, file_path: str) -> Dict:
        """扫描文件"""
        result = {
            'safe': False,
            'method': 'clamd' if self.config['use_clamd'] else 'clamscan',
            'virus': None,
            'details': {}
        }
        
        if self.config['use_clamd'] and self.clamd_client:
            virus_result = self._scan_with_clamd(file_path)
        else:
            virus_result = self._scan_with_clamscan(file_path)
        
        result.update(virus_result)
        
        # 扫描压缩包内容
        if self.config['scan_archives'] and self._is_archive(file_path):
            archive_result = self._scan_archive_contents(file_path)
            result['archive_contents'] = archive_result
        
        return result
    
    def _scan_with_clamd(self, file_path: str) -> Dict:
        """使用 clamd 扫描"""
        result = {'safe': False, 'virus': None, 'details': {}}
        
        try:
            scan_result = self.clamd_client.scan(file_path)
            
            for fname, status in scan_result.items():
                if status[0] == 'OK':
                    result['safe'] = True
                    result['details'] = {'status': 'clean'}
                elif status[0] == 'FOUND':
                    result['safe'] = False
                    result['virus'] = status[1]
                    result['details'] = {'status': 'infected', 'virus': status[1]}
                else:
                    result['safe'] = False
                    result['details'] = {'status': 'error', 'message': status}
                    
        except Exception as e:
            self.logger.error(f"ClamAV 扫描出错: {e}")
            return self._scan_with_clamscan(file_path)
        
        return result
    
    def _scan_with_clamscan(self, file_path: str) -> Dict:
        """使用命令行 clamscan 扫描"""
        result = {'safe': False, 'virus': None, 'details': {}}
        
        try:
            cmd = [
                self.config['clamscan_path'],
                '--stdout',
                '--no-summary',
                '--quiet',
                file_path
            ]
            
            process = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.config['clamav_timeout']
            )
            
            stdout = process.stdout.lower()
            
            if 'found' in stdout or 'infected' in stdout:
                result['safe'] = False
                for line in stdout.split('\n'):
                    if 'founds' in line or 'infected' in line:
                        parts = line.split(':')
                        if len(parts) > 1:
                            result['virus'] = parts[1].strip()
                        break
                result['details'] = {'output': stdout}
                
            elif process.returncode == 0:
                result['safe'] = True
                result['details'] = {'status': 'clean'}
                
            else:
                result['safe'] = False
                result['details'] = {'error': process.stderr}
                
        except subprocess.TimeoutExpired:
            result['details'] = {'error': '扫描超时'}
        except Exception as e:
            result['details'] = {'error': str(e)}
        
        return result
    
    def _is_archive(self, file_path: str) -> bool:
        """判断是否为压缩文件"""
        archive_exts = {'.zip', '.rar', '.7z', '.tar', '.gz', '.bz2'}
        ext = Path(file_path).suffix.lower()
        return ext in archive_exts
    
    def _scan_archive_contents(self, file_path: str) -> Dict:
        """分析压缩包内容"""
        result = {'file_count': 0, 'suspicious_files': [], 'total_size': 0}
        
        try:
            if file_path.endswith('.zip'):
                import zipfile
                with zipfile.ZipFile(file_path, 'r') as zf:
                    for info in zf.infolist():
                        result['file_count'] += 1
                        result['total_size'] += info.file_size
                        
                        if self._is_suspicious_filename(info.filename):
                            result['suspicious_files'].append({
                                'name': info.filename,
                                'size': info.file_size,
                                'reason': '可疑文件名'
                            })
            
            elif file_path.endswith(('.tar', '.tar.gz', '.tgz')):
                import tarfile
                with tarfile.open(file_path, 'r:*') as tf:
                    for info in tf.getmembers():
                        if info.isfile():
                            result['file_count'] += 1
                            result['total_size'] += info.size
                            
                            if self._is_suspicious_filename(info.name):
                                result['suspicious_files'].append({
                                    'name': info.name,
                                    'size': info.size,
                                    'reason': '可疑文件名'
                                })
        except Exception as e:
            self.logger.warning(f"分析压缩包失败: {e}")
        
        return result
    
    def _is_suspicious_filename(self, filename: str) -> bool:
        """检查可疑文件名"""
        suspicious = ['.exe', '.bat', '.cmd', '.ps1', '.vbs', '.js', '.jar']
        lower_name = filename.lower()
        return any(p in lower_name for p in suspicious)
    
    def _get_file_info(self, file_path: str, original_filename: Optional[str] = None) -> Dict:
        """获取文件信息"""
        stat = os.stat(file_path)
        
        return {
            'name': original_filename or os.path.basename(file_path),
            'size': stat.st_size,
            'created': datetime.fromtimestamp(stat.st_ctime).isoformat(),
            'modified': datetime.fromtimestamp(stat.st_mtime).isoformat(),
            'hash': self._calculate_hash(file_path)
        }
    
    def _calculate_hash(self, file_path: str) -> str:
        """计算文件哈希"""
        sha256 = hashlib.sha256()
        with open(file_path, 'rb') as f:
            for chunk in iter(lambda: f.read(8192), b''):
                sha256.update(chunk)
        return sha256.hexdigest()
    
    def _check_cache(self, file_hash: str) -> Optional[Dict]:
        """检查缓存"""
        if file_hash in self.scan_cache:
            entry = self.scan_cache[file_hash]
            age = (datetime.now() - entry['cache_time']).total_seconds()
            if age < self.config['cache_ttl']:
                return entry['result']
        return None
    
    def _add_to_cache(self, file_hash: str, result: Dict):
        """添加到缓存"""
        self.scan_cache[file_hash] = {
            'result': result,
            'cache_time': datetime.now()
        }
    
    def _log_scan(self, result: Dict):
        """记录扫描日志"""
        if result['safe']:
            self.logger.info(f"安全文件: {result['file_info'].get('name', 'unknown')}")
        elif result.get('virus'):
            self.logger.warning(f"发现病毒: {result['virus']} 在文件 {result['file_info'].get('name', 'unknown')}")
    
    def quarantine_file(self, file_path: str, reason: str = "infected") -> Optional[str]:
        """隔离文件"""
        try:
            if not os.path.exists(file_path):
                return None
            
            filename = Path(file_path).name
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            quarantine_name = f"{timestamp}_{reason}_{filename}"
            quarantine_path = os.path.join(self.config['quarantine_dir'], quarantine_name)
            
            os.rename(file_path, quarantine_path)
            
            # 保存元数据
            meta_path = quarantine_path + '.meta.json'
            file_info = self._get_file_info(quarantine_path)
            file_info['reason'] = reason
            file_info['quarantine_time'] = datetime.now().isoformat()
            
            with open(meta_path, 'w') as f:
                json.dump(file_info, f, indent=2)
            
            self.logger.info(f"文件已隔离: {quarantine_path}")
            return quarantine_path
            
        except Exception as e:
            self.logger.error(f"隔离文件失败: {e}")
            return None


# 简易接口
def quick_scan(file_input, filename=None):
    """快速扫描文件"""
    scanner = FileScanner()
    return scanner.scan(file_input, filename)


# 使用示例
if __name__ == '__main__':
    # 测试各种 HZK 字体
    for size in [16, 24, 32]:
        result = quick_scan(f'hzk{size}', f'hzk{size}')
        print(f"\nHZK{size} 扫描结果:")
        print(f"  安全: {result['safe']}")
        print(f"  文件类型: {result['type_detection']['mime_type']}")
        print(f"  置信度: {result['type_detection']['confidence']}")
        if result['type_detection'].get('font_info'):
            print(f"  字体信息: {result['type_detection']['font_info']}")
