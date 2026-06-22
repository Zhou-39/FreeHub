from flask import (
    Flask,
    request,
    jsonify,
    session,
    redirect,
    render_template
)

from flask_socketio import SocketIO, emit

from functools import wraps
from werkzeug.utils import secure_filename

import docker
import os
import uuid
import pty
import select
import subprocess
import threading
import signal
import json
import shutil
import time
import requests
import termios
import fcntl
import struct
import re
import string
import secrets

def generate_random_string(length=12):
    characters = string.ascii_letters + string.digits + string.punctuation
    random_string = ''.join(secrets.choice(characters) for i in range(length))
    return random_string

# =====================================================
# Flask
# =====================================================

app = Flask(__name__)

app.secret_key = generate_random_string(100)

socketio = SocketIO(
    app,
    cors_allowed_origins="*",
    async_mode="threading",
    ping_timeout=120,
    ping_interval=30
)

# =====================================================
# Config
# =====================================================

BASE_DIR = "/var/website/ide"

WORKSPACE_CODER = os.path.join(
    BASE_DIR,
    "workspaces"
)

MAIN_SITE = "https://free-hub.cn"
SHARE_SERVICE_URL = "http://127.0.0.1:8002"

DOCKER_IMAGE = "freehub-ide-base"
DOCKER_NETWORK = "freehub_bridge"  # 自定义桥接网络

os.makedirs(
    WORKSPACE_CODER,
    exist_ok=True
)

docker_client = docker.from_env()


# =====================================================
# Docker Network
# =====================================================

def ensure_network():
    """确保自定义 Docker 网络存在"""
    try:
        docker_client.networks.get(DOCKER_NETWORK)
        print(f"✅ Docker 网络已存在: {DOCKER_NETWORK}")
    except docker.errors.NotFound:
        docker_client.networks.create(
            DOCKER_NETWORK,
            driver="bridge",
            ipam=docker.types.IPAMConfig(
                driver="default",
                configs=[{"Subnet": "172.20.0.0/16"}]
            )
        )
        print(f"✅ 创建 Docker 网络: {DOCKER_NETWORK}")
    except Exception as e:
        print(f"⚠️ Docker 网络操作失败: {e}")


# 应用启动时确保网络存在
ensure_network()


# =====================================================
# Utils
# =====================================================

def login_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if not session.get("logged_in"):
            return redirect("/")
        return f(*args, **kwargs)
    return wrapper


def get_username():
    return session.get("nickname")


def get_current_project():
    return session.get("current_project")


def get_workspace():
    username = get_username()
    project = get_current_project()

    if not username or not project:
        return None

    workspace = os.path.join(
        WORKSPACE_CODER,
        username,
        project
    )

    os.makedirs(workspace, exist_ok=True)
    os.chmod(workspace, 0o777)

    return workspace


def safe_join(base, path):
    final = os.path.realpath(os.path.join(base, path))
    base = os.path.realpath(base)

    if not final.startswith(base):
        raise Exception("非法路径")

    return final


def notify_share_container_destroyed(username, project_name):
    """通知 Share 服务容器已销毁，清理端口转发"""
    try:
        requests.post(
            f"{SHARE_SERVICE_URL}/api/container/destroyed",
            json={
                "username": username,
                "project_name": project_name
            },
            timeout=3
        )
        print(f"✅ 已通知 Share 服务清理 {username}/{project_name} 的端口转发")
    except Exception as e:
        print(f"⚠️ 通知 Share 服务失败: {e}")


def get_user_projects(username):
    """获取用户的所有项目列表"""
    coder_root = os.path.join(WORKSPACE_CODER, username)
    projects = []
    if os.path.exists(coder_root):
        for name in os.listdir(coder_root):
            full = os.path.join(coder_root, name)
            if os.path.isdir(full):
                projects.append(name)
    return projects


def get_container_ip(container):
    """获取容器 IP（桥接网络模式）"""
    try:
        container.reload()
        network_settings = container.attrs['NetworkSettings']
        
        # 优先从自定义网络获取 IP
        networks = network_settings.get('Networks', {})
        if DOCKER_NETWORK in networks:
            ip = networks[DOCKER_NETWORK].get('IPAddress')
            if ip:
                return ip
        
        # 回退到默认网络
        ip = network_settings.get('IPAddress')
        if ip:
            return ip
        
        return None
    except Exception as e:
        print(f"获取容器 IP 失败: {e}")
        return None


# =====================================================
# Docker
# =====================================================

def container_name(username, project):
    return f"ide_{username}_{project}"


def get_container(username, project):
    name = container_name(username, project)
    try:
        return docker_client.containers.get(name)
    except:
        return None


def create_container(username, project):
    workspace = os.path.join(
        WORKSPACE_CODER,
        username,
        project
    )

    os.makedirs(workspace, exist_ok=True)
    os.chmod(workspace, 0o777)

    name = container_name(username, project)

    existing = get_container(username, project)

    if existing:
        try:
            existing.reload()
            if existing.status == "running":
                return existing
        except:
            pass

        try:
            existing.stop(timeout=5)
            existing.remove(force=True)
        except:
            pass

    time.sleep(1)

    try:
        container = docker_client.containers.run(
            DOCKER_IMAGE,
            name=name,
            command="sleep infinity",
            detach=True,
            tty=True,
            working_dir="/workspace",
            mem_limit="512m",
            nano_cpus=500000000,
            pids_limit=50,
            network=DOCKER_NETWORK,  # 使用自定义桥接网络
            volumes={
                workspace: {
                    "bind": "/workspace",
                    "mode": "rw"
                }
            },
            cap_add=["DAC_OVERRIDE"],
            user="coder",
            read_only=False,
            environment={
                "HOME": "/workspace",
                "USER": "coder",
                "LANG": "C.UTF-8",
                "LC_ALL": "C.UTF-8",
                "TERM": "xterm-256color",
                "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
                "PS1": "\\u@\\h:\\w\\$ "
            }
        )

        time.sleep(2)

        # 设置 workspace 目录权限
        try:
            container.exec_run("chmod -R 777 /workspace", user="coder", workdir="/workspace")
        except Exception as e:
            print(f"设置权限失败: {e}")

        # 等待容器网络就绪
        retry_count = 0
        while retry_count < 10:
            ip = get_container_ip(container)
            if ip:
                print(f"✅ 容器 {name} IP: {ip}")
                break
            time.sleep(1)
            retry_count += 1

        return container

    except docker.errors.APIError as e:
        if "Conflict" in str(e):
            existing = get_container(username, project)
            if existing:
                return existing
        print(f"Docker API 错误: {e}")
        raise e
    except Exception as e:
        print(f"创建容器失败: {e}")
        raise e


# =====================================================
# SSO
# =====================================================

@app.route("/")
def home():
    if not session.get("logged_in"):
        return redirect(
            "https://free-hub.cn/user/api/auth/ide-login"
            "?ide_url=https://ide.free-hub.cn"
        )
    return redirect("/dashboard")


@app.route("/api/auth/callback")
def auth_callback():
    token = request.args.get("token")

    if not token:
        return "Missing token", 400

    try:
        r = requests.post(
            f"{MAIN_SITE}/user/api/auth/verify",
            json={
                "token": token,
                "service": "ide"
            },
            timeout=10
        )

        data = r.json()

        if not data.get("success"):
            return "Auth failed", 401

        user = data["user_info"]

        session["logged_in"] = True
        session["user_id"] = user["user_id"]
        session["nickname"] = user["nickname"]
        session["email"] = user["email"]

        return redirect("/dashboard")

    except Exception as e:
        return str(e), 500


@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")


# =====================================================
# Dashboard
# =====================================================

@app.route("/dashboard")
@login_required
def dashboard():
    username = get_username()
    projects = get_user_projects(username)
    return render_template(
        "dashboard.html",
        projects=projects,
        username=username
    )


@app.route("/api/user/projects", methods=["GET"])
def api_get_user_projects():
    """获取用户项目列表（供 Share 服务调用，支持内部调用）"""
    # 支持两种方式获取用户名：
    # 1. 从 session 获取（浏览器访问）
    # 2. 从请求头获取（Share 服务内部调用）
    username = get_username()
    
    # 如果 session 中没有，尝试从请求头获取（Share 服务调用）
    if not username:
        username = request.headers.get('X-Username')
    
    if not username:
        return jsonify({
            "success": False,
            "error": "未登录"
        }), 401
    
    projects = get_user_projects(username)
    return jsonify({
        "success": True,
        "projects": projects
    })


@app.route("/api/project/create", methods=["POST"])
@login_required
def create_project():
    data = request.get_json()
    name = data.get("name", "").strip()

    if not name:
        return jsonify({"error": "项目名不能为空"})

    username = get_username()

    project_dir = os.path.join(
        WORKSPACE_CODER,
        username,
        name
    )

    os.makedirs(project_dir, exist_ok=True)
    os.chmod(project_dir, 0o777)

    return jsonify({"success": True})


@app.route("/api/project/open", methods=["POST"])
@login_required
def open_project():
    data = request.get_json()
    project = data.get("project")
    username = get_username()

    workspace = os.path.join(
        WORKSPACE_CODER,
        username,
        project
    )

    if not os.path.exists(workspace):
        return jsonify({
            "success": False,
            "error": "项目不存在"
        })

    session["current_project"] = project

    try:
        container = create_container(username, project)

        time.sleep(2)

        container.reload()
        if container.status != "running":
            container.start()
            time.sleep(1)

        return jsonify({"success": True})

    except docker.errors.ImageNotFound:
        return jsonify({
            "success": False,
            "error": "Docker 镜像不存在，请联系管理员"
        })
    except docker.errors.APIError as e:
        return jsonify({
            "success": False,
            "error": f"Docker API 错误: {str(e)}"
        })
    except Exception as e:
        print(f"创建容器失败: {e}")
        return jsonify({
            "success": False,
            "error": f"创建容器失败: {str(e)}"
        })


@app.route("/api/project/delete", methods=["POST"])
@login_required
def delete_project():
    data = request.get_json()
    project = data.get("project")
    username = get_username()

    if not project:
        return jsonify({
            "success": False,
            "error": "项目名不能为空"
        })

    project_dir = os.path.join(
        WORKSPACE_CODER,
        username,
        project
    )

    if not os.path.exists(project_dir):
        return jsonify({
            "success": False,
            "error": "项目不存在"
        })

    # 停止并删除对应的容器
    try:
        container = get_container(username, project)
        if container:
            container.stop(timeout=5)
            container.remove(force=True)
    except Exception as e:
        print(f"删除容器失败: {e}")

    # 删除项目目录
    try:
        shutil.rmtree(project_dir)
    except Exception as e:
        return jsonify({
            "success": False,
            "error": f"删除项目失败: {str(e)}"
        })

    # 通知 Share 服务清理端口转发
    notify_share_container_destroyed(username, project)

    return jsonify({"success": True})


# =====================================================
# IDE
# =====================================================

@app.route("/ide")
@login_required
def ide():
    if not get_current_project():
        return redirect("/dashboard")

    username = get_username()
    project = get_current_project()

    container = get_container(username, project)
    if not container:
        try:
            create_container(username, project)
        except Exception as e:
            print(f"IDE 页面创建容器失败: {e}")

    return render_template(
        "index.html",
        username=username,
        project=project
    )


# =====================================================
# Files
# =====================================================

@app.route("/api/fs/list", methods=["POST"])
@login_required
def fs_list():
    workspace = get_workspace()
    data = request.get_json() or {}
    path = data.get("path", "")
    target = safe_join(workspace, path)
    os.makedirs(target, exist_ok=True)

    result = []
    for name in os.listdir(target):
        full = os.path.join(target, name)
        result.append({
            "name": name,
            "is_dir": os.path.isdir(full)
        })

    return jsonify({"files": result})


@app.route("/api/fs/read", methods=["POST"])
@login_required
def fs_read():
    workspace = get_workspace()
    data = request.get_json()
    path = data["path"]
    target = safe_join(workspace, path)
    
    # 只允许读取文本文件，排除二进制文件
    # 定义允许的扩展名
    allowed_extensions = ['.py', '.js', '.html', '.css', '.json', '.txt', '.md', 
                          '.xml', '.yaml', '.yml', '.toml', '.ini', '.cfg', 
                          '.conf', '.sh', '.bash', '.c', '.cpp', '.h', '.hpp',
                          '.java', '.go', '.rs', '.sql', '.log']
    
    ext = os.path.splitext(path)[1].lower()
    if ext not in allowed_extensions:
        return jsonify({"error": "不支持的预览文件类型"}), 400
    
    # 检查文件大小（不超过 5MB）
    if os.path.getsize(target) > 5 * 1024 * 1024:
        return jsonify({"error": "文件过大，无法预览"}), 400
    
    try:
        # 尝试 UTF-8 编码
        with open(target, "r", encoding="utf-8") as f:
            content = f.read()
    except UnicodeDecodeError:
        # 如果 UTF-8 失败，尝试 GBK（中文）
        try:
            with open(target, "r", encoding="gbk") as f:
                content = f.read()
        except UnicodeDecodeError:
            # 仍然失败，返回二进制提示
            return jsonify({"error": "文件编码不支持，请下载后查看"}), 400
    
    return jsonify({"content": content})


@app.route("/api/fs/write", methods=["POST"])
@login_required
def fs_write():
    workspace = get_workspace()
    data = request.get_json()
    path = data["path"]
    content = data["content"]
    target = safe_join(workspace, path)

    os.makedirs(os.path.dirname(target), exist_ok=True)

    with open(target, "w", encoding="utf-8") as f:
        f.write(content)

    os.chmod(target, 0o666)

    return jsonify({"success": True})


@app.route("/api/fs/mkdir", methods=["POST"])
@login_required
def fs_mkdir():
    workspace = get_workspace()
    data = request.get_json()
    path = data["path"]
    target = safe_join(workspace, path)

    os.makedirs(target, exist_ok=True)
    os.chmod(target, 0o777)

    return jsonify({"success": True})


@app.route("/api/fs/delete", methods=["POST"])
@login_required
def fs_delete():
    workspace = get_workspace()
    data = request.get_json()
    path = data["path"]
    target = safe_join(workspace, path)

    if os.path.isdir(target):
        shutil.rmtree(target)
    else:
        os.remove(target)

    return jsonify({"success": True})


@app.route("/api/fs/rename", methods=["POST"])
@login_required
def fs_rename():
    workspace = get_workspace()
    data = request.get_json()
    old_path = data.get("old_path")
    new_path = data.get("new_path")

    if not old_path or not new_path:
        return jsonify({"success": False, "error": "参数错误"})

    old_target = safe_join(workspace, old_path)
    new_target = safe_join(workspace, new_path)

    if not os.path.exists(old_target):
        return jsonify({"success": False, "error": "源文件不存在"})

    if os.path.exists(new_target):
        return jsonify({"success": False, "error": "目标文件已存在"})

    try:
        os.rename(old_target, new_target)
        return jsonify({"success": True})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)})


# =====================================================
# Container Status
# =====================================================

@app.route("/api/container/status", methods=["GET"])
@login_required
def container_status():
    username = get_username()
    project = get_current_project()

    if not project:
        return jsonify({
            "running": False,
            "error": "未选择项目"
        })

    container = get_container(username, project)

    if not container:
        return jsonify({
            "running": False,
            "error": "容器不存在"
        })

    try:
        container.reload()
        return jsonify({
            "running": container.status == "running",
            "status": container.status,
            "created": container.attrs.get("Created")
        })
    except Exception as e:
        return jsonify({
            "running": False,
            "error": str(e)
        })


@app.route("/api/container/restart", methods=["POST"])
@login_required
def container_restart():
    username = get_username()
    project = get_current_project()

    if not project:
        return jsonify({
            "success": False,
            "error": "未选择项目"
        })

    try:
        container = create_container(username, project)

        container.reload()
        if container.status != "running":
            container.start()
            time.sleep(2)

        return jsonify({"success": True})
    except Exception as e:
        return jsonify({
            "success": False,
            "error": str(e)
        })


# =====================================================
# Run
# =====================================================

@app.route("/api/run", methods=["POST"])
@login_required
def run_code():
    workspace = get_workspace()
    username = get_username()
    project = get_current_project()

    container = get_container(username, project)

    if not container:
        return jsonify({
            "success": False,
            "error": "容器不存在"
        })

    if container.status != "running":
        try:
            container.start()
            time.sleep(2)
        except Exception as e:
            return jsonify({
                "success": False,
                "error": f"无法启动容器: {str(e)}"
            })

    data = request.get_json()
    filename = data["filename"]
    ext = os.path.splitext(filename)[1].lower()
    timeout_seconds = 30

    file_path = filename

    cmd = ""
    display_cmd = ""

    if ext == ".py":
        display_cmd = f"python3 {file_path}"
        cmd = f"""
cd /workspace && timeout {timeout_seconds} python3 "{file_path}" 2>&1
exit_code=$?
if [ $exit_code -eq 124 ]; then
    echo "错误: 执行超时 ({timeout_seconds}秒)"
elif [ $exit_code -ne 0 ]; then
    echo "错误: 程序退出码 $exit_code"
fi
"""

    elif ext == ".c":
        output_name = file_path.replace('.c', '.out')
        display_cmd = f"gcc {file_path} -o {output_name} && ./{output_name}"
        cmd = f"""
cd /workspace && gcc "{file_path}" -o "{output_name}" 2>&1
if [ $? -eq 0 ]; then
    chmod +x "{output_name}"
    timeout {timeout_seconds} ./"{output_name}" 2>&1
    exit_code=$?
    if [ $exit_code -eq 124 ]; then
        echo "错误: 执行超时 ({timeout_seconds}秒)"
    fi
else
    echo "编译失败"
fi
"""

    elif ext in [".cpp", ".cc", ".cxx"]:
        output_name = file_path.replace(ext, '.out')
        display_cmd = f"g++ {file_path} -o {output_name} && ./{output_name}"
        cmd = f"""
cd /workspace && g++ "{file_path}" -o "{output_name}" 2>&1
if [ $? -eq 0 ]; then
    chmod +x "{output_name}"
    timeout {timeout_seconds} ./"{output_name}" 2>&1
    exit_code=$?
    if [ $exit_code -eq 124 ]; then
        echo "错误: 执行超时 ({timeout_seconds}秒)"
    fi
else
    echo "编译失败"
fi
"""

    elif ext == ".java":
        class_name = os.path.splitext(os.path.basename(filename))[0]
        display_cmd = f"javac {file_path} && java {class_name}"
        cmd = f"""
cd /workspace && javac "{file_path}" 2>&1
if [ $? -eq 0 ]; then
    timeout {timeout_seconds} java {class_name} 2>&1
    exit_code=$?
    if [ $exit_code -eq 124 ]; then
        echo "错误: 执行超时 ({timeout_seconds}秒)"
    fi
else
    echo "编译失败"
fi
"""

    elif ext in [".js", ".mjs"]:
        display_cmd = f"node {file_path}"
        cmd = f"""
cd /workspace && timeout {timeout_seconds} node "{file_path}" 2>&1
exit_code=$?
if [ $exit_code -eq 124 ]; then
    echo "错误: 执行超时 ({timeout_seconds}秒)"
fi
"""

    elif ext == ".go":
        display_cmd = f"go run {file_path}"
        cmd = f"""
cd /workspace && timeout {timeout_seconds} go run "{file_path}" 2>&1
exit_code=$?
if [ $exit_code -eq 124 ]; then
    echo "错误: 执行超时 ({timeout_seconds}秒)"
fi
"""

    elif ext == ".rs":
        output_name = file_path.replace('.rs', '.out')
        display_cmd = f"rustc {file_path} -o {output_name} && ./{output_name}"
        cmd = f"""
cd /workspace && rustc "{file_path}" -o "{output_name}" 2>&1
if [ $? -eq 0 ]; then
    chmod +x "{output_name}"
    timeout {timeout_seconds} ./"{output_name}" 2>&1
    exit_code=$?
    if [ $exit_code -eq 124 ]; then
        echo "错误: 执行超时 ({timeout_seconds}秒)"
    fi
else
    echo "编译失败"
fi
"""

    elif ext == ".sh":
        display_cmd = f"bash {file_path}"
        cmd = f"""
cd /workspace && chmod +x "{file_path}"
timeout {timeout_seconds} bash "{file_path}" 2>&1
exit_code=$?
if [ $exit_code -eq 124 ]; then
    echo "错误: 执行超时 ({timeout_seconds}秒)"
fi
"""

    else:
        return jsonify({
            "success": False,
            "error": f"不支持的文件类型: {ext}"
        })

    try:
        container.exec_run("chmod 777 /workspace", user="coder", workdir="/workspace")

        exec_result = container.exec_run(
            ["bash", "-c", cmd],
            stdout=True,
            stderr=True,
            user="coder",
            workdir="/workspace"
        )

        output = exec_result.output.decode(errors="ignore")

        if len(output) > 100000:
            output = output[:100000] + "\n\n... (输出过长，已截断)"

        return jsonify({
            "success": True,
            "output": output if output else "(无输出)",
            "command": display_cmd
        })

    except Exception as e:
        print(f"执行错误: {e}")
        return jsonify({
            "success": False,
            "output": f"执行错误: {str(e)}",
            "command": display_cmd
        })


# =====================================================
# Upload
# =====================================================

@app.route("/api/upload", methods=["POST"])
@login_required
def upload():
    workspace = get_workspace()

    if "file" not in request.files:
        return jsonify({"error": "没有文件"})

    file = request.files["file"]
    filename = secure_filename(file.filename)
    save_path = os.path.join(workspace, filename)
    file.save(save_path)
    os.chmod(save_path, 0o666)

    return jsonify({"success": True})


# =====================================================
# Terminal (使用真正的 PTY)
# =====================================================

class TerminalSession:
    def __init__(self, sid, container_name, workspace):
        self.sid = sid
        self.container_name = container_name
        self.workspace = workspace
        self.master_fd = None
        self.slave_fd = None
        self.process = None
        self.running = True

    def start(self):
        try:
            self.master_fd, self.slave_fd = pty.openpty()
            self.set_terminal_size(80, 24)

            cmd = [
                "docker", "exec",
                "-i",
                "-t",
                "--workdir", self.workspace,
                self.container_name,
                "/bin/bash", "-i"
            ]

            self.process = subprocess.Popen(
                cmd,
                stdin=self.slave_fd,
                stdout=self.slave_fd,
                stderr=self.slave_fd,
                close_fds=True,
                preexec_fn=os.setsid
            )

            os.close(self.slave_fd)
            self.slave_fd = None

            flags = fcntl.fcntl(self.master_fd, fcntl.F_GETFL)
            fcntl.fcntl(self.master_fd, fcntl.F_SETFL, flags | os.O_NONBLOCK)

            print(f"终端会话启动: {self.sid}, PID: {self.process.pid}")
            return True

        except Exception as e:
            print(f"启动终端会话失败: {e}")
            import traceback
            traceback.print_exc()
            return False

    def set_terminal_size(self, cols, rows):
        if self.master_fd is not None:
            try:
                winsize = struct.pack("HHHH", rows, cols, 0, 0)
                fcntl.ioctl(self.master_fd, termios.TIOCSWINSZ, winsize)
            except Exception as e:
                print(f"设置终端大小失败: {e}")

    def read_output(self):
        if not self.running or self.master_fd is None:
            return None

        try:
            rlist, _, _ = select.select([self.master_fd], [], [], 0.05)
            if rlist:
                data = os.read(self.master_fd, 4096)
                if data:
                    return data.decode('utf-8', errors='replace')
            return None
        except BlockingIOError:
            return None
        except OSError as e:
            if e.errno == 5:
                self.running = False
            return None
        except Exception as e:
            print(f"读取终端输出失败: {e}")
            return None

    def write_input(self, data):
        if not self.running or self.master_fd is None:
            return False

        try:
            os.write(self.master_fd, data.encode('utf-8'))
            return True
        except Exception as e:
            print(f"写入终端输入失败: {e}")
            return False

    def is_alive(self):
        if not self.process:
            return False
        return self.process.poll() is None

    def close(self):
        self.running = False

        if self.master_fd is not None:
            try:
                os.close(self.master_fd)
            except:
                pass
            self.master_fd = None

        if self.process:
            try:
                self.process.terminate()
                self.process.wait(timeout=3)
            except:
                try:
                    self.process.kill()
                except:
                    pass
            self.process = None

        print(f"终端会话关闭: {self.sid}")


terminal_sessions = {}


def get_container_name_by_session():
    username = get_username()
    project = get_current_project()
    if username and project:
        return f"ide_{username}_{project}"
    return None


@socketio.on("connect")
def ws_connect():
    print(f"WebSocket 连接尝试: {request.sid}")

    if not session.get("logged_in"):
        print(f"拒绝连接: 未登录 {request.sid}")
        return False

    username = get_username()
    project = get_current_project()

    if not project:
        print(f"拒绝连接: 未选择项目 {request.sid}")
        return False

    container_name_val = get_container_name_by_session()
    if not container_name_val:
        print(f"拒绝连接: 无法获取容器名 {request.sid}")
        return False

    workspace = "/workspace"

    container = get_container(username, project)
    if not container:
        print(f"拒绝连接: 容器不存在 {request.sid}")
        return False

    if container.status != "running":
        try:
            container.start()
            time.sleep(2)
        except Exception as e:
            print(f"启动容器失败: {e}")
            return False

    session_obj = TerminalSession(request.sid, container_name_val, workspace)
    if not session_obj.start():
        print(f"创建终端会话失败: {request.sid}")
        return False

    terminal_sessions[request.sid] = session_obj
    current_sid = request.sid

    def read_loop(sid):
        while True:
            sess = terminal_sessions.get(sid)
            if not sess or not sess.running or not sess.is_alive():
                break

            output = sess.read_output()
            if output:
                socketio.emit("terminal_output", output, room=sid)
            else:
                time.sleep(0.02)

        if sid in terminal_sessions:
            terminal_sessions[sid].close()
            del terminal_sessions[sid]
        print(f"终端读循环结束: {sid}")

    thread = threading.Thread(target=read_loop, args=(current_sid,), daemon=True)
    thread.start()

    print(f"终端连接成功: {request.sid}")
    return True


@socketio.on("terminal_input")
def terminal_input(data):
    sess = terminal_sessions.get(request.sid)
    if not sess:
        return

    text = data.get("input", "")
    sess.write_input(text)


@socketio.on("terminal_resize")
def terminal_resize(data):
    sess = terminal_sessions.get(request.sid)
    if not sess:
        return

    cols = data.get("cols", 80)
    rows = data.get("rows", 24)
    sess.set_terminal_size(cols, rows)
    print(f"终端 resize: {request.sid} -> {cols}x{rows}")


@socketio.on("disconnect")
def ws_disconnect():
    sess = terminal_sessions.pop(request.sid, None)
    if sess:
        sess.close()
    print(f"WebSocket 断开: {request.sid}")
        

# =====================================================
# Health
# =====================================================

@app.route("/health")
def health():
    return jsonify({"status": "ok", "service": "ide"})


# =====================================================
# Start
# =====================================================

if __name__ == "__main__":
    socketio.run(
        app,
        host="0.0.0.0",
        port=8001,
        debug=False,
        allow_unsafe_werkzeug=True
    )
