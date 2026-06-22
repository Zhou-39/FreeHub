from flask import Blueprint, jsonify, current_app, render_template, request
import os
from utils.utils import ensure_model, predict_url, _MODEL, _VECT, _DEVICE

api_bp = Blueprint('api', __name__, url_prefix='/api')

def check(document, name='FreeHub'):
    if os.path.exists(document):
        with current_app.app_context():
            path = document.replace(current_app.template_folder, '').replace('\\', '/')
            return render_template(path, name=name)

    return jsonify({'success': False, 'error': 'Document not found.'})

@api_bp.route('/user-agreement/<int:id>')
def user_agreement(id):
    name = request.args.get('name', 'FreeHub')
    with current_app.app_context():
        document = os.path.join(current_app.template_folder, 'system-files', 'Users', 'user-agreement', f'{id}.html')
    
    return check(document, name)

@api_bp.route('/admin-guideline/<int:id>')
def admin_guideline(id):
    name = request.args.get('name', 'FreeHub')
    with current_app.app_context():
        document = os.path.join(current_app.template_folder, 'system-files', 'Admins', 'admin-guideline', f'{id}.html')
    
    return check(document, name)

@api_bp.route('/superadmin-guideline/<int:id>')
def superadmin_guideline(id):
    name = request.args.get('name', 'FreeHub')
    with current_app.app_context():
        document = os.path.join(current_app.template_folder, 'system-files', 'SuperAdmins','superadmin-guideline', f'{id}.html')

    return check(document, name)

@api_bp.route('/posts', methods=['GET'])
def api_list_posts():
    """API: 获取帖子列表"""
    from bps.users import user_bp
    
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 10, type=int)
    
    posts = user_bp.Posts.query.filter_by(is_deleted=False)\
        .order_by(user_bp.Posts.created_at.desc())\
        .paginate(page=page, per_page=per_page, error_out=False)
    
    return jsonify({
        'code': 200,
        'data': [{
            'id': p.id,
            'title': p.title,
            'excerpt': p.content[:200],
            'created_at': p.created_at.isoformat(),
            'author': get_author_info(p.author_id, p.author_type)
        } for p in posts.items],
        'total': posts.total,
        'page': page,
        'per_page': per_page
    })

@api_bp.route('/check')
def link_checker():
    global _MODEL, _VECT
    url = request.args.get('url')
    if not url:
        return render_template('/system-files/400.html'), 400

    if _MODEL is None or _VECT is None:
        try:
            _MODEL, _VECT = ensure_model(text_dim=500, device=_DEVICE)
        except Exception as e:
            return render_template('/system-files/500.html'), 500

    try:
        res = predict_url(url, _MODEL, _VECT, device=_DEVICE)
        return render_template('/system-files/check.html', **res)
    except Exception as e:
        return render_template('/system-files/500.html'), 500
