from flask import Flask, render_template, send_from_directory, session

app = Flask(__name__)

def renderTemplate(template_name_or_list, **context):
    try:
        basic_url = session.get('role', 'user')
        role = basic_url.capitalize() + 's'
        if role == 'Users':
            user = db.session.get(IDs, int(session.get('user_id')))
        elif role == 'Admins':
            user = db.session.get(Admins, int(session.get('admin_id')))
        else:
            raise Exception("No valid role in session")
    except:
        user = ''
    has_avatar = False
    theme = session.get('theme', 'system')
    
    if user and user.nickname:
        avatar_path = os.path.join(app.static_folder, 'img', 'upload', 'avatar', role, f'{user.nickname}.png')
        has_avatar = os.path.exists(avatar_path)

    return render_template('/system-files/'+template_name_or_list, **context, role=[role, user], has_avatar=has_avatar, theme=theme, basic_url=basic_url)

@app.errorhandler(404)
def page_not_found(e):
    return renderTemplate('404.html'), 404

@app.errorhandler(500)
def internal_server_error(e):
    return renderTemplate('500.html'), 500

@app.errorhandler(502)
def bad_gateway(e):
    return renderTemplate('502.html'), 502

@app.errorhandler(403)
def forbidden(e):
    return renderTemplate('403.html'), 403

@app.errorhandler(429)
def too_many_requests(e):
    return renderTemplate('429.html'), 429

@app.route('/favicon.ico')
def favicon():
    return send_from_directory(
        os.path.join(app.static_folder, 'img', 'system'),
        'favicon.ico',
        mimetype='image/vnd.microsoft.icon'
    )

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080, debug=False)
