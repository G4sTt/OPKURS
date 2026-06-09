from flask import Flask, render_template, request, jsonify, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
from authlib.integrations.flask_client import OAuth
import logging
import os
import json
from dotenv import load_dotenv
import base64
from werkzeug.utils import secure_filename

load_dotenv()

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

app = Flask(__name__)

basedir = os.path.abspath(os.path.dirname(__file__))
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(basedir, 'instance', 'events.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'dev-secret-key-change-in-production')

app.config['GOOGLE_CLIENT_ID'] = os.getenv('GOOGLE_CLIENT_ID')
app.config['GOOGLE_CLIENT_SECRET'] = os.getenv('GOOGLE_CLIENT_SECRET')

db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
login_manager.login_message = 'Пожалуйста, войдите, чтобы получить доступ к этой странице.'

oauth = OAuth(app)
google = oauth.register(
    name='google',
    client_id=app.config['GOOGLE_CLIENT_ID'],
    client_secret=app.config['GOOGLE_CLIENT_SECRET'],
    server_metadata_url='https://accounts.google.com/.well-known/openid-configuration',
    client_kwargs={
        'scope': 'openid email profile'
    }
)

# пользователь
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=True)
    name = db.Column(db.String(100), nullable=False)
    avatar = db.Column(db.String(500), nullable=True)  # URL
    avatar_data = db.Column(db.Text, nullable=True)  # base64
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    events = db.relationship('Event', backref='author', lazy=True, cascade="all, delete-orphan")

    def get_avatar(self):
        if self.avatar_data:
            return self.avatar_data
        if self.avatar:
            return self.avatar
        return None

# событие
class Event(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

    title = db.Column(db.String(150), nullable=False)
    start = db.Column(db.String(50), nullable=False)
    end = db.Column(db.String(50), nullable=True)
    difficulty = db.Column(db.String(20), default='medium')
    points = db.Column(db.Integer, default=0)
    color = db.Column(db.String(20), default='#562370')
    done = db.Column(db.Boolean, default=False)
    all_day = db.Column(db.Boolean, default=False)

    def to_dict(self):
        return {
            'id': str(self.id),
            'title': self.title,
            'start': self.start,
            'end': self.end,
            'difficulty': self.difficulty,
            'points': self.points,
            'color': self.color,
            'done': self.done,
            'allDay': self.all_day
        }


# форматы авы
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'webp'}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/api/upload_avatar', methods=['POST'])
@login_required
def upload_avatar():
    try:
        if 'avatar' not in request.files:
            return jsonify({'error': 'Нет файла'}), 400

        file = request.files['avatar']
        if file.filename == '':
            return jsonify({'error': 'Файл не выбран'}), 400

        if file and allowed_file(file.filename):
            # читаем файл и конвертируем в base64
            file_data = file.read()
            base64_data = base64.b64encode(file_data).decode('utf-8')
            mime_type = file.content_type
            avatar_base64 = f"data:{mime_type};base64,{base64_data}"

            # сейв
            current_user.avatar_data = avatar_base64
            db.session.commit()

            return jsonify({
                'success': True,
                'avatar': avatar_base64
            })
        else:
            return jsonify({'error': 'Неподдерживаемый формат. Используйте PNG, JPG, GIF, WEBP'}), 400

    except Exception as e:
        logger.error(f"Ошибка загрузки аватара: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/remove_avatar', methods=['DELETE'])
@login_required
def remove_avatar():
    """Удалить загруженный аватар"""
    current_user.avatar_data = None
    db.session.commit()
    return jsonify({'success': True})


@app.route('/api/user_profile')
@login_required
def get_user_profile():
    """Получить профиль пользователя"""
    return jsonify({
        'name': current_user.name,
        'email': current_user.email,
        'avatar_url': current_user.avatar,
        'avatar_data': current_user.avatar_data
    })


@app.route('/api/update_profile', methods=['POST'])
@login_required
def update_profile():
    """Обновить имя пользователя"""
    data = request.json
    new_name = data.get('name', '').strip()

    if not new_name:
        return jsonify({'error': 'Имя не может быть пустым'}), 400

    current_user.name = new_name
    db.session.commit()

    return jsonify({'success': True, 'name': new_name})


# загрузка пользователя
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


@app.context_processor
def inject_user():
    return dict(current_user=current_user)


with app.app_context():
    db.create_all()

# авторизация
@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))

    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        user = User.query.filter_by(email=email).first()

        if user and user.check_password(password):
            login_user(user)
            next_page = request.args.get('next')
            flash('Вы успешно вошли!', 'success')
            return redirect(next_page or url_for('index'))
        else:
            flash('Неверный email или пароль', 'danger')

    return render_template('login.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('index'))

    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        name = request.form.get('name')

        if User.query.filter_by(email=email).first():
            flash('Email уже зарегистрирован', 'warning')
            return redirect(url_for('register'))

        new_user = User(email=email, name=name)
        new_user.set_password(password)
        db.session.add(new_user)
        db.session.commit()

        login_user(new_user)
        flash('Аккаунт создан! Добро пожаловать.', 'success')
        return redirect(url_for('index'))

    return render_template('register.html')


@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Вы вышли из системы', 'info')
    return redirect(url_for('index'))


@app.route('/auth/google')
def google_login():
    redirect_uri = url_for('google_callback', _external=True)
    return google.authorize_redirect(redirect_uri)


@app.route('/auth/google/callback')
def google_callback():
    try:
        token = google.authorize_access_token()
        resp = google.get('https://www.googleapis.com/oauth2/v3/userinfo')
        user_info = resp.json()

        email = user_info.get('email')
        name = user_info.get('name')
        picture = user_info.get('picture')

        user = User.query.filter_by(email=email).first()

        if not user:
            user = User(email=email, name=name, avatar=picture)
            db.session.add(user)
            db.session.commit()
        else:
            if picture and user.avatar != picture:
                user.avatar = picture
                db.session.commit()

        login_user(user)
        flash('Вы успешно вошли через Google!', 'success')
        return redirect(url_for('index'))

    except Exception as e:
        logger.error(f"Ошибка входа через Google: {e}")
        flash('Ошибка при входе через Google', 'danger')
        return redirect(url_for('login'))


@app.route('/')
def index():
    return render_template('home.html')


@app.route('/calendar')
@login_required
def calendar_page():
    return render_template('calendar.html')


@app.route('/stats')
@login_required
def stats_page():
    return render_template('stats.html')


@app.route('/api/events', methods=['GET'])
@login_required
def get_events():
    events = Event.query.filter_by(user_id=current_user.id).all()
    events_list = [event.to_dict() for event in events]
    logger.info(f"[GET] Пользователь {current_user.email} запросил {len(events_list)} событий")
    return jsonify(events_list)


@app.route('/api/events', methods=['POST'])
@login_required
def add_event():
    try:
        data = request.json
        logger.info(f"[POST] Получены данные: {data}")

        if not data:
            logger.error("Нет данных в запросе")
            return jsonify({'error': 'Нет данных'}), 400

        start_date = data.get('start', '')
        end_date = data.get('end', '')

        logger.info(f"Raw start_date: {start_date}")
        logger.info(f"Raw end_date: {end_date}")

        if start_date and '+' in str(start_date):
            start_date = start_date.split('+')[0]
        if end_date and '+' in str(end_date):
            end_date = end_date.split('+')[0]

        if not start_date:
            start_date = datetime.now().isoformat()
            logger.warning(f"start_date пуст, установлен: {start_date}")

        try:
            points_val = int(data.get('points', 0))
        except (ValueError, TypeError):
            points_val = 0

        new_event = Event(
            user_id=current_user.id,
            title=data.get('title', 'Новая задача'),
            start=start_date,
            end=end_date if end_date else None,
            difficulty=data.get('difficulty', 'medium'),
            points=points_val,
            color=data.get('color', '#562370'),
            done=data.get('done', False),
            all_day=data.get('allDay', False)
        )

        db.session.add(new_event)
        db.session.commit()

        logger.info(f"[SUCCESS] Создано событие ID {new_event.id}")
        return jsonify({
            'success': True,
            'id': str(new_event.id),
            'event': new_event.to_dict()
        })

    except Exception as e:
        logger.error(f"ОШИБКА при создании события: {str(e)}")
        import traceback
        traceback.print_exc()
        db.session.rollback()
        return jsonify({'error': str(e)}), 500


@app.route('/api/events/<event_id>', methods=['PUT'])
@login_required
def update_event(event_id):
    event = Event.query.filter_by(id=event_id, user_id=current_user.id).first()
    if not event:
        return jsonify({'error': 'Не найдено или нет доступа'}), 404

    data = request.json
    logger.info(f"[PUT] Обновление события {event_id}")

    if 'title' in data:
        event.title = data['title']
    if 'color' in data:
        event.color = data['color']
    if 'difficulty' in data:
        event.difficulty = data['difficulty']
    if 'points' in data:
        try:
            event.points = int(data['points'])
        except ValueError:
            pass
    if 'done' in data:
        event.done = bool(data['done'])

    if 'start' in data:
        start_val = data['start']
        if '+' in start_val: start_val = start_val.split('+')[0]
        event.start = start_val
    if 'end' in data:
        end_val = data['end']
        if end_val and '+' in end_val: end_val = end_val.split('+')[0]
        event.end = end_val

    db.session.commit()
    return jsonify({'success': True, 'event': event.to_dict()})


@app.route('/api/events/<event_id>', methods=['DELETE'])
@login_required
def delete_event(event_id):
    event = Event.query.filter_by(id=event_id, user_id=current_user.id).first()
    if event:
        db.session.delete(event)
        db.session.commit()
        logger.info(f"[DELETE] Удалено событие {event_id}")
        return jsonify({'success': True})
    return jsonify({'error': 'Не найдено или нет доступа'}), 404


@app.route('/api/stats', methods=['GET'])
@login_required
def get_stats():
    events = Event.query.filter_by(user_id=current_user.id).all()
    total_xp = 0
    completed_count = 0

    for event in events:
        if event.done:
            total_xp += event.points
            completed_count += 1

    level = 1
    threshold = 100
    current_sum = 0
    while total_xp >= current_sum + threshold:
        current_sum += threshold
        level += 1
        threshold = int(threshold * 1.2)

    xp_to_next = max(0, (current_sum + threshold) - total_xp)

    return jsonify({
        'total_xp': total_xp,
        'level': level,
        'completed_tasks': completed_count,
        'xp_to_next_level': xp_to_next,
        'user_name': current_user.name,
        'user_avatar': current_user.avatar
    })


@app.route('/api/xp-history')
@login_required
def get_xp_history():
    events = Event.query.filter_by(user_id=current_user.id, done=True).order_by(Event.end).all()
    data = {'daily': {}, 'weekly': {}, 'monthly': {}}
    now = datetime.now()
    days_ru = ['Пн', 'Вт', 'Ср', 'Чт', 'Пт', 'Сб', 'Вс']
    months_ru = ['янв', 'фев', 'мар', 'апр', 'мая', 'июн', 'июл', 'авг', 'сен', 'окт', 'ноя', 'дек']

    for event in events:
        if isinstance(event.end, str):
            try:
                event_date = datetime.fromisoformat(event.end.replace('Z', '+00:00')).replace(tzinfo=None)
            except:
                continue
        else:
            event_date = event.end

        points = event.points or 0
        if (now - event_date).total_seconds() < 86400:
            hour_key = event_date.strftime('%H:00')
            data['daily'][hour_key] = data['daily'].get(hour_key, 0) + points
        if (now - event_date).days < 7:
            day_name = days_ru[event_date.weekday()]
            data['weekly'][day_name] = data['weekly'].get(day_name, 0) + points
        if (now - event_date).days < 30:
            day_key = f"{event_date.day} {months_ru[event_date.month - 1]}"
            data['monthly'][day_key] = data['monthly'].get(day_key, 0) + points

    return jsonify(data)


if __name__ == '__main__':
    print("--- ЗАПУСК СЕРВЕРА HORIZON С АВТОРИЗАЦИЕЙ ---")
    if not os.path.exists(os.path.join(basedir, 'instance')):
        os.makedirs(os.path.join(basedir, 'instance'))

    if not app.config['GOOGLE_CLIENT_ID']:
        print("WARNING: GOOGLE_CLIENT_ID не найден. Вход через Google не будет работать.")

    app.run(host='0.0.0.0', debug=True, port=5000, use_reloader=False)