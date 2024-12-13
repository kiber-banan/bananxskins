import os
from datetime import datetime
from PIL import Image
import io
from yookassa import Configuration, Payment
import uuid
from yookassa.domain.notification import WebhookNotification
from pyqiwip2p import QiwiP2P  # pip install pyqiwip2p
from crypto_pay_api_sdk import CryptoPayAPI  # pip install crypto-pay-api
import hashlib

# Определим базовую директорию проекта
basedir = os.path.abspath(os.path.dirname(__file__))

# Конфигурация ЮKassa
Configuration.account_id = 'YOUR_SHOP_ID'  # ID магазина
Configuration.secret_key = 'YOUR_SECRET_KEY'  # Секретный ключ

# Конфигурация QIWI
QIWI_SECRET_KEY = 'ваш_секретный_ключ'
p2p = QiwiP2P(auth_key=QIWI_SECRET_KEY)

# Конфигурация CryptoBot
CRYPTO_BOT_TOKEN = 'ваш_токен'
crypto = CryptoPayAPI(CRYPTO_BOT_TOKEN)

# Конфигурация FreeKassa
MERCHANT_ID = "ваш_merchant_id"  # ID магазина
SECRET_KEY_1 = "секретное_слово_1"  # Первое секретное слово
SECRET_KEY_2 = "секретное_слово_2"  # Второе секретное слово

def generate_freekassa_signature(merchant_id, amount, secret, order_id):
    """Генерация подписи для FreeKassa"""
    sign_str = f"{merchant_id}:{amount}:{secret}:{order_id}"
    return hashlib.md5(sign_str.encode('utf-8')).hexdigest()

from flask import Flask, render_template, request, redirect, url_for, flash, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import random

app = Flask(__name__)
app.config['SECRET_KEY'] = 'ваш-секретный-ключ'
app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{os.path.join(basedir, "shop.db")}'
app.config['UPLOAD_FOLDER'] = 'static/uploads'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# В начале файла, после определения app
upload_folder = os.path.join(basedir, 'static', 'uploads')
if not os.path.exists(upload_folder):
    os.makedirs(upload_folder)
app.config['UPLOAD_FOLDER'] = upload_folder

# Модел
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    login = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(120), nullable=False)
    balance = db.Column(db.Float, default=0.0)
    is_admin = db.Column(db.Boolean, default=False)
    avatar = db.Column(db.String(200), default='default_avatar.png')
    inventory = db.relationship('Inventory', backref='user', lazy=True)
    withdrawals = db.relationship('Withdrawal', backref='user', lazy=True)
    notifications = db.relationship('Notification', backref='user', lazy=True)

class Item(db.Model):
    __tablename__ = 'item'
    id = db.Column(db.String(3), primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    image = db.Column(db.String(200), nullable=False)
    price = db.Column(db.Float, nullable=False)
    case_items = db.relationship('CaseItem', backref='item', lazy=True)

class Case(db.Model):
    __tablename__ = 'cases'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    image = db.Column(db.String(200), nullable=False)
    price = db.Column(db.Float, nullable=False)
    items = db.relationship('CaseItem', backref='case', lazy=True)

class CaseItem(db.Model):
    __tablename__ = 'case_item'
    id = db.Column(db.Integer, primary_key=True)
    case_id = db.Column(db.Integer, db.ForeignKey('cases.id'), nullable=False)
    item_id = db.Column(db.String(3), db.ForeignKey('item.id'), nullable=False)
    chance = db.Column(db.Float, nullable=False)

class Inventory(db.Model):
    __tablename__ = 'inventory'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    item_id = db.Column(db.String(3), db.ForeignKey('item.id'), nullable=False)
    item = db.relationship('Item')

class Withdrawal(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    item_id = db.Column(db.String(3), db.ForeignKey('item.id'), nullable=False)
    status = db.Column(db.String(20), default='pending')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    screenshot = db.Column(db.String(200), nullable=False)
    item = db.relationship('Item')

class Notification(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    message = db.Column(db.String(200), nullable=False)
    type = db.Column(db.String(20), nullable=False)  # withdrawal_completed, withdrawal_rejected
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    is_read = db.Column(db.Boolean, default=False)

class Payment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    amount = db.Column(db.Float, nullable=False)
    payment_id = db.Column(db.String(36), nullable=False)
    status = db.Column(db.String(20), default='pending')  # pending, completed, failed
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

# Функции для работы с файлами
def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def save_file(file):
    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        try:
            file.save(file_path)
            return filename
        except Exception as e:
            print(f"Ошибка при сохранении файла: {e}")
            return None
    return None

# Админские маршруты
@app.route('/admin')
@login_required
def admin_index():
    if not current_user.is_admin:
        return redirect(url_for('index'))
    return render_template('admin/index.html')

@app.route('/admin/items', methods=['GET', 'POST'])
@login_required
def admin_items():
    if not current_user.is_admin:
        return redirect(url_for('index'))
        
    if request.method == 'POST':
        try:
            name = request.form.get('name')
            price = float(request.form.get('price', 0))
            image = request.files.get('image')
            
            if not name or not price or not image:
                flash('Все поля должны быть заполнены')
                return redirect(url_for('admin_items'))
            
            # Проверяем, существует ли папка uploads
            if not os.path.exists(app.config['UPLOAD_FOLDER']):
                os.makedirs(app.config['UPLOAD_FOLDER'])
            
            # Генерация уникального ID
            while True:
                item_id = ''.join(random.choices('0123456789', k=3))
                if not Item.query.get(item_id):
                    break
            
            # Сохраняем файл
            if image and allowed_file(image.filename):
                filename = secure_filename(image.filename)
                image_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                image.save(image_path)
                
                # Создаем предмет
                item = Item(
                    id=item_id,
                    name=name,
                    image=filename,
                    price=price
                )
                db.session.add(item)
                db.session.commit()
                
                flash('Предмет успешно создан!')
                return redirect(url_for('admin_items'))
            else:
                flash('Неверный формат файла')
                
        except Exception as e:
            flash(f'Ошибка при создании предмета: {str(e)}')
            db.session.rollback()
            
    items = Item.query.all()
    return render_template('admin/items.html', items=items)

@app.route('/admin/cases', methods=['GET', 'POST'])
@login_required
def admin_cases():
    if not current_user.is_admin:
        return redirect(url_for('index'))
        
    if request.method == 'POST':
        try:
            name = request.form.get('name')
            price = float(request.form.get('price', 0))
            image = request.files.get('image')
            
            if not name or not price or not image:
                flash('Все поля должны быть заполнены')
                return redirect(url_for('admin_cases'))
            
            # Сохраняем файл
            filename = save_file(image)
            if not filename:
                flash('Ошибка при сохранении изображения')
                return redirect(url_for('admin_cases'))
            
            # ��оздаем кейс
            case = Case(name=name, image=filename, price=price)
            db.session.add(case)
            db.session.flush()  # Получаем ID кейса
            
            # Добавление предметов в кейс
            total_chance = 0
            selected_items = False
            
            for key, value in request.form.items():
                if key.startswith('item_') and value:
                    item_id = value
                    chance_key = f'chance_{item_id}'
                    
                    if chance_key in request.form:
                        try:
                            chance = float(request.form[chance_key])
                            if chance > 0:
                                case_item = CaseItem(case_id=case.id, item_id=item_id, chance=chance)
                                db.session.add(case_item)
                                total_chance += chance
                                selected_items = True
                        except ValueError:
                            continue
            
            if not selected_items:
                flash('Добавьте хотя бы один предмет в кейс')
                db.session.rollback()
                return redirect(url_for('admin_cases'))
            
            if abs(total_chance - 100) > 0.01:  # Учитываем возможную погрешность float
                flash(f'Сумма шансов должна быть равна 100% (текущая сумма: {total_chance}%)')
                db.session.rollback()
                return redirect(url_for('admin_cases'))
            
            db.session.commit()
            flash('Кейс успешно создан!')
            return redirect(url_for('admin_cases'))
            
        except Exception as e:
            db.session.rollback()
            flash(f'Ошибка при создании кейса: {str(e)}')
            return redirect(url_for('admin_cases'))
            
    items = Item.query.all()
    cases = Case.query.all()
    return render_template('admin/cases.html', items=items, cases=cases)

@app.route('/admin/cases/delete/<int:case_id>', methods=['POST'])
@login_required
def admin_delete_case(case_id):
    if not current_user.is_admin:
        return redirect(url_for('index'))
        
    case = Case.query.get_or_404(case_id)
    
    # Удаляем связанные записи
    CaseItem.query.filter_by(case_id=case.id).delete()
    
    # Удаляем изображение
    try:
        os.remove(os.path.join(app.config['UPLOAD_FOLDER'], case.image))
    except:
        pass
    
    # Удаляем кейс
    db.session.delete(case)
    db.session.commit()
    
    flash('Кейс успешно удален')
    return redirect(url_for('admin_cases'))

@app.route('/admin/users')
@login_required
def admin_users():
    if not current_user.is_admin:
        return redirect(url_for('index'))
    users = User.query.all()
    return render_template('admin/users.html', users=users)

@app.route('/admin/users/update_balance', methods=['POST'])
@login_required
def admin_update_balance():
    if not current_user.is_admin:
        return jsonify({'success': False, 'message': 'Недостаточно прав'})
    
    try:
        user_id = int(request.form.get('userId'))
        new_balance = float(request.form.get('newBalance'))
        
        user = User.query.get_or_404(user_id)
        user.balance = new_balance
        db.session.commit()
        
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)})

@app.route('/admin/items/delete/<item_id>', methods=['POST'])
@login_required
def admin_delete_item(item_id):
    if not current_user.is_admin:
        return redirect(url_for('index'))
        
    item = Item.query.get_or_404(item_id)
    
    # Удаляем связанные запи��и
    CaseItem.query.filter_by(item_id=item.id).delete()
    Inventory.query.filter_by(item_id=item.id).delete()
    
    # Удаляем изображение
    try:
        os.remove(os.path.join(app.config['UPLOAD_FOLDER'], item.image))
    except:
        pass
    
    # Удаляем предмет
    db.session.delete(item)
    db.session.commit()
    
    flash('Предмет успешно удален')
    return redirect(url_for('admin_items'))

# Пользовательские маршруты
@app.route('/')
def index():
    cases = Case.query.all()
    return render_template('index.html', cases=cases)

@app.route('/case/<int:case_id>')
def view_case(case_id):
    case = Case.query.get_or_404(case_id)
    return render_template('case.html', case=case)

@app.route('/open_case/<int:case_id>', methods=['POST'])
@login_required
def open_case(case_id):
    case = Case.query.get_or_404(case_id)
    
    if current_user.balance < case.price:
        return jsonify({'success': False, 'message': 'Недостаточно средств'})
        
    # Вычисление выпавшего предмета на основе шансов
    items = case.items
    total_chance = sum(item.chance for item in items)
    random_num = random.uniform(0, total_chance)
    current_sum = 0
    
    for case_item in items:
        current_sum += case_item.chance
        if random_num <= current_sum:
            won_item = Item.query.get(case_item.item_id)
            break
            
    # Спиание средств и добавление предмета в инвентарь
    current_user.balance -= case.price
    inventory_item = Inventory(user_id=current_user.id, item_id=won_item.id)
    db.session.add(inventory_item)
    db.session.commit()
    
    return jsonify({
        'success': True,
        'item': {
            'id': won_item.id,
            'name': won_item.name,
            'image': url_for('static', filename='uploads/' + won_item.image),
            'price': won_item.price
        },
        'inventory_id': inventory_item.id  # Добавляем ID записи в инвентаре
    })

@app.route('/profile')
@login_required
def profile():
    inventory = Inventory.query.filter_by(user_id=current_user.id).all()
    notifications = Notification.query.filter_by(user_id=current_user.id).order_by(Notification.created_at.desc()).all()
    unread_notifications = [n for n in notifications if not n.is_read]
    return render_template('profile.html', 
                         inventory=inventory, 
                         notifications=notifications,
                         unread_notifications=unread_notifications)

@app.route('/about')
def about():
    return render_template('about.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        login = request.form['login']
        password = request.form['password']
        user = User.query.filter_by(login=login).first()
        
        if user and check_password_hash(user.password_hash, password):
            login_user(user)
            return redirect(url_for('index'))
        flash('Неверный логин или пароль')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        login = request.form['login']
        password = request.form['password']
        
        if User.query.filter_by(login=login).first():
            flash('Этот логин уже занят')
            return redirect(url_for('register'))
            
        user = User(
            username=username,
            login=login,
            password_hash=generate_password_hash(password)
        )
        db.session.add(user)
        db.session.commit()
        
        return redirect(url_for('login'))
    return render_template('register.html')

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/sell_item', methods=['POST'])
@login_required
def sell_item():
    try:
        data = request.get_json()
        inventory_id = data.get('inventory_id')
        
        # Получаем предмет из инвентаря
        inventory_item = Inventory.query.get_or_404(inventory_id)
        
        # Проверяем, принадлежи ли предмет текущему пользователю
        if inventory_item.user_id != current_user.id:
            return jsonify({'success': False, 'message': 'Предмет вам не принадлежит'})
        
        # Добавляем стоимость предмета к балансу пользователя
        current_user.balance += inventory_item.item.price
        
        # Удаляем предмет из инвентаря
        db.session.delete(inventory_item)
        db.session.commit()
        
        return jsonify({
            'success': True,
            'new_balance': current_user.balance
        })
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)})

@app.route('/sell_won_item', methods=['POST'])
@login_required
def sell_won_item():
    try:
        data = request.get_json()
        inventory_id = data.get('inventory_id')
        
        # Находим предмет в инвентаре по его ID
        inventory_item = Inventory.query.get(inventory_id)
        
        if not inventory_item or inventory_item.user_id != current_user.id:
            return jsonify({'success': False, 'message': 'Предмет не найден'})
        
        # Добавляем стоимость предмета к балансу пользователя
        current_user.balance += inventory_item.item.price
        
        # Удаляем предмет из инвентаря
        db.session.delete(inventory_item)
        db.session.commit()
        
        return jsonify({
            'success': True,
            'new_balance': current_user.balance
        })
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)})

@app.route('/sell_all_items', methods=['POST'])
@login_required
def sell_all_items():
    try:
        # Получаем все предметы пользователя
        inventory_items = Inventory.query.filter_by(user_id=current_user.id).all()
        
        if not inventory_items:
            return jsonify({'success': False, 'message': 'Инвентарь пуст'})
        
        # Считаем общую стоимость и удаляем предметы
        total_price = 0
        for inv_item in inventory_items:
            total_price += inv_item.item.price
            db.session.delete(inv_item)
        
        # Добавляем деньги пользователю
        current_user.balance += total_price
        db.session.commit()
        
        return jsonify({
            'success': True,
            'new_balance': current_user.balance,
            'total_sold': len(inventory_items)
        })
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': str(e)})

@app.route('/sell_all_won_items', methods=['POST'])
@login_required
def sell_all_won_items():
    try:
        # Получаем последние выигранные предметы
        inventory_items = Inventory.query.filter_by(user_id=current_user.id)\
            .order_by(Inventory.id.desc())\
            .limit(10)\
            .all()
        
        if not inventory_items:
            return jsonify({'success': False, 'message': 'Нет предметов для продажи'})
        
        total_price = 0
        for inv_item in inventory_items:
            total_price += inv_item.item.price
            db.session.delete(inv_item)
        
        current_user.balance += total_price
        db.session.commit()
        
        return jsonify({
            'success': True,
            'new_balance': current_user.balance,
            'total_sold': len(inventory_items)
        })
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': str(e)})

@app.route('/contracts')
@login_required
def contracts():
    inventory = current_user.inventory
    return render_template('contracts.html', inventory=inventory)

@app.route('/execute_contract', methods=['POST'])
@login_required
def execute_contract():
    try:
        data = request.get_json()
        item_ids = data.get('item_ids', [])
        
        if len(item_ids) < 5 or len(item_ids) > 10:
            return jsonify({'success': False, 'message': 'Выберите от 5 до 10 предметов'})
            
        # Получаем предметы из инвентаря
        inventory_items = Inventory.query.filter(
            Inventory.id.in_(item_ids),
            Inventory.user_id == current_user.id
        ).all()
        
        if len(inventory_items) != len(item_ids):
            return jsonify({'success': False, 'message': 'Некоторые предметы не найдены'})
            
        # Считаем общую стоимость
        total_value = sum(item.item.price for item in inventory_items)
        min_price = total_value * 0.2  # 20% от суммы
        max_price = total_value * 1.2  # 120% от суммы
        
        # Находим подходящие предметы для выпадения
        possible_items = Item.query.filter(
            Item.price >= min_price,
            Item.price <= max_price
        ).all()
        
        if not possible_items:
            return jsonify({'success': False, 'message': 'Нет подходящих предметов для контракта'})
            
        # Выбираем случайный предмет
        won_item = random.choice(possible_items)
        
        # Удаляем использованные предметы
        for inv_item in inventory_items:
            db.session.delete(inv_item)
            
        # Добавляем новый предмет в инвентарь
        new_inventory_item = Inventory(user_id=current_user.id, item_id=won_item.id)
        db.session.add(new_inventory_item)
        db.session.commit()
        
        return jsonify({
            'success': True,
            'used_items': [{
                'id': item.id,
                'name': item.item.name,
                'image': url_for('static', filename='uploads/' + item.item.image),
                'price': item.item.price
            } for item in inventory_items],
            'won_item': {
                'id': won_item.id,
                'name': won_item.name,
                'image': url_for('static', filename='uploads/' + won_item.image),
                'price': won_item.price
            }
        })
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': str(e)})

@app.route('/withdraw_item', methods=['POST'])
@login_required
def withdraw_item():
    try:
        inventory_id = request.form.get('inventory_id')
        screenshot = request.files.get('screenshot')
        
        if not screenshot:
            return jsonify({'success': False, 'message': 'Не загружен скриншот'})
            
        inventory_item = Inventory.query.get_or_404(inventory_id)
        
        if inventory_item.user_id != current_user.id:
            return jsonify({'success': False, 'message': 'Предмет вам не принадлежит'})
            
        if inventory_item.item.price < 100:
            return jsonify({'success': False, 'message': 'Минимальная сумма вывода 100₽'})
            
        if screenshot and allowed_file(screenshot.filename):
            filename = secure_filename(screenshot.filename)
            screenshot.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            
            withdrawal = Withdrawal(
                user_id=current_user.id,
                item_id=inventory_item.item_id,
                screenshot=filename
            )
            
            db.session.add(withdrawal)
            db.session.delete(inventory_item)
            db.session.commit()
            
            return jsonify({'success': True})
        else:
            return jsonify({'success': False, 'message': 'Недопустимый формат файла'})
            
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': str(e)})

@app.route('/admin/withdrawals')
@login_required
def admin_withdrawals():
    if not current_user.is_admin:
        return redirect(url_for('index'))
        
    withdrawals = Withdrawal.query.filter_by(status='pending').all()
    return render_template('admin/withdrawals.html', withdrawals=withdrawals)

@app.route('/admin/process_withdrawal', methods=['POST'])
@login_required
def process_withdrawal():
    if not current_user.is_admin:
        return jsonify({'success': False})
        
    withdrawal_id = request.form.get('withdrawal_id')
    action = request.form.get('action')
    
    withdrawal = Withdrawal.query.get_or_404(withdrawal_id)
    
    if action == 'complete':
        withdrawal.status = 'completed'
        notification = Notification(
            user_id=withdrawal.user_id,
            message=f'Ваш вывод предмета {withdrawal.item.name} успешно обработан',
            type='withdrawal_completed'
        )
    else:
        withdrawal.status = 'rejected'
        notification = Notification(
            user_id=withdrawal.user_id,
            message=f'Ваш вывод предмета {withdrawal.item.name} отклонен',
            type='withdrawal_rejected'
        )
        
        # Возвращаем предмет в инвентарь
        inventory_item = Inventory(
            user_id=withdrawal.user_id,
            item_id=withdrawal.item_id
        )
        db.session.add(inventory_item)
    
    db.session.add(notification)
    db.session.commit()
    
    return jsonify({'success': True})

def compress_image(file, size=(100, 100)):
    image = Image.open(file)
    
    # Конвертируем в RGB если изображение в RGBA
    if image.mode in ('RGBA', 'P'):
        image = image.convert('RGB')
    
    # Сохраняем пропорции
    image.thumbnail(size, Image.Resampling.LANCZOS)
    
    # Сохраняем в буфер
    buffer = io.BytesIO()
    image.save(buffer, format='JPEG', quality=85, optimize=True)
    buffer.seek(0)
    
    return buffer

@app.route('/update_avatar', methods=['POST'])
@login_required
def update_avatar():
    if 'avatar' not in request.files:
        return jsonify({'success': False, 'message': 'Нет файла'})
        
    file = request.files['avatar']
    if file.filename == '':
        return jsonify({'success': False, 'message': 'Файл не выбран'})
        
    if file and allowed_file(file.filename):
        # Сжимаем изображение
        compressed = compress_image(file)
        filename = secure_filename(file.filename)
        
        # Удаляем старый аватар
        if current_user.avatar != 'default_avatar.png':
            try:
                os.remove(os.path.join(app.config['UPLOAD_FOLDER'], current_user.avatar))
            except:
                pass
        
        # Сохраняем сжатое изображение
        with open(os.path.join(app.config['UPLOAD_FOLDER'], filename), 'wb') as f:
            f.write(compressed.getvalue())
        
        current_user.avatar = filename
        db.session.commit()
        
        return jsonify({'success': True, 'avatar': filename})
    
    return jsonify({'success': False, 'message': 'Недопустимый формат файла'})

@app.route('/admin/withdrawals/history')
@login_required
def admin_withdrawals_history():
    if not current_user.is_admin:
        return redirect(url_for('index'))
        
    completed_withdrawals = Withdrawal.query.filter(
        Withdrawal.status.in_(['completed', 'rejected'])
    ).order_by(Withdrawal.created_at.desc()).all()
    
    return render_template('admin/withdrawals_history.html', withdrawals=completed_withdrawals)

@app.route('/mark_notifications_read', methods=['POST'])
@login_required
def mark_notifications_read():
    try:
        Notification.query.filter_by(user_id=current_user.id, is_read=False).update({'is_read': True})
        db.session.commit()
        return jsonify({'success': True})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': str(e)})

@app.route('/create_payment', methods=['POST'])
@login_required
def create_payment():
    try:
        data = request.get_json()
        amount = float(data.get('amount', 0))
        
        if amount < 100:
            return jsonify({'error': 'Минимальная сумма 100₽'})
            
        payment_id = str(uuid.uuid4())
        
        # Сохраняем информацию о платеже в базе
        db_payment = Payment(
            user_id=current_user.id,
            amount=amount,
            payment_id=payment_id,
            status='pending'
        )
        db.session.add(db_payment)
        db.session.commit()
        
        # Генерируем подпись для FreeKassa
        sign = generate_freekassa_signature(
            MERCHANT_ID, 
            amount, 
            SECRET_KEY_1,
            payment_id
        )
        
        # Формируем URL для оплаты
        payment_url = f"https://pay.freekassa.ru/?m={MERCHANT_ID}&oa={amount}&o={payment_id}&s={sign}"
        
        return jsonify({'payment_url': payment_url})
        
    except Exception as e:
        return jsonify({'error': str(e)})

@app.route('/payment/freekassa/callback', methods=['POST'])
def freekassa_callback():
    try:
        # Получаем данные от FreeKassa
        merchant_id = request.form.get('MERCHANT_ID')
        amount = request.form.get('AMOUNT')
        order_id = request.form.get('MERCHANT_ORDER_ID')
        received_sign = request.form.get('SIGN')
        
        # Проверяем подпись
        expected_sign = generate_freekassa_signature(
            merchant_id,
            amount,
            SECRET_KEY_2,  # Используем второе секретное слово для проверки
            order_id
        )
        
        if received_sign.lower() != expected_sign.lower():
            return 'Invalid signature', 400
            
        # Находим платеж в базе
        payment = Payment.query.filter_by(payment_id=order_id).first()
        if payment and payment.status == 'pending':
            # Проверяем сумму
            if float(amount) == payment.amount:
                # Обновляем статус платежа
                payment.status = 'completed'
                
                # Начисляем баланс пользователю
                user = User.query.get(payment.user_id)
                user.balance += payment.amount
                
                db.session.commit()
                
                # Добавляем уведомление
                notification = Notification(
                    user_id=user.id,
                    message=f'Баланс пополнен на {payment.amount}₽',
                    type='payment_completed'
                )
                db.session.add(notification)
                db.session.commit()
                
                return 'YES', 200
            else:
                payment.status = 'failed'
                db.session.commit()
                return 'Wrong amount', 400
                
        return 'Payment not found', 400
        
    except Exception as e:
        return str(e), 400

@app.route('/payment/success')
def payment_success():
    flash('Оплата успешно выполнена!', 'success')
    return redirect(url_for('profile'))

@app.route('/payment/fail')
def payment_fail():
    flash('Произошла ошибка при оплате', 'error')
    return redirect(url_for('profile'))

if __name__ == '__main__':
    app.run(debug=True)