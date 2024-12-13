import os
import sys
import subprocess
from app import app, db, User, Item, Case, CaseItem, Inventory, Withdrawal, Notification
from werkzeug.security import generate_password_hash
from datetime import datetime

def setup_upload_folder():
    upload_path = os.path.join('static', 'uploads')
    
    # Создаем папку, если её нет
    if not os.path.exists(upload_path):
        try:
            os.makedirs(upload_path)
            print("Папка uploads создана успешно")
        except Exception as e:
            print(f"Ошибка при создании папки: {e}")
            return False
    
    # Проверяем права доступа
    test_file = os.path.join(upload_path, 'test.txt')
    try:
        with open(test_file, 'w') as f:
            f.write('test')
        os.remove(test_file)
        print("Права доступа установлены корректно")
        return True
    except Exception as e:
        print(f"Недостаточно прав доступа: {e}")
        print("Попытка установить права доступа...")
        
        try:
            if sys.platform == 'win32':
                subprocess.run(['icacls', upload_path, '/grant', 'Users:(OI)(CI)F'], check=True)
            else:
                os.chmod(upload_path, 0o777)
            print("Права доступа успешно установлены")
            return True
        except Exception as e:
            print(f"Ошибка при установке прав доступа: {e}")
            return False

if __name__ == '__main__':
    # Получаем абсолютный путь к директории проекта
    basedir = os.path.abspath(os.path.dirname(__file__))
    db_path = os.path.join(basedir, 'shop.db')
    
    print(f"Текущая директория: {basedir}")
    print(f"Путь к базе данных: {db_path}")
    
    with app.app_context():
        # Удаляем существующую базу данных
        if os.path.exists(db_path):
            os.remove(db_path)
            print("Старая база данных удалена")
        
        # Создаем все таблицы
        db.create_all()
        print("База данных создана")
        
        # Проверяем, что файл существует
        if os.path.exists(db_path):
            print(f"Файл базы данных создан успешно")
        else:
            print("ОШИБКА: Файл базы данных не создан!")
            sys.exit(1)
        
        # Создаем админа
        admin = User(
            username='admin',
            login='admin',
            password_hash=generate_password_hash('admin'),
            is_admin=True,
            avatar='default_avatar.png'
        )
        db.session.add(admin)
        
        try:
            db.session.commit()
            print("\nАдмин создан успешно")
        except Exception as e:
            print(f"\nОшибка при создании админа: {e}")
            db.session.rollback()
        
        # Настраиваем папку uploads
        if setup_upload_folder():
            print("\nПапка uploads готова к использованию")
        else:
            print("\nОшибка настройки папки uploads")
            input("Нажмите Enter после установки прав доступа вручную...")