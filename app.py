from flask import Flask, render_template_string, request, jsonify, session, redirect, url_for
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = 'super_secret_key_for_crm' # В реальном проекте смените на случайную строку

def get_db():
    conn = sqlite3.connect('crm.db')
    conn.row_factory = sqlite3.Row
    return conn

# Инициализация базы данных с пользователями
def init_db():
    with get_db() as conn:
        conn.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                role TEXT NOT NULL DEFAULT 'employee' -- 'admin' или 'employee'
            )
        ''')
        conn.execute('''
            CREATE TABLE IF NOT EXISTS clients (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                phone TEXT,
                email TEXT,
                status TEXT DEFAULT 'Новый',
                user_id INTEGER, -- Какой сотрудник добавил / ведет клиента
                comment TEXT,
                FOREIGN KEY (user_id) REFERENCES users (id)
            )
        ''')
        # Создаем администратора по умолчанию (логин: admin, пароль: admin123)
        try:
            hashed_pw = generate_password_hash('admin123')
            conn.execute("INSERT INTO users (username, password, role) VALUES (?, ?, ?)", ('admin', hashed_pw, 'admin'))
        except sqlite3.IntegrityError:
            pass
        conn.commit()

# --- Авторизация ---
@app.route('/login', methods=['POST'])
def login():
    data = request.json
    username = data.get('username')
    password = data.get('password')
    
    with get_db() as conn:
        user = conn.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
        
    if user and check_password_hash(user['password'], password):
        session['user_id'] = user['id']
        session['username'] = user['username']
        session['role'] = user['role']
        return jsonify({'status': 'success', 'role': user['role']})
    return jsonify({'status': 'error', 'message': 'Неверный логин или пароль'}), 401

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))

# --- Создание сотрудника (только для Админа) ---
@app.route('/api/users', methods=['POST'])
def create_user():
    if session.get('role') != 'admin':
        return jsonify({'status': 'error', 'message': 'Нет прав'}), 403
    data = request.json
    hashed_pw = generate_password_hash(data['password'])
    try:
        with get_db() as conn:
            conn.execute('INSERT INTO users (username, password, role) VALUES (?, ?, ?)', (data['username'], hashed_pw, 'employee'))
            conn.commit()
        return jsonify({'status': 'success'})
    except sqlite3.IntegrityError:
        return jsonify({'status': 'error', 'message': 'Пользователь уже существует'}), 400

# --- Работа с клиентами (с фильтрацией) ---
@app.route('/api/clients', methods=['GET'])
def get_clients():
    if 'user_id' not in session:
        return jsonify({'status': 'error', 'message': 'Не авторизован'}), 401
    
    with get_db() as conn:
        # Админ видит всех, сотрудник — только своих клиентов
        if session['role'] == 'admin':
            clients = conn.execute('''
                SELECT clients.*, users.username as manager 
                FROM clients 
                LEFT JOIN users ON clients.user_id = users.id
            ''').fetchall()
        else:
            clients = conn.execute('SELECT *, username as manager FROM clients JOIN users ON clients.user_id = users.id WHERE user_id = ?', (session['user_id'],)).fetchall()
            
    return jsonify([dict(c) for c in clients])

@app.route('/api/clients', methods=['POST'])
def add_client():
    if 'user_id' not in session:
        return jsonify({'status': 'error', 'message': 'Не авторизован'}), 401
    data = request.json
    with get_db() as conn:
        conn.execute('''
            INSERT INTO clients (name, phone, email, status, user_id, comment)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (data['name'], data.get('phone'), data.get('email'), data.get('status', 'Новый'), session['user_id'], data.get('comment')))
        conn.commit()
    return jsonify({'status': 'success'}), 201

@app.route('/')
def index():
    with open('index.html', 'r', encoding='utf-8') as f:
        return render_template_string(f.read())

if __name__ == '__main__':
    init_db()
    # Этот параметр host='0.0.0.0' обязателен, чтобы Render смог открыть сайт всему интернету
    app.run(host='0.0.0.0', port=10000) 

