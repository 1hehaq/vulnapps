from flask import Flask, request, render_template_string, render_template, redirect, url_for, flash, session
from functools import wraps
import sqlite3
import os

app = Flask(__name__)
app.secret_key = os.urandom(24)

def init_db():
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS users
                (id INTEGER PRIMARY KEY AUTOINCREMENT,
                 username TEXT UNIQUE NOT NULL,
                 password TEXT NOT NULL,
                 profile TEXT)''')
    c.execute('''CREATE TABLE IF NOT EXISTS posts
                (id INTEGER PRIMARY KEY AUTOINCREMENT,
                 title TEXT NOT NULL,
                 content TEXT NOT NULL,
                 author TEXT NOT NULL,
                 template TEXT)''')
    conn.commit()
    conn.close()

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in session:
            flash('Please login first', 'danger')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        conn = sqlite3.connect('users.db')
        c = conn.cursor()
        user = c.execute('SELECT * FROM users WHERE username = ? AND password = ?',
                        (username, password)).fetchone()
        conn.close()
        
        if user:
            session['username'] = username
            flash('Login successful!', 'success')
            return redirect(url_for('dashboard'))
        flash('Invalid credentials', 'danger')
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        # Vulnerable: profile template injection
        profile_template = '''
        <div class="card">
            <div class="card-body">
                <h5 class="card-title">Welcome, %s!</h5>
                <p class="card-text">This is your profile page.</p>
            </div>
        </div>
        ''' % username
        
        conn = sqlite3.connect('users.db')
        c = conn.cursor()
        try:
            c.execute('INSERT INTO users (username, password, profile) VALUES (?, ?, ?)',
                     (username, password, profile_template))
            conn.commit()
            flash('Registration successful!', 'success')
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            flash('Username already exists', 'danger')
        finally:
            conn.close()
    return render_template('register.html')

@app.route('/dashboard')
@login_required
def dashboard():
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    posts = c.execute('SELECT * FROM posts WHERE author = ?', 
                     (session['username'],)).fetchall()
    conn.close()
    return render_template('dashboard.html', posts=posts)

@app.route('/profile')
@login_required
def profile():
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    user = c.execute('SELECT * FROM users WHERE username = ?',
                    (session['username'],)).fetchone()
    conn.close()
    
    # Vulnerable: Direct template string rendering
    return render_template_string(user[3])

@app.route('/create_post', methods=['GET', 'POST'])
@login_required
def create_post():
    if request.method == 'POST':
        title = request.form['title']
        content = request.form['content']
        # Vulnerable: Custom template injection
        template = request.form.get('template', '''
        <div class="post">
            <h3>{{ title }}</h3>
            <p>{{ content }}</p>
            <small>By: {{ author }}</small>
        </div>
        ''')
        
        conn = sqlite3.connect('users.db')
        c = conn.cursor()
        c.execute('INSERT INTO posts (title, content, author, template) VALUES (?, ?, ?, ?)',
                 (title, content, session['username'], template))
        conn.commit()
        conn.close()
        
        flash('Post created successfully!', 'success')
        return redirect(url_for('dashboard'))
    return render_template('create_post.html')

@app.route('/view_post/<int:post_id>')
def view_post(post_id):
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    post = c.execute('SELECT * FROM posts WHERE id = ?', (post_id,)).fetchone()
    conn.close()
    
    if post:
        # Vulnerable: Template injection from database
        return render_template_string(
            post[4],
            title=post[1],
            content=post[2],
            author=post[3]
        )
    return 'Post not found', 404

@app.route('/search')
def search():
    query = request.args.get('q', '')
    # Vulnerable: Template injection in search results
    template = '''
        <h3>Search Results for: {{ query }}</h3>
        <div class="search-results">
            {% if query %}
                <p>You searched for: {{ query }}</p>
            {% else %}
                <p>Please enter a search term</p>
            {% endif %}
        </div>
    '''
    return render_template_string(template, query=query)

@app.route('/preview_template', methods=['POST'])
@login_required
def preview_template():
    # Vulnerable: Direct template preview
    template = request.form.get('template', '')
    return render_template_string(template)

if __name__ == '__main__':
    init_db()
    app.run(debug=True)