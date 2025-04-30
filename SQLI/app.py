from flask import Flask, render_template, request, redirect, url_for, session, jsonify
import sqlite3
import os
import hashlib
import secrets
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.secret_key = secrets.token_hex(16)
app.config['UPLOAD_FOLDER'] = 'static/uploads'
app.config['DATABASE'] = 'shop.db'

# Ensure uploads directory exists
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# Initialize database
def init_db():
    conn = sqlite3.connect(app.config['DATABASE'])
    cursor = conn.cursor()
    
    # Create tables with intentional SQL injection vulnerabilities
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        is_admin BOOLEAN DEFAULT 0
    )
    ''')
    
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS products (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        description TEXT,
        price REAL NOT NULL,
        image TEXT,
        category TEXT
    )
    ''')
    
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS cart (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        product_id INTEGER,
        quantity INTEGER DEFAULT 1,
        FOREIGN KEY (user_id) REFERENCES users (id),
        FOREIGN KEY (product_id) REFERENCES products (id)
    )
    ''')
    
    # Insert admin user
    admin_pass = hashlib.sha256("admin123".encode()).hexdigest()
    cursor.execute("INSERT OR IGNORE INTO users (username, password, is_admin) VALUES ('admin', ?, 1)", (admin_pass,))
    
    # Insert sample products with dummy image names
    sample_products = [
        ('MacBook Pro', 'Latest model with M2 chip and 16GB RAM', 1999.99, 'dummy.png', 'Laptops'),
        ('iPhone 15 Pro', '6.1-inch Super Retina XDR display, A17 Pro chip', 999.99, 'dummy.png', 'Phones'),
        ('Samsung Galaxy S23', '6.8-inch Dynamic AMOLED 2X, Snapdragon 8 Gen 2', 1199.99, 'dummy.png', 'Phones'),
        ('Sony WH-1000XM5', 'Wireless Noise Cancelling Headphones', 349.99, 'dummy.png', 'Audio'),
        ('iPad Pro', '12.9-inch Liquid Retina XDR display, M2 chip', 1099.99, 'dummy.png', 'Tablets'),
        ('Dell XPS 15', '15.6-inch 4K UHD display, Intel Core i9, 32GB RAM', 2499.99, 'dummy.png', 'Laptops'),
        ('Canon EOS R5', 'Full-frame mirrorless camera, 45MP, 8K video', 3899.99, 'dummy.png', 'Cameras'),
        ('Nintendo Switch OLED', '7-inch OLED screen, enhanced audio', 349.99, 'dummy.png', 'Gaming'),
        ('LG C2 OLED TV', '65-inch 4K Smart OLED TV with AI ThinQ', 1799.99, 'dummy.png', 'TVs'),
        ('Bose QuietComfort Earbuds', 'Wireless noise cancelling earbuds', 279.99, 'dummy.png', 'Audio')
    ]
    
    cursor.executemany(
        "INSERT OR IGNORE INTO products (name, description, price, image, category) VALUES (?, ?, ?, ?, ?)",
        sample_products
    )
    
    conn.commit()
    conn.close()

# SQLi vulnerable function to execute queries
def query_db(query, args=(), one=False):
    conn = sqlite3.connect(app.config['DATABASE'])
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute(query, args)
    rv = cursor.fetchall()
    conn.close()
    return (rv[0] if rv else None) if one else rv

@app.route('/')
def index():
    # Vulnerable query - directly concatenates user input
    category = request.args.get('category', '')
    
    if category:
        # Vulnerable to SQLi
        products = query_db(f"SELECT * FROM products WHERE category = '{category}'")
    else:
        products = query_db("SELECT * FROM products")
    
    categories = query_db("SELECT DISTINCT category FROM products")
    categories = [dict(cat) for cat in categories]
    
    return render_template('index.html', products=products, categories=categories)

@app.route('/product/<int:product_id>')
def product_details(product_id):
    # Vulnerable to SQLi - directly uses string formatting
    product = query_db(f"SELECT * FROM products WHERE id = {product_id}", one=True)
    if product:
        return render_template('product.html', product=product)
    return redirect(url_for('index'))

@app.route('/search')
def search():
    query = request.args.get('q', '')
    # Vulnerable to SQLi - directly embeds the query
    products = query_db(f"SELECT * FROM products WHERE name LIKE '%{query}%' OR description LIKE '%{query}%'")
    return render_template('search_results.html', products=products, query=query)

@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        username = request.form['username']
        password = hashlib.sha256(request.form['password'].encode()).hexdigest()
        
        # Vulnerable to SQLi - directly concatenates user input
        user = query_db(f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'", one=True)
        
        if user:
            session['user_id'] = user['id']
            session['username'] = user['username']
            session['is_admin'] = user['is_admin']
            return redirect(url_for('index'))
        else:
            error = 'Invalid credentials'
    
    return render_template('login.html', error=error)

@app.route('/register', methods=['GET', 'POST'])
def register():
    error = None
    if request.method == 'POST':
        username = request.form['username']
        password = hashlib.sha256(request.form['password'].encode()).hexdigest()
        
        try:
            conn = sqlite3.connect(app.config['DATABASE'])
            cursor = conn.cursor()
            cursor.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, password))
            conn.commit()
            conn.close()
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            error = 'Username already exists'
    
    return render_template('register.html', error=error)

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    session.pop('username', None)
    session.pop('is_admin', None)
    return redirect(url_for('index'))

@app.route('/add_to_cart/<int:product_id>')
def add_to_cart(product_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    conn = sqlite3.connect(app.config['DATABASE'])
    cursor = conn.cursor()
    
    # Check if product already in cart
    cursor.execute(
        "SELECT id, quantity FROM cart WHERE user_id = ? AND product_id = ?", 
        (session['user_id'], product_id)
    )
    existing_item = cursor.fetchone()
    
    if existing_item:
        cursor.execute(
            "UPDATE cart SET quantity = quantity + 1 WHERE id = ?", 
            (existing_item[0],)
        )
    else:
        cursor.execute(
            "INSERT INTO cart (user_id, product_id) VALUES (?, ?)",
            (session['user_id'], product_id)
        )
    
    conn.commit()
    conn.close()
    
    return redirect(url_for('cart'))

@app.route('/cart')
def cart():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    # Vulnerable to SQLi
    cart_items = query_db(f"""
        SELECT p.id, p.name, p.price, p.image, c.quantity
        FROM cart c 
        JOIN products p ON c.product_id = p.id
        WHERE c.user_id = {session['user_id']}
    """)
    
    total = sum(item['price'] * item['quantity'] for item in cart_items)
    
    return render_template('cart.html', cart_items=cart_items, total=total)

@app.route('/remove_from_cart/<int:product_id>')
def remove_from_cart(product_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    conn = sqlite3.connect(app.config['DATABASE'])
    cursor = conn.cursor()
    cursor.execute(
        "DELETE FROM cart WHERE user_id = ? AND product_id = ?",
        (session['user_id'], product_id)
    )
    conn.commit()
    conn.close()
    
    return redirect(url_for('cart'))

@app.route('/admin')
def admin_panel():
    if not session.get('is_admin', False):
        return redirect(url_for('index'))
    
    users = query_db("SELECT * FROM users")
    products = query_db("SELECT * FROM products")
    
    return render_template('admin.html', users=users, products=products)

@app.route('/admin/user/<int:user_id>', methods=['GET'])
def admin_user_info(user_id):
    if not session.get('is_admin', False):
        return jsonify({'error': 'Unauthorized'}), 403
    
    # Vulnerable to SQLi
    user = query_db(f"SELECT * FROM users WHERE id = {user_id}", one=True)
    
    if user:
        return jsonify({
            'id': user['id'],
            'username': user['username'],
            'is_admin': user['is_admin']
        })
    return jsonify({'error': 'User not found'}), 404

@app.route('/admin/add_product', methods=['POST'])
def add_product():
    if not session.get('is_admin', False):
        return redirect(url_for('index'))
    
    name = request.form['name']
    description = request.form['description']
    price = float(request.form['price'])
    category = request.form['category']
    
    image_file = request.files['image']
    image_filename = secure_filename(image_file.filename)
    image_path = os.path.join(app.config['UPLOAD_FOLDER'], image_filename)
    image_file.save(image_path)
    
    conn = sqlite3.connect(app.config['DATABASE'])
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO products (name, description, price, image, category) VALUES (?, ?, ?, ?, ?)",
        (name, description, price, image_filename, category)
    )
    conn.commit()
    conn.close()
    
    return redirect(url_for('admin_panel'))

@app.route('/checkout')
def checkout():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    # Clear cart after checkout
    conn = sqlite3.connect(app.config['DATABASE'])
    cursor = conn.cursor()
    cursor.execute("DELETE FROM cart WHERE user_id = ?", (session['user_id'],))
    conn.commit()
    conn.close()
    
    return render_template('checkout.html')

@app.context_processor
def inject_user():
    return {
        'username': session.get('username', None),
        'is_admin': session.get('is_admin', False)
    }

if __name__ == '__main__':
    init_db()
    app.run(host='0.0.0.0', port=5000, debug=True) 