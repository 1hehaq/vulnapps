# TechGadgets - SQLi Vulnerable E-commerce Site

This is a deliberately vulnerable Flask-based e-commerce website created for educational purposes to demonstrate SQL injection (SQLi) vulnerabilities. 

⚠️ **WARNING**: This application contains intentional security vulnerabilities. DO NOT deploy this in a production environment or expose it on a public network without proper isolation.

## Features

- Modern responsive UI with Bootstrap 5
- Product browsing with categories
- Product search (SQLi vulnerable)
- User registration and login (SQLi vulnerable)
- Shopping cart functionality
- Admin panel with user and product management
- Multiple SQLi vulnerabilities for testing and educational purposes

## Vulnerabilities

This application contains several intentional SQL injection vulnerabilities:

1. **Search functionality**: The search query parameter is directly embedded in the SQL query
2. **Product filtering**: Category filtering is vulnerable to SQLi
3. **Login form**: Username and password fields are vulnerable to authentication bypass
4. **User info endpoint**: The user_id parameter is directly embedded in the SQL query

## Installation

1. Clone the repository:
```
git clone https://github.com/yourusername/techgadgets-sqli.git
cd techgadgets-sqli
```

2. Create a virtual environment and activate it:
```
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. Install dependencies:
```
pip install -r requirements.txt
```

4. Run the application:
```
python app.py
```

5. Access the application at `http://localhost:5000`

## Default Credentials

- Admin User:
  - Username: `admin`
  - Password: `admin123`

## Exploitation Examples

### Login Bypass
```
Username: admin' --
Password: anything
```

### Search Exploitation
```
' UNION SELECT id, username, password, 1, 1 FROM users --
```

### Product ID Exploitation
```
1 OR 1=1 --
```

## Disclaimer

This application is designed for educational purposes only. It should be used solely in controlled environments for learning about web security vulnerabilities and practicing ethical hacking techniques. The creator assumes no liability for misuse of this software.

## License

This project is licensed under the MIT License - see the LICENSE file for details. 