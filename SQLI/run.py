import os
import sqlite3
import app

# Ensure uploads directory exists
os.makedirs('static/uploads', exist_ok=True)

# Create dummy image file
# with open('static/uploads/dummy.png', 'wb') as f:
#     # Create a minimal valid PNG file (hex values for an empty 1x1 transparent PNG)
#     f.write(bytes.fromhex('89504e470d0a1a0a0000000d49484452000000010000000108060000001f15c4890000000d4944415478da6364f8ffbf0c000bf600055a369ea0000000049454e44ae426082'))

# Initialize the database
print("Initializing database...")
app.init_db()
print("Database initialized successfully.")

# Run the app
print("Starting the application. Access it at http://localhost:5000")
app.app.run(host='0.0.0.0', port=5000, debug=True) 