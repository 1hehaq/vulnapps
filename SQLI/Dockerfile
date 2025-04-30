FROM python:3.9-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Create necessary directories
RUN mkdir -p static/uploads

# Create dummy image files instead of downloading real ones
RUN touch static/uploads/dummy.png && \
    touch static/uploads/dummy.png && \
    touch static/uploads/dummy.png && \
    touch static/uploads/dummy.png && \
    touch static/uploads/dummy.png && \
    touch static/uploads/dummy.png && \
    touch static/uploads/dummy.png && \
    touch static/uploads/dummy.png && \
    touch static/uploads/dummy.png && \
    touch static/uploads/dummy.png

# Initialize the database
RUN python -c "import app; app.init_db()"

EXPOSE 5000

# Use gunicorn for production
CMD ["gunicorn", "--bind", "0.0.0.0:5000", "app:app"] 