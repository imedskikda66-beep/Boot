FROM python:3.10-slim

WORKDIR /app

# نسخ المتطلبات وتثبيتها
COPY requirements.txt /app/
RUN pip install --no-cache-dir -r requirements.txt

# نسخ السكربت
COPY . /app

# تشغيل السكربت
CMD ["python", "main.py"]