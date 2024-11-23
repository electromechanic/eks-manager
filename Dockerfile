FROM python:3.9-slim

# Set environment variables for Python
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

# Set working directory
WORKDIR /eks-manager

# Copy project files
COPY . /eks-manager

# Install the package
RUN pip install --no-cache-dir .
