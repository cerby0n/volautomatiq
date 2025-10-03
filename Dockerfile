FROM python:3.11-slim-bullseye

# Install system dependencies including Python 2.7 for Volatility 2
RUN apt-get update && apt-get install -y \
    git \
    build-essential \
    python2.7 \
    python2.7-dev \
    curl \
    pcre2-utils \
    libpcre2-dev \
    && rm -rf /var/lib/apt/lists/*

# Install pip for Python 2.7
RUN curl https://bootstrap.pypa.io/pip/2.7/get-pip.py -o get-pip.py && \
    python2.7 get-pip.py && \
    rm get-pip.py

# Install Volatility 2.6.1 dependencies for Python 2.7
RUN python2.7 -m pip install pycrypto distorm3

# Install Volatility 2.6.1
RUN git clone https://github.com/volatilityfoundation/volatility.git /opt/volatility && \
    cd /opt/volatility && \
    git checkout 2.6.1 && \
    python2.7 setup.py install

# Create wrapper script for vol.py
RUN echo '#!/bin/bash\npython2.7 /opt/volatility/vol.py "$@"' > /usr/local/bin/vol.py && \
    chmod +x /usr/local/bin/vol.py

# Set working directory
WORKDIR /app

# Copy application files
COPY pyproject.toml /app/
COPY volautomatiq/ /app/volautomatiq/
COPY README.md /app/

# Install Python dependencies including MCP (use pip3 for Python 3)
RUN pip3 install --no-cache-dir \
    mcp \
    jinja2>=3.1.2 \
    flask>=3.0.0 \
    flask-cors>=4.0.0

# Install volautomatiq
RUN pip3 install -e .

# Create directories for dumps and extract with proper permissions
RUN mkdir -p /data/dumps /data/extract && \
    chmod 777 /data/extract

# Expose API port
EXPOSE 5555

# Set environment variables for performance
ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1
ENV MALLOC_MMAP_THRESHOLD_=131072
ENV MALLOC_TRIM_THRESHOLD_=131072
ENV MALLOC_TOP_PAD_=131072
ENV MALLOC_MMAP_MAX_=65536

# Default command runs MCP server (use python3 explicitly)
CMD ["python3", "-m", "volautomatiq.mcp_server"]
