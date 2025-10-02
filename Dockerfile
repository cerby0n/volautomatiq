FROM python:3.13-slim

# Install system dependencies
RUN apt-get update && apt-get install -y \
    git \
    build-essential \
    python3-dev \
    libpython3-dev \
    pcregrep \
    libpcre++-dev \
    python3-pycryptodome \
    && rm -rf /var/lib/apt/lists/*

# Install Volatility 2.6.1
RUN git clone https://github.com/volatilityfoundation/volatility.git /opt/volatility && \
    cd /opt/volatility && \
    git checkout 2.6.1 && \
    python3 setup.py install

# Create symlink for vol.py
RUN ln -s /opt/volatility/vol.py /usr/local/bin/vol.py

# Set working directory
WORKDIR /app

# Copy application files
COPY pyproject.toml /app/
COPY volautomatiq/ /app/volautomatiq/
COPY README.md /app/

# Install Python dependencies including MCP
RUN pip install --no-cache-dir \
    mcp \
    jinja2>=3.1.2 \
    flask>=3.0.0 \
    flask-cors>=4.0.0

# Install volautomatiq
RUN pip install -e .

# Create directories for dumps and reports
RUN mkdir -p /data/dumps /data/reports

# Expose API port
EXPOSE 5555

# Set environment variables
ENV PYTHONUNBUFFERED=1

# Default command runs MCP server
CMD ["python", "-m", "volautomatiq.mcp_server"]
