FROM python:3.12-slim

LABEL challenge="noteboard-stored-xss"
LABEL difficulty="medium"
LABEL category="web/xss/stored"

RUN apt-get update && apt-get install -y \
    libnss3 libatk1.0-0 libatk-bridge2.0-0 \
    libcups2 libdrm2 libxkbcommon0 libxcomposite1 \
    libxdamage1 libxfixes3 libxrandr2 libgbm1 \
    libasound2 libpango-1.0-0 libpangocairo-1.0-0 \
    libgtk-3-0 libx11-xcb1 fonts-liberation \
    --no-install-recommends && rm -rf /var/lib/apt/lists/*

    WORKDIR /app

    COPY app/requirements.txt .
    RUN pip install --no-cache-dir -r requirements.txt
    
    # 1. Define a global location for Playwright browsers
    ENV PLAYWRIGHT_BROWSERS_PATH=/usr/local/share/ms-playwright
    
    # 2. Install the browser to that specific path
    RUN mkdir -p $PLAYWRIGHT_BROWSERS_PATH && \
        playwright install chromium && \
        # Ensure all users can read/execute the browser binaries
        chmod -R 755 $PLAYWRIGHT_BROWSERS_PATH
    
    COPY app/ .
    
    # 3. Create user and fix app directory permissions
    RUN useradd -m appuser && \
        chown -R appuser:appuser /app && \
        chmod +x entrypoint.sh
    
    ENV FLAG=FLAG{5t0r3d_xss_c00k13_th3ft_4dm1n_b0t}
    ENV ADMIN_SESSION=4dm1n_5up3r_53cr3t_5e551on_t0k3n
    
    USER appuser
    EXPOSE 5000
    ENTRYPOINT ["./entrypoint.sh"]
