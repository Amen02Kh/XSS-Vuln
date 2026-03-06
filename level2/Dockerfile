FROM python:3.12-slim

LABEL challenge="safesearch-xss-filter-bypass"
LABEL difficulty="medium"
LABEL category="web/xss/filter-bypass"

RUN useradd -m appuser
WORKDIR /app
COPY app/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY app/ .
RUN chmod +x entrypoint.sh

ENV FLAG=FLAG{f1lt3r_byp4ss_xss_c0nf1rm3d}

USER appuser
EXPOSE 5000
ENTRYPOINT ["./entrypoint.sh"]
