FROM python:3.11-slim

WORKDIR /app
# Sem dependências externas: o pacote roda direto, sem pip/PyPI no build.
COPY blade_monitor ./blade_monitor
RUN useradd --system --uid 10001 blade && mkdir /data && chown blade /data

USER blade
ENV BLADE_DB=/data/platform.db \
    BLADE_HOST=0.0.0.0 \
    PORT=8080 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app
VOLUME /data
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s \
    CMD python -c "import os,urllib.request;urllib.request.urlopen(f'http://127.0.0.1:{os.environ[\"PORT\"]}/api/v1/program')"

ENTRYPOINT ["python", "-m", "blade_monitor.platform"]
CMD ["serve"]
