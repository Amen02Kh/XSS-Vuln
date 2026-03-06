#!/bin/sh
set -e
echo "[*] Initializing NoteBoard database..."
python -c "from app import init_db; init_db()"
echo "[*] Starting NoteBoard with Playwright admin bot..."
exec python app.py
