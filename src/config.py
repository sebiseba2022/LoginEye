import os
import sys
import logging
from logging.handlers import RotatingFileHandler

# Base directories
if getattr(sys, 'frozen', False):
    # Running as compiled PyInstaller executable
    BASE_DIR = os.path.dirname(sys.executable)
else:
    # Running as Python script
    BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

CAPTURES_DIR = os.path.join(BASE_DIR, "captures")
LOGS_DIR = os.path.join(BASE_DIR, "logs")
LAST_CAPTURE_FILE = os.path.join(CAPTURES_DIR, ".last_capture.json")

os.makedirs(CAPTURES_DIR, exist_ok=True)
os.makedirs(LOGS_DIR, exist_ok=True)

# Camera settings
CAMERA_INDEX = 0
WARMUP_FRAMES = 4        # Discard early frames for sensor auto-exposure settling
CAPTURE_TIMEOUT_SEC = 5.0
JPEG_QUALITY = 95
COOLDOWN_SECONDS = 3.0   # Prevent duplicate captures within this interval

# Visual badge & styling settings (BGR format for OpenCV)
PASS_COLOR = (60, 225, 60)       # Vibrant Emerald Green
FAIL_COLOR = (45, 45, 235)       # Vibrant Red
BANNER_BG_COLOR = (20, 20, 25)   # Deep Charcoal Dark Backdrop
TEXT_LIGHT = (240, 240, 240)
TEXT_MUTED = (180, 180, 180)

# Logger setup
logger = logging.getLogger("LoginEye")
logger.setLevel(logging.DEBUG)

if not logger.handlers:
    log_file = os.path.join(LOGS_DIR, "logineye.log")
    file_handler = RotatingFileHandler(
        log_file,
        maxBytes=3 * 1024 * 1024,  # 3 MB
        backupCount=3,
        encoding="utf-8"
    )
    formatter = logging.Formatter(
        "[%(asctime)s] [%(levelname)s] [%(threadName)s] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S"
    )
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)

    # Optional console output for interactive debugging
    if sys.stdout and sys.stdout.isatty():
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setFormatter(formatter)
        logger.addHandler(console_handler)
