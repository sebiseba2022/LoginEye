import os
import sys
import argparse

# Ensure src module is discoverable
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from src.config import (
    logger,
    CAPTURES_DIR,
    LOGS_DIR
)
from src.camera import is_camera_available
from src.service import LoginEyeService

def show_status():
    print("==================================================")
    print("           LoginEye - Status Check                ")
    print("==================================================")
    
    # 1. Camera
    cam_ok = is_camera_available()
    cam_status = "[OK] Connected & Functional" if cam_ok else "[FAIL] Not Accessible"
    print(f"Webcam Status          : {cam_status}")

    # 2. Captures Folder
    os.makedirs(CAPTURES_DIR, exist_ok=True)
    files = [f for f in os.listdir(CAPTURES_DIR) if f.lower().endswith(('.jpg', '.jpeg', '.png'))]
    pass_count = sum(1 for f in files if f.upper().startswith("PASS"))
    fail_count = sum(1 for f in files if f.upper().startswith("FAIL"))
    print(f"Captures Directory     : {CAPTURES_DIR}")
    print(f"Total Snapshots Stored : {len(files)} (PASS: {pass_count}, FAIL: {fail_count})")

    # 3. Security Event Log Access
    try:
        import ctypes
        wevtapi = ctypes.windll.wevtapi
        h = wevtapi.EvtQuery(None, "Security", "*[System[(EventID=4625)]]", 0x1)
        if h:
            wevtapi.EvtClose(h)
            sec_status = "[OK] Full Access (Admin privileges active)"
        else:
            sec_status = "[WARNING] Restricted (Run install.bat as Admin to enable)"
    except Exception:
        sec_status = "[WARNING] Restricted (Run install.bat as Admin to enable)"
    print(f"Security Log Access    : {sec_status}")

    # 4. Logs
    log_file = os.path.join(LOGS_DIR, "logineye.log")
    log_exists = os.path.exists(log_file)
    print(f"Activity Log File      : {log_file} ({'Active' if log_exists else 'Not yet created'})")
    print("==================================================")

def main():
    parser = argparse.ArgumentParser(
        description="LoginEye: Automatic webcam intruder detection on Windows login/lock screen."
    )
    parser.add_argument(
        "--daemon",
        action="store_true",
        help="Run continuously in the background monitoring session changes and security events."
    )
    parser.add_argument(
        "--trigger",
        choices=["PASS", "FAIL"],
        help="Immediately capture and stamp a single photo for PASS or FAIL event."
    )
    parser.add_argument(
        "--user",
        type=str,
        default=None,
        help="Specify the target account name for the capture banner."
    )
    parser.add_argument(
        "--reason",
        type=str,
        default=None,
        help="Specify custom event description text for the watermark footer."
    )
    parser.add_argument(
        "--test",
        action="store_true",
        help="Run a self-test capturing sample PASS and FAIL images to test camera and watermarking."
    )
    parser.add_argument(
        "--status",
        action="store_true",
        help="Display system status, webcam health, and capture stats."
    )

    args = parser.parse_args()
    service = LoginEyeService()

    if args.status:
        show_status()
    elif args.test:
        service.run_test()
    elif args.trigger:
        service.trigger_once(args.trigger, reason=args.reason, username=args.user)
    else:
        # Default behavior: run as background daemon
        service.start_daemon()

if __name__ == "__main__":
    main()
