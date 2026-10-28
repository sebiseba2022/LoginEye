import time
import threading
import signal
import sys
from src.config import logger, CAPTURES_DIR
from src.camera import capture_frame, start_lock_standby, stop_lock_standby
from src.stamper import save_stamped_image
from src.event_watcher import (
    CooldownManager,
    SessionWatcherThread,
    SecurityLogWatcherThread
)

class LoginEyeService:
    """
    Main background service orchestrating event monitoring and camera snapshots.
    Runs silently in the background with zero GUI footprint.
    """
    def __init__(self, boot_mode=False):
        self.boot_mode = boot_mode
        self.cooldown = CooldownManager()
        self.session_watcher = None
        self.security_watcher = None
        self._stop_event = threading.Event()

    def handle_event(self, status, reason=None, username=None):
        """
        Callback invoked when a login event (PASS or FAIL) is detected.
        """
        clean_status = status.upper()
        if not self.cooldown.can_trigger(clean_status):
            return None

        logger.info(f">>> Triggering camera snapshot for [{clean_status}] - {reason} (User: {username})")
        
        # Capture from webcam (release lock-screen standby if this is a PASS unlock event)
        success, frame = capture_frame(release_standby=(clean_status == "PASS"))
        if not success or frame is None:
            logger.error(f"Snapshot failed for [{clean_status}]: webcam was unavailable.")
            return None

        # Stamp and save
        saved_path = save_stamped_image(frame, clean_status, username=username, reason=reason)
        if saved_path:
            logger.info(f"Successfully recorded [{clean_status}] snapshot -> {saved_path}")

        # If running as pre-login boot guard, exit after initial user logon PASS so user session daemon takes over
        if self.boot_mode and clean_status == "PASS":
            logger.info("Boot-time login captured! Handing over monitoring to user session daemon.")
            stop_lock_standby()
            self._stop_event.set()

        return saved_path

    def trigger_once(self, status, reason=None, username=None):
        """
        Executes a direct, immediate capture (used by Task Scheduler triggers or CLI).
        """
        clean_status = status.upper()
        logger.info(f"Direct capture requested for [{clean_status}] (Reason: {reason}, User: {username})")
        
        success, frame = capture_frame()
        if not success or frame is None:
            logger.error("Direct capture failed: camera could not be opened.")
            return None

        saved_path = save_stamped_image(frame, clean_status, username=username, reason=reason)
        return saved_path

    def run_test(self):
        """
        Runs a self-test by taking both a PASS and a FAIL snapshot to verify
        the camera and watermark stamping.
        """
        print("[LoginEye] Running camera self-test...")
        
        # Test 1: PASS
        print("Capturing sample [PASS] photo...")
        pass_file = self.trigger_once("PASS", reason="Self-Test Verification")
        if pass_file:
            print(f"[OK] Sample PASS saved: {pass_file}")
        else:
            print("[ERROR] Failed to capture PASS sample!")

        time.sleep(1.0)

        # Test 2: FAIL
        print("Capturing sample [FAIL] photo...")
        fail_file = self.trigger_once("FAIL", reason="Self-Test Verification (Simulated Failure)")
        if fail_file:
            print(f"[OK] Sample FAIL saved: {fail_file}")
        else:
            print("[ERROR] Failed to capture FAIL sample!")

        return pass_file, fail_file

    def start_daemon(self):
        """
        Starts the continuous background monitoring threads.
        """
        import ctypes
        mutex_name = "Global\\LoginEyeBootGuardMutex" if self.boot_mode else "Local\\LoginEyeDaemonMutex"
        self._mutex = ctypes.windll.kernel32.CreateMutexW(None, True, mutex_name)
        if ctypes.windll.kernel32.GetLastError() == 183:  # ERROR_ALREADY_EXISTS
            logger.info(f"LoginEye ({mutex_name}) is already running. Exiting duplicate instance.")
            return

        logger.info("==================================================")
        logger.info(f"LoginEye Background Service starting up (boot_mode={self.boot_mode})...")
        logger.info(f"Captures output directory: {CAPTURES_DIR}")
        logger.info("==================================================")

        # If starting at boot (before user login), immediately pre-warm camera on the boot login screen!
        if self.boot_mode:
            logger.info("Pre-login boot mode active: warming up camera on initial boot screen...")
            start_lock_standby()

        # Start Session notification watcher (WTS Unlock / Logon)
        self.session_watcher = SessionWatcherThread(self.handle_event)
        self.session_watcher.start()

        # Start Security log watcher (Event 4625 Failed Logon)
        self.security_watcher = SecurityLogWatcherThread(self.handle_event)
        self.security_watcher.start()

        def signal_handler(sig, frame):
            logger.info("Termination signal received. Stopping LoginEye...")
            self.stop()
            sys.exit(0)

        signal.signal(signal.SIGINT, signal_handler)
        signal.signal(signal.SIGTERM, signal_handler)

        logger.info("LoginEye background monitoring is active and guarding the workstation.")

        # Keep main thread alive
        try:
            while not self._stop_event.is_set():
                time.sleep(1.0)
        except (KeyboardInterrupt, SystemExit):
            self.stop()

    def stop(self):
        self._stop_event.set()
        if self.session_watcher:
            self.session_watcher.stop()
        if self.security_watcher:
            self.security_watcher.stop()
        logger.info("LoginEye background service stopped.")
