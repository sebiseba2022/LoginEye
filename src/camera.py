import time
import threading
import cv2
import numpy as np
from src.config import (
    logger,
    CAMERA_INDEX,
    WARMUP_FRAMES,
    CAPTURE_TIMEOUT_SEC
)

_camera_lock = threading.Lock()
_standby_lock = threading.Lock()
_standby_thread = None
_standby_stop = threading.Event()
_standby_ready = threading.Event()
_standby_frame = None
_standby_frame_time = 0.0
_standby_active = False


def _standby_worker(camera_index=CAMERA_INDEX):
    """
    Keeps the camera open and auto-exposed ONLY while the workstation is on the Lock Screen,
    so that any FAIL (wrong PIN/fingerprint/password) or PASS (unlock) photo is captured
    in < 10 milliseconds with zero startup delay, and immediately released upon unlock.
    """
    global _standby_frame, _standby_frame_time, _standby_active

    logger.info("Lock-screen camera standby activating (pre-warming sensor)...")
    cap = None
    try:
        with _camera_lock:
            cap = cv2.VideoCapture(camera_index, cv2.CAP_DSHOW)
            if not cap.isOpened():
                cap = cv2.VideoCapture(camera_index)

            if not cap.isOpened():
                logger.error(f"Standby could not open camera index {camera_index}")
                return

            # Discard initial black frame(s) until sensor outputs valid brightness
            for _ in range(3):
                if _standby_stop.is_set():
                    break
                ret, frm = cap.read()
                if ret and frm is not None and frm.size > 0 and frm.mean() > 10.0:
                    with _standby_lock:
                        _standby_frame = frm.copy()
                        _standby_frame_time = time.time()
                    _standby_ready.set()
                    break

        logger.info("Lock-screen camera standby is warm and ready for instant capture.")

        # Continuously keep a fresh frame ready while locked (max 15 minutes safety limit)
        start_standby = time.time()
        while not _standby_stop.is_set() and (time.time() - start_standby) < 900:
            with _camera_lock:
                if _standby_stop.is_set():
                    break
                ret, frm = cap.read()
                if ret and frm is not None and frm.size > 0:
                    with _standby_lock:
                        _standby_frame = frm.copy()
                        _standby_frame_time = time.time()
                    _standby_ready.set()
            time.sleep(0.04)

    except Exception as e:
        logger.debug(f"Standby worker exception: {e}")
    finally:
        with _camera_lock:
            if cap is not None:
                try:
                    cap.release()
                except Exception:
                    pass
        with _standby_lock:
            _standby_active = False
        _standby_ready.set()
        logger.info("Lock-screen camera standby released (camera OFF).")


def start_lock_standby(camera_index=CAMERA_INDEX):
    """Pre-warms the camera when the workstation is locked."""
    global _standby_thread, _standby_active
    with _standby_lock:
        if _standby_active and _standby_thread and _standby_thread.is_alive():
            return
        _standby_stop.clear()
        _standby_ready.clear()
        _standby_active = True
        _standby_thread = threading.Thread(
            target=_standby_worker,
            args=(camera_index,),
            name="CameraStandbyThread",
            daemon=True
        )
        _standby_thread.start()


def stop_lock_standby():
    """Stops the lock-screen standby and turns off the camera immediately."""
    global _standby_active
    _standby_stop.set()
    with _standby_lock:
        _standby_active = False


def capture_frame(camera_index=CAMERA_INDEX, warmup_frames=WARMUP_FRAMES, release_standby=False):
    """
    Captures a frame from the webcam.
    - If lock-screen standby is active, grabs the already-warmed frame in ~0.001s (instant!).
    - If release_standby=True (e.g. on PASS / unlock), immediately turns off standby after grabbing the frame.
    - Otherwise falls back to direct camera open.
    """
    start_time = time.time()

    # 1. Fast path: use pre-warmed lock-screen standby frame if active or recently captured
    with _standby_lock:
        is_active = _standby_active
        cached_frame = _standby_frame.copy() if _standby_frame is not None else None
        cached_age = start_time - _standby_frame_time

    if is_active:
        # Wait up to 2.5s if standby is still in its initial 1s sensor warmup
        _standby_ready.wait(timeout=2.5)
        with _standby_lock:
            if _standby_frame is not None and (time.time() - _standby_frame_time) < 3.0:
                frame = _standby_frame.copy()
            else:
                frame = None

        if release_standby:
            stop_lock_standby()

        if frame is not None:
            elapsed = time.time() - start_time
            h, w = frame.shape[:2]
            logger.info(f"Instant capture ({w}x{h}) from warm standby in {elapsed:.3f}s")
            return True, frame

    elif cached_frame is not None and cached_age < 1.5:
        if release_standby:
            stop_lock_standby()
        h, w = cached_frame.shape[:2]
        logger.info(f"Instant capture ({w}x{h}) from recent buffer in 0.001s")
        return True, cached_frame

    if release_standby:
        stop_lock_standby()

    # 2. Direct cold-start capture fallback
    with _camera_lock:
        logger.info(f"Opening camera index {camera_index} (DirectShow mode)...")
        cap = None
        try:
            cap = cv2.VideoCapture(camera_index, cv2.CAP_DSHOW)
            if not cap.isOpened():
                logger.warning("DirectShow failed, falling back to default capture API...")
                cap = cv2.VideoCapture(camera_index)

            if not cap.isOpened():
                logger.error(f"Cannot open webcam with index {camera_index}!")
                return False, None

            frame = None
            max_reads = max(2, warmup_frames)
            for i in range(max_reads):
                ret, frm = cap.read()
                if ret and frm is not None and frm.size > 0:
                    frame = frm
                    # Stop warming up as soon as sensor exposure is non-black (after at least 1 discard)
                    if i >= 1 and frm.mean() > 15.0:
                        break
                if time.time() - start_time > 2.5:
                    break

            elapsed = time.time() - start_time
            if frame is not None and frame.size > 0:
                h, w = frame.shape[:2]
                logger.info(f"Successfully captured frame ({w}x{h}) in {elapsed:.2f}s")
                return True, frame
            else:
                logger.error("Failed to read frame from webcam device!")
                return False, None

        except Exception as e:
            logger.exception(f"Unexpected error during camera capture: {e}")
            return False, None
        finally:
            if cap is not None:
                cap.release()
                logger.debug("Camera device released.")


def is_camera_available(camera_index=CAMERA_INDEX):
    """Checks if the camera device can be opened."""
    with _standby_lock:
        if _standby_active and _standby_frame is not None:
            return True
    with _camera_lock:
        try:
            cap = cv2.VideoCapture(camera_index, cv2.CAP_DSHOW)
            if not cap.isOpened():
                cap = cv2.VideoCapture(camera_index)
            opened = cap.isOpened()
            cap.release()
            return opened
        except Exception:
            return False
