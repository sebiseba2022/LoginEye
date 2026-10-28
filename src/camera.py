import time
import cv2
import numpy as np
from src.config import (
    logger,
    CAMERA_INDEX,
    WARMUP_FRAMES,
    CAPTURE_TIMEOUT_SEC
)

def capture_frame(camera_index=CAMERA_INDEX, warmup_frames=WARMUP_FRAMES):
    """
    Safely opens the webcam, discards warmup frames to allow auto-exposure
    and auto-white-balance to settle, captures a sharp frame, and immediately
    releases the camera device so that the indicator LED turns off.
    
    Returns:
        tuple (bool success, np.ndarray or None frame)
    """
    logger.info(f"Opening camera index {camera_index} (DirectShow mode)...")
    start_time = time.time()
    
    cap = None
    try:
        # On Windows, DirectShow is fastest and cleanest for USB/integrated webcams
        cap = cv2.VideoCapture(camera_index, cv2.CAP_DSHOW)
        if not cap.isOpened():
            logger.warning("DirectShow failed, falling back to default capture API...")
            cap = cv2.VideoCapture(camera_index)
            
        if not cap.isOpened():
            logger.error(f"Cannot open webcam with index {camera_index}!")
            return False, None

        # Discard initial dark/overexposed frames during hardware sensor startup
        for i in range(warmup_frames):
            cap.read()
            if time.time() - start_time > CAPTURE_TIMEOUT_SEC:
                logger.warning("Camera warmup timed out!")
                break

        # Capture target frame
        ret, frame = cap.read()
        elapsed = time.time() - start_time
        
        if ret and frame is not None and frame.size > 0:
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
    try:
        cap = cv2.VideoCapture(camera_index, cv2.CAP_DSHOW)
        if not cap.isOpened():
            cap = cv2.VideoCapture(camera_index)
        opened = cap.isOpened()
        cap.release()
        return opened
    except Exception:
        return False
