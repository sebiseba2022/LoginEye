import os
import socket
import datetime
import cv2
import numpy as np
from src.config import (
    logger,
    CAPTURES_DIR,
    PASS_COLOR,
    FAIL_COLOR,
    BANNER_BG_COLOR,
    TEXT_LIGHT,
    TEXT_MUTED,
    JPEG_QUALITY
)

def stamp_image(frame, status, username=None, reason=None):
    """
    Overlays a professional, high-visibility security banner onto the captured frame.
    Stamps [ PASS ] in vibrant green or [ FAIL ] in vibrant red, along with
    timestamp, target username, hostname, and event details.
    
    Args:
        frame (np.ndarray): The captured BGR image.
        status (str): "PASS" or "FAIL".
        username (str, optional): Target account name.
        reason (str, optional): Description of the trigger event.
        
    Returns:
        np.ndarray: The stamped BGR image.
    """
    if frame is None or frame.size == 0:
        return frame

    out = frame.copy()
    h, w = out.shape[:2]
    
    is_pass = (status.upper() == "PASS")
    badge_color = PASS_COLOR if is_pass else FAIL_COLOR
    badge_text = f"[ {status.upper()} ]"
    
    # Defaults
    if not username:
        try:
            username = os.getlogin()
        except Exception:
            username = os.environ.get("USERNAME", "UnknownUser")
            
    if not reason:
        reason = "Authentication Succeeded" if is_pass else "Incorrect Password Attempt"
        
    hostname = socket.gethostname()
    now_str = datetime.datetime.now().strftime("%Y-%m-%d  %H:%M:%S")

    # 1. Top Header Banner
    header_h = max(60, int(h * 0.12))
    overlay = out.copy()
    cv2.rectangle(overlay, (0, 0), (w, header_h), BANNER_BG_COLOR, -1)
    
    # 2. Bottom Footer Bar
    footer_h = max(32, int(h * 0.07))
    cv2.rectangle(overlay, (0, h - footer_h), (w, h), BANNER_BG_COLOR, -1)
    
    # Blend overlay with 80% opacity for clear backdrop
    cv2.addWeighted(overlay, 0.82, out, 0.18, 0, out)

    # 3. Draw Accent Lines
    cv2.line(out, (0, header_h), (w, header_h), badge_color, 2)
    cv2.line(out, (0, h - footer_h), (w, h - footer_h), badge_color, 1)

    # 4. Render Badge [ PASS ] / [ FAIL ]
    # Scale font size based on image width
    badge_scale = max(0.9, w / 700.0 * 1.1)
    cv2.putText(
        out,
        badge_text,
        (20, int(header_h * 0.68)),
        cv2.FONT_HERSHEY_DUPLEX,
        badge_scale,
        badge_color,
        2,
        cv2.LINE_AA
    )

    # 5. Render Timestamp
    time_scale = max(0.6, w / 700.0 * 0.75)
    # Estimate width to right-align
    (time_w, _), _ = cv2.getTextSize(now_str, cv2.FONT_HERSHEY_SIMPLEX, time_scale, 2)
    time_x = max(20 + int(w * 0.4), w - time_w - 20)
    cv2.putText(
        out,
        now_str,
        (time_x, int(header_h * 0.65)),
        cv2.FONT_HERSHEY_SIMPLEX,
        time_scale,
        TEXT_LIGHT,
        2,
        cv2.LINE_AA
    )

    # 6. Render Footer Information
    footer_text = f"Device: {hostname}   |   Account: {username}   |   {reason}"
    footer_scale = max(0.42, w / 700.0 * 0.48)
    cv2.putText(
        out,
        footer_text,
        (15, h - int(footer_h * 0.32)),
        cv2.FONT_HERSHEY_SIMPLEX,
        footer_scale,
        TEXT_MUTED,
        1,
        cv2.LINE_AA
    )

    return out

def save_stamped_image(frame, status, username=None, reason=None):
    """
    Stamps the frame and saves it to the captures directory with a clean timestamped filename.
    
    Returns:
        str: Absolute path of the saved JPEG image, or None if failed.
    """
    stamped = stamp_image(frame, status, username, reason)
    if stamped is None:
        logger.error("Failed to stamp frame!")
        return None

    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    clean_status = status.upper()
    filename = f"{clean_status}_{timestamp}.jpg"
    out_path = os.path.join(CAPTURES_DIR, filename)

    # Handle collision if multiple events fire in same second
    counter = 1
    while os.path.exists(out_path):
        filename = f"{clean_status}_{timestamp}_{counter}.jpg"
        out_path = os.path.join(CAPTURES_DIR, filename)
        counter += 1

    try:
        encode_params = [int(cv2.IMWRITE_JPEG_QUALITY), JPEG_QUALITY]
        cv2.imwrite(out_path, stamped, encode_params)
        logger.info(f"Saved {clean_status} image: {out_path}")
        return out_path
    except Exception as e:
        logger.exception(f"Failed to write image to {out_path}: {e}")
        return None
