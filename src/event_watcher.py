import os
import sys
import time
import json
import threading
import xml.etree.ElementTree as ET
import ctypes
from ctypes import wintypes

from src.config import (
    logger,
    COOLDOWN_SECONDS,
    LAST_CAPTURE_FILE
)

# Win32 Constants
WM_WTSSESSION_CHANGE = 0x02B1
WTS_SESSION_LOGON = 0x5
WTS_SESSION_LOGOFF = 0x6
WTS_SESSION_LOCK = 0x7
WTS_SESSION_UNLOCK = 0x8
NOTIFY_FOR_THIS_SESSION = 0
NOTIFY_FOR_ALL_SESSIONS = 1

class CooldownManager:
    """Thread-safe cooldown manager to prevent redundant camera triggers."""
    def __init__(self, cooldown_seconds=COOLDOWN_SECONDS):
        self.cooldown = cooldown_seconds
        self.lock = threading.Lock()
        self.last_time = 0.0
        self.last_status = None

    def can_trigger(self, status):
        with self.lock:
            now = time.time()
            # If triggered very recently, skip
            if (now - self.last_time) < self.cooldown:
                logger.debug(f"Event '{status}' suppressed by cooldown ({now - self.last_time:.1f}s < {self.cooldown}s)")
                return False
            self.last_time = now
            self.last_status = status
            self._save_state(status, now)
            return True

    def _save_state(self, status, timestamp):
        try:
            data = {"status": status, "timestamp": timestamp}
            with open(LAST_CAPTURE_FILE, "w", encoding="utf-8") as f:
                json.dump(data, f)
        except Exception:
            pass

class SessionWatcherThread(threading.Thread):
    """
    Listens for Windows Terminal Services (WTS) session changes:
    - WTS_SESSION_UNLOCK (0x8): Triggered immediately when correct password unlocks the PC.
    - WTS_SESSION_LOGON (0x5): Triggered when a user logs on.
    """
    def __init__(self, on_trigger_callback):
        super().__init__(name="SessionWatcherThread", daemon=True)
        self.on_trigger_callback = on_trigger_callback
        self.hwnd = None
        self._stop_event = threading.Event()

    def run(self):
        try:
            import win32gui
            import win32con
            import win32ts

            wc = win32gui.WNDCLASS()
            wc.lpfnWndProc = self._wnd_proc
            wc.lpszClassName = "LoginEyeSessionWatcherClass"
            wc.hInstance = win32gui.GetModuleHandle(None)
            
            try:
                class_atom = win32gui.RegisterClass(wc)
            except Exception:
                # Class may already be registered
                pass

            self.hwnd = win32gui.CreateWindow(
                wc.lpszClassName,
                "LoginEyeSessionWatcher",
                0, 0, 0, 0, 0, 0, 0,
                wc.hInstance,
                None
            )

            # Register for session notifications
            win32ts.WTSRegisterSessionNotification(self.hwnd, win32ts.NOTIFY_FOR_THIS_SESSION)
            logger.info(f"Registered Windows Session Notifications on HWND: {self.hwnd}")

            # Message pump loop
            while not self._stop_event.is_set():
                win32gui.PumpWaitingMessages()
                time.sleep(0.05)

        except Exception as e:
            logger.exception(f"SessionWatcherThread failed: {e}")

    def _wnd_proc(self, hwnd, msg, wparam, lparam):
        import win32gui
        if msg == WM_WTSSESSION_CHANGE:
            if wparam == WTS_SESSION_UNLOCK:
                logger.info("Windows Session UNLOCK event detected (PASS)!")
                self.on_trigger_callback("PASS", reason="Workstation Unlocked")
            elif wparam == WTS_SESSION_LOGON:
                logger.info("Windows Session LOGON event detected (PASS)!")
                self.on_trigger_callback("PASS", reason="User Logon Success")
            elif wparam == WTS_SESSION_LOCK:
                logger.info("Workstation was LOCKED.")
        return win32gui.DefWindowProc(hwnd, msg, wparam, lparam)

    def stop(self):
        self._stop_event.set()
        if self.hwnd:
            try:
                import win32ts
                import win32gui
                win32ts.WTSUnRegisterSessionNotification(self.hwnd)
                win32gui.DestroyWindow(self.hwnd)
            except Exception:
                pass


class SecurityLogWatcherThread(threading.Thread):
    """
    Watches the Windows Security Event Log for:
    - Event ID 4625: An account failed to log on (FAIL / Wrong Password)
    - Event ID 4624: Successful Interactive logon / Unlock (PASS)
    """
    def __init__(self, on_trigger_callback, poll_interval=1.0):
        super().__init__(name="SecurityLogWatcherThread", daemon=True)
        self.on_trigger_callback = on_trigger_callback
        self.poll_interval = poll_interval
        self._stop_event = threading.Event()
        self.wevtapi = None
        self.last_record_id = 0

    def run(self):
        try:
            self.wevtapi = ctypes.windll.wevtapi
        except Exception as e:
            logger.error(f"Cannot load wevtapi.dll: {e}")
            return

        # Check access to Security log
        has_access = self._verify_access()
        if not has_access:
            logger.warning(
                "Access to Security Event Log is restricted. "
                "Run as Administrator or execute install.bat to enable failed password detection (Event 4625)."
            )
            # Will keep trying periodically in case privileges change or elevated task starts
        else:
            logger.info("Security Event Log access confirmed. Monitoring Event 4625 (FAIL)...")
            # Initialize latest record ID so we only process new events
            self._init_latest_record()

        while not self._stop_event.is_set():
            try:
                self._poll_security_events()
            except Exception as e:
                logger.debug(f"Security event poll warning: {e}")
            time.sleep(self.poll_interval)

    def _verify_access(self):
        """Verifies if the process can query the Security log."""
        try:
            EvtQueryChannelPath = 0x1
            query = "*[System[(EventID=4625)]]"
            h = self.wevtapi.EvtQuery(None, "Security", query, EvtQueryChannelPath)
            if h:
                self.wevtapi.EvtClose(h)
                return True
            return False
        except Exception:
            return False

    def _init_latest_record(self):
        """Reads the newest event record ID so we don't re-trigger past events on startup."""
        try:
            EvtQueryChannelPath = 0x1
            EvtQueryReverseDirection = 0x200
            query = "*[System[(EventID=4625 or EventID=4624)]]"
            h = self.wevtapi.EvtQuery(None, "Security", query, EvtQueryChannelPath | EvtQueryReverseDirection)
            if not h:
                return

            events = (ctypes.c_void_p * 1)()
            returned = wintypes.DWORD(0)
            if self.wevtapi.EvtNext(h, 1, events, 500, 0, ctypes.byref(returned)) and returned.value > 0:
                record_id, _, _, _, _ = self._render_event(events[0])
                if record_id:
                    self.last_record_id = record_id
                    logger.debug(f"Baseline Security Event RecordID: {self.last_record_id}")
                self.wevtapi.EvtClose(events[0])
            self.wevtapi.EvtClose(h)
        except Exception as e:
            logger.debug(f"Could not initialize latest record ID: {e}")

    def _poll_security_events(self):
        """Queries for recent 4625 (Failed logon) events in Security log."""
        EvtQueryChannelPath = 0x1
        EvtQueryReverseDirection = 0x200
        query = "*[System[(EventID=4625)]]"
        
        h = self.wevtapi.EvtQuery(None, "Security", query, EvtQueryChannelPath | EvtQueryReverseDirection)
        if not h:
            return

        events = (ctypes.c_void_p * 5)()
        returned = wintypes.DWORD(0)
        
        try:
            if self.wevtapi.EvtNext(h, 5, events, 1000, 0, ctypes.byref(returned)) and returned.value > 0:
                count = returned.value
                newest_seen = 0
                
                # Iterate in reverse (oldest of batch first)
                for i in range(count - 1, -1, -1):
                    ev_handle = events[i]
                    record_id, event_id, target_user, sub_status, logon_type = self._render_event(ev_handle)
                    self.wevtapi.EvtClose(ev_handle)
                    
                    if record_id and record_id > self.last_record_id:
                        if record_id > newest_seen:
                            newest_seen = record_id
                            
                        # Check if logon attempt was interactive (console/lock screen)
                        # LogonType 2 (Interactive), 7 (Unlock), 11 (CachedInteractive)
                        if event_id == 4625:
                            logger.warning(
                                f"FAILED LOGIN ATTEMPT detected! Account: {target_user}, "
                                f"LogonType: {logon_type}, SubStatus: {sub_status}"
                            )
                            reason = "Bad Password / Auth Failure"
                            if sub_status == "0xc000006a":
                                reason = "Incorrect Password"
                            elif sub_status == "0xc0000064":
                                reason = "Unknown Account"

                            self.on_trigger_callback("FAIL", username=target_user, reason=reason)

                if newest_seen > self.last_record_id:
                    self.last_record_id = newest_seen
        finally:
            self.wevtapi.EvtClose(h)

    def _render_event(self, ev_handle):
        """Renders an event handle into XML and extracts key fields."""
        EvtRenderEventXml = 1
        buffer_size = wintypes.DWORD(0)
        prop_count = wintypes.DWORD(0)
        
        # Get required buffer size
        self.wevtapi.EvtRender(None, ev_handle, EvtRenderEventXml, 0, None, ctypes.byref(buffer_size), ctypes.byref(prop_count))
        if buffer_size.value == 0:
            return None, None, None, None, None

        buf = ctypes.create_unicode_buffer(buffer_size.value // 2 + 1)
        if not self.wevtapi.EvtRender(None, ev_handle, EvtRenderEventXml, buffer_size.value, buf, ctypes.byref(buffer_size), ctypes.byref(prop_count)):
            return None, None, None, None, None

        xml_content = buf.value
        try:
            root = ET.fromstring(xml_content)
            ns = {'e': 'http://schemas.microsoft.com/win/2004/08/events/event'}
            
            # Event ID & Record ID
            eid_elem = root.find('e:System/e:EventID', ns)
            event_id = int(eid_elem.text) if eid_elem is not None else 0
            
            rec_elem = root.find('e:System/e:EventRecordID', ns)
            record_id = int(rec_elem.text) if rec_elem is not None else 0

            # Event Data
            data_map = {}
            for d in root.findall('e:EventData/e:Data', ns):
                name = d.attrib.get('Name')
                if name:
                    data_map[name] = d.text or ""

            target_user = data_map.get('TargetUserName', 'Unknown')
            sub_status = data_map.get('SubStatus', '')
            logon_type = data_map.get('LogonType', '')
            
            return record_id, event_id, target_user, sub_status, logon_type
        except Exception as e:
            logger.debug(f"Error parsing event XML: {e}")
            return None, None, None, None, None

    def stop(self):
        self._stop_event.set()
