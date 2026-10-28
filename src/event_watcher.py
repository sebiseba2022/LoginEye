import os
import sys
import time
import json
import datetime
import threading
import xml.etree.ElementTree as ET
import ctypes
from ctypes import wintypes

from src.config import (
    logger,
    COOLDOWN_SECONDS,
    LAST_CAPTURE_FILE
)
from src.camera import start_lock_standby, stop_lock_standby

# Win32 Constants
WM_WTSSESSION_CHANGE = 0x02B1
WTS_SESSION_LOGON = 0x5
WTS_SESSION_LOGOFF = 0x6
WTS_SESSION_LOCK = 0x7
WTS_SESSION_UNLOCK = 0x8
NOTIFY_FOR_THIS_SESSION = 0
NOTIFY_FOR_ALL_SESSIONS = 1


class CooldownManager:
    """Thread-safe and cross-process cooldown manager to prevent redundant camera triggers."""
    def __init__(self, cooldown_seconds=COOLDOWN_SECONDS):
        self.cooldown = cooldown_seconds
        self.lock = threading.Lock()
        self.last_times = {"PASS": 0.0, "FAIL": 0.0}

    def can_trigger(self, status):
        clean_status = status.upper()
        with self.lock:
            now = time.time()
            # Check in-memory and shared state file
            file_state = self._load_state()
            last_t = max(
                self.last_times.get(clean_status, 0.0),
                file_state.get(clean_status, 0.0)
            )
            # Use slightly longer cooldown for PASS (since multiple unlock events fire together)
            effective_cooldown = max(self.cooldown, 4.0) if clean_status == "PASS" else 0.8
            if (now - last_t) < effective_cooldown:
                logger.debug(
                    f"Event '{clean_status}' suppressed by cooldown "
                    f"({now - last_t:.1f}s < {effective_cooldown}s)"
                )
                return False

            self.last_times[clean_status] = now
            file_state[clean_status] = now
            self._save_state(file_state)
            return True

    def _load_state(self):
        try:
            if os.path.exists(LAST_CAPTURE_FILE):
                with open(LAST_CAPTURE_FILE, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    if isinstance(data, dict):
                        return {
                            "PASS": float(data.get("PASS", 0.0)),
                            "FAIL": float(data.get("FAIL", 0.0)),
                        }
        except Exception:
            pass
        return {"PASS": 0.0, "FAIL": 0.0}

    def _save_state(self, state_dict):
        try:
            with open(LAST_CAPTURE_FILE, "w", encoding="utf-8") as f:
                json.dump(state_dict, f)
        except Exception:
            pass


class SessionWatcherThread(threading.Thread):
    """
    Listens for Windows Terminal Services (WTS) session changes:
    - WTS_SESSION_UNLOCK (0x8): Triggered immediately when correct password/PIN/fingerprint unlocks the PC.
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
            import win32ts

            wc = win32gui.WNDCLASS()
            wc.lpfnWndProc = {WM_WTSSESSION_CHANGE: self._on_session_change}
            wc.lpszClassName = "LoginEyeSessionWatcherClass"
            wc.hInstance = win32gui.GetModuleHandle(None)

            try:
                win32gui.RegisterClass(wc)
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

    def _on_session_change(self, hwnd, msg, wparam, lparam):
        if msg == WM_WTSSESSION_CHANGE:
            if wparam == WTS_SESSION_UNLOCK:
                logger.info("Windows Session UNLOCK event detected (PASS)!")
                threading.Thread(
                    target=self.on_trigger_callback,
                    args=("PASS",),
                    kwargs={"reason": "Workstation Unlocked"},
                    daemon=True
                ).start()
            elif wparam == WTS_SESSION_LOGON:
                logger.info("Windows Session LOGON event detected (PASS)!")
                threading.Thread(
                    target=self.on_trigger_callback,
                    args=("PASS",),
                    kwargs={"reason": "User Logon Success"},
                    daemon=True
                ).start()
            elif wparam == WTS_SESSION_LOCK:
                logger.info("Workstation was LOCKED. Pre-warming camera standby...")
                start_lock_standby()
        return 0

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
    Watches Windows Event Logs in real time for all authentication methods:
    1. Microsoft-Windows-Biometrics/Operational (No Admin needed):
       - Event 1005 / 1606: Wrong Fingerprint / Biometric failed (FAIL)
       - Event 1605: Fingerprint / Biometric unlock succeeded (PASS)
    2. Microsoft-Windows-HelloForBusiness/Operational (No Admin needed):
       - Event 7001: Wrong PIN / Windows Hello failed (FAIL)
       - Event 5001: PIN / Windows Hello unlock succeeded (PASS)
    3. Microsoft-Windows-Winlogon/Operational (No Admin needed):
       - Event 812 (TermSrv Event=5): Workstation Unlocked (PASS)
       - Event 812 (TermSrv Event=1,2): User Logon (PASS)
    4. Security (Admin or Event Log Readers):
       - Event 4625: Failed password logon (FAIL)
    """
    CHANNELS = [
        (
            "Microsoft-Windows-Biometrics/Operational",
            "*[System[(EventID=1003 or EventID=1005 or EventID=1006 or EventID=1605 or EventID=1606)]]"
        ),
        (
            "Microsoft-Windows-HelloForBusiness/Operational",
            "*[System[(EventID=7001 or EventID=5001)]]"
        ),
        (
            "Microsoft-Windows-Winlogon/Operational",
            "*[System[(EventID=812)]]"
        ),
        (
            "Security",
            "*[System[(EventID=4625)]]"
        ),
    ]

    def __init__(self, on_trigger_callback, poll_interval=0.25):
        super().__init__(name="SecurityLogWatcherThread", daemon=True)
        self.on_trigger_callback = on_trigger_callback
        self.poll_interval = poll_interval
        self._stop_event = threading.Event()
        self.wevtapi = None
        self.last_record_ids = {}
        self.channel_initialized = {}

    def run(self):
        try:
            self.wevtapi = ctypes.windll.wevtapi
        except Exception as e:
            logger.error(f"Cannot load wevtapi.dll: {e}")
            return

        for channel, query in self.CHANNELS:
            ok = self._init_channel_baseline(channel, query)
            self.channel_initialized[channel] = ok
            if ok:
                logger.info(f"Monitoring event channel: {channel} (baseline RecordID={self.last_record_ids.get(channel, 0)})")
            elif channel == "Security":
                logger.info(
                    "Note: Classic Security Log (Event 4625) requires Admin, "
                    "but Biometrics (Fingerprint), Windows Hello (PIN), and Winlogon channels are active!"
                )

        while not self._stop_event.is_set():
            for channel, query in self.CHANNELS:
                try:
                    if not self.channel_initialized.get(channel, False):
                        if self._init_channel_baseline(channel, query):
                            self.channel_initialized[channel] = True
                            logger.info(f"Event channel now accessible: {channel}")
                        continue
                    self._poll_channel(channel, query)
                except Exception as e:
                    logger.debug(f"Event poll warning on {channel}: {e}")
            time.sleep(self.poll_interval)

    def _init_channel_baseline(self, channel, query):
        """
        Reads the newest event record ID on a channel so we don't re-trigger old events on startup,
        EXCEPT if a login/fail event occurred within the last 20 seconds (e.g. during boot login
        right before the daemon finished starting) and hasn't been captured yet.
        """
        EvtQueryChannelPath = 0x1
        EvtQueryReverseDirection = 0x200
        h = self.wevtapi.EvtQuery(None, channel, query, EvtQueryChannelPath | EvtQueryReverseDirection)
        if not h:
            return False

        try:
            events = (ctypes.c_void_p * 5)()
            returned = wintypes.DWORD(0)
            if self.wevtapi.EvtNext(h, 5, events, 500, 0, ctypes.byref(returned)) and returned.value > 0:
                count = returned.value
                now = time.time()
                last_state = {"PASS": 0.0, "FAIL": 0.0}
                try:
                    if os.path.exists(LAST_CAPTURE_FILE):
                        with open(LAST_CAPTURE_FILE, "r", encoding="utf-8") as f:
                            last_state = json.load(f)
                except Exception:
                    pass
                last_any_capture = max(float(last_state.get("PASS", 0.0)), float(last_state.get("FAIL", 0.0)))

                newest_id = 0
                replay_from_id = None

                # Inspect from oldest to newest among the recent batch
                for i in range(count - 1, -1, -1):
                    rec_id, ev_id, data_map, ev_ts = self._render_event(events[i])
                    self.wevtapi.EvtClose(events[i])
                    if rec_id and rec_id > newest_id:
                        newest_id = rec_id
                    # If this event happened in the last 45s (e.g. boot screen before daemon started)
                    # and after the last recorded capture, allow it to be replayed immediately
                    if rec_id and ev_ts and (now - ev_ts) <= 45.0 and ev_ts > (last_any_capture + 2.0):
                        # Ignore lock event 4 for replay
                        if channel == "Microsoft-Windows-Winlogon/Operational" and data_map.get("Event") == "4":
                            continue
                        if replay_from_id is None or rec_id < replay_from_id:
                            replay_from_id = rec_id

                if replay_from_id is not None:
                    self.last_record_ids[channel] = replay_from_id - 1
                    logger.info(
                        f"Detected recent uncaptured boot/login event on {channel} "
                        f"(RecordID={replay_from_id}), queuing immediate capture!"
                    )
                else:
                    self.last_record_ids[channel] = newest_id
            else:
                self.last_record_ids[channel] = 0
            return True
        except Exception:
            return False
        finally:
            self.wevtapi.EvtClose(h)

    def _poll_channel(self, channel, query):
        EvtQueryChannelPath = 0x1
        EvtQueryReverseDirection = 0x200

        h = self.wevtapi.EvtQuery(None, channel, query, EvtQueryChannelPath | EvtQueryReverseDirection)
        if not h:
            return

        events = (ctypes.c_void_p * 6)()
        returned = wintypes.DWORD(0)
        baseline = self.last_record_ids.get(channel, 0)

        try:
            if self.wevtapi.EvtNext(h, 6, events, 500, 0, ctypes.byref(returned)) and returned.value > 0:
                count = returned.value
                newest_seen = baseline

                # Process oldest of the batch first
                for i in range(count - 1, -1, -1):
                    ev_handle = events[i]
                    record_id, event_id, data_map, _ = self._render_event(ev_handle)
                    self.wevtapi.EvtClose(ev_handle)

                    if record_id and record_id > baseline:
                        if record_id > newest_seen:
                            newest_seen = record_id
                        self._dispatch_event(channel, event_id, data_map)

                if newest_seen > baseline:
                    self.last_record_ids[channel] = newest_seen
        finally:
            self.wevtapi.EvtClose(h)

    def _trigger_async(self, status, username=None, reason=None):
        threading.Thread(
            target=self.on_trigger_callback,
            args=(status,),
            kwargs={"username": username, "reason": reason},
            daemon=True
        ).start()

    def _dispatch_event(self, channel, event_id, data_map):
        if channel == "Microsoft-Windows-Biometrics/Operational":
            raw_user = data_map.get("Username")
            username = raw_user.split("\\")[-1] if raw_user else None
            if event_id in (1003, 1005, 1006, 1606):
                logger.warning(f"FAILED FINGERPRINT/BIOMETRIC attempt detected (Event {event_id})!")
                self._trigger_async(
                    "FAIL",
                    username=username,
                    reason="Unrecognized Fingerprint / Biometric Failed"
                )
            elif event_id == 1605:
                logger.info(f"Successful Fingerprint/Biometric unlock detected for {username}!")
                self._trigger_async(
                    "PASS",
                    username=username,
                    reason="Fingerprint Authentication Succeeded"
                )

        elif channel == "Microsoft-Windows-HelloForBusiness/Operational":
            if event_id == 7001:
                sub = data_map.get("AuthenticationErrorSubStatus", "")
                logger.warning(f"FAILED PIN / Windows Hello attempt detected (Event 7001, SubStatus={sub})!")
                self._trigger_async(
                    "FAIL",
                    username=None,
                    reason="Incorrect PIN / Windows Hello Failure"
                )
            elif event_id == 5001:
                logger.info("Successful PIN / Windows Hello sign-in detected (Event 5001)!")
                self._trigger_async(
                    "PASS",
                    username=None,
                    reason="PIN Authentication Succeeded"
                )

        elif channel == "Microsoft-Windows-Winlogon/Operational":
            if event_id == 812:
                sub_name = data_map.get("SubscriberName", "")
                ev_code = data_map.get("Event", "")
                if sub_name == "TermSrv" and ev_code == "4":
                    start_lock_standby()
                elif sub_name == "TermSrv" and ev_code == "5":
                    logger.info("Winlogon Workstation UNLOCK detected (Event 812, code 5)!")
                    self._trigger_async(
                        "PASS",
                        username=None,
                        reason="Workstation Unlocked"
                    )
                elif (sub_name == "Sens" and ev_code in ("1", "2")) or (
                    sub_name == "TermSrv" and ev_code in ("1", "2", "12")
                ):
                    logger.info(f"Winlogon User LOGON detected (Event 812, sub={sub_name}, code={ev_code})!")
                    self._trigger_async(
                        "PASS",
                        username=None,
                        reason="User Logon Success"
                    )

        elif channel == "Security":
            if event_id == 4625:
                target_user = data_map.get("TargetUserName")
                sub_status = data_map.get("SubStatus", "").lower()
                logon_type = data_map.get("LogonType", "")
                logger.warning(
                    f"FAILED PASSWORD LOGIN detected (Event 4625)! "
                    f"Account: {target_user}, LogonType: {logon_type}, SubStatus: {sub_status}"
                )
                reason = "Incorrect Password"
                if sub_status == "0xc0000064":
                    reason = "Unknown Account"
                self._trigger_async("FAIL", username=target_user, reason=reason)

    def _render_event(self, ev_handle):
        """Renders an event handle into XML and extracts RecordID, EventID, EventData dict, and UTC timestamp."""
        EvtRenderEventXml = 1
        buffer_size = wintypes.DWORD(0)
        prop_count = wintypes.DWORD(0)

        self.wevtapi.EvtRender(
            None, ev_handle, EvtRenderEventXml, 0, None,
            ctypes.byref(buffer_size), ctypes.byref(prop_count)
        )
        if buffer_size.value == 0:
            return None, None, {}, None

        buf = ctypes.create_unicode_buffer(buffer_size.value // 2 + 1)
        if not self.wevtapi.EvtRender(
            None, ev_handle, EvtRenderEventXml, buffer_size.value, buf,
            ctypes.byref(buffer_size), ctypes.byref(prop_count)
        ):
            return None, None, {}, None

        try:
            root = ET.fromstring(buf.value)
            ns = {'e': 'http://schemas.microsoft.com/win/2004/08/events/event'}

            eid_elem = root.find('e:System/e:EventID', ns)
            event_id = int(eid_elem.text) if eid_elem is not None else 0

            rec_elem = root.find('e:System/e:EventRecordID', ns)
            record_id = int(rec_elem.text) if rec_elem is not None else 0

            event_ts = None
            tc_elem = root.find('e:System/e:TimeCreated', ns)
            if tc_elem is not None:
                sys_time = tc_elem.attrib.get('SystemTime', '')
                if sys_time:
                    try:
                        s_clean = sys_time.rstrip('Z')[:26] + '+00:00'
                        event_ts = datetime.datetime.fromisoformat(s_clean).timestamp()
                    except Exception:
                        pass

            data_map = {}
            for d in root.findall('e:EventData/e:Data', ns):
                name = d.attrib.get('Name')
                if name:
                    data_map[name] = d.text or ""

            return record_id, event_id, data_map, event_ts
        except Exception as e:
            logger.debug(f"Error parsing event XML: {e}")
            return None, None, {}, None

    def stop(self):
        self._stop_event.set()
