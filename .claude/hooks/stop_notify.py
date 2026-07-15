#!/usr/bin/env python3
"""Stop hook: fixed, generic desktop notification via notify-send.

Fires when Claude finishes responding. Never blocks the stop and never
alters Claude's turn -- no `decision`/`continue` output, exit code always 0,
so this hook can have zero effect on control flow regardless of whether
notify-send succeeds, fails, or is missing.

Notification text is a fixed literal, never built from hook input -- no
prompt text, transcript content, file paths, or session/system details are
ever passed to notify-send. The only state this hook writes is one small
timestamp file in the OS temp dir (a single float, no content), named by a
hash of the project directory rather than the raw path, used solely to
suppress rapid duplicate notifications.
"""

import hashlib
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from _common import project_dir, read_hook_input  # noqa: E402

DEBOUNCE_SECONDS = 20
NOTIFICATION_TEXT = "Task complete - review required"


def state_file_path(root: Path) -> Path:
    digest = hashlib.sha256(str(root).encode("utf-8")).hexdigest()[:16]
    return Path(tempfile.gettempdir()) / f"claude-stop-notify-{digest}.state"


def read_last_notified(state_path: Path) -> float | None:
    try:
        return float(state_path.read_text(encoding="utf-8").strip())
    except (OSError, ValueError):
        return None


def write_last_notified(state_path: Path, now: float) -> None:
    try:
        state_path.write_text(str(now), encoding="utf-8")
    except OSError:
        pass


def should_notify(last: float | None, now: float, window: float = DEBOUNCE_SECONDS) -> bool:
    return last is None or (now - last) >= window


def send_notification() -> None:
    try:
        subprocess.run(
            ["notify-send", NOTIFICATION_TEXT],
            timeout=5,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        pass


def main() -> int:
    hook_input = read_hook_input()
    root = project_dir(hook_input)
    state_path = state_file_path(root)
    now = time.time()

    if shutil.which("notify-send") and should_notify(read_last_notified(state_path), now):
        send_notification()
        write_last_notified(state_path, now)

    return 0


if __name__ == "__main__":
    sys.exit(main())
