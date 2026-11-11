
# -*- coding: utf-8 -*-
import argparse
import functools
import logging
import os
from pathlib import Path
import runpy
import sys
import threading
import time
import traceback

import psutil

LOGGER = logging.getLogger("TrashCanDiagnostic")
STOP = threading.Event()

STATE = {
    "scan_started": 0,
    "scan_completed": 0,
    "scan_failed": 0,
    "service_seen": False,
    "twlib_seen": False,
    "dib_files": set(),
    "jpg_files": set(),
    "last_stage": "INIT",
}

WATCH_EXTENSIONS = {
    ".dib", ".bmp", ".jpg", ".jpeg", ".tif", ".tiff"
}

WATCH_FOLDERS = set()
WATCH_LOCK = threading.Lock()


def get_desktop():
    try:
        from PySide2.QtCore import QStandardPaths

        result = QStandardPaths.writableLocation(
            QStandardPaths.DesktopLocation
        )

        if result:
            return Path(result)
    except Exception:
        pass

    return Path.home() / "Desktop"


def setup_logger():
    desktop = get_desktop()
    desktop.mkdir(parents=True, exist_ok=True)

    log_path = desktop / "debug.txt"

    LOGGER.setLevel(logging.DEBUG)
    LOGGER.propagate = False

    if not LOGGER.handlers:
        handler = logging.FileHandler(
            str(log_path),
            encoding="utf-8"
        )

        handler.setFormatter(logging.Formatter(
            "%(asctime)s.%(msecs)03d "
            "[%(levelname)s] "
            "[PID:%(process)d] "
            "[%(threadName)s] "
            "%(message)s",
            datefmt="%Y-%m-%d %H:%M:%S"
        ))

        LOGGER.addHandler(handler)

    log("START", "TrashCan 진단 시작")
    log("PYTHON", sys.version.split()[0])
    log("BITNESS", str(
        __import__("struct").calcsize("P") * 8
    ))
    log("EXECUTABLE", sys.executable)
    log("LOG_PATH", str(log_path))

    return log_path


def log(stage, message):
    STATE["last_stage"] = stage
    LOGGER.info(
        "[%s] %s",
        stage,
        str(message)
    )


def log_error(stage, message):
    LOGGER.error(
        "[%s] %s",
        stage,
        str(message)
    )


def log_exception(stage):
    LOGGER.error(
        "[%s] EXCEPTION\n%s",
        stage,
        traceback.format_exc()
    )


def add_watch_folder(folder):
    if not folder:
        return

    try:
        folder = str(Path(folder).resolve())

        with WATCH_LOCK:
            WATCH_FOLDERS.add(folder)

        log("WATCH_FOLDER", folder)
    except Exception:
        log_exception("WATCH_FOLDER")


def monitor_files():
    seen = {}

    log("FILE_MONITOR", "파일 감시 시작")

    while not STOP.is_set():
        with WATCH_LOCK:
            folders = list(WATCH_FOLDERS)

        for folder in folders:
            path = Path(folder)

            if not path.is_dir():
                continue

            try:
                for file in path.iterdir():
                    if not file.is_file():
                        continue

                    extension = file.suffix.lower()

                    if extension not in WATCH_EXTENSIONS:
                        continue

                    stat = file.stat()

                    key = str(file).lower()

                    signature = (
                        stat.st_mtime_ns,
                        stat.st_size
                    )

                    if seen.get(key) == signature:
                        continue

                    seen[key] = signature

                    # 내용이나 이미지 바이트는 기록하지 않음
                    log(
                        "FILE_DETECTED",
                        f"name={file.name}, "
                        f"size={stat.st_size}, "
                        f"folder={folder}"
                    )

                    if extension == ".dib":
                        STATE["dib_files"].add(key)

                    if extension in (".jpg", ".jpeg"):
                        STATE["jpg_files"].add(key)

            except Exception:
                log_exception("FILE_MONITOR")

        STOP.wait(0.5)


def monitor_processes():
    previous = set()
    reported_dll = set()
    reported_access_error = set()

    log("PROCESS_MONITOR", "프로세스 감시 시작")

    while not STOP.is_set():
        current = set()

        try:
            for proc in psutil.process_iter(
                ["pid", "name"]
            ):
                name = (
                    proc.info["name"] or ""
                ).lower()

                if not any(x in name for x in (
                    "ezsifsvr",
                    "trashcan",
                    "python",
                    "휴지통"
                )):
                    continue

                pid = proc.info["pid"]
                current.add((pid, name))

                if "ezsifsvr" not in name:
                    continue

                STATE["service_seen"] = True

                try:
                    modules = proc.memory_maps(
                        grouped=False
                    )

                    for module in modules:
                        module_path = module.path or ""

                        if os.path.basename(
                            module_path
                        ).lower() != "twlib.dll":
                            continue

                        STATE["twlib_seen"] = True

                        key = (pid, module_path)

                        if key not in reported_dll:
                            log(
                                "TWLIB_FOUND",
                                f"PID={pid}, DLL={module_path}"
                            )
                            reported_dll.add(key)

                except (
                    psutil.AccessDenied,
                    psutil.NoSuchProcess
                ) as e:
                    if pid not in reported_access_error:
                        log_error(
                            "TWLIB_ACCESS",
                            f"PID={pid}, error={type(e).__name__}"
                        )
                        reported_access_error.add(pid)

            for pid, name in sorted(current - previous):
                log(
                    "PROCESS_FOUND",
                    f"PID={pid}, name={name}"
                )

            for pid, name in sorted(previous - current):
                log(
                    "PROCESS_EXIT",
                    f"PID={pid}, name={name}"
                )

            previous = current

        except Exception:
            log_exception("PROCESS_MONITOR")

        STOP.wait(1.0)


def instrument_method(owner, method_name, category):
    original = getattr(owner, method_name, None)

    if not callable(original):
        log_error(
            "INSTRUMENT",
            f"{owner.__name__}.{method_name} 없음"
        )
        return

    @functools.wraps(original)
    def wrapped(*args, **kwargs):
        start = time.monotonic()

        log(category, f"{method_name} START")

        if method_name == "start_id_scan":
            STATE["scan_started"] += 1

        try:
            result = original(*args, **kwargs)

            elapsed = (
                time.monotonic() - start
            ) * 1000

            log(
                category,
                f"{method_name} END "
                f"elapsed={elapsed:.1f}ms"
            )

            if method_name == "start_id_scan":
                obj = args[0]

                error_code = getattr(
                    obj, "err_code", None
                )

                if error_code in (0, "0"):
                    STATE["scan_completed"] += 1
                    log("SCAN_RESULT", "SUCCESS")
                else:
                    STATE["scan_failed"] += 1
                    log_error(
                        "SCAN_RESULT",
                        f"error_code={error_code}"
                    )

            return result

        except Exception:
            if method_name == "start_id_scan":
                STATE["scan_failed"] += 1

            log_exception(
                f"{category}.{method_name}"
            )
            raise

    setattr(owner, method_name, wrapped)


def instrument_kait():
    import kait_extract

    log(
        "KAIT_MODULE",
        "kait_extract 모듈 확인"
    )

    if hasattr(kait_extract, "KaitScan"):
        for method in (
            "__init__",
            "load_kp_code",
            "kait_server_start",
            "kait_certify",
            "kait_onlyidScan",
            "start_id_scan",
        ):
            instrument_method(
                kait_extract.KaitScan,
                method,
                "KAIT"
            )

    if hasattr(kait_extract, "KaitDebuggerThread"):
        instrument_method(
            kait_extract.KaitDebuggerThread,
            "run",
            "DEBUGGER"
        )

    if callable(getattr(
        kait_extract,
        "get_process_id_by_name",
        None
    )):
        original = kait_extract.get_process_id_by_name
        previous = object()
        state = {"pid": previous}

        @functools.wraps(original)
        def monitored_pid(name):
            result = original(name)

            if state["pid"] != result:
                log(
                    "TARGET_PROCESS",
                    f"name={name}, "
                    f"found={bool(result)}, PID={result}"
                )
                state["pid"] = result

            return result

        kait_extract.get_process_id_by_name = monitored_pid

    if callable(getattr(
        kait_extract,
        "get_remote_module_base",
        None
    )):
        original = kait_extract.get_remote_module_base
        state = {"found": None}

        @functools.wraps(original)
        def monitored_module(pid, name):
            result = original(pid, name)
            found = bool(result)

            if state["found"] != found:
                log(
                    "TARGET_MODULE",
                    f"module={name}, "
                    f"PID={pid}, found={found}"
                )
                state["found"] = found

            return result

        kait_extract.get_remote_module_base = monitored_module

    if callable(getattr(
        kait_extract,
        "calculate_dib_size",
        None
    )):
        original = kait_extract.calculate_dib_size

        @functools.wraps(original)
        def monitored_dib_header(header):
            log(
                "DIB_HEADER",
                "DIB 헤더 검증 시작"
            )

            try:
                result = original(header)

                log(
                    "DIB_HEADER",
                    f"검증 성공, size={result}"
                )

                return result

            except Exception:
                log_exception("DIB_HEADER")
                raise

        kait_extract.calculate_dib_size = (
            monitored_dib_header
        )

    if callable(getattr(
        kait_extract,
        "show_error_box",
        None
    )):
        original = kait_extract.show_error_box

        @functools.wraps(original)
        def monitored_popup(title, message):
            # 메시지 본문에는 개인 식별정보가
            # 있을 수 있으므로 기록하지 않음.
            log(
                "POPUP",
                f"title={str(title)[:80]}"
            )

            return original(title, message)

        kait_extract.show_error_box = (
            monitored_popup
        )

    log("INSTRUMENT", "KAIT 관찰 함수 연결 완료")


def instrument_gui():
    # GUI에서 사용자가 선택한 JPG 저장 폴더도 감시
    try:
        import __main__

        window_class = getattr(
            __main__,
            "ExtractWindow",
            None
        )

        if window_class is None:
            return

        original = getattr(
            window_class,
            "select_folder",
            None
        )

        if not callable(original):
            return

        @functools.wraps(original)
        def monitored_select_folder(self, *args, **kwargs):
            result = original(self, *args, **kwargs)

            folder = getattr(
                self, "save_folder_path", None
            )

            if folder:
                add_watch_folder(folder)

            return result

        window_class.select_folder = (
            monitored_select_folder
        )

    except Exception:
        log_exception("GUI_INSTRUMENT")


def summarize():
    log(
        "SUMMARY",
        f"scan_started={STATE['scan_started']}, "
        f"scan_completed={STATE['scan_completed']}, "
        f"scan_failed={STATE['scan_failed']}"
    )

    log(
        "SUMMARY",
        f"service_seen={STATE['service_seen']}, "
        f"twlib_seen={STATE['twlib_seen']}, "
        f"dib_files={len(STATE['dib_files'])}, "
        f"jpg_files={len(STATE['jpg_files'])}"
    )

    if STATE["scan_started"] == 0:
        log(
            "DIAGNOSIS",
            "KAIT 스캔 시작이 관찰되지 않았습니다."
        )

    elif (
        STATE["scan_completed"] > 0
        and not STATE["dib_files"]
    ):
        log(
            "DIAGNOSIS",
            "KAIT 스캔 완료, DIB 파일 미관측. "
            "내부 브레이크포인트 히트 여부는 "
            "이 로그만으로 확인할 수 없습니다."
        )

    elif STATE["scan_failed"] > 0:
        log(
            "DIAGNOSIS",
            "KAIT 스캔 실패. ERROR 기록을 확인하세요."
        )

    else:
        log(
            "DIAGNOSIS",
            "세부 로그 확인 필요."
        )


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--main",
        default="Untitled-1.py"
    )
    args = parser.parse_args()

    main_file = Path(args.main).resolve()

    if not main_file.exists():
        raise FileNotFoundError(
            f"GUI 파일 없음: {main_file}"
        )

    log_path = setup_logger()
    add_watch_folder(get_desktop())

    log("GUI_FILE", str(main_file))

    STOP.clear()

    threads = [
        threading.Thread(
            target=monitor_files,
            name="FileMonitor",
            daemon=True
        ),
        threading.Thread(
            target=monitor_processes,
            name="ProcessMonitor",
            daemon=True
        )
    ]

    for thread in threads:
        thread.start()

    old_cwd = Path.cwd()
    old_argv = list(sys.argv)

    sys.argv = [str(main_file)]
    sys.path.insert(0, str(main_file.parent))

    try:
        os.chdir(str(main_file.parent))

        instrument_kait()

        # GUI 파일을 __main__으로 실행
        log("APP", "GUI 시작")

        runpy.run_path(
            str(main_file),
            run_name="__main__"
        )

        log("APP", "GUI 종료")

    except SystemExit as e:
        log(
            "APP",
            f"SystemExit={e.code}"
        )

    except Exception:
        log_exception("APP_FATAL")

    finally:
        STOP.set()

        for thread in threads:
            thread.join(timeout=2)

        summarize()

        os.chdir(str(old_cwd))
        sys.argv = old_argv

        log(
            "DONE",
            f"진단 완료. 로그={log_path}"
        )

    return 0


if __name__ == "__main__":
    sys.exit(main())
