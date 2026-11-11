
# -*- coding: utf-8 -*-
import sys
from pathlib import Path

import kait_extract
import common
import psutil
import requests
import sympy
from PySide2 import QtCore, QtGui, QtWidgets, QtUiTools
from qt_material import apply_stylesheet

import kait_debug_run


def main():
    root = Path(
        getattr(
            sys,
            "_MEIPASS",
            Path(__file__).resolve().parent
        )
    )

    gui_file = root / "Untitled-1.py"

    if not gui_file.exists():
        raise FileNotFoundError(
            f"GUI 시작 파일이 없습니다: {gui_file}"
        )

    sys.argv = [
        sys.argv[0],
        "--main",
        str(gui_file)
    ]

    return kait_debug_run.main()


if __name__ == "__main__":
    sys.exit(main())
