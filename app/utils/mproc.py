"""多进程辅助：抑制 Windows spawn 子进程重执行"主模块文件"。

背景（实测）：Windows 上 multiprocessing 用 spawn，子进程启动时会
``runpy.run_path(__main__.__file__)`` 再执行一遍主模块（见 ``multiprocessing.spawn.
get_preparation_data``）。这带来两种后果：

  - **Streamlit 页面**：``__main__`` 就是页面文件本身，于是每个 worker 都把整页在 bare
    模式下渲染一遍——实测单次"重新分析 59 封"打出 **1089 条** ScriptRunContext 警告；
  - **普通脚本**（如 ``python scripts/foo.py`` 里调用了多进程分析）：子进程把该脚本从头
    再跑一遍，于是重复建连、重复取信、甚至递归起池（实测验证脚本打印了 4 次"原游标"）。

修法：spawn 只在 ``__main__.__file__`` 存在时才做这次重执行，所以临时把它置空即可；子进程
照常 import 项目模块并执行被提交的函数（本项目提交的是 ``app.pipeline`` 的模块级函数，
不依赖主模块）。**必须由创建进程池的父进程调用**——放在 worker 函数里已经太晚。

排除过的两个方案（都实测过）：
  - ``sys.exit(0)`` 让子进程提前退出 → 在 spawn 的 ``_fixup_main_from_path`` 阶段打死
    worker，父进程拿到 ``BrokenProcessPool``；
  - "把页面/脚本体包进函数"最干净，但页面里若干辅助函数读的是模块级变量，包进函数后
    失去作用域，属大改动。
"""
from __future__ import annotations

import contextlib
import sys
from typing import Iterator


@contextlib.contextmanager
def suppress_spawn_main_reexec() -> Iterator[None]:
    """在窗口内让 spawn 子进程不要重执行主模块文件（用完恢复，异常路径也恢复）。"""
    main_mod = sys.modules.get("__main__")
    saved = getattr(main_mod, "__file__", None)
    try:
        if main_mod is not None and saved is not None:
            main_mod.__file__ = None            # spawn 不再拿到 init_main_from_path
        yield
    finally:
        if main_mod is not None and saved is not None:
            main_mod.__file__ = saved
