"""图片 OCR 文本回收（图片钓鱼根治方案）：把图内文字回填给关键词规则体系。

依赖与降级
----------
- RapidOCR（onnxruntime）为**可选依赖**：未安装 / 初始化失败 / `OCR_ENABLED=0`
  时静默降级（返回空文本），沿用 oletools/yara-python 的可选依赖模式；
- 模型懒加载单例：每个进程只初始化一次（实测 0.8s），失败后置位不再重试。

为什么按需触发
--------------
单图 OCR 约 2s（CPU），对所有图片盲跑会让批量分析慢一个数量级。触发条件由
调用方（analyzer）把关：正文文字极少（<200 字符）且存在图片时才跑——这正是
"文字藏在图内"的规避形态；正常长文本邮件零 OCR 成本。
"""
from __future__ import annotations

import os
from typing import Any

# 预算：单封邮件最多 OCR 3 张图、单图 ≤2MB（防大图把耗时和内存打爆）
_MAX_IMAGES = 3
_MAX_IMAGE_BYTES = 2 * 1024 * 1024

_OCR_INSTANCE: Any | None = None
_OCR_FAILED = False
_THREADS_CAPPED = False

# 会话线程上限：rapidocr 1.2.3 的 OrtInferSession 不读任何线程配置，每会话默认
# 开满逻辑核（本机 20 线程），det/cls/rec 三会话 × N 个批量分析 worker 会产生
# 数百线程挤占 CPU，实测单图 OCR 从 1.4s 恶化到 ~16s。限制到 2 线程后并发恢复
# 到 3.5s/图、单封分析几乎无损（模型很小，多线程收益本来就低）。
_OCR_THREADS = int(os.environ.get("OCR_THREADS", "2"))


def _cap_runtime_threads() -> None:
    """限制 onnxruntime 会话与 cv2 的内部线程数（每进程一次）。"""
    global _THREADS_CAPPED
    if _THREADS_CAPPED:
        return
    _THREADS_CAPPED = True
    try:
        import cv2
        cv2.setNumThreads(1)
        import onnxruntime
        orig = onnxruntime.SessionOptions

        class _CappedSessionOptions(orig):  # type: ignore[misc,valid-type]
            def __init__(self, *a, **kw):
                super().__init__(*a, **kw)
                self.intra_op_num_threads = _OCR_THREADS
                self.inter_op_num_threads = _OCR_THREADS

        onnxruntime.SessionOptions = _CappedSessionOptions
        # rapidocr 的 utils 模块持有自己的 SessionOptions 引用，需一并替换
        import rapidocr_onnxruntime.utils as rt_utils
        rt_utils.SessionOptions = _CappedSessionOptions
    except Exception:  # noqa: BLE001 - 限线程失败不影响功能，只影响并发吞吐
        pass


def ocr_available() -> bool:
    """OCR 是否可用：开关打开 + 依赖可导入（不触发模型初始化）。"""
    if os.environ.get("OCR_ENABLED", "1") == "0":
        return False
    if _OCR_FAILED:
        return False
    try:
        import rapidocr_onnxruntime  # noqa: F401
        return True
    except ImportError:
        return False


def _get_ocr() -> Any | None:
    """懒加载单例；初始化失败置位 _OCR_FAILED，后续调用直接放弃（不反复重试）。"""
    global _OCR_INSTANCE, _OCR_FAILED
    if os.environ.get("OCR_ENABLED", "1") == "0":
        return None
    if _OCR_FAILED:
        return None
    if _OCR_INSTANCE is None:
        try:
            _cap_runtime_threads()
            from rapidocr_onnxruntime import RapidOCR
            _OCR_INSTANCE = RapidOCR()
        except Exception:  # noqa: BLE001 - 初始化失败（缺依赖/模型损坏）
            _OCR_FAILED = True
            return None
    return _OCR_INSTANCE


def ocr_images(images: list[bytes]) -> str:
    """对一批图片字节做 OCR，返回拼接文本（空串表示无结果/不可用）。

    多图时用线程池并行：onnxruntime 的 run() 释放 GIL，是真正的并发；
    会话线程已在 _cap_runtime_threads 限到 2，多线程不会重新引发超订阅。
    """
    ocr = _get_ocr()
    if ocr is None:
        return ""
    selected = [d for d in images if d and len(d) <= _MAX_IMAGE_BYTES][:_MAX_IMAGES]
    if not selected:
        return ""

    def _one(data: bytes) -> list[str]:
        try:
            result, _ = ocr(data)
            return [str(line[1]).strip() for line in (result or []) if str(line[1]).strip()]
        except Exception:  # noqa: BLE001 - 单图失败不影响整体
            return []

    if len(selected) == 1:
        texts = _one(selected[0])
    else:
        from concurrent.futures import ThreadPoolExecutor
        with ThreadPoolExecutor(max_workers=min(len(selected), 3)) as ex:
            texts = [t for lines in ex.map(_one, selected) for t in lines]
    return "\n".join(texts)[:6000]


def decode_qr(data: bytes) -> list[str]:
    """二维码解码（零新增依赖：opencv 为 RapidOCR 同族依赖，自带 QRCodeDetector）。

    OCR 引擎不认二维码图形（它是编码图案不是字形），而中文钓鱼图内的码才是
    载荷入口——真实样本 00b92083 的 GIF 码解出 http://www.trnxa.sbs。
    支持 PNG/JPEG/GIF（imdecode 取首帧）；返回全部解码内容（可为 URL/文本/vCard）。
    """
    try:
        import cv2
        import numpy as np
    except ImportError:
        return []
    arr = np.frombuffer(data, dtype=np.uint8)
    img = cv2.imdecode(arr, cv2.IMREAD_COLOR)
    if img is None:
        return []
    det = cv2.QRCodeDetector()
    out: list[str] = []
    try:
        ok, decoded, _points, _ = det.detectAndDecodeMulti(img)
        if ok and decoded is not None:
            out = [s.strip() for s in decoded if s]
    except Exception:  # noqa: BLE001 - 多码接口跨版本签名有差异
        pass
    if not out:
        try:
            s, _, _ = det.detectAndDecode(img)
            if s:
                out = [s.strip()]
        except Exception:  # noqa: BLE001
            pass
    return out
