import unittest

from meshtalk.ui_settings_tabs import (
    build_compression_tab,
    build_log_tab,
    build_security_tab,
    build_theme_tab,
)


class _StubSignal:
    def connect(self, _fn):
        return None


class _StubModelItem:
    def setEnabled(self, _v):
        return None


class _StubModel:
    def item(self, _idx):
        return _StubModelItem()


class _StubWidget:
    ExpandingFieldsGrow = 1
    WrapAllRows = 2
    HLine = 3
    Sunken = 4

    def __init__(self, *args, **kwargs):
        self._data = []
        self._current = -1
        self._viewport = self
        self.finished = _StubSignal()

    def setContentsMargins(self, *args): return None
    def setSpacing(self, *args): return None
    def addWidget(self, *args, **kwargs): return None
    def addLayout(self, *args, **kwargs): return None
    def addRow(self, *args, **kwargs): return None
    def addStretch(self, *args, **kwargs): return None
    def setObjectName(self, *args): return None
    def setStyleSheet(self, *args): return None
    def setWordWrap(self, *args): return None
    def setLabelAlignment(self, *args): return None
    def setFormAlignment(self, *args): return None
    def setVerticalSpacing(self, *args): return None
    def setHorizontalSpacing(self, *args): return None
    def setFieldGrowthPolicy(self, *args): return None
    def setRowWrapPolicy(self, *args): return None
    def setReadOnly(self, *args): return None
    def installEventFilter(self, *args): return None
    def viewport(self): return self._viewport
    def setToolTip(self, *args): return None
    def setChecked(self, *args): return None
    def model(self): return _StubModel()
    def count(self): return len(self._data)
    def addItem(self, label, data=None): self._data.append((label, data))
    def findData(self, data):
        for i, (_, d) in enumerate(self._data):
            if d == data:
                return i
        return -1
    def setCurrentIndex(self, idx): self._current = idx
    def currentData(self):
        if 0 <= self._current < len(self._data):
            return self._data[self._current][1]
        return None
    def setFrameShape(self, *args): return None
    def setFrameShadow(self, *args): return None


class _StubTabWidget(_StubWidget):
    def addTab(self, widget, label):
        self._data.append((widget, label))


class _StubQtWidgets:
    QWidget = _StubWidget
    QVBoxLayout = _StubWidget
    QHBoxLayout = _StubWidget
    QFormLayout = _StubWidget
    QGroupBox = _StubWidget
    QLabel = _StubWidget
    QComboBox = _StubWidget
    QCheckBox = _StubWidget
    QPushButton = _StubWidget
    QTextEdit = _StubWidget
    QGridLayout = _StubWidget
    QFrame = _StubWidget


class _StubQtCore:
    class Qt:
        AlignLeft = 1
        AlignTop = 2
        AlignHCenter = 3


class UiSettingsTabsTests(unittest.TestCase):
    def test_builders_return_widgets(self):
        tabs = _StubTabWidget()
        tr = lambda x: x
        compact_field = lambda widget, width=0: widget
        theme = build_theme_tab(
            tabs=tabs, tr=tr, current_theme="ubuntu_style", compact_field=compact_field, QtWidgets=_StubQtWidgets, QtCore=_StubQtCore
        )
        self.assertIn("theme_combo", theme)
        security = build_security_tab(
            tabs=tabs,
            tr=tr,
            security_policy="auto",
            session_rekey_enabled=True,
            compact_field=compact_field,
            QtWidgets=_StubQtWidgets,
            QtCore=_StubQtCore,
            wire_version=3,
        )
        self.assertIn("sec_policy", security)
        compression = build_compression_tab(
            tabs=tabs,
            tr=tr,
            cfg={"compression_policy": "auto", "compression_normalize": "auto"},
            compact_field=compact_field,
            QtWidgets=_StubQtWidgets,
            QtCore=_StubQtCore,
            mode_byte_dict=1,
            mode_fixed_bits=2,
            mode_deflate=3,
            mode_zlib=4,
            mode_bz2=5,
            mode_lzma=6,
            mode_zstd=7,
            zstd_available=True,
        )
        self.assertIn("cmp_choice", compression)
        log = build_log_tab(
            tabs=tabs,
            tr=tr,
            verbose_log=True,
            packet_trace_log=True,
            runtime_log_file=True,
            log_buffer=[("txt", "info")],
            append_log_to_view=lambda *args, **kwargs: None,
            set_mono=lambda *args, **kwargs: None,
            no_ctrl_zoom=None,
            QtWidgets=_StubQtWidgets,
        )
        self.assertIn("log_view", log)


if __name__ == "__main__":
    unittest.main()
