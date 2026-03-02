from __future__ import annotations

from typing import Callable, Dict, Iterable


def _style_monitor_table(table) -> None:
    try:
        table.setAlternatingRowColors(False)
    except Exception:
        pass
    try:
        table.setStyleSheet(
            "QTableWidget { background: transparent; alternate-background-color: transparent; }"
            " QTableWidget::item { background: transparent; }"
        )
    except Exception:
        pass


def build_theme_tab(
    *,
    tabs,
    tr: Callable[[str], str],
    current_theme: str,
    compact_field: Callable[[object, int], object],
    QtWidgets,
    QtCore,
):
    tab_theme = QtWidgets.QWidget()
    tabs.addTab(tab_theme, tr("tab_theme"))
    theme_root = QtWidgets.QVBoxLayout(tab_theme)
    theme_root.setContentsMargins(14, 12, 14, 10)
    theme_root.setSpacing(12)

    theme_title = QtWidgets.QLabel(tr("theme_title"))
    theme_title.setObjectName("muted")
    theme_title.setStyleSheet("font-weight:600;")
    theme_title.setContentsMargins(6, 8, 0, 0)
    theme_root.addWidget(theme_title)

    theme_group = QtWidgets.QGroupBox("")
    theme_layout = QtWidgets.QFormLayout(theme_group)
    theme_layout.setLabelAlignment(QtCore.Qt.AlignLeft)
    theme_layout.setFormAlignment(QtCore.Qt.AlignTop)
    theme_layout.setVerticalSpacing(8)
    theme_layout.setFieldGrowthPolicy(QtWidgets.QFormLayout.ExpandingFieldsGrow)
    try:
        theme_layout.setContentsMargins(10, 10, 10, 10)
    except Exception:
        pass

    theme_combo = QtWidgets.QComboBox()
    theme_combo.addItem(tr("theme_ubuntu_style"), "ubuntu_style")
    theme_combo.addItem(tr("theme_brutal_man"), "brutal_man")
    theme_combo.addItem(tr("theme_pretty_girl"), "pretty_girl")
    theme_combo.addItem(tr("theme_froggy"), "froggy")
    theme_combo.addItem(tr("theme_spinach"), "spinach")
    try:
        idx = theme_combo.findData(current_theme)
        theme_combo.setCurrentIndex(idx if idx >= 0 else 0)
    except Exception:
        pass
    compact_field(theme_combo, width=320)
    theme_layout.addRow(tr("theme_select"), theme_combo)
    theme_hint = QtWidgets.QLabel(tr("theme_hint"))
    theme_hint.setObjectName("hint")
    theme_hint.setWordWrap(True)
    theme_layout.addRow(theme_hint)

    theme_root.addWidget(theme_group)
    theme_root.addStretch(1)
    return {
        "tab": tab_theme,
        "theme_combo": theme_combo,
    }


def build_compression_tab(
    *,
    tabs,
    tr: Callable[[str], str],
    cfg: Dict[str, object],
    compact_field: Callable[[object, int], object],
    QtWidgets,
    QtCore,
    mode_byte_dict: int,
    mode_fixed_bits: int,
    mode_deflate: int,
    mode_zlib: int,
    mode_bz2: int,
    mode_lzma: int,
    mode_zstd: int,
    zstd_available: bool,
):
    tab_cmp = QtWidgets.QWidget()
    tabs.addTab(tab_cmp, tr("tab_compression"))
    cmp_root = QtWidgets.QVBoxLayout(tab_cmp)
    cmp_root.setContentsMargins(14, 12, 14, 10)
    cmp_root.setSpacing(12)

    cmp_title = QtWidgets.QLabel(tr("compression_title"))
    cmp_title.setObjectName("muted")
    cmp_title.setStyleSheet("font-weight:600;")
    cmp_title.setContentsMargins(6, 8, 0, 0)
    cmp_root.addWidget(cmp_title)

    cmp_group = QtWidgets.QGroupBox("")
    cmp_layout = QtWidgets.QFormLayout(cmp_group)
    cmp_layout.setLabelAlignment(QtCore.Qt.AlignLeft)
    cmp_layout.setFormAlignment(QtCore.Qt.AlignTop)
    cmp_layout.setVerticalSpacing(8)
    cmp_layout.setFieldGrowthPolicy(QtWidgets.QFormLayout.ExpandingFieldsGrow)
    cmp_layout.setRowWrapPolicy(QtWidgets.QFormLayout.WrapAllRows)
    try:
        cmp_layout.setContentsMargins(10, 10, 10, 10)
    except Exception:
        pass

    compression_policy = str(cfg.get("compression_policy", "auto") or "auto").strip().lower()
    compression_force_mode = int(cfg.get("compression_force_mode", int(mode_deflate)) or int(mode_deflate))
    compression_normalize = str(cfg.get("compression_normalize", "auto") or "auto").strip().lower()

    cmp_norm = QtWidgets.QComboBox()
    cmp_norm.addItem(tr("compression_normalize_auto"), "auto")
    cmp_norm.addItem(tr("compression_normalize_off"), "off")
    cmp_norm.addItem(tr("compression_normalize_tokens"), "tokens")
    cmp_norm.addItem(tr("compression_normalize_sp_vocab"), "sp_vocab")
    try:
        idx = cmp_norm.findData(compression_normalize)
        cmp_norm.setCurrentIndex(idx if idx >= 0 else 0)
    except Exception:
        pass
    compact_field(cmp_norm, width=320)
    cmp_layout.addRow(tr("compression_normalize"), cmp_norm)
    norm_hint = QtWidgets.QLabel(tr("compression_normalize_hint"))
    norm_hint.setObjectName("hint")
    norm_hint.setWordWrap(True)
    cmp_layout.addRow(norm_hint)

    cmp_choice = QtWidgets.QComboBox()
    cmp_choice.addItem(tr("compression_policy_auto"), "auto")
    cmp_choice.addItem(tr("compression_policy_off"), "off")
    cmp_choice.addItem("BYTE_DICT", int(mode_byte_dict))
    cmp_choice.addItem("FIXED_BITS", int(mode_fixed_bits))
    cmp_choice.addItem("DEFLATE", int(mode_deflate))
    cmp_choice.addItem("ZLIB", int(mode_zlib))
    cmp_choice.addItem("BZ2", int(mode_bz2))
    cmp_choice.addItem("LZMA", int(mode_lzma))
    cmp_choice.addItem("ZSTD", int(mode_zstd))
    try:
        model = cmp_choice.model()
        if model is not None:
            item = model.item(cmp_choice.count() - 1)
            if item is not None and not zstd_available:
                item.setEnabled(False)
    except Exception:
        pass

    try:
        if compression_policy == "off":
            idx = cmp_choice.findData("off")
        elif compression_policy == "force":
            idx = cmp_choice.findData(int(compression_force_mode))
        else:
            idx = cmp_choice.findData("auto")
        cmp_choice.setCurrentIndex(idx if idx >= 0 else 0)
    except Exception:
        pass
    compact_field(cmp_choice, width=320)
    cmp_layout.addRow(tr("compression_policy"), cmp_choice)
    force_hint = QtWidgets.QLabel(tr("compression_force_hint"))
    force_hint.setObjectName("hint")
    force_hint.setWordWrap(True)
    cmp_layout.addRow(force_hint)

    cmp_root.addWidget(cmp_group)
    cmp_root.addStretch(1)
    return {
        "tab": tab_cmp,
        "cmp_choice": cmp_choice,
        "cmp_norm": cmp_norm,
    }


def build_security_tab(
    *,
    tabs,
    tr: Callable[[str], str],
    security_policy: str,
    session_rekey_enabled: bool,
    compact_field: Callable[[object, int], object],
    QtWidgets,
    QtCore,
    wire_version: int,
):
    tab_sec = QtWidgets.QWidget()
    tabs.addTab(tab_sec, tr("tab_security"))
    sec_root = QtWidgets.QVBoxLayout(tab_sec)
    sec_root.setContentsMargins(14, 12, 14, 10)
    sec_root.setSpacing(12)

    sec_title = QtWidgets.QLabel(tr("security"))
    sec_title.setObjectName("muted")
    sec_title.setStyleSheet("font-weight:600;")
    sec_title.setContentsMargins(6, 8, 0, 0)
    sec_root.addWidget(sec_title)

    sec_group = QtWidgets.QGroupBox("")
    sec_layout = QtWidgets.QFormLayout(sec_group)
    sec_layout.setLabelAlignment(QtCore.Qt.AlignLeft)
    sec_layout.setFormAlignment(QtCore.Qt.AlignTop)
    sec_layout.setVerticalSpacing(8)
    sec_layout.setFieldGrowthPolicy(QtWidgets.QFormLayout.ExpandingFieldsGrow)
    sec_layout.setRowWrapPolicy(QtWidgets.QFormLayout.WrapAllRows)
    try:
        sec_layout.setContentsMargins(10, 10, 10, 10)
    except Exception:
        pass

    sec_policy = QtWidgets.QComboBox()
    sec_policy.addItem(tr("security_policy_auto"), "auto")
    sec_policy.addItem(tr("security_policy_strict"), "strict")
    sec_policy.addItem(tr("security_policy_always"), "always")
    try:
        idx = sec_policy.findData(security_policy)
        sec_policy.setCurrentIndex(idx if idx >= 0 else 0)
    except Exception:
        pass
    compact_field(sec_policy, width=320)
    sec_policy_label = QtWidgets.QLabel(tr("security_policy"))
    sec_policy_label.setWordWrap(True)
    sec_layout.addRow(sec_policy_label, sec_policy)
    sec_policy_hint = QtWidgets.QLabel(tr("security_auto_hint"))
    sec_policy_hint.setObjectName("hint")
    sec_policy_hint.setWordWrap(True)
    sec_layout.addRow(sec_policy_hint)

    try:
        sec_crypto_text = tr("security_crypto_summary").format(wire=int(wire_version))
    except Exception:
        sec_crypto_text = tr("security_crypto_summary")
    sec_crypto_hint = QtWidgets.QLabel(sec_crypto_text)
    sec_crypto_hint.setObjectName("hint")
    sec_crypto_hint.setWordWrap(True)
    sec_layout.addRow(sec_crypto_hint)

    cb_rekey = QtWidgets.QCheckBox(tr("session_rekey"))
    cb_rekey.setChecked(bool(session_rekey_enabled))
    cb_rekey.setToolTip(tr("session_rekey_hint"))
    sec_layout.addRow(cb_rekey)
    cb_rekey_hint = QtWidgets.QLabel(tr("session_rekey_hint"))
    cb_rekey_hint.setObjectName("hint")
    cb_rekey_hint.setWordWrap(True)
    sec_layout.addRow(cb_rekey_hint)

    keys_title = QtWidgets.QLabel(tr("security_keys_title"))
    keys_title.setObjectName("muted")
    keys_title.setStyleSheet("font-weight:600;")
    keys_title.setContentsMargins(0, 6, 0, 0)
    sec_layout.addRow(keys_title)

    keys_hint = QtWidgets.QLabel(tr("security_keys_hint"))
    keys_hint.setObjectName("hint")
    keys_hint.setWordWrap(True)
    sec_layout.addRow(keys_hint)

    keys_btn_col = QtWidgets.QVBoxLayout()
    keys_btn_col.setContentsMargins(0, 0, 0, 0)
    keys_btn_col.setSpacing(8)
    btn_keys_copy_pub = QtWidgets.QPushButton(tr("security_keys_copy_pub"))
    btn_keys_backup = QtWidgets.QPushButton(tr("security_keys_backup_priv"))
    btn_keys_import = QtWidgets.QPushButton(tr("security_keys_import_priv"))
    btn_keys_regen = QtWidgets.QPushButton(tr("security_keys_regen"))
    btn_full_reset_profile = QtWidgets.QPushButton(tr("full_reset_profile"))
    btn_full_reset_all = QtWidgets.QPushButton(tr("full_reset_all"))
    btn_style_green = (
        "QPushButton { background:#1f6f3a; border:1px solid #2fa760; color:#eafff1; font-weight:600; }"
        "QPushButton:hover { background:#238042; }"
    )
    btn_style_yellow = (
        "QPushButton { background:#8a5a00; border:1px solid #d3a33d; color:#fff7df; font-weight:600; }"
        "QPushButton:hover { background:#a36b00; }"
    )
    btn_style_red = (
        "QPushButton { background:#8f1d1d; border:1px solid #c85a5a; color:#ffecec; font-weight:600; }"
        "QPushButton:hover { background:#a82424; }"
    )
    try:
        btn_keys_copy_pub.setStyleSheet(btn_style_green)
        btn_keys_backup.setStyleSheet(btn_style_yellow)
        btn_keys_import.setStyleSheet(btn_style_yellow)
        btn_keys_regen.setStyleSheet(btn_style_red)
        btn_full_reset_profile.setStyleSheet(btn_style_red)
        btn_full_reset_all.setStyleSheet(btn_style_red)
    except Exception:
        pass
    for _btn in (
        btn_keys_copy_pub,
        btn_keys_backup,
        btn_keys_import,
        btn_keys_regen,
        btn_full_reset_profile,
        btn_full_reset_all,
    ):
        keys_btn_col.addWidget(_btn, 0, QtCore.Qt.AlignHCenter)
    sec_layout.addRow(keys_btn_col)

    sec_root.addWidget(sec_group)
    sec_root.addStretch(1)
    return {
        "tab": tab_sec,
        "sec_policy": sec_policy,
        "cb_rekey": cb_rekey,
        "btn_keys_copy_pub": btn_keys_copy_pub,
        "btn_keys_backup": btn_keys_backup,
        "btn_keys_import": btn_keys_import,
        "btn_keys_regen": btn_keys_regen,
        "btn_full_reset_profile": btn_full_reset_profile,
        "btn_full_reset_all": btn_full_reset_all,
    }


def build_log_tab(
    *,
    tabs,
    tr: Callable[[str], str],
    verbose_log: bool,
    packet_trace_log: bool,
    runtime_log_file: bool,
    log_buffer: Iterable[tuple[str, str]],
    append_log_to_view: Callable[[object, str, str], None],
    set_mono: Callable[[object, int], None],
    no_ctrl_zoom,
    QtWidgets,
):
    tab_log = QtWidgets.QWidget()
    tabs.addTab(tab_log, tr("tab_log"))
    tab_log_l = QtWidgets.QVBoxLayout(tab_log)
    tab_log_l.setContentsMargins(14, 12, 14, 10)
    tab_log_l.setSpacing(10)

    cb_verbose = QtWidgets.QCheckBox(tr("verbose_events"), tab_log)
    cb_verbose.setChecked(verbose_log)
    tab_log_l.addWidget(cb_verbose)
    verbose_hint = QtWidgets.QLabel(tr("hint_verbose"))
    verbose_hint.setObjectName("hint")
    verbose_hint.setWordWrap(True)
    tab_log_l.addWidget(verbose_hint)

    cb_pkt_trace = QtWidgets.QCheckBox(tr("packet_trace"), tab_log)
    cb_pkt_trace.setChecked(bool(packet_trace_log))
    tab_log_l.addWidget(cb_pkt_trace)
    pkt_trace_hint = QtWidgets.QLabel(tr("hint_packet_trace"))
    pkt_trace_hint.setObjectName("hint")
    pkt_trace_hint.setWordWrap(True)
    tab_log_l.addWidget(pkt_trace_hint)

    cb_runtime_log = QtWidgets.QCheckBox(tr("runtime_log_file"), tab_log)
    cb_runtime_log.setChecked(runtime_log_file)
    tab_log_l.addWidget(cb_runtime_log)
    runtime_log_hint = QtWidgets.QLabel(tr("hint_runtime_log_file"))
    runtime_log_hint.setObjectName("hint")
    runtime_log_hint.setWordWrap(True)
    tab_log_l.addWidget(runtime_log_hint)

    legend_title = QtWidgets.QLabel(tr("log_legend_title"))
    legend_title.setObjectName("hint")
    tab_log_l.addWidget(legend_title)
    legend_grid = QtWidgets.QGridLayout()
    legend_grid.setContentsMargins(0, 0, 0, 0)
    legend_grid.setHorizontalSpacing(8)
    legend_grid.setVerticalSpacing(4)

    def _legend_chip(label_text: str, color: str):
        chip = QtWidgets.QLabel(label_text)
        chip.setStyleSheet(
            "QLabel {"
            f"color:{color};"
            "border:1px solid #4b2740;"
            "border-radius:6px;"
            "padding:2px 6px;"
            "background:#2a1022;"
            "}"
        )
        return chip

    legend_items = [
        (tr("log_legend_error"), "#f92672"),
        (tr("log_legend_warn"), "#fd971f"),
        (tr("log_legend_key"), "#ffd75f"),
        (tr("log_legend_discovery"), "#b894ff"),
        (tr("log_legend_radio"), "#74b2ff"),
        (tr("log_legend_queue"), "#c3b38a"),
        (tr("log_legend_send"), "#c6f08c"),
        (tr("log_legend_recv"), "#66d9ef"),
        (tr("log_legend_compress"), "#f4a3d7"),
        (tr("log_legend_pkt"), "#9ec4ff"),
    ]
    for idx, (text_label, color) in enumerate(legend_items):
        row = idx // 5
        col = idx % 5
        legend_grid.addWidget(_legend_chip(text_label, color), row, col)
    tab_log_l.addLayout(legend_grid)

    try:
        sep = QtWidgets.QFrame()
        sep.setFrameShape(QtWidgets.QFrame.HLine)
        sep.setFrameShadow(QtWidgets.QFrame.Sunken)
        tab_log_l.addWidget(sep)
    except Exception:
        pass

    log_view = QtWidgets.QTextEdit()
    log_view.setReadOnly(True)
    set_mono(log_view, 10)
    try:
        log_view.setStyleSheet(
            "QTextEdit { background:#300a24; color:#eeeeec; border:1px solid #3c0f2e; }"
        )
    except Exception:
        pass
    try:
        log_view.installEventFilter(no_ctrl_zoom)
        log_view.viewport().installEventFilter(no_ctrl_zoom)
    except Exception:
        pass
    tab_log_l.addWidget(log_view, 1)

    copy_row = QtWidgets.QHBoxLayout()
    copy_row.setContentsMargins(0, 0, 0, 0)
    copy_row.addStretch(1)
    btn_ack = QtWidgets.QPushButton(tr("ack_alerts"))
    btn_clear = QtWidgets.QPushButton(tr("clear_log"))
    btn_copy = QtWidgets.QPushButton(tr("copy_log"))
    copy_row.addWidget(btn_ack)
    copy_row.addWidget(btn_clear)
    copy_row.addWidget(btn_copy)
    tab_log_l.addLayout(copy_row)

    for text, level in list(log_buffer)[-500:]:
        append_log_to_view(log_view, text, level)

    return {
        "tab": tab_log,
        "cb_verbose": cb_verbose,
        "cb_pkt_trace": cb_pkt_trace,
        "cb_runtime_log": cb_runtime_log,
        "log_view": log_view,
        "btn_ack": btn_ack,
        "btn_clear": btn_clear,
        "btn_copy": btn_copy,
    }


def build_routing_tab(
    *,
    tabs,
    tr: Callable[[str], str],
    cfg: Dict[str, object],
    compact_field: Callable[[object, int], object],
    row_with_hint: Callable[[object, str], object],
    QtWidgets,
    QtCore,
):
    tab_routing = QtWidgets.QWidget()
    tabs.addTab(tab_routing, tr("tab_routing"))
    routing_root = QtWidgets.QVBoxLayout(tab_routing)
    routing_root.setContentsMargins(14, 12, 14, 10)
    routing_root.setSpacing(12)

    routing_title = QtWidgets.QLabel(tr("routing_title"))
    routing_title.setObjectName("muted")
    routing_title.setStyleSheet("font-weight:600;")
    routing_title.setContentsMargins(6, 8, 0, 0)
    routing_root.addWidget(routing_title)
    summary_label = QtWidgets.QLabel(tr("routing_monitor_hint"))
    summary_label.setObjectName("hint")
    summary_label.setWordWrap(True)
    routing_root.addWidget(summary_label)

    status_box = QtWidgets.QGroupBox(tr("routing_status_box"))
    status_form = QtWidgets.QFormLayout(status_box)
    try:
        status_form.setContentsMargins(10, 14, 10, 10)
        status_form.setVerticalSpacing(6)
    except Exception:
        pass
    status_transport = QtWidgets.QLabel("-")
    status_role = QtWidgets.QLabel("-")
    status_metrics = QtWidgets.QLabel("-")
    status_policy = QtWidgets.QLabel("-")
    status_weights = QtWidgets.QLabel("-")
    for _lbl in (status_transport, status_role, status_metrics, status_policy, status_weights):
        try:
            _lbl.setWordWrap(True)
        except Exception:
            pass
    status_form.addRow(tr("routing_status_transport"), status_transport)
    status_form.addRow(tr("routing_status_role"), status_role)
    status_form.addRow(tr("routing_status_metrics"), status_metrics)
    status_form.addRow(tr("routing_status_policy"), status_policy)
    status_form.addRow(tr("routing_status_weights"), status_weights)

    route_table = QtWidgets.QTableWidget(0, 10)
    route_table.setHorizontalHeaderLabels(
        [
            tr("routing_hdr_peer"),
            tr("routing_hdr_selected"),
            tr("routing_hdr_score"),
            tr("routing_hdr_delivery"),
            tr("routing_hdr_timeout"),
            tr("routing_hdr_rtt"),
            tr("routing_hdr_hops"),
            tr("routing_hdr_retry"),
            tr("routing_hdr_snr"),
            tr("routing_hdr_age"),
        ]
    )
    try:
        route_table.verticalHeader().setVisible(False)
        route_table.setSelectionMode(QtWidgets.QAbstractItemView.NoSelection)
        route_table.setEditTriggers(QtWidgets.QAbstractItemView.NoEditTriggers)
        _style_monitor_table(route_table)
        route_hdr = route_table.horizontalHeader()
        route_hdr.setStretchLastSection(False)
        route_hdr.setSectionResizeMode(QtWidgets.QHeaderView.Stretch)
    except Exception:
        pass

    buffer_table = QtWidgets.QTableWidget(0, 8)
    buffer_table.setHorizontalHeaderLabels(
        [
            tr("routing_hdr_from"),
            tr("routing_hdr_to"),
            tr("routing_hdr_type"),
            tr("routing_hdr_msg"),
            tr("routing_hdr_parts"),
            tr("routing_hdr_attempts"),
            tr("routing_hdr_next"),
            tr("routing_hdr_age"),
        ]
    )
    try:
        buffer_table.verticalHeader().setVisible(False)
        buffer_table.setSelectionMode(QtWidgets.QAbstractItemView.NoSelection)
        buffer_table.setEditTriggers(QtWidgets.QAbstractItemView.NoEditTriggers)
        _style_monitor_table(buffer_table)
        buffer_hdr = buffer_table.horizontalHeader()
        buffer_hdr.setStretchLastSection(False)
        buffer_hdr.setSectionResizeMode(QtWidgets.QHeaderView.Stretch)
    except Exception:
        pass

    routes_box = QtWidgets.QGroupBox(tr("routing_routes_box"))
    routes_box_l = QtWidgets.QVBoxLayout(routes_box)
    routes_box_l.setContentsMargins(8, 18, 8, 8)
    routes_box_l.setSpacing(6)
    routes_box_l.addWidget(route_table)

    buffer_box = QtWidgets.QGroupBox(tr("routing_buffer_box"))
    buffer_box_l = QtWidgets.QVBoxLayout(buffer_box)
    buffer_box_l.setContentsMargins(8, 18, 8, 8)
    buffer_box_l.setSpacing(6)
    buffer_box_l.addWidget(buffer_table)

    routing_root.addWidget(status_box, 0)
    routing_root.addWidget(routes_box, 1)
    routing_root.addWidget(buffer_box, 1)
    routing_root.addStretch(1)
    return {
        "tab": tab_routing,
        "summary_label": summary_label,
        "status_transport": status_transport,
        "status_role": status_role,
        "status_metrics": status_metrics,
        "status_policy": status_policy,
        "status_weights": status_weights,
        "route_table": route_table,
        "buffer_table": buffer_table,
    }
