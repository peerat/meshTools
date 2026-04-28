from __future__ import annotations

from typing import Callable, Dict, Optional


def handle_recv_plain_ui(
    *,
    peer_norm: str,
    text_plain: str,
    msg_id_plain: str,
    dialog_id_plain: str,
    chat_history: Dict[str, list],
    history_has_msg: Callable[[Dict[str, list], str, str], bool],
    update_peer_meta: Callable[[str], None],
    chat_line: Callable[..., None],
    append_history: Callable[..., None],
    log_line: Callable[[str, str], None],
    format_plain_transport_meta: Callable[..., str],
    now_ts: float,
    ts_local: Callable[[], str],
) -> bool:
    if not (peer_norm and text_plain and msg_id_plain):
        return False
    if history_has_msg(chat_history, dialog_id_plain, msg_id_plain):
        return False
    update_peer_meta(peer_norm)
    meta_data_in: Dict[str, object] = {
        "incoming": True,
        "done": True,
        "received_at_ts": now_ts,
        "transport": "meshtastic_text",
        "from_peer": peer_norm,
    }
    chat_line(
        dialog_id_plain,
        text_plain,
        "#66d9ef",
        meta=format_plain_transport_meta(incoming=True, received_at_ts=now_ts),
        meta_data=meta_data_in,
        msg_id=msg_id_plain,
    )
    append_history("recv", dialog_id_plain, msg_id_plain, text_plain, meta_data=meta_data_in)
    try:
        preview = " ".join(str(text_plain or "").split())
    except Exception:
        preview = ""
    if len(preview) > 120:
        preview = preview[:117] + "..."
    log_line(
        f"{ts_local()} RECVSTD: {msg_id_plain} <- {peer_norm} via {dialog_id_plain} port=TEXT_MESSAGE_APP text={preview!r}",
        "info",
    )
    return True


def handle_trace_done_ui(
    *,
    peer_norm: str,
    trace_id: str,
    meta_data: Optional[Dict[str, object]],
    resp_text: str,
    chat_history: Dict[str, list],
    history_has_msg: Callable[[Dict[str, list], str, str], bool],
    format_meta: Callable[..., str],
    chat_line: Callable[..., None],
    append_history: Callable[..., None],
    tr: Callable[[str], str],
    as_optional_float: Callable[[object], Optional[float]],
    now_ts: float,
) -> bool:
    if not peer_norm or not trace_id:
        return False
    meta = ""
    if isinstance(meta_data, dict):
        status_raw = meta_data.get("status")
        status = str(status_raw).strip() if status_raw is not None else None
        done_raw = meta_data.get("done")
        done = bool(done_raw) if done_raw is not None else None
        meta = format_meta(
            as_optional_float(meta_data.get("delivery")),
            as_optional_float(meta_data.get("attempts")),
            as_optional_float(meta_data.get("forward_hops")),
            as_optional_float(meta_data.get("ack_hops")),
            None,
            status=status or None,
            delivered_at_ts=as_optional_float(meta_data.get("delivered_at_ts")),
            incoming=False,
            done=done,
            sent_at_ts=as_optional_float(meta_data.get("sent_at_ts")),
        )
    chat_line(
        peer_norm,
        tr("trace_request"),
        "#fd971f",
        outgoing=True,
        msg_id=trace_id,
        meta=meta,
        meta_data=meta_data,
        replace_msg_id=trace_id,
        keep_ts_on_replace=True,
    )
    try:
        entries = chat_history.get(peer_norm, [])
        for entry in reversed(entries):
            if isinstance(entry, dict) and entry.get("msg_id") == trace_id:
                if not entry.get("logged"):
                    append_history(
                        "sent",
                        peer_norm,
                        trace_id,
                        tr("trace_request"),
                        meta_data=(dict(meta_data) if isinstance(meta_data, dict) else None),
                    )
                    entry["logged"] = True
                break
    except Exception:
        pass
    if resp_text:
        resp_id = f"{trace_id}:resp"
        if not history_has_msg(chat_history, peer_norm, resp_id):
            received_at_ts = as_optional_float(meta_data.get("delivered_at_ts")) if isinstance(meta_data, dict) else None
            if received_at_ts is None:
                received_at_ts = now_ts
            forward_hops = as_optional_float(meta_data.get("forward_hops")) if isinstance(meta_data, dict) else None
            ack_hops = as_optional_float(meta_data.get("ack_hops")) if isinstance(meta_data, dict) else None
            resp_meta_data: Dict[str, object] = {
                "delivery": None,
                "attempts": None,
                "forward_hops": forward_hops,
                "ack_hops": ack_hops,
                "incoming": True,
                "done": True,
                "received_at_ts": received_at_ts,
            }
            meta_resp = format_meta(
                None,
                None,
                forward_hops,
                ack_hops,
                None,
                incoming=True,
                done=True,
                received_at_ts=received_at_ts,
            )
            chat_line(
                peer_norm,
                resp_text,
                "#66d9ef",
                outgoing=False,
                msg_id=resp_id,
                meta=meta_resp,
                meta_data=resp_meta_data,
            )
            try:
                entries = chat_history.get(peer_norm, [])
                for entry in reversed(entries):
                    if isinstance(entry, dict) and entry.get("msg_id") == resp_id:
                        if not entry.get("logged"):
                            append_history(
                                "recv",
                                peer_norm,
                                resp_id,
                                resp_text,
                                meta_data=resp_meta_data,
                            )
                            entry["logged"] = True
                        break
            except Exception:
                pass
    return True
