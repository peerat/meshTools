from __future__ import annotations

from typing import Dict, MutableMapping, MutableSequence, MutableSet


def sync_peer_meta_to_states(
    peer_meta: Dict[str, Dict[str, float]],
    peer_states: MutableMapping[str, object],
) -> None:
    for peer_norm, rec in peer_meta.items():
        st = peer_states.get(peer_norm)
        if not st:
            continue
        if float(getattr(st, "last_seen_ts", 0.0) or 0.0) <= 0.0 and rec.get("last_seen_ts"):
            st.last_seen_ts = float(rec["last_seen_ts"])
        if float(getattr(st, "device_seen_ts", 0.0) or 0.0) <= 0.0 and rec.get("device_seen_ts"):
            st.device_seen_ts = float(rec["device_seen_ts"])
        if float(getattr(st, "key_confirmed_ts", 0.0) or 0.0) <= 0.0 and rec.get("key_confirmed_ts"):
            st.key_confirmed_ts = float(rec["key_confirmed_ts"])


def clear_runtime_collections(
    *,
    known_peers: MutableSet[str],
    peer_states: MutableMapping[str, object],
    key_response_last_ts: MutableMapping[str, float],
    key_conflict_ignored: MutableMapping[str, object],
    key_conflict_hidden_log_ts: MutableMapping[str, float],
    incoming_state: MutableMapping[str, object],
    pending_by_peer: MutableMapping[str, object],
    dialogs: MutableMapping[str, object],
    chat_history: MutableMapping[str, object],
    list_index: MutableSequence[str],
) -> None:
    known_peers.clear()
    peer_states.clear()
    key_response_last_ts.clear()
    key_conflict_ignored.clear()
    key_conflict_hidden_log_ts.clear()
    incoming_state.clear()
    pending_by_peer.clear()
    dialogs.clear()
    chat_history.clear()
    try:
        list_index.clear()
    except Exception:
        del list_index[:]
