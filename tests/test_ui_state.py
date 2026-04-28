import unittest

from meshtalk.ui_state import clear_runtime_collections, sync_peer_meta_to_states


class _PeerState:
    def __init__(self):
        self.last_seen_ts = 0.0
        self.device_seen_ts = 0.0
        self.key_confirmed_ts = 0.0


class UiStateTests(unittest.TestCase):
    def test_sync_peer_meta_to_states(self):
        st = _PeerState()
        sync_peer_meta_to_states(
            {"peer1": {"last_seen_ts": 1.0, "device_seen_ts": 2.0, "key_confirmed_ts": 3.0}},
            {"peer1": st},
        )
        self.assertEqual(st.last_seen_ts, 1.0)
        self.assertEqual(st.device_seen_ts, 2.0)
        self.assertEqual(st.key_confirmed_ts, 3.0)

    def test_clear_runtime_collections(self):
        known_peers = {"a"}
        peer_states = {"a": object()}
        key_response_last_ts = {"a": 1.0}
        key_conflict_ignored = {"a": {"sig": "x"}}
        key_conflict_hidden_log_ts = {"a": 2.0}
        incoming_state = {"a:g": {"parts": {}}}
        pending_by_peer = {"a": [{"msg": "x"}]}
        dialogs = {"a": {"last_text": "x"}}
        chat_history = {"a": [{"msg_id": "m"}]}
        list_index = ["a"]
        clear_runtime_collections(
            known_peers=known_peers,
            peer_states=peer_states,
            key_response_last_ts=key_response_last_ts,
            key_conflict_ignored=key_conflict_ignored,
            key_conflict_hidden_log_ts=key_conflict_hidden_log_ts,
            incoming_state=incoming_state,
            pending_by_peer=pending_by_peer,
            dialogs=dialogs,
            chat_history=chat_history,
            list_index=list_index,
        )
        self.assertFalse(known_peers)
        self.assertFalse(peer_states)
        self.assertFalse(key_response_last_ts)
        self.assertFalse(key_conflict_ignored)
        self.assertFalse(key_conflict_hidden_log_ts)
        self.assertFalse(incoming_state)
        self.assertFalse(pending_by_peer)
        self.assertFalse(dialogs)
        self.assertFalse(chat_history)
        self.assertFalse(list_index)


if __name__ == "__main__":
    unittest.main()
