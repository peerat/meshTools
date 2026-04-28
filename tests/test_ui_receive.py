import unittest

from meshtalk.ui_receive import ingest_incoming_ui_fragment


class UiReceiveTests(unittest.TestCase):
    def test_ingest_incoming_ui_fragment_plain(self):
        state = {}

        def eff(label, **_kwargs):
            return str(label or "none")

        def assemble(parts, total, *_args, **_kwargs):
            joined = "".join(parts[str(i)] for i in range(1, total + 1) if str(i) in parts)
            return joined, True

        result = ingest_incoming_ui_fragment(
            incoming_state=state,
            peer_norm="peer1",
            group_id="gid1",
            total=1,
            delivery=0.5,
            fwd_hops=2,
            attempt_in=3,
            compact_wire=False,
            compression_flag=0,
            legacy_codec=None,
            payload_cmp="none",
            chunk_b64=None,
            text="hello",
            part=1,
            recv_now_ts=100.0,
            effective_payload_cmp_label=eff,
            merge_compact_compression=lambda a, b: a | b,
            assemble_incoming_text=assemble,
            infer_compact_cmp_label_from_joined_parts=lambda *_a, **_k: None,
            normalize_compression_name=lambda value: value,
            infer_compact_norm_from_joined_parts=lambda *_a, **_k: None,
            compression_efficiency_pct=lambda *_a, **_k: None,
            b64d=lambda s: s.encode("utf-8"),
        )

        self.assertEqual(result["full_text"], "hello")
        self.assertTrue(result["done_now"])
        self.assertTrue(result["decode_ok"])
        self.assertEqual(result["record"]["parts"]["1"], "hello")
        self.assertIn("peer1:gid1", state)


if __name__ == "__main__":
    unittest.main()
