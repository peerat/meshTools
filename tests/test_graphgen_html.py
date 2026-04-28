import json
import re
import tempfile
import unittest
from pathlib import Path

import graphGen


class WriteD3HtmlTests(unittest.TestCase):
    def test_payload_is_embedded_without_raw_script_breakout(self) -> None:
        payload = {
            "meta": {"nodes": 1, "links": 0, "minEdge": 1, "includeUnknown": False},
            "nodes": [{"id": "!11111111", "label": "</script><script>alert(1)</script>"}],
            "links": [],
            "timeSeries": [],
        }

        with tempfile.TemporaryDirectory() as tmp_dir:
            html_path = Path(tmp_dir) / "graph.html"
            graphGen.write_d3_html(html_path, payload)

            html = html_path.read_text(encoding="utf-8")
            self.assertIn('type="application/json"', html)
            self.assertNotIn("</script><script>alert(1)</script>", html)

            match = re.search(
                r'<script id="graph-data" type="application/json">(.*?)</script>',
                html,
                flags=re.DOTALL,
            )
            self.assertIsNotNone(match)

            parsed = json.loads(match.group(1))
            self.assertEqual(parsed, payload)


if __name__ == "__main__":
    unittest.main()
