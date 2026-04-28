import os
import tempfile
import unittest

from meshtalk.ui_security import (
    apply_imported_keypair_atomically,
    handle_security_keys_backup_priv,
    handle_security_keys_copy_pub,
    handle_security_keys_import_priv,
    handle_security_keys_regen,
    refresh_security_keys_view,
)


class UiSecurityTests(unittest.TestCase):
    def test_refresh_security_keys_view(self):
        with tempfile.TemporaryDirectory() as td:
            pub_path = os.path.join(td, "pub.key")
            with open(pub_path, "w", encoding="utf-8") as f:
                f.write("PUBTEXT")
            seen = {}
            refresh_security_keys_view(
                self_id="id1",
                priv_path="x",
                pub_path=pub_path,
                fallback_text="COPY",
                set_button_text=lambda v: seen.setdefault("text", v),
                set_button_width=lambda v: seen.setdefault("width", v),
            )
            self.assertEqual(seen["text"], "PUBTEXT")
            self.assertEqual(seen["width"], "PUBTEXT")

    def test_handle_regen_and_copy(self):
        seen = {"regen": 0, "info": 0, "warn": 0, "clip": None}
        ok = handle_security_keys_regen(
            ask_confirm=lambda: True,
            regenerate_keys=lambda: seen.__setitem__("regen", seen["regen"] + 1),
            refresh_view=lambda: None,
            info=lambda: seen.__setitem__("info", seen["info"] + 1),
            warn=lambda: seen.__setitem__("warn", seen["warn"] + 1),
        )
        self.assertTrue(ok)
        self.assertEqual(seen["regen"], 1)
        with tempfile.TemporaryDirectory() as td:
            pub_path = os.path.join(td, "pub.key")
            with open(pub_path, "w", encoding="utf-8") as f:
                f.write("PUB")
            ok2 = handle_security_keys_copy_pub(
                pub_path=pub_path,
                set_clipboard_text=lambda text: seen.__setitem__("clip", text),
                animate_copied=lambda _text: None,
                animate_restore=lambda _text: None,
                copied_label="COPIED",
                warn=lambda: seen.__setitem__("warn", seen["warn"] + 1),
            )
            self.assertTrue(ok2)
            self.assertEqual(seen["clip"], "PUB")

    def test_backup_and_import(self):
        with tempfile.TemporaryDirectory() as td:
            priv_path = os.path.join(td, "priv.key")
            with open(priv_path, "w", encoding="utf-8") as f:
                f.write("PRIVTEXT")
            out_path = os.path.join(td, "backup.key")
            seen = {"info": 0, "apply": None}
            ok = handle_security_keys_backup_priv(
                self_id="id1",
                priv_path=priv_path,
                ask_save_path=lambda default_name, file_filter: out_path,
                ask_passphrase=lambda: "pw",
                ask_passphrase_repeat=lambda: "pw",
                file_filter="*.key",
                pack_private_backup=lambda priv_txt, passphrase: f"{priv_txt}:{passphrase}",
                harden_file=lambda _path: None,
                info=lambda: seen.__setitem__("info", seen["info"] + 1),
                warn_unavailable=lambda: None,
                warn_failed=lambda: None,
                warn_mismatch=lambda: None,
            )
            self.assertTrue(ok)
            self.assertEqual(seen["info"], 1)
            with open(out_path, "r", encoding="utf-8") as f:
                self.assertIn("PRIVTEXT:pw", f.read())

            in_path = os.path.join(td, "import.key")
            with open(in_path, "wb") as f:
                f.write(b"BLOB")
            ok2 = handle_security_keys_import_priv(
                priv_path=priv_path,
                pub_path=os.path.join(td, "pub.key"),
                ask_confirm=lambda: True,
                ask_open_path=lambda file_filter: in_path,
                file_filter="*.key",
                load_private_key_from_backup_blob=lambda blob, passphrase_provider: b"RAW",
                ask_passphrase=lambda: "pw",
                apply_imported_private_key=lambda raw: seen.__setitem__("apply", raw),
                info=lambda: seen.__setitem__("info", seen["info"] + 1),
                warn_unavailable=lambda: None,
                warn_failed=lambda: None,
            )
            self.assertTrue(ok2)
            self.assertEqual(seen["apply"], b"RAW")

    def test_apply_imported_keypair_atomically_success_and_rollback(self):
        with tempfile.TemporaryDirectory() as td:
            priv_path = os.path.join(td, "priv.key")
            pub_path = os.path.join(td, "pub.key")
            with open(priv_path, "w", encoding="utf-8") as f:
                f.write("OLDPRIV")
            with open(pub_path, "w", encoding="utf-8") as f:
                f.write("OLDPUB")

            hardened = []

            def _harden(path):
                hardened.append(os.path.basename(path))

            apply_imported_keypair_atomically(
                priv_path=priv_path,
                pub_path=pub_path,
                priv_text="NEWPRIV",
                pub_text="NEWPUB",
                validate_private_file=lambda path: path,
                validate_public_file=lambda path: path,
                harden_file=_harden,
            )
            with open(priv_path, "r", encoding="utf-8") as f:
                self.assertEqual(f.read(), "NEWPRIV")
            with open(pub_path, "r", encoding="utf-8") as f:
                self.assertEqual(f.read(), "NEWPUB")
            self.assertIn("priv.key", hardened)
            self.assertIn("pub.key", hardened)

            with self.assertRaises(RuntimeError):
                apply_imported_keypair_atomically(
                    priv_path=priv_path,
                    pub_path=pub_path,
                    priv_text="BROKENPRIV",
                    pub_text="BROKENPUB",
                    validate_private_file=lambda path: path,
                    validate_public_file=lambda path: (_ for _ in ()).throw(RuntimeError("boom")),
                    harden_file=_harden,
                )
            with open(priv_path, "r", encoding="utf-8") as f:
                self.assertEqual(f.read(), "NEWPRIV")
            with open(pub_path, "r", encoding="utf-8") as f:
                self.assertEqual(f.read(), "NEWPUB")


if __name__ == "__main__":
    unittest.main()
