from __future__ import annotations

import os
import tempfile


def refresh_security_keys_view(
    *,
    self_id: str,
    priv_path: str | None,
    pub_path: str | None,
    fallback_text: str,
    set_button_text,
    set_button_width,
) -> None:
    try:
        if not self_id or not priv_path or not pub_path:
            set_button_text(fallback_text)
            set_button_width(fallback_text)
            return
        pub_txt = ""
        if os.path.isfile(pub_path):
            with open(pub_path, "r", encoding="utf-8") as f:
                pub_txt = str(f.read().strip() or "")
        shown = pub_txt if pub_txt else fallback_text
        set_button_text(shown)
        set_button_width(shown)
    except Exception:
        set_button_text(fallback_text)
        set_button_width(fallback_text)


def handle_security_keys_regen(
    *,
    ask_confirm,
    regenerate_keys,
    refresh_view,
    info,
    warn,
) -> bool:
    if not ask_confirm():
        return False
    try:
        regenerate_keys()
        refresh_view()
        info()
        return True
    except Exception:
        warn()
        return False


def handle_security_keys_copy_pub(
    *,
    pub_path: str | None,
    set_clipboard_text,
    animate_copied,
    animate_restore,
    copied_label: str,
    warn,
) -> bool:
    try:
        if not pub_path or not os.path.isfile(pub_path):
            raise FileNotFoundError("public key missing")
        with open(pub_path, "r", encoding="utf-8") as f:
            pub_txt = str(f.read() or "").strip()
        if not pub_txt:
            raise ValueError("empty public key")
        set_clipboard_text(pub_txt)
        animate_copied(copied_label)
        animate_restore(pub_txt)
        return True
    except Exception:
        warn()
        return False


def handle_security_keys_backup_priv(
    *,
    self_id: str,
    priv_path: str | None,
    ask_save_path,
    ask_passphrase,
    ask_passphrase_repeat,
    file_filter: str,
    pack_private_backup,
    harden_file,
    info,
    warn_unavailable,
    warn_failed,
    warn_mismatch,
) -> bool:
    try:
        if not self_id or not priv_path or not os.path.isfile(priv_path):
            warn_unavailable()
            return False
        default_name = f"{self_id}.private.backup.key"
        out_path = ask_save_path(default_name, file_filter)
        if not out_path:
            return False
        passphrase = ask_passphrase()
        if passphrase is None:
            return False
        passphrase = str(passphrase or "")
        if not passphrase:
            warn_failed()
            return False
        passphrase2 = ask_passphrase_repeat()
        if passphrase2 is None:
            return False
        if str(passphrase2 or "") != passphrase:
            warn_mismatch()
            return False
        with open(priv_path, "r", encoding="utf-8") as f:
            priv_txt = str(f.read() or "").strip()
        packed = pack_private_backup(priv_txt, passphrase)
        with open(out_path, "w", encoding="utf-8") as f:
            f.write(packed + "\n")
        try:
            harden_file(out_path)
        except Exception:
            pass
        info()
        return True
    except Exception:
        warn_failed()
        return False


def handle_security_keys_import_priv(
    *,
    priv_path: str | None,
    pub_path: str | None,
    ask_confirm,
    ask_open_path,
    file_filter: str,
    load_private_key_from_backup_blob,
    ask_passphrase,
    apply_imported_private_key,
    info,
    warn_unavailable,
    warn_failed,
) -> bool:
    if not priv_path or not pub_path:
        warn_unavailable()
        return False
    if not ask_confirm():
        return False
    in_path = ask_open_path(file_filter)
    if not in_path:
        return False
    try:
        with open(in_path, "rb") as f:
            blob = bytes(f.read() or b"")

        def _passphrase_provider() -> str:
            value = ask_passphrase()
            if value is None:
                return ""
            return str(value or "")

        priv_raw = load_private_key_from_backup_blob(blob, passphrase_provider=_passphrase_provider)
        apply_imported_private_key(priv_raw)
        info()
        return True
    except Exception:
        warn_failed()
        return False


def apply_imported_keypair_atomically(
    *,
    priv_path: str,
    pub_path: str,
    priv_text: str,
    pub_text: str,
    validate_private_file,
    validate_public_file,
    harden_file,
) -> None:
    os.makedirs(os.path.dirname(priv_path) or ".", exist_ok=True)
    os.makedirs(os.path.dirname(pub_path) or ".", exist_ok=True)
    priv_dir = os.path.dirname(priv_path) or "."
    pub_dir = os.path.dirname(pub_path) or "."

    old_priv_text = None
    old_pub_text = None
    try:
        if os.path.isfile(priv_path):
            with open(priv_path, "r", encoding="utf-8") as f:
                old_priv_text = str(f.read())
    except Exception:
        old_priv_text = None
    try:
        if os.path.isfile(pub_path):
            with open(pub_path, "r", encoding="utf-8") as f:
                old_pub_text = str(f.read())
    except Exception:
        old_pub_text = None

    priv_tmp = None
    pub_tmp = None
    try:
        priv_fd, priv_tmp = tempfile.mkstemp(prefix=".priv-import-", suffix=".tmp", dir=priv_dir)
        with os.fdopen(priv_fd, "w", encoding="utf-8") as f:
            f.write(str(priv_text))
            f.flush()
            os.fsync(f.fileno())
        harden_file(priv_tmp)

        pub_fd, pub_tmp = tempfile.mkstemp(prefix=".pub-import-", suffix=".tmp", dir=pub_dir)
        with os.fdopen(pub_fd, "w", encoding="utf-8") as f:
            f.write(str(pub_text))
            f.flush()
            os.fsync(f.fileno())
        harden_file(pub_tmp)

        validate_private_file(priv_tmp)
        validate_public_file(pub_tmp)

        os.replace(priv_tmp, priv_path)
        priv_tmp = None
        os.replace(pub_tmp, pub_path)
        pub_tmp = None
        harden_file(priv_path)
        harden_file(pub_path)
    except Exception:
        if priv_tmp:
            try:
                os.unlink(priv_tmp)
            except Exception:
                pass
        if pub_tmp:
            try:
                os.unlink(pub_tmp)
            except Exception:
                pass
        try:
            if old_priv_text is not None:
                with open(priv_path, "w", encoding="utf-8") as f:
                    f.write(old_priv_text)
                harden_file(priv_path)
            elif os.path.exists(priv_path):
                os.unlink(priv_path)
        except Exception:
            pass
        try:
            if old_pub_text is not None:
                with open(pub_path, "w", encoding="utf-8") as f:
                    f.write(old_pub_text)
                harden_file(pub_path)
            elif os.path.exists(pub_path):
                os.unlink(pub_path)
        except Exception:
            pass
        raise
