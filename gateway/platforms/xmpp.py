"""XMPP gateway adapter.

Connects to any XMPP server via slixmpp (async XMPP library).
Supports OMEMO 1 end-to-end encryption for 1:1 chats, inbound/outbound
image support via XEP-0363 (HTTP File Upload) and XEP-0454 (OMEMO Media
Sharing), OOB data (XEP-0066), typing indicators, and message editing.

Environment variables:
    XMPP_JID                        Jabber ID (e.g. bot@example.com)
    XMPP_PASSWORD                   Password for the JID
    XMPP_NICKNAME                   Nickname in MUC rooms (default: "Hermes")
    XMPP_AUTO_JOIN                  Comma-separated MUC rooms to auto-join on connect
    XMPP_ALLOWED_USERS              Comma-separated JIDs allowed to interact
    XMPP_ALLOW_ALL_USERS            Set "true" to allow all users
    XMPP_REQUIRE_MENTION            Require @mention in MUC rooms (default: true)
    XMPP_HOME_ROOM                  Room JID for cron/notification delivery
    XMPP_OMEMO_ENABLED              Enable OMEMO encryption (default: "true")
    XMPP_ALLOW_PLAINTEXT_INBOUND    Accept incoming plaintext DMs (default: "false")
    XMPP_OMEMO_STORE_DIR            Override OMEMO store directory
                                    (default: ~/.hermes/platforms/xmpp/store)
"""

from __future__ import annotations

import asyncio
import logging
import mimetypes
import os
import re
from io import BytesIO
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import urlparse

from gateway.config import Platform, PlatformConfig
from gateway.platforms.base import (
    BasePlatformAdapter,
    MessageEvent,
    MessageType,
    SendResult,
    cache_image_from_url,
)

logger = logging.getLogger(__name__)

MAX_MESSAGE_LENGTH = 4000

_OMEMO_AVAILABLE = False
try:
    import slixmpp
    from slixmpp import JID
    _OMEMO_AVAILABLE = True
except ImportError:
    pass

try:
    import slixmpp
    from slixmpp import JID
except ImportError:
    slixmpp = None
    JID = str


def check_xmpp_requirements() -> bool:
    jid = os.getenv("XMPP_JID", "")
    password = os.getenv("XMPP_PASSWORD", "")
    if not jid or not password:
        logger.debug("XMPP: XMPP_JID or XMPP_PASSWORD not set")
        return False
    if slixmpp is None:
        logger.warning(
            "XMPP: slixmpp not installed. Run: pip install slixmpp"
        )
        return False
    return True


class _HermesXMPPClient(slixmpp.ClientXMPP):
    """Thin slixmpp ClientXMPP subclass that signals session start."""

    def __init__(self, jid: str, password: str, adapter: "XmppAdapter"):
        import ssl
        ssl_ctx = ssl.create_default_context()
        super().__init__(jid, password, ssl_context=ssl_ctx)
        self._adapter = adapter
        self.register_plugin("xep_0030")
        self.register_plugin("xep_0045")
        self.register_plugin("xep_0066")
        self.register_plugin("xep_0198")
        self.register_plugin("xep_0249")
        self.register_plugin("xep_0280")  # Message Carbons — echo to all user devices
        self.register_plugin("xep_0363")  # HTTP File Upload (images, audio, etc.)

        self._omemo_enabled = adapter._omemo_enabled

        if self._omemo_enabled and _OMEMO_AVAILABLE:
            from slixmpp.plugins.base import register_plugin as _rp
            from gateway.platforms._xmpp_omemo_plugin import HermesOMEMOPlugin
            _rp(HermesOMEMOPlugin)
            self.register_plugin("xep_0060")
            self.register_plugin("xep_0163")
            self.register_plugin("xep_0334")
            self.register_plugin("xep_0380")
            self.register_plugin(
                "xep_0384",
                pconfig={"store_dir": adapter._omemo_store_dir},
            )
            self.register_plugin("xep_0454")  # OMEMO Media Sharing (aesgcm://)

        self.add_event_handler("session_start", self._on_session_start)
        self.add_event_handler("message", self._on_message)
        self.add_event_handler("disconnected", self._on_disconnected)

    async def _on_session_start(self, event: Any) -> None:
        logger.info("XMPP: session started as %s", self.boundjid)
        try:
            self.send_presence()
            await self.get_roster()
            # Enable Message Carbons (XEP-0280) so outbound messages echo to all user devices
            try:
                self["xep_0280"].enable()
                logger.info("XMPP: Message Carbons (XEP-0280) enabled")
            except Exception as exc:
                logger.warning("XMPP: failed to enable Message Carbons: %s", exc)
        except Exception as exc:
            logger.warning("XMPP: error during session start: %s", exc)
        # Fire-and-forget: warm the XEP-0363 upload-service cache so the first
        # user-facing image upload doesn't pay the disco#info walk over the
        # server's (often graveyard-filled) advertised services.
        asyncio.create_task(self._adapter._prefetch_upload_service())
        self._adapter._connected_event.set()

    async def _on_message(self, msg: Any) -> None:
        await self._adapter._handle_xmpp_message(msg)

    async def _on_disconnected(self, event: Any) -> None:
        """Handle session-end disconnection and notify gateway for retry."""
        logger.warning("XMPP: received 'disconnected' event")
        await self._handle_connection_loss("session_end")

    async def _handle_connection_loss(self, reason: str) -> None:
        """Mark adapter disconnected and notify gateway when connection drops."""
        logger.warning("XMPP: entering _handle_connection_loss (reason=%s)", reason)
        was_connected = self._adapter.is_connected
        self._adapter._mark_disconnected()
        self._adapter._stop_watchdog()
        if was_connected:
            logger.warning("XMPP: connection lost unexpectedly (%s)", reason)
            self._adapter._set_fatal_error(
                "xmpp_connection_lost",
                f"XMPP connection lost unexpectedly ({reason})",
                retryable=True,
            )
            await self._adapter._notify_fatal_error()


class XmppAdapter(BasePlatformAdapter):
    """Gateway adapter for XMPP via slixmpp."""

    def __init__(self, config: PlatformConfig):
        super().__init__(config, Platform.XMPP)

        self._jid: str = config.extra.get("jid", "") or os.getenv("XMPP_JID", "")
        self._password: str = config.extra.get("password", "") or os.getenv("XMPP_PASSWORD", "")
        self._nickname: str = config.extra.get("nickname", "") or os.getenv("XMPP_NICKNAME", "Hermes")
        self._auto_join_raw: str = config.extra.get("auto_join", "") or os.getenv("XMPP_AUTO_JOIN", "")

        self._client: Optional[_HermesXMPPClient] = None
        self._connected_event: asyncio.Event = asyncio.Event()
        self._muc_joined: Set[str] = set()
        self._processed_ids: Set[str] = set()
        self._watchdog_task: Optional[asyncio.Task] = None
        self._watchdog_interval: float = 60.0

        self._require_mention: bool = os.getenv(
            "XMPP_REQUIRE_MENTION", "true"
        ).lower() not in ("false", "0", "no")

        self._omemo_enabled: bool = os.getenv(
            "XMPP_OMEMO_ENABLED", "true"
        ).lower() not in ("false", "0", "no")

        self._allow_plaintext_inbound: bool = os.getenv(
            "XMPP_ALLOW_PLAINTEXT_INBOUND", "false"
        ).lower() in ("true", "1", "yes")

        hermes_home = os.environ.get("HERMES_HOME", os.path.expanduser("~/.hermes"))
        self._omemo_store_dir: str = os.getenv(
            "XMPP_OMEMO_STORE_DIR",
            os.path.join(hermes_home, "platforms", "xmpp", "store"),
        )

        self._muc_blocked_logged: Set[str] = set()

        self._auto_join_rooms: List[str] = [
            r.strip() for r in self._auto_join_raw.split(",") if r.strip()
        ]

        if self._omemo_enabled and not _OMEMO_AVAILABLE:
            logger.warning(
                "XMPP: OMEMO requested but slixmpp-omemo not installed — "
                "falling back to plaintext. Run: pip install 'hermes-agent[xmpp]'"
            )
            self._omemo_enabled = False

    # ------------------------------------------------------------------
    # Connection lifecycle
    # ------------------------------------------------------------------

    async def connect(self) -> bool:
        if not self._jid or not self._password:
            logger.error("XMPP: JID or password not configured")
            return False

        if slixmpp is None:
            logger.error("XMPP: slixmpp not installed")
            return False

        self._client = _HermesXMPPClient(self._jid, self._password, self)
        self._connected_event.clear()

        try:
            self._client.connect()
        except Exception as exc:
            logger.error("XMPP: failed to initiate connection: %s", exc)
            return False

        try:
            await asyncio.wait_for(self._connected_event.wait(), timeout=30)
        except asyncio.TimeoutError:
            logger.error("XMPP: connection timed out after 30s")
            try:
                self._client.disconnect()
            except Exception:
                pass
            return False

        if self._omemo_enabled and _OMEMO_AVAILABLE:
            try:
                xep_0384 = self._client["xep_0384"]
                session_manager = await xep_0384.get_session_manager()
                own_device, other_devices = await session_manager.get_own_device_information()
                logger.info(
                    "XMPP: OMEMO session manager initialised (device_id=%s, trust=%s)",
                    own_device.device_id,
                    own_device.trust_level_name,
                )
            except Exception as exc:
                logger.warning("XMPP: OMEMO init failed, continuing without encryption: %s", exc)
                self._omemo_enabled = False

        for room in self._auto_join_rooms:
            await self._join_muc(room)

        self._mark_connected()
        self._start_watchdog()
        return True

    async def disconnect(self) -> None:
        self._stop_watchdog()
        self._running = False
        if self._client:
            if self._omemo_enabled and _OMEMO_AVAILABLE:
                try:
                    xep_0384 = self._client.plugin.get("xep_0384", None)
                    if xep_0384 is not None:
                        sm = await xep_0384.get_session_manager()
                        await sm.shutdown()
                except Exception:
                    pass
                try:
                    storage = getattr(xep_0384, "storage", None)
                    if storage is not None and hasattr(storage, "close"):
                        await storage.close()
                except Exception:
                    pass
            try:
                self._client.disconnect()
            except Exception:
                pass
            self._client = None
        logger.info("XMPP: disconnected")
        self._mark_disconnected()

    # ------------------------------------------------------------------
    # Watchdog
    # ------------------------------------------------------------------

    def _start_watchdog(self) -> None:
        if self._watchdog_task and not self._watchdog_task.done():
            return
        self._watchdog_task = asyncio.create_task(self._watchdog_loop())
        logger.debug("XMPP: transport watchdog started (%ss)", self._watchdog_interval)

    def _stop_watchdog(self) -> None:
        if self._watchdog_task and not self._watchdog_task.done():
            self._watchdog_task.cancel()
            self._watchdog_task = None
            logger.debug("XMPP: transport watchdog stopped")

    async def _watchdog_loop(self) -> None:
        """Periodically verify slixmpp transport is alive."""
        while self._running:
            try:
                await asyncio.sleep(self._watchdog_interval)
            except asyncio.CancelledError:
                return
            if not self._running:
                return
            client = self._client
            if not client:
                continue
            try:
                transport_alive = client.is_connected()
            except Exception:
                transport_alive = False
            if not transport_alive and self.is_connected:
                logger.warning(
                    "XMPP: watchdog detected dead transport (transport=%s), "
                    "forcing reconnect",
                    getattr(client, "transport", None),
                )
                self._mark_disconnected()
                self._set_fatal_error(
                    "xmpp_connection_lost",
                    "XMPP connection lost unexpectedly (watchdog)",
                    retryable=True,
                )
                await self._notify_fatal_error()
                return

    # ------------------------------------------------------------------
    # Send (with OMEMO encrypt-or-fail)
    # ------------------------------------------------------------------

    async def send(
        self,
        chat_id: str,
        content: str,
        reply_to: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> SendResult:
        if not content:
            return SendResult(success=True)

        if self._is_muc(chat_id):
            return SendResult(
                success=False,
                error="MUC OMEMO not implemented; refusing to send in cleartext",
            )

        chunks = self.truncate_message(content, MAX_MESSAGE_LENGTH)
        last_id = None

        for chunk in chunks:
            try:
                mtype = "chat"
                result = await self._send_omemo(chat_id, chunk, mtype, reply_to)
                if result is not None:
                    last_id = result
                    continue
            except Exception as exc:
                logger.error("XMPP: OMEMO encrypt failed for %s: %s", chat_id, exc)
                return SendResult(success=False, error=f"omemo: {exc}")

            try:
                msg = self._client.make_message(
                    mto=chat_id,
                    mbody=chunk,
                    mtype="chat",
                )
                if reply_to:
                    msg["replace"] = reply_to
                if bool(re.search(r"<[a-zA-Z/][^>]*>", chunk)):
                    msg["html"] = {"body": chunk}
                msg.send()
                last_id = msg["id"]
            except Exception as exc:
                logger.error("XMPP: failed to send to %s: %s", chat_id, exc)
                return SendResult(success=False, error=str(exc))

        return SendResult(success=True, message_id=last_id)

    async def _send_omemo(
        self,
        chat_id: str,
        plaintext: str,
        mtype: str,
        reply_to: Optional[str] = None,
        oob_url: Optional[str] = None,
        oob_desc: Optional[str] = None,
    ) -> Optional[str]:
        """Attempt OMEMO-encrypted send. Returns message ID on success, None if OMEMO not active.

        If *oob_url* is provided, an XEP-0066 OOB element is embedded in the
        encrypted stanza so that OMEMO-aware clients can render the image.
        """
        if not (self._omemo_enabled and _OMEMO_AVAILABLE and self._client):
            return None

        xep_0384 = self._client.plugin.get("xep_0384", None)
        if xep_0384 is None:
            return None

        from slixmpp.jid import JID as _JID
        import oldmemo

        msg = self._client.make_message(mto=chat_id, mtype=mtype)
        msg["body"] = plaintext
        if reply_to:
            msg["replace"] = reply_to

        encrypt_for = {_JID(chat_id)}
        logger.info("XMPP: _send_omemo — calling encrypt_message for %s (oob=%s)", chat_id, bool(oob_url))
        encrypted_msg, encryption_errors = await xep_0384.encrypt_message(msg, encrypt_for)

        if encryption_errors:
            for err in encryption_errors:
                logger.warning("XMPP OMEMO: non-critical encrypt error: %s", err)

        if encrypted_msg is None:
            logger.error("XMPP OMEMO: encrypt_message returned None for %s", chat_id)
            raise RuntimeError("OMEMO encryption produced no output")

        # slixmpp_omemo.encrypt_message() calls encrypted_message.clear(), which
        # wipes any OOB element set on the input.  For XEP-0454 (OMEMO Media
        # Sharing) the aesgcm:// URL is expected as a *plaintext* OOB element
        # alongside the OMEMO-encrypted body (file contents are already
        # encrypted via aesgcm).  Add OOB *after* encryption so it survives.
        if oob_url:
            encrypted_msg["oob"]["url"] = oob_url
            if oob_desc:
                encrypted_msg["oob"]["desc"] = oob_desc

        logger.info("XMPP: _send_omemo — encryption succeeded, sending stanza for %s", chat_id)
        encrypted_msg["eme"]["namespace"] = oldmemo.oldmemo.NAMESPACE
        encrypted_msg["eme"]["name"] = self._client["xep_0380"].mechanisms[oldmemo.oldmemo.NAMESPACE]
        encrypted_msg.enable("no-store")
        encrypted_msg.send()
        logger.info("XMPP: _send_omemo — stanza sent for %s, msg_id=%s", chat_id, encrypted_msg["id"])
        return encrypted_msg["id"]

    # ------------------------------------------------------------------
    # send_image (OOB for remote URLs; local files use send_image_file)
    # ------------------------------------------------------------------

    async def send_image(
        self,
        chat_id: str,
        image_url: str,
        caption: Optional[str] = None,
        reply_to: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> SendResult:
        """Send an image URL via XEP-0066 OOB data embedded in the message.

        For local files, use ``send_image_file`` which uploads via XEP-0363
        (and encrypts via XEP-0454 when OMEMO is active).

        When OMEMO is active, this sends the URL embedded in the OMEMO body
        alongside the OOB element (plaintext in the stanza).  This is the
        same compromise as regular OOB images in OMEMO sessions — the URL
        is visible in the unencrypted OOB element, but the message body
        containing it is encrypted.
        """
        if not self._client:
            return SendResult(success=False, error="Not connected")

        if self._is_muc(chat_id):
            return SendResult(
                success=False,
                error="MUC OMEMO not implemented; refusing to send image in cleartext",
            )

        if self._omemo_enabled:
            logger.info(
                "XMPP: send_image — OOB URL in OMEMO session for %s "
                "(plaintext URL in stanza, encrypted in body)",
                chat_id,
            )

        body = caption or image_url

        # For 1:1 OMEMO sessions, encrypt the body with OOB inline.
        if self._omemo_enabled and not self._is_muc(chat_id):
            try:
                msg_id = await self._send_omemo(
                    chat_id,
                    body,
                    "chat",
                    reply_to=reply_to,
                    oob_url=image_url,
                    oob_desc=caption,
                )
                if msg_id is not None:
                    return SendResult(success=True, message_id=msg_id)
            except Exception as exc:
                logger.warning(
                    "XMPP: OMEMO-encrypted OOB send failed, falling back: %s", exc
                )

        # Fallback: plaintext OOB stanza (MUC or OMEMO unavailable)
        try:
            msg = self._client.make_message(
                mto=chat_id,
                mbody=body,
                mtype="chat",
            )
            if reply_to:
                msg["replace"] = reply_to

            msg["oob"]["url"] = image_url
            if caption:
                msg["oob"]["desc"] = caption

            msg.send()
            return SendResult(success=True, message_id=msg["id"])
        except Exception as exc:
            logger.warning("XMPP: OOB send failed, falling back to text: %s", exc)
            text = f"{caption}\n{image_url}" if caption else image_url
            return await self.send(chat_id, content=text, reply_to=reply_to)

    # ------------------------------------------------------------------
    # File upload helpers (XEP-0363 + XEP-0454)
    # ------------------------------------------------------------------

    async def _prefetch_upload_service(self, timeout: float = 5.0) -> None:
        """Warm slixmpp's XEP-0363 upload-service cache.

        slixmpp's :meth:`XEP_0363.upload_file` lazily calls
        :meth:`find_upload_service` on first use, which fans out
        ``disco#info`` to every service advertised by the server.  On hosts
        with dead legacy services (e.g. jabb.im's ``smtp-t.netlab.cz``,
        ``dict.jabbim.cz``), that walk blocks for 40-60s on each
        unresponsive sibling.  Resolving the service once at session start
        moves that latency off the user-facing send path.
        """
        if not self._client:
            return
        try:
            upload = self._client["xep_0363"]
        except Exception:
            return
        if getattr(upload, "upload_service", None) is not None:
            return
        try:
            info_iq = await upload.find_upload_service(timeout=timeout)
        except Exception as exc:
            logger.warning("XMPP: upload-service prefetch failed: %s", exc)
            return
        if info_iq is None:
            logger.warning("XMPP: upload-service prefetch found no service in %.0fs", timeout)
            return
        upload.upload_service = info_iq["from"]
        for form in info_iq["disco_info"].iterables:
            values = form["values"]
            if values.get("FORM_TYPE") == ["urn:xmpp:http:upload:0"]:
                try:
                    upload.max_file_size = int(values["max-file-size"])
                except (TypeError, ValueError):
                    upload.max_file_size = float("+inf")
                break
        logger.info(
            "XMPP: upload service prefetched: %s (max_file_size=%s)",
            upload.upload_service,
            getattr(upload, "max_file_size", "?"),
        )

    async def _upload_file(
        self,
        file_path: str,
        content_type: Optional[str] = None,
        encrypt: bool = False,
    ) -> Tuple[str, Optional[str]]:
        """Upload a local file via XEP-0363 HTTP File Upload.

        If *encrypt* is True and XEP-0454 is available, the file is
        AES-256-GCM encrypted before upload (OMEMO Media Sharing) and
        the returned URL uses the ``aesgcm://`` scheme.

        Returns:
            (url, fragment) — url is the public (or aesgcm) download link.
            fragment is the hex-encoded IV+key when encrypted, None otherwise.

        Raises on upload failure so callers can fall back gracefully.
        """
        if not self._client:
            raise RuntimeError("XMPP client not connected")

        path = Path(file_path)
        if not path.is_file():
            raise FileNotFoundError(f"File not found: {file_path}")

        size = path.stat().st_size

        if content_type is None:
            content_type, _ = mimetypes.guess_type(str(path))
        if content_type is None:
            content_type = "application/octet-stream"

        if encrypt and self._omemo_enabled and _OMEMO_AVAILABLE:
            from slixmpp.plugins.xep_0454 import XEP_0454

            try:
                aesgcm_url = await self._client["xep_0454"].upload_file(
                    filename=path,
                    content_type=content_type,
                    timeout=10,
                )
                # aesgcm:// URLs contain the fragment (IV+key) after '#'
                # The URL format is: aesgcm://host/path#iv_key_hex
                # For decrypt we need the https URL and fragment separately
                logger.info(
                    "XMPP: XEP-0454 encrypted upload succeeded for %s → %s",
                    path.name,
                    aesgcm_url[:60] + "…" if len(aesgcm_url) > 60 else aesgcm_url,
                )
                return aesgcm_url, None  # fragment is embedded in the URL
            except Exception as exc:
                logger.warning(
                    "XMPP: XEP-0454 upload failed, falling back to plaintext: %s", exc
                )
                # Fall through to plaintext upload below

        # Plaintext upload via XEP-0363
        url = await self._client["xep_0363"].upload_file(
            filename=path,
            size=size,
            content_type=content_type,
            timeout=10,
        )
        logger.info(
            "XMPP: XEP-0363 upload succeeded for %s → %s",
            path.name,
            url[:60] + "…" if len(url) > 60 else url,
        )
        return url, None

    async def send_image_file(
        self,
        chat_id: str,
        image_path: str,
        caption: Optional[str] = None,
        reply_to: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> SendResult:
        """Send a local image file via XEP-0363 upload + OOB (or XEP-0454 if OMEMO).

        Falls back to base-class text behaviour if upload fails.
        """
        if not self._client:
            return SendResult(success=False, error="Not connected")

        encrypt = self._omemo_enabled and not self._is_muc(chat_id)

        try:
            url, fragment = await self._upload_file(
                image_path,
                content_type=None,  # auto-detect from extension
                encrypt=encrypt,
            )
        except Exception as exc:
            logger.warning(
                "XMPP: image upload failed, falling back to text: %s", exc
            )
            # Fall back to base class (prints path as text)
            text = f"🖼️ Image: {image_path}"
            if caption:
                text = f"{caption}\n{text}"
            return await self.send(chat_id, content=text, reply_to=reply_to)

        if url.startswith("aesgcm://"):
            # XEP-0454 encrypted upload: the URL contains the fragment (IV+key).
            # Per XEP-0454 §4.1, the message body MUST be the URL alone so
            # receiving clients recognize the media-share pattern.  Captions are
            # sent as a separate text message before the image.
            if caption:
                # Best-effort caption delivery; ignore failure so the image still goes out.
                try:
                    await self.send(chat_id, content=caption, reply_to=reply_to)
                except Exception as exc:
                    logger.warning("XMPP: caption send failed (continuing with image): %s", exc)

            # In an OMEMO session, use _send_omemo so the body is encrypted.
            if self._omemo_enabled and not self._is_muc(chat_id):
                try:
                    logger.info(
                        "XMPP: send_image_file — calling _send_omemo for %s "
                        "(aesgcm URL, oob_url=%s)",
                        chat_id,
                        url[:60] + "…" if len(url) > 60 else url,
                    )
                    msg_id = await asyncio.wait_for(
                        self._send_omemo(
                            chat_id,
                            url,  # body = URL only (XEP-0454)
                            "chat",
                            reply_to=reply_to,
                            oob_url=url,  # plaintext OOB so non-OMEMO clients render too
                        ),
                        timeout=30.0,  # 30s timeout for OMEMO encrypt + send
                    )
                    if msg_id is not None:
                        logger.info(
                            "XMPP: send_image_file — OMEMO aesgcm send succeeded, msg_id=%s",
                            msg_id,
                        )
                        return SendResult(success=True, message_id=msg_id)
                    logger.warning(
                        "XMPP: send_image_file — _send_omemo returned None for %s, "
                        "falling back to plaintext OOB",
                        chat_id,
                    )
                except asyncio.TimeoutError:
                    logger.warning(
                        "XMPP: OMEMO-encrypted aesgcm send timed out (30s) for %s, "
                        "falling back to plaintext OOB",
                        chat_id,
                    )
                except Exception as exc:
                    logger.warning(
                        "XMPP: OMEMO-encrypted aesgcm send failed, falling back to plaintext OOB: %s",
                        exc,
                    )
                    # Fall through to plaintext OOB below

            # Plaintext OOB stanza (MUC, or OMEMO unavailable/failed)
            msg = self._client.make_message(
                mto=chat_id,
                mbody=url,
                mtype="chat",
            )
            msg["oob"]["url"] = url  # aesgcm:// URL with fragment for XEP-0454 clients
            if reply_to:
                msg["replace"] = reply_to
            msg.send()
            return SendResult(success=True, message_id=msg["id"])

        # Plaintext OOB (or OMEMO session with plaintext URL — logged)
        if self._omemo_enabled and not self._is_muc(chat_id):
            logger.info(
                "XMPP: sending image URL via plaintext OOB in OMEMO session "
                "(XEP-0454 upload failed or disabled)"
            )
        return await self.send_image(
            chat_id, url, caption=caption, reply_to=reply_to, metadata=metadata
        )

    # ------------------------------------------------------------------
    # Typing / edit / misc
    # ------------------------------------------------------------------

    async def send_typing(self, chat_id: str, metadata=None) -> None:
        if not self._client:
            return
        try:
            from slixmpp.xmlstream import ET as _ET

            chat_state = _ET.Element("{urn:xmpp:chat-markers:0}composing")
            msg = self._client.make_message(
                mto=chat_id,
                mtype="groupchat" if self._is_muc(chat_id) else "chat",
            )
            msg.append(chat_state)
            msg.send()
        except Exception:
            pass

    async def edit_message(
        self, chat_id: str, message_id: str, content: str, *, finalize: bool = False
    ) -> SendResult:
        try:
            msg = self._client.make_message(
                mto=chat_id,
                mbody=content,
                mtype="groupchat" if self._is_muc(chat_id) else "chat",
            )
            msg["replace"] = message_id
            msg.send()
            return SendResult(success=True, message_id=msg["id"])
        except Exception as exc:
            return SendResult(success=False, error=str(exc))

    async def get_chat_info(self, chat_id: str) -> Dict[str, Any]:
        chat_type = "group" if self._is_muc(chat_id) else "dm"
        name = chat_id.split("@")[0] if "@" in chat_id else chat_id
        return {"name": name, "type": chat_type}

    def format_message(self, content: str) -> str:
        content = re.sub(r"!\[([^\]]*)\]\(([^)]+)\)", r"\2", content)
        return content

    def _is_muc(self, chat_id: str) -> bool:
        return chat_id in self._muc_joined or (
            "conference" in chat_id.lower() or "muc" in chat_id.lower()
        )

    async def _join_muc(self, room_jid: str) -> None:
        if not self._client:
            return
        try:
            self._client.plugin["xep_0045"].join_muc(
                room_jid, self._nickname
            )
            self._muc_joined.add(room_jid)
            logger.info("XMPP: joined MUC %s", room_jid)
        except Exception as exc:
            logger.warning("XMPP: failed to join MUC %s: %s", room_jid, exc)

    # ------------------------------------------------------------------
    # Inbound message handler (with OMEMO decrypt-or-drop)
    # ------------------------------------------------------------------

    async def _extract_oob(self, msg: Any) -> Tuple[Optional[str], Optional[str]]:
        """Extract OOB URL and description from an XMPP message stanza.

        Works on both raw and decrypted (OMEMO) Message stanzas via the
        slixmpp ``msg["oob"]["url"]`` / ``msg["oob"]["desc"]`` accessors.
        """
        try:
            oob_url = msg["oob"]["url"] if msg["oob"] else None
            oob_desc = msg["oob"]["desc"] if msg["oob"] else None
            if oob_url:
                return oob_url, oob_desc
        except Exception:
            pass
        return None, None

    def _detect_aesgcm(self, body: str) -> Optional[str]:
        """If *body* contains an aesgcm:// URL, return it.  Otherwise None."""
        if not body:
            return None
        for part in body.split():
            if part.startswith("aesgcm://"):
                return part
        return None

    async def _decrypt_aesgcm_url(self, aesgcm_url: str) -> Optional[str]:
        """Download and decrypt an aesgcm:// URL (XEP-0454).

        Returns a local cache path for the decrypted file, or None on failure.
        """
        if not _OMEMO_AVAILABLE:
            return None
        try:
            from slixmpp.plugins.xep_0454 import XEP_0454

            # aesgcm://host/path#iv_key_hex  →  https://host/path
            https_url = "https://" + aesgcm_url[len("aesgcm://"):]
            fragment = None
            hash_idx = https_url.find("#")
            if hash_idx != -1:
                fragment = https_url[hash_idx + 1 :]
                https_url = https_url[:hash_idx]

            if not fragment or len(fragment) != 88:
                logger.warning("XMPP: aesgcm URL has invalid fragment (need 88 hex chars)")
                return None

            # Download the ciphertext
            import httpx

            async with httpx.AsyncClient(timeout=30.0, follow_redirects=True) as client:
                resp = await client.get(https_url)
                resp.raise_for_status()
                ciphertext = resp.content

            # Decrypt
            from io import BytesIO

            encrypted_file = BytesIO(ciphertext)
            plaintext = XEP_0454.decrypt(encrypted_file, fragment)

            # Save decrypted bytes directly to cache
            from gateway.platforms.base import cache_image_from_bytes

            ext = os.path.splitext(urlparse(https_url).path)[1] or ".jpg"
            local_path = cache_image_from_bytes(plaintext, ext)
            logger.info(
                "XMPP: decrypted aesgcm image → %s (%d bytes)", local_path, len(plaintext)
            )
            return local_path
        except Exception as exc:
            logger.warning("XMPP: failed to decrypt aesgcm URL: %s", exc)
            return None

    async def _process_inbound_media(
        self,
        oob_url: Optional[str],
        aesgcm_url: Optional[str],
    ) -> Tuple[Optional[str], Optional[str]]:
        """Download and cache an inbound image (plain OOB or aesgcm).

        Returns (local_path, media_type) or (None, None) on failure.
        """
        # Prefer aesgcm (encrypted) over plain OOB
        if aesgcm_url:
            local = await self._decrypt_aesgcm_url(aesgcm_url)
            if local:
                ext = os.path.splitext(urlparse(aesgcm_url).path)[1] or ".jpg"
                mime = mimetypes.guess_type(f"file{ext}")[0] or "image/jpeg"
                return local, mime
            # Decryption failed — fall through to try plain OOB

        if oob_url:
            try:
                ext = os.path.splitext(urlparse(oob_url).path)[1] or ".jpg"
                local = await cache_image_from_url(oob_url, ext=ext)
                mime = mimetypes.guess_type(f"file{ext}")[0] or "image/jpeg"
                return local, mime
            except Exception as exc:
                logger.warning("XMPP: failed to download OOB image %s: %s", oob_url, exc)
                return None, None

        return None, None

    async def _handle_xmpp_message(self, msg: Any) -> None:
        if msg["type"] == "error":
            return

        sender = str(msg["from"])
        msg_id = msg["id"]

        own_jid_bare = self._jid.split("/")[0]
        sender_bare = sender.split("/")[0]
        if sender_bare == own_jid_bare:
            return

        if msg_id and msg_id in self._processed_ids:
            return
        if msg_id:
            self._processed_ids.add(msg_id)

        is_muc = msg["type"] == "groupchat"

        # --- Decrypt OMEMO if present and enabled ---
        if self._omemo_enabled and _OMEMO_AVAILABLE:
            xep_0384 = self._client.plugin.get("xep_0384", None)
            if xep_0384 is not None:
                namespaces = xep_0384.is_encrypted(msg)
                if namespaces:
                    try:
                        decrypted_msg, device_info = await xep_0384.decrypt_message(msg)
                        body = decrypted_msg["body"]
                        # Extract OOB from decrypted stanza
                        oob_url, oob_desc = await self._extract_oob(decrypted_msg)
                        aesgcm_url = self._detect_aesgcm(body) or (
                            self._detect_aesgcm(oob_url) if oob_url else None
                        )

                        # If no body but has image, treat as photo
                        if not body or not body.strip():
                            if oob_url or aesgcm_url:
                                # Deduplicate: if body is just the aesgcm URL, use desc
                                text = oob_desc or "📷 Image"
                            else:
                                return  # truly empty

                        if is_muc:
                            logger.info("XMPP: dropping decrypted MUC message (MUC OMEMO not implemented)")
                            return

                        # Download and cache media if present
                        media_path, media_type = await self._process_inbound_media(
                            oob_url, aesgcm_url
                        )
                        text = (body or "").strip() or (oob_desc or oob_url or "📷 Image")
                        message_type = MessageType.TEXT
                        media_urls = []
                        media_types = []
                        if media_path:
                            message_type = MessageType.PHOTO
                            media_urls = [media_path]
                            media_types = [media_type or "image/jpeg"]

                        await self._handle_dm_message(
                            msg, sender, text, msg_id,
                            media_urls=media_urls, media_types=media_types,
                            message_type=message_type,
                        )
                        return
                    except Exception as exc:
                        logger.warning(
                            "XMPP: OMEMO decrypt failed from %s: %s — "
                            "sending handshake-hint",
                            sender_bare, exc,
                        )
                        await self._send_decrypt_failure_hint(sender_bare)
                        return
                else:
                    # No OMEMO envelope on the message
                    body = msg["body"]
                    oob_url, oob_desc = await self._extract_oob(msg)
                    aesgcm_url = self._detect_aesgcm(body) or (
                        self._detect_aesgcm(oob_url) if oob_url else None
                    )

                    if not body or not body.strip():
                        if oob_url or aesgcm_url:
                            # Image-only message from non-OMEMO contact
                            text = oob_desc or oob_url or "📷 Image"
                        else:
                            return  # truly empty
                    else:
                        text = body.strip()

                    if is_muc:
                        return
                    if self._allow_plaintext_inbound:
                        logger.warning(
                            "XMPP: accepting plaintext DM from %s (insecure)",
                            sender_bare,
                        )
                        # Download and cache media if present
                        media_path, media_type = await self._process_inbound_media(
                            oob_url, aesgcm_url
                        )
                        message_type = MessageType.TEXT
                        media_urls = []
                        media_types = []
                        if media_path:
                            message_type = MessageType.PHOTO
                            media_urls = [media_path]
                            media_types = [media_type or "image/jpeg"]
                        await self._handle_dm_message(
                            msg, sender, text, msg_id,
                            media_urls=media_urls, media_types=media_types,
                            message_type=message_type,
                        )
                        return
                    logger.info(
                        "XMPP: dropping plaintext DM from %s (OMEMO required)",
                        sender_bare,
                    )
                    return

        # --- Fallback: no OMEMO, process normally ---
        body = msg["body"]
        oob_url, oob_desc = await self._extract_oob(msg)
        aesgcm_url = self._detect_aesgcm(body) or (
            self._detect_aesgcm(oob_url) if oob_url else None
        )

        if not body or not body.strip():
            if oob_url or aesgcm_url:
                text = oob_desc or oob_url or "📷 Image"
            else:
                return  # truly empty
        else:
            text = body.strip()

        # Download and cache media if present
        media_path, media_type = await self._process_inbound_media(oob_url, aesgcm_url)
        media_urls = []
        media_types = []
        message_type = MessageType.TEXT
        if media_path:
            message_type = MessageType.PHOTO
            media_urls = [media_path]
            media_types = [media_type or "image/jpeg"]

        if is_muc:
            await self._handle_muc_message(
                msg, sender, text, msg_id,
                media_urls=media_urls, media_types=media_types,
                message_type=message_type,
            )
        else:
            await self._handle_dm_message(
                msg, sender, text, msg_id,
                media_urls=media_urls, media_types=media_types,
                message_type=message_type,
            )

    # ------------------------------------------------------------------
    # Plaintext handlers
    # ------------------------------------------------------------------

    async def _handle_dm_message(
        self,
        msg: Any,
        sender: str,
        body: str,
        msg_id: str,
        media_urls: Optional[List[str]] = None,
        media_types: Optional[List[str]] = None,
        message_type: MessageType = MessageType.TEXT,
    ) -> None:
        sender_bare = sender.split("/")[0]
        display_name = sender_bare.split("@")[0]

        source = self.build_source(
            chat_id=sender_bare,
            chat_type="dm",
            user_id=sender_bare,
            user_name=display_name,
        )
        event = MessageEvent(
            text=body.strip(),
            message_type=message_type,
            source=source,
            message_id=msg_id,
            media_urls=media_urls or [],
            media_types=media_types or [],
        )
        await self.handle_message(event)

    async def _handle_muc_message(
        self,
        msg: Any,
        sender: str,
        body: str,
        msg_id: str,
        media_urls: Optional[List[str]] = None,
        media_types: Optional[List[str]] = None,
        message_type: MessageType = MessageType.TEXT,
    ) -> None:
        room_jid = str(msg["from"].bare)
        nick = str(msg["from"].resource)

        own_nick = self._nickname
        if nick == own_nick:
            return

        if self._require_mention and own_nick.lower() not in body.lower():
            return

        cleaned_body = re.sub(
            re.compile(re.escape(own_nick), re.IGNORECASE), "", body
        ).strip()
        if not cleaned_body:
            cleaned_body = body.strip()

        sender_jid = sender
        display_name = nick

        source = self.build_source(
            chat_id=room_jid,
            chat_type="group",
            user_id=sender_jid,
            user_name=display_name,
        )
        event = MessageEvent(
            text=cleaned_body,
            message_type=message_type,
            source=source,
            message_id=msg_id,
            media_urls=media_urls or [],
            media_types=media_types or [],
        )
        await self.handle_message(event)

    # ------------------------------------------------------------------
    # Decrypt failure hint
    # ------------------------------------------------------------------

    _decrypt_hint_sent: Set[str] = set()

    async def _send_decrypt_failure_hint(self, bare_jid: str) -> None:
        """Send a one-time cleartext hint when OMEMO decryption fails."""
        if bare_jid in self._decrypt_hint_sent:
            return
        self._decrypt_hint_sent.add(bare_jid)
        if not self._client:
            return
        try:
            msg = self._client.make_message(
                mto=bare_jid,
                mbody="[Hermes] OMEMO session handshake failed — "
                "please re-establish the session from your client.",
                mtype="chat",
            )
            msg.send()
        except Exception:
            pass