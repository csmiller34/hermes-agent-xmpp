"""OMEMO plugin subclass for the Hermes XMPP adapter.

Provides the XEP_0384 plugin implementation that slixmpp-omemo requires,
configured for Blind Trust Before Verification (BTBV) and backed by our
SQLite storage.

This module is imported conditionally — only when slixmpp-omemo is
available — so the rest of the adapter degrades gracefully on systems
without the OMEMO libraries.
"""

from __future__ import annotations

import logging
from typing import FrozenSet, Optional

from omemo.types import DeviceInformation

from slixmpp_omemo import TrustLevel, XEP_0384

from gateway.platforms._xmpp_omemo_storage import HermesOMEMOStorage

log = logging.getLogger(__name__)


class HermesOMEMOPlugin(XEP_0384):
    """Hermes-specific XEP_0384 implementation.

    Uses :class:`HermesOMEMOStorage` (SQLite) and enables BTBV so that
    the first device seen for each JID is automatically trusted, while
    subsequent new devices require manual verification.

    To instantiate this plugin, register it via
    ``client.register_plugin("xep_0384", module=sys.modules[__name__])``
    (or by passing the module that contains this class).

    The ``json_file_path`` default config key is ignored — we always use
    SQLite.  If callers pass ``store_dir``, it is forwarded to
    :class:`HermesOMEMOStorage`.
    """

    default_config = {
        "fallback_message": "This message is OMEMO encrypted.",
        "store_dir": None,
    }

    def plugin_init(self) -> None:
        store_dir: Optional[str] = self.config.get("store_dir", None)
        self.__storage = HermesOMEMOStorage(db_path=None if store_dir is None else None)
        if store_dir is not None:
            import os
            os.makedirs(store_dir, exist_ok=True)
            self.__storage = HermesOMEMOStorage(
                db_path=os.path.join(store_dir, "omemo.db")
            )
        super().plugin_init()

    @property
    def storage(self) -> HermesOMEMOStorage:
        return self.__storage

    @property
    def _btbv_enabled(self) -> bool:
        return True

    async def _devices_blindly_trusted(
        self,
        blindly_trusted: FrozenSet[DeviceInformation],
        identifier: Optional[str],
    ) -> None:
        names = ", ".join(
            f"{d.bare_jid}/{d.device_id}" for d in blindly_trusted
        )
        log.info("XMPP OMEMO: blindly trusted devices: %s (context=%s)", names, identifier)

    async def _prompt_manual_trust(
        self,
        manually_trusted: FrozenSet[DeviceInformation],
        identifier: Optional[str],
    ) -> None:
        for device in manually_trusted:
            log.warning(
                "XMPP OMEMO: manual trust required for %s/%s — "
                "auto-distrusting until verified (use 'hermes xmpp omemo trust')",
                device.bare_jid,
                device.device_id,
            )
            await self.set_trust(
                device.bare_jid,
                device.identity_key,
                TrustLevel.DISTRUSTED.value,
            )