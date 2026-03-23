from dataclasses import dataclass
from typing import Optional

@dataclass
class Envelope:
    msg_id: str
    client_msg_id: str
    from_device_id: str
    to_device_id: str
    type: str  # "direct" | "control" | later: "group"
    header_b64: str
    ciphertext_b64: str
    created_at_ms: int
    ttl_seconds: int = 7 * 24 * 3600
    group_id: Optional[str] = None