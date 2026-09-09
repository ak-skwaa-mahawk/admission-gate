from dataclasses import dataclass, field, asdict
from typing import Any, Dict, Optional
import json

@dataclass(frozen=True)
class ActionEnvelope:
    action_type: str
    principal: str
    target_resource: str
    payload: Dict[str, Any] = field(default_factory=dict)

    def to_json(self) -> str:
        return json.dumps(asdict(self))

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ActionEnvelope":
        return cls(
            action_type=data.get("action_type", "SHELL_EXEC"),
            principal=data.get("principal", "UNKNOWN_AGENT"),
            target_resource=data.get("target_resource", ""),
            payload=data.get("payload", {})
        )

@dataclass(frozen=True)
class AuthorityVerdict:
    allowed: bool
    regime: str
    charter_hash: str
    attestation: Optional[str] = None
    error: Optional[str] = None

    def to_json(self) -> str:
        return json.dumps(asdict(self))

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "AuthorityVerdict":
        return cls(
            allowed=bool(data.get("allowed", False)),
            regime=data.get("regime", "STATUTORY_BREACH"),
            charter_hash=data.get("charter_hash", ""),
            attestation=data.get("attestation"),
            error=data.get("error")
        )
