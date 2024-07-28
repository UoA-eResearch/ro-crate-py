#utilities for use in encryption and key management
from typing import Optional

from .model import Entity
from .utils import get_norm_value


class NoValidKeysError(ValueError):
    "Raised if encrypting or sigining and no valid public/private keys are avaibale"
    def __init__(self, message):            
        super().__init__(message)
        self.message=message
    def __str__(self):
        return f'No target has a valid public key for encryption.{self.message}'


class MissingMemberException(Exception):
    "Raised if sigining to a set of members and one is missing a key"
    def __init__(self, message):            
        super().__init__(message)
    def __str__(self):
        return 'At least one target lacks a valid key, or cannot be found in the graph'

def combine_recipient_keys(target_entity: Entity, allow_missing: Optional[bool]=False) -> list[str]:
    """Return the complete set of all keys found on this entity and it's recipients

    Returns:
        list[str]: all pubkeyfingerprints of this entity and it's recipients
    """
    if recipients := get_norm_value(target_entity, "recipients"):
        recipient_keys = []
        missing_member = False
        for recipient in recipients:
            if recipient_entity := target_entity.crate.dereference(recipient):
                if keys := get_norm_value(recipient_entity,"pubkey_fingerprints"):
                    recipient_keys.extend(keys)
                    continue
            missing_member = True
        recipient_keys = list(set(recipient_keys))
        if not allow_missing and missing_member:
            raise MissingMemberException(f"one or more recipients of {target_entity.id} are missing public keys")
        if len(recipient_keys) > 0:
            return recipient_keys
    raise NoValidKeysError(message=f"No Keys found for {target_entity.id}")


