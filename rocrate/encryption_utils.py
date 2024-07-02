

from .model import Entity, keyholder

class NoValidKeysError(ValueError):
    "Raised if encrypting or sigining and no valid public/private keys are avaibale"
    def __init__(self, message, errors):            
        super().__init__(message)
        self.errors = errors
    def __str__(self):
        return f'No target has a valid public key for encryption.{self.errors}'


class MissingMemberException(Exception):
    "Raised if sigining to a set of members and one is missing a key"
    def __init__(self, message, missing_members: Optional[list[str]]):            
        super().__init__(message)
        self.missing_members = missing_members
    def __str__(self):
        return f'At least one target lacks a valid key, or cannot be found in the graph. Missing targets {self.missing_members}'

def combine_recipient_keys(target_entity: Entity) -> list[str]:
    """Retrun the complete set of all keys found on this entity and it's recipients

    Returns:
        list[str]: all pubkeyfingerprints of this entity and it's recipients
    """
    def get_recipient_keys(entity:Entity) -> list[str]:
        recipient_fingerprints = get_norm_value(entity,"pubkey_fingerprints")
        if not recipient_fingerprints:
            raise MissingMemberException("No Key for recipient", missing_members=entity.id)
        return recipient_fingerprints or []


    if recipients := get_norm_value(self, "recipients"):
        recipient_keys = []
        for recipient in recipients:
            if recipient_entity := self.crate.dereference(recipient):
                recipient_keys.extend(get_recipient_keys(recipient_entity))
            else:
                raise MissingMemberException("recipient not in graph",missing_members=recipient)
        recipient_keys = list(set(recipient_keys))
        if len(recipient_keys > 0):
            return recipient_keys
    raise NoValidKeysError(f"No Keys found for {entity.id}")
    return []

