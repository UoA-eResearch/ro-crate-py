



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
        return f'At least one target lacks a valid key. Missing targets {self.missing_members}'

