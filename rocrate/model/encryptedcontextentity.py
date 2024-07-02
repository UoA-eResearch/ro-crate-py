#!/usr/bin/env python

# Copyright 2024 The University of Auckland
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from typing import Any, List, Optional

from .contextentity import ContextEntity
from .entity import Entity
from ..utils import get_norm_value


class EncryptedContextEntity(ContextEntity):
    """EncryptedContextEntity
    
        An encrypted context entity is a subclass of ContextEntity designed to hold metadata fields
    that are sensitive in nature and should only be visible to selected people.

    Attributes:
        recipient_keys (List(str)): A list of the 'fingerprints' of keys that the entity should
            be encrypted against
    """


    def __init__(
        self,
        crate,
        identifier: Optional[Any] = None,
        properties: Optional[Any] = None,
    ) -> None:
        fingerprints = set()
        if pubkey_fingerprints:
            fingerprints.update(pubkey_fingerprints)
        if properties and properties.get("pubkey_fingerprints"):
            fingerprints.update([properties["pubkey_fingerprints"]])
            properties.pop("pubkey_fingerprints")
        self.pubkey_fingerprints = list(fingerprints)

        super().__init__(crate, identifier, properties)
