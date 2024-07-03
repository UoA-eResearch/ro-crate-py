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

from typing import List, Optional, Dict, Any
import uuid
from pydantic import BaseModel
from .contextentity import ContextEntity

class EncryptedGraphMessage(ContextEntity):

    """EncryptedGraphMessage

        An encrypted graph message is holds encrypted sensitive data as it is written to the 
    RO-Crate metadata file.


    Attributes:
        pubkey_fingerprints (List[Pubkey_Object]) : the public keys of the recipients.
        encrypted_graph (str) : the aggregated and encrypted portion of the RO-Crate @graph.
        identifier (Optional[str]) : the identifier of this element in the RO-Crate @encrypted
                = Default: None,
        action_type: (Optional[str]) : the action as defined in the context e.g.(SendAction)
            = Default: "SendAction",
        recipients (List[PubkeyObeject]): a list of keys, algorithims and user ids 
            this block is encrypted to.
        method (Optional[str]) : the message packaging format (e.g. openPGP https://doi.org/10.17487/RFC4880)
    """

    def __init__(self,
        crate,
        identifier: Optional[str] = None,
        properties: Optional[Any] = None,
        encrypted_graph: Optional[str] = None
    ):
        if encrypted_graph:
            properties["encryptedGraph"] = encrypted_graph
        super().__init__(crate, identifier, properties)


    def _empty(self) -> Dict:
        val = {
            "@id": self.id,
            "@type": ["SendAction", "EncryptedGraphMessage"],
            "actionStatus":"PotentialActionStatus"
            #"conformsTo":"profileURI"
        }
        return val


