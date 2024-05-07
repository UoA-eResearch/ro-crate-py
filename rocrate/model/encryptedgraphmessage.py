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

from typing import List, Optional, Dict
import uuid
from pydantic import BaseModel


class PubkeyObject(BaseModel):
    """Pubkey_Object

    A class for holding public key information as it will be written into the RO-Crate

    Attributes:
        method(str):the algorithim used to generate the key
        key(str): the public key or it's fingerprint
    """
    method:str
    key:str

    @property
    def combined(self) -> str:
        return f"{self.key}:{self.method}"

class EncryptedGraphMessage():

    """EncryptedGraphMessage

        An encrypted graph message is holds encrypted sensitive data as it is written to the 
    RO-Crate metadata file.


    Attributes:
        pubkey_fingerprints (List[Pubkey_Object]) : the public keys of the recipents.
        encrypted_graph (str) : the aggregated and encrypted portion of the RO-Crate @graph.
        identifier (Optional[str]) : the identifier of this element in the RO-Crate @encrypted
                = Default: None,
        action_type: (Optional[str]) : the action as defined in the context e.g.(SendAction)
            = Default: "SendAction",
    """

    def __init__(self,
        pubkey_fingerprints: List[PubkeyObject],
        encrypted_graph: str,
        identifier:Optional[str] = None,
        action_type: Optional[str] = None,
    ):
        if identifier:
            self.id = str(identifier)
        else:
            self.id = f"#{uuid.uuid4()}"
        if action_type:
            self.action_type = action_type
        else:
            self.action_type = "SendAction"

        self.recipents = [{"@id":fingerprint.key,"method":fingerprint.method} for
             fingerprint in pubkey_fingerprints]
        self.encrypted_graph = encrypted_graph

    def output_entity(self) -> Dict:
        """Output the graph entity to be written directly into the crate

        Returns:
            Dict: the encrypted graph entity's key information to be serialized to json
        """
        output_info =  {
            "@id":self.id,
            "@type":self.action_type,
            "recipents":self.recipents,
            "encrypted_graph":self.encrypted_graph,
            }
        return output_info
