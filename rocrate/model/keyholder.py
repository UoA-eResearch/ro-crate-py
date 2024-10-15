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

from typing import Any, Dict, List, Optional

import re
import warnings
from gnupg import GPG
from pydantic import BaseModel

from . import ContextEntity

HPK_STUB = "/pks/lookup?op=index&exact=true&search="
EMAIL_RE = re.compile(r"(^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$)")
NO_VALID_EMAIL = "No Valid Email"

class KeyserverWarning(Warning):
    pass

class PubkeyObject(BaseModel):
    """Pubkey_Object

    A class for holding public key information as it will be written into the RO-Crate

    Attributes:
        method(str):the algorithim used to generate the key
        key(str): the public key or it's fingerprint
        uids: Identifiers from gpg 'uids' value
    """
    #values can be retreived from gpg.list_keys()
    method:str #algo
    key:str #key
    uids:List[str] #uids

def split_uid(uid: str) -> Dict[str, str]:
    """split supplied uids from gpg's key information into email and name"""
    uid_sections = uid.split(" ")
    if len(uid_sections) > 1: #split if uid contains two entries
        email = uid_sections[-1].strip("<> ")
        user = (" ".join(uid_sections[:-1])).strip(" ")
    else:#email and name may be the same
        user = uid.strip("<> ")
        email = user
    if not EMAIL_RE.match(email):
        return (uid, NO_VALID_EMAIL)
    return (user, email)



class Keyholder(ContextEntity):

    def __init__(
            self,
            crate,
            identifier: Optional[Any] = None,
            properties: Optional[Any] = None,
            pubkey_fingerprint: Optional[PubkeyObject] = None,
            keyserver:Optional[str] = None
        ) -> None:
        properties = properties or {}
        if not identifier:
            if pubkey_fingerprint:
                if keyserver:
                    identifier = f"{keyserver}{HPK_STUB}{pubkey_fingerprint.key}"
                else:
                    identifier = pubkey_fingerprint.key
            else:
                raise ValueError("No valid identifier combination supplied for keyholder")
        if pubkey_fingerprint:
            names, emails =  zip(*[split_uid(uid) for uid in pubkey_fingerprint.uids])
            properties["pubkey_fingerprints"] = pubkey_fingerprint.key
            properties["email"] = emails
            properties["name"] = names
        if keyserver:
            properties["keyserver"] = keyserver
            properties["url"] = f"{keyserver}{HPK_STUB}{pubkey_fingerprint.key}"
        super().__init__(crate, identifier, properties)

    def retreive_keys(self, gpg: GPG):
        """Retrive keys from a keyserver if possible

        Args:
            gpg (GPG): a gpg object that can recive keys
        Returns:
            List[str]: A list of strings returned by the gpg recv_keys method
        """
        if pubkeys := self.get("pubkey_fingerprints"):
            if keyserver := self.get("keyserver"):
                results = gpg.recv_keys(keyserver, pubkeys)
                result_list = results.results
                if len(result_list) < 1:
                    return None
                for result in results.results:
                    if result.get("problem"):
                        warnings.warn(f""""invalid response from keyserver for keys
                        {result.get("fingerprint")}: {result.get("text")} - return code: {results.returncode}""",
                        KeyserverWarning)
                return results.fingerprints
        return None

    def _empty(self) -> Dict:
        val = {
            "@id": self.id,
            "@type": ["ContactPoint", "EncryptionKeyholder"],
            #"conformsTo":"profileURI"
        }
        return val
