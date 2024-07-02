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
from . import ContextEntity
from . import PubkeyObject
from gnupg import GPG

def split_uid(uid: str) -> Tuple[str, str]:
    uid_sections = uid.split(" ")
    if len(uid_sections) > 1:
        email = uid_sections[-1].strip("<> ")
        user = uid_sections[:-1].strip(" ")
        return user, email
    return uid, ""

class EncryptionKeyholder(ContextEntity):

    HPK_STUB = "/pks/lookup?op=index&exact=true&search="

    def __init__(
            self,
            crate,
            identifier: Optional[Any] = None,
            properties: Optional[Any] = None,
            pubkey_fingerprint: Optional[PubkeyObject] = None,
            keyserver:Optional[str] = None
        ) -> None:
            if not identifier:
                if len(pubkey_fingerprints > 0):
                    if keyserver:
                        identifier = f"{keyserver}{HPK_STUB}{pubkey_fingerprint.key}"
                    else:
                        identifier = pubkey_fingerprints[0]
                else:
                    raise ValueError(f"No valid identifier combination supplied for keyholder")
            if pubkey_fingerprint:
                names, emails = [split_uid(uid) for uid in pubkey_fingerprint.uids]
                properties["pubkey_fingerprints"] = pubkey_fingerprint.key
                properties["email"] = [email for email in emails if email != ""]
                properties["name"] = names
            if keyserver:
                properties["keyserver"] = keyserver
                properties["url"] = f"{keyserver}{HPK_STUB}{pubkey_fingerprint.key}"
            super().__init__(crate, identifier, properties)

    def retreive_keys(self, gpg: GPG):
        if pubkeys := self.get("pubkey_fingerprints"):
            if keyserver := self.get("keyserver"):
                gpg.recv_keys(keyserver, pubkeys)


    def _empty(self) -> Dict:
        val = {
            "@id": self.id,
            "@type": ["ContactPoint", "EncryptionKeyholder"],
            #"conformsTo":"profileURI"
        }
        return val
