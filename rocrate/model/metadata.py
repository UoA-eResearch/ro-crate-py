#!/usr/bin/env python

# Copyright 2019-2024 The University of Manchester, UK
# Copyright 2020-2024 Vlaams Instituut voor Biotechnologie (VIB), BE
# Copyright 2020-2024 Barcelona Supercomputing Center (BSC), ES
# Copyright 2020-2024 Center for Advanced Studies, Research and Development in Sardinia (CRS4), IT
# Copyright 2022-2024 École Polytechnique Fédérale de Lausanne, CH
# Copyright 2024 Data Centre, SciLifeLab, SE
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

import json
from pathlib import Path
from typing import List, Dict, Tuple
from gnupg import GPG

from rocrate.model.encryptedcontextentity import EncryptedContextEntity
from .encryptedgraphmessage import EncryptedGraphMessage, PubkeyObject
from .contextentity import ContextEntity
from ..encryption_utils import combine_recipient_keys
# from rocrate.rocrate import ROCrate

from .dataset import Dataset
from .file import File

WORKFLOW_PROFILE = "https://w3id.org/workflowhub/workflow-ro-crate/1.0"


class Metadata(File):
    """\
    RO-Crate metadata file.
    """

    BASENAME = "ro-crate-metadata.json"
    PROFILE = "https://w3id.org/ro/crate/1.1"

    def __init__(self, crate, source=None, dest_path=None, properties=None,):
        if source is None and dest_path is None:
            dest_path = self.BASENAME
        super().__init__(
            crate= crate,
            source=source,
            dest_path=dest_path,
            fetch_remote=False,
            validate_url=False,
            properties=properties,
        )
        # https://www.researchobject.org/ro-crate/1.1/appendix/jsonld.html#extending-ro-crate
        self.extra_contexts = []#extend the crate with another profile
        self.extra_terms = {}

    def _empty(self):
        # default properties of the metadata entry
        val = {
            "@id": self.id,
            "@type": "CreativeWork",
            "conformsTo": {"@id": self.PROFILE},
            "about": {"@id": "./"},
        }
        return val

    # Generate the crate's `ro-crate-metadata.json`.
    # @return [String] The rendered JSON-LD as a "prettified" string.
    def generate(self):
        graph = []
        encrypted_fields = []
        for entity in self.crate.get_entities():
            if isinstance(entity, EncryptedContextEntity):
                entity.pubkey_fingerprints = combine_recipient_keys(entity)
                encrypted_fields.append(
                    (entity, entity.pubkey_fingerprints)
                )
            else:
                graph.append(entity.properties())
        encrypted_fields = self.__aggregate_encrypted_fields(encrypted_fields)
        encrypted_data = self.__encrypt_fields(encrypted_fields)
        graph.extend([encrypted_graph.properties() for encrypted_graph in encrypted_data])
        context = [f"{self.PROFILE}/context"]
        context.extend(self.extra_contexts)
        if self.extra_terms:
            context.append(self.extra_terms)
        if len(context) == 1:
            context = context[0]
        return {"@context": context, "@graph": graph}

    def __aggregate_encrypted_fields(
        self,
        encrypted_fields: List[Tuple[Dict[str, str], List[str]]],
    ) -> Dict[List[str], List[Dict[str, str]]]:
        """Aggregate any encrypted fields into a list of JSON fragments ready to be
        encrypted.

        Args:
            encrypted_fields: The fields from the encrypted context entities and their pubkeys

        Returns:
            Dict[List[str],List[str]]
            ]: A dictionary aggreated by pubkeys
        """
        aggregated_fields = {}
        for field in encrypted_fields:
            pubkey_fingerprints = field[1]
            pubkey_fingerprints = tuple(set(pubkey_fingerprints))  # strip out duplicates
            if pubkey_fingerprints in aggregated_fields:
                aggregated_fields[pubkey_fingerprints].append(field[0])
            else:
                aggregated_fields[pubkey_fingerprints] = [field[0]]
        return aggregated_fields

    def __encrypt_fields(self, encrypted_fields: Dict[List[str],List[EncryptedContextEntity]],) -> list[EncryptedGraphMessage]:
        """Encrypt the JSON representation of the encrypted fields using the fingerprints provided
        
        Args:
            encrypted_fields: The aggregated encrypted fields

        Returns:
            Dict[str,str]: The encrypted fields
        """
        encrypted_field_list = []
        gpg = GPG(gpgbinary=self.crate.gpg_binary)
        for fingerprints, fields in encrypted_fields.items():
            recipents = set()
            feilds_properties = []
            for feild in feilds:
                recipents.extend([field.get_norm_value("recipients") for feild in feilds])
                feilds_properties.extend(feild.properties())
            json_representation = json.dumps(feilds_properties)
            gpg.trust_keys(fingerprints, 'TRUST_ULTIMATE')
            encrypted_field = gpg.encrypt(json_representation, fingerprints)
            if not encrypted_field.ok:
                raise Warning(f'Unable to encrypt field. GPG status: {encrypted_field.status}')
            encrypted_message = EncryptedGraphMessage(
                crate= self.crate,
                encrypted_graph=encrypted_field._as_text(),
                properties={
                    "deliveryMethod":"https://doi.org/10.17487/RFC4880",
                    "recipients": [{"@id":recipent} for recipient in recipients]
                }                
            )
            encrypted_field_list.append(encrypted_message)
        return encrypted_field_list         


    def write(self, base_path):
        write_path = Path(base_path) / self.id
        as_jsonld = self.generate()
        with open(write_path, "w") as outfile:
            json.dump(as_jsonld, outfile, indent=4, sort_keys=True)

    @property
    def root(self) -> Dataset:
        return self.crate.root_dataset


class LegacyMetadata(Metadata):

    BASENAME = "ro-crate-metadata.jsonld"
    PROFILE = "https://w3id.org/ro/crate/1.0"


# https://github.com/ResearchObject/ro-terms/tree/master/test
TESTING_EXTRA_TERMS = {
    "TestSuite": "https://w3id.org/ro/terms/test#TestSuite",
    "TestInstance": "https://w3id.org/ro/terms/test#TestInstance",
    "TestService": "https://w3id.org/ro/terms/test#TestService",
    "TestDefinition": "https://w3id.org/ro/terms/test#TestDefinition",
    "PlanemoEngine": "https://w3id.org/ro/terms/test#PlanemoEngine",
    "JenkinsService": "https://w3id.org/ro/terms/test#JenkinsService",
    "TravisService": "https://w3id.org/ro/terms/test#TravisService",
    "GithubService": "https://w3id.org/ro/terms/test#GithubService",
    "instance": "https://w3id.org/ro/terms/test#instance",
    "runsOn": "https://w3id.org/ro/terms/test#runsOn",
    "resource": "https://w3id.org/ro/terms/test#resource",
    "definition": "https://w3id.org/ro/terms/test#definition",
    "engineVersion": "https://w3id.org/ro/terms/test#engineVersion",
}


def metadata_class(descriptor_id):
    basename = descriptor_id.rsplit("/", 1)[-1]
    if basename == Metadata.BASENAME:
        return Metadata
    elif basename == LegacyMetadata.BASENAME:
        return LegacyMetadata
    else:
        raise ValueError(f"Invalid metadata descriptor ID: {descriptor_id!r}")
