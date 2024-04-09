# Copyright 2019-2023 The University of Manchester, UK
# Copyright 2020-2023 Vlaams Instituut voor Biotechnologie (VIB), BE
# Copyright 2020-2023 Barcelona Supercomputing Center (BSC), ES
# Copyright 2020-2023 Center for Advanced Studies, Research and Development in Sardinia (CRS4), IT
# Copyright 2022-2023 École Polytechnique Fédérale de Lausanne, CH
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
import warnings

from .model import Metadata, LegacyMetadata


def read_metadata(metadata_path):
    """\
    Read an RO-Crate metadata file.

    Return a tuple of two elements: the context; a dictionary that maps entity
    ids to the entities themselves.
    """
    with open(metadata_path) as f:
        metadata = json.load(f)
    try:
        context = metadata['@context']
        graph = metadata['@graph']
    except KeyError:
        raise ValueError(f"{metadata_path} must have a @context and a @graph")
    return context, {_["@id"]: _ for _ in graph}, metadata.get("@encrypted")

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
        self.extra_contexts = []
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
                encrypted_fields.append(
                    (entity.properties(), entity.pubkey_fingerprints)
                )
            else:
                graph.append(entity.properties())
        encrypted_fields = self.__aggregate_encrypted_fields(encrypted_fields)
        encrypted_data = self.__encrypt_fields(encrypted_fields)
        context = [f"{self.PROFILE}/context"]
        context.extend(self.extra_contexts)
        if self.extra_terms:
            context.append(self.extra_terms)
        if len(context) == 1:
            context = context[0]
        return {"@context": context, "@graph": graph, "@encrypted": encrypted_data}

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
            pubkey_fingerprints.extend(self.crate.pubkey_fingerprints)
            pubkey_fingerprints = tuple(set(pubkey_fingerprints))  # strip out duplicates
            if pubkey_fingerprints in aggregated_fields:
                aggregated_fields[pubkey_fingerprints].append(field[0])
            else:
                aggregated_fields[pubkey_fingerprints] = [field[0]]
        return aggregated_fields
        
    def __encrypt_fields(self, encrypted_fields: Dict[List[str],List[Dict[str,str]]],) -> Dict[str,str]:
        """Encrypt the JSON representation of the encrypted fields using the fingerprints provided
        
        Args:
            encrypted_fields: The aggregated encrypted fields

        Returns:
            Dict[str,str]: The encrypted fields
        """
        encrypted_field_list = []
        encrypted_field_dictionary = {}
        from gnupg import GPG
        gpg = GPG(gpgbinary=self.crate.gpg_binary)
        for fingerprints, fields in encrypted_fields.items():
            json_representation = json.dumps(fields)
            gpg.trust_keys(fingerprints, 'TRUST_ULTIMATE')
            encrypted_field = gpg.encrypt(json_representation, fingerprints)
            if not encrypted_field.ok:
                raise Warning(f'Unable to encrypt field. GPG status: {encrypted_field.status}')
            encrypted_field_dictionary[','.join(str, fingerprints) if len(fingerprints) > 1 else fingerprints[0]] = encrypted_field._as_text()
            encrypted_field_list.append(encrypted_field_dictionary)
        return encrypted_field_list


def _check_descriptor(descriptor, entities):
    if descriptor["@type"] != "CreativeWork":
        raise ValueError('metadata descriptor must be of type "CreativeWork"')
    try:
        root = entities[descriptor["about"]["@id"]]
    except (KeyError, TypeError):
        raise ValueError("metadata descriptor does not reference the root entity")
    if ("Dataset" not in root["@type"] if isinstance(root["@type"], list) else root["@type"] != "Dataset"):
        raise ValueError('root entity must have "Dataset" among its types')
    return descriptor["@id"], root["@id"]


def find_root_entity_id(entities):
    """\
    Find metadata file descriptor and root data entity.

    Expects as input a dictionary that maps JSON entity IDs to the entities
    themselves (like the second element returned by read_metadata).

    Return a tuple of the corresponding identifiers (descriptor, root).
    If the entities are not found, raise KeyError. If they are found,
    but they don't satisfy the required constraints, raise ValueError.

    In the general case, the metadata file descriptor id can be an
    absolute URI whose last path segment is "ro-crate-metadata.json[ld]".
    Since there can be more than one such id in the crate, we need to
    choose among the corresponding (descriptor, root) entity pairs. First, we
    exclude those that don't satisfy other constraints, such as the
    descriptor entity being of type CreativeWork, etc.; if this doesn't
    leave us with a single pair, we try to pick one with a
    heuristic. Suppose we are left with the (m1, r1) and (m2, r2) pairs:
    if r1 is the actual root of this crate, then m2 and r2 are regular
    files in it, and as such they must appear in r1's hasPart; r2,
    however, is not required to have a hasPart property listing other
    files. Thus, we look for a pair whose root entity "contains" all
    descriptor entities from other pairs. If there is no such pair, or there
    is more than one, we just return an arbitrary pair.

    """
    descriptor = entities.get(Metadata.BASENAME, entities.get(LegacyMetadata.BASENAME))
    if descriptor:
        return _check_descriptor(descriptor, entities)
    candidates = []
    for id_, e in entities.items():
        basename = id_.rsplit("/", 1)[-1]
        if basename == Metadata.BASENAME or basename == LegacyMetadata.BASENAME:
            try:
                candidates.append(_check_descriptor(e, entities))
            except ValueError:
                pass
    if not candidates:
        raise KeyError("Metadata file descriptor not found")
    elif len(candidates) == 1:
        return candidates[0]
    else:
        warnings.warn("Multiple metadata file descriptors, will pick one with a heuristic")
        descriptor_ids = set(_[0] for _ in candidates)
        for m_id, r_id in candidates:
            try:
                root = entities[r_id]
                part_ids = set(_["@id"] for _ in root["hasPart"])
            except KeyError:
                continue
            if part_ids >= descriptor_ids - {m_id}:
                # if True for more than one candidate, this pick is arbitrary
                return m_id, r_id
        return candidates[0]  # fall back to arbitrary pick