"""test the encryption of elements in the ROCrate"""

import pytest
import json

from rocrate.rocrate import ROCrate
from rocrate.model.encryptedcontextentity import EncryptedContextEntity
from gnupg import GPG, GenKey



def test_confrim_gpg_binary():
    crate = ROCrate()
    assert crate.gpg_binary is not None

#fixture for keys
@pytest.fixture
def test_gpg_object():
    crate = ROCrate()
    gpg = GPG(crate.gpg_binary)
    return gpg

@pytest.fixture
def test_sensitive_json():
    return ""

@pytest.fixture
def test_encrypted_data():
    return ""

@pytest.fixture
def test_passphrase():
    return "JosiahCarberry'sSecret"

@pytest.fixture
def test_gpg_key(test_gpg_object: GPG, test_passphrase):
    key_input = test_gpg_object.gen_key_input(key_type="RSA", key_length=1024,Passphrase=test_passphrase,key_usage='sign encrypt')
    key = test_gpg_object.gen_key(key_input)
    print(key)
    return key

def test_add_encryptedmetadadata(test_gpg_key:GenKey):
    crate = ROCrate()
    crate.add(EncryptedContextEntity(
        crate=crate,
        identifier="#test_encrypted_meta",
        properties = None,
        pubkey_fingerprints =[test_gpg_key.fingerprint],
    ))
    assert crate.dereference("#test_encrypted_meta")
    assert crate.dereference("#test_encrypted_meta").pubkey_fingerprints[0] == test_gpg_key.fingerprint

def test_encrypted_write_with_crate_key(tmpdir, test_gpg_key:GenKey, test_encrypted_data, test_passphrase): 
    crate = ROCrate(pubkey_fingerprints=[test_gpg_key.fingerprint])
    crate.add(EncryptedContextEntity(
        crate=crate,
        identifier="#test_encrypted_meta",
        properties = None,
        pubkey_fingerprints =None,
    ))
    out_path = tmpdir / "ro_crate_out"
    crate.write(out_path)
    with open(out_path / "ro-crate-metadata.json") as f:
        metadata = json.load(f)
    assert metadata.get("@encrypted")
    encrypted_data = metadata["@encrypted"]
    gpg = GPG(crate.gpg_binary)
    gpg.decrypt(encrypted_data[0][test_gpg_key.fingerprint], passphrase= test_passphrase)

def test_encrypted_write_with_enitity_key(tmpdir, test_gpg_key:GenKey, test_encrypted_data, test_passphrase): 
    crate = ROCrate()
    crate.add(EncryptedContextEntity(
        crate=crate,
        identifier="#test_encrypted_meta",
        properties = None,
        pubkey_fingerprints =[test_gpg_key.fingerprint],
    ))
    out_path = tmpdir / "ro_crate_out"
    crate.write(out_path)
    with open(out_path / "ro-crate-metadata.json") as f:
        metadata = json.load(f)
    assert metadata.get("@encrypted")
    encrypted_data = metadata["@encrypted"]
    gpg = GPG(crate.gpg_binary)
    gpg.decrypt(encrypted_data[0][test_gpg_key.fingerprint], passphrase= test_passphrase)