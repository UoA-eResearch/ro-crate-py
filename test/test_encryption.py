"""Tests the encryption of elements in the RO-Crate"""
from pathlib import Path

import pytest
from gnupg import GPG, GenKey

from rocrate.encryption_utils import (
    MissingMemberException,
    NoValidKeysError,
    combine_recipient_keys
    )
from rocrate.model.contextentity import ContextEntity
from rocrate.model.encryptedcontextentity import EncryptedContextEntity
from rocrate.model.keyholder import Keyholder, PubkeyObject
from rocrate.rocrate import ROCrate


def test_confrim_gpg_binary():
    crate = ROCrate()
    assert crate.gpg_binary is not None


#Fixtures specific to testing gpg keys and decryption
@pytest.fixture
def test_gpg_object():
    crate = ROCrate()
    gpg = GPG(crate.gpg_binary)
    return gpg

@pytest.fixture
def test_passphrase():
    return "JosiahCarberry1929/13/09"

@pytest.fixture
def test_gpg_key(test_gpg_object: GPG, test_passphrase:str):
    key_input = test_gpg_object.gen_key_input(key_type="RSA",
     key_length=1024,Passphrase=test_passphrase,
     key_usage='sign encrypt')
    key = test_gpg_object.gen_key(key_input)
    yield key
    test_gpg_object.delete_keys(key.fingerprint, True, passphrase=test_passphrase)
    test_gpg_object.delete_keys(key.fingerprint, passphrase=test_passphrase)

@pytest.fixture
def test_gpg_key_2(test_gpg_object: GPG, test_passphrase:str):
    key_input = test_gpg_object.gen_key_input(key_type="RSA",
     key_length=1024,Passphrase=test_passphrase,
     key_usage='sign encrypt')
    key = test_gpg_object.gen_key(key_input)
    yield key
    test_gpg_object.delete_keys(key.fingerprint, True, passphrase=test_passphrase)
    test_gpg_object.delete_keys(key.fingerprint, passphrase=test_passphrase)

@pytest.fixture
def test_pubkey_object(test_gpg_object: GPG, test_gpg_key) -> PubkeyObject:
    current_keys = test_gpg_object.list_keys()
    fingerprint = test_gpg_key.fingerprint

    return PubkeyObject(
        method=current_keys.key_map[fingerprint]["algo"],
        key=fingerprint,
        uids=current_keys.key_map[fingerprint]["uids"]

    )


@pytest.fixture
def test_pubkey_nosecret(test_gpg_object: GPG, test_gpg_key) -> PubkeyObject:
    return PubkeyObject(
        method="1",
        key="643BE0B0159AEFC2B9428D578533F9C66A9E7628",
        uids=[""]
    )


def test_add_keyholder(test_pubkey_object):
    crate = ROCrate()
    test_keyholder = Keyholder(
        crate=crate,
        pubkey_fingerprint=test_pubkey_object
    )
    crate.add(test_keyholder)
    assert test_keyholder.id == "#"+test_pubkey_object.key
    keyholder_in_crate = crate.dereference("#"+test_pubkey_object.key)
    assert isinstance(keyholder_in_crate, Keyholder)
    assert keyholder_in_crate.get("pubkey_fingerprints") == test_pubkey_object.key



def test_add_encryptedmetadadata(test_pubkey_object:PubkeyObject):
    """Tests for the addition of encrypted metadata to the RO-Crate 
        and holding fingerprints for encryption
    """
    crate = ROCrate()
    
    test_keyholder = Keyholder(
        crate=crate,
        pubkey_fingerprint=test_pubkey_object
    )
    crate.add(test_keyholder)
    crate.add(EncryptedContextEntity(
        crate=crate,
        identifier="#test_encrypted_meta",
    ))
    encrypted_entity = crate.dereference("#test_encrypted_meta")
    assert encrypted_entity
    encrypted_entity.append_to("recipients", test_keyholder)
    assert test_pubkey_object.key in combine_recipient_keys(encrypted_entity)


def test_fail_find_keys(test_pubkey_object:PubkeyObject):
    crate = ROCrate()
    
    test_keyholder = Keyholder(
        crate=crate,
        identifier="keyholder without a key"
    )
    crate.add(test_keyholder)
    encrypted_entity = crate.add(EncryptedContextEntity(
        crate=crate,
        identifier="#test_encrypted_meta",
    ))
    encrypted_entity.append_to("recipients", test_keyholder)
    with pytest.raises(NoValidKeysError):
            combine_recipient_keys(encrypted_entity, True)
    test_keyholder2 = Keyholder(
        crate=crate,
        pubkey_fingerprint=test_pubkey_object
    )
    encrypted_entity.append_to("recipients", test_keyholder2)
    with pytest.raises(MissingMemberException):
        combine_recipient_keys(encrypted_entity)



def test_fail_decrypt_without_key(tmpdir:Path, test_pubkey_nosecret:PubkeyObject, test_passphrase:str):
    """fail to read an encrypted entity when the user lacks the private key 
    """
    crate = ROCrate()
    test_keyholder = Keyholder(
        crate=crate,
        pubkey_fingerprint=test_pubkey_nosecret
    )
    crate.add(test_keyholder)
    encrypted_entity= crate.add(EncryptedContextEntity(
        crate=crate,
        identifier="#test_encrypted_meta",
        properties = {"name":"test_encrypted_meta"},
    ))
    encrypted_entity.append_to("recipients", test_keyholder)
    out_path = tmpdir / "ro_crate_out"
    crate.write(out_path)
    crate = ROCrate(source=out_path, gpg_passphrase=test_passphrase)
    decrypted_result = crate.dereference("#test_encrypted_meta")
    assert decrypted_result is None





def test_decrypt(tmpdir, test_pubkey_object:PubkeyObject, test_passphrase:str):
    """Test decryption of an encrypted crate
    """
    crate = ROCrate()
    test_keyholder = Keyholder(
        crate=crate,
        pubkey_fingerprint=test_pubkey_object
    )
    crate.add(test_keyholder)
    encrypted_entity= crate.add(EncryptedContextEntity(
        crate=crate,
        identifier="#test_encrypted_meta",
        properties = {"name":"test_encrypted_meta"},
    ))
    encrypted_entity.append_to("recipients", test_keyholder)
    out_path = tmpdir / "ro_crate_out"
    crate.write(out_path)
    crate = ROCrate(source=out_path, gpg_passphrase=test_passphrase)
    decrypted_result = crate.dereference("#test_encrypted_meta")
    print(decrypted_result)
    assert isinstance(decrypted_result, EncryptedContextEntity)
    assert decrypted_result.as_jsonld() == encrypted_entity.as_jsonld()

def test_re_encrypt(tmpdir,  test_pubkey_object:PubkeyObject, test_passphrase):
    """Test a cycle of writing, reading and re-writing an RO-Crate with
        Encrypted metadata to confirm encrypted entities remain re-encrytped
        without loss of data or keys
    """
    crate = ROCrate()
    test_keyholder = Keyholder(
        crate=crate,
        pubkey_fingerprint=test_pubkey_object
    )
    crate.add(test_keyholder)
    encrypted_entity= crate.add(EncryptedContextEntity(
        crate=crate,
        identifier="#test_encrypted_meta",
        properties = {"name":"test_encrypted_meta"},
    ))
    encrypted_entity.append_to("recipients", test_keyholder)
    out_path = tmpdir / "ro_crate_out"
    crate.write(out_path)
    crate = ROCrate(source=out_path, gpg_passphrase=test_passphrase)
    decrypted_result = crate.dereference("#test_encrypted_meta")
    assert isinstance(decrypted_result, EncryptedContextEntity)
    out_path = tmpdir / "ro_crate_out_again"
    crate.write(out_path)
    crate = ROCrate(source=out_path, gpg_passphrase=test_passphrase)
    decrypted_result = crate.dereference("#test_encrypted_meta")
    print(decrypted_result)
    assert isinstance(decrypted_result, EncryptedContextEntity)
    assert decrypted_result.as_jsonld() == encrypted_entity.as_jsonld()


def test_multiple_keys(
    test_pubkey_object:PubkeyObject,
    test_gpg_key_2:GenKey,
    test_gpg_key:GenKey,
    tmpdir:Path,
    test_passphrase:str):
    """Test the encryption and decryption of an RO-Crate using multiple separate private keys"""
    crate = ROCrate()
    test_keyholder = Keyholder(
        crate=crate,
        pubkey_fingerprint=test_pubkey_object
    )
    test_recipient = ContextEntity(
        crate=crate,
        identifier="test_recipient",
        properties={
            "pubkey_fingerprints":test_gpg_key_2.fingerprint
        }
    )
    crate.add(test_keyholder)
    crate.add(test_recipient)
    encrypted_entity_a= crate.add(EncryptedContextEntity(
        crate=crate,
        identifier="#test_encrypted_meta_a",
        properties = {"name":"test_encrypted_meta_a"},
    ))
    encrypted_entity_b= crate.add(EncryptedContextEntity(
        crate=crate,
        identifier="#test_encrypted_meta_b",
        properties = {"name":"test_encrypted_meta_b"},
    ))
    encrypted_entity_a.append_to("recipients", test_keyholder)
    encrypted_entity_b.append_to("recipients", test_recipient)
    encrypted_entity_b.append_to("recipients", test_keyholder)
    out_path = tmpdir / "ro_crate_out"
    crate.write(out_path)
    GPG(crate.gpg_binary).delete_keys(test_gpg_key.fingerprint, True, passphrase=test_passphrase)
    crate = ROCrate(source=out_path, gpg_passphrase=test_passphrase)
    assert not crate.dereference("#test_encrypted_meta_a")
    assert crate.dereference("#test_encrypted_meta_b")
