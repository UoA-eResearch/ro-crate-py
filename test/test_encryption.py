"""Tests the encryption of elements in the RO-Crate"""
import json
from pathlib import Path
import pytest

from gnupg import GPG, GenKey


from rocrate.rocrate import ROCrate
from rocrate.model.encryptedcontextentity import EncryptedContextEntity


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
def test_fingerprint_no_secret():
    return "643BE0B0159AEFC2B9428D578533F9C66A9E7628"

def test_add_encryptedmetadadata(test_gpg_key:GenKey, test_fingerprint_no_secret:str):
    """Tests for the addition of encrypted metadata to the RO-Crate 
        and holding fingerprints for encryption
    """
    crate = ROCrate()
    crate.add(EncryptedContextEntity(
        crate=crate,
        identifier="#test_encrypted_meta",
        properties = None,
        pubkey_fingerprints =[test_gpg_key.fingerprint,test_fingerprint_no_secret],
    ))
    encrypted_entity = crate.dereference("#test_encrypted_meta")
    assert encrypted_entity
    assert test_gpg_key.fingerprint in encrypted_entity.pubkey_fingerprints


def test_fail_decrypt_without_key(tmpdir:Path, test_fingerprint_no_secret, test_passphrase:str):
    """fail to read an encrypted entity when the user lacks the private key 
    """
    crate = ROCrate(pubkey_fingerprints=[test_fingerprint_no_secret])
    crate.add(EncryptedContextEntity(
        crate=crate,
        identifier="#test_encrypted_meta",
        properties = {"name":"test_encrypted_meta"},
        pubkey_fingerprints =None,
    ))
    out_path = tmpdir / "ro_crate_out"
    crate.write(out_path)
    crate = ROCrate(source=out_path, gpg_passphrase=test_passphrase)
    decrypted_result = crate.dereference("#test_encrypted_meta")
    assert decrypted_result is None





def test_decrypt(tmpdir, test_gpg_key:GenKey, test_passphrase:str):
    """Test decryption of an encrypted crate
    """
    crate = ROCrate(pubkey_fingerprints=[test_gpg_key.fingerprint])
    encrypted_entity = EncryptedContextEntity(
        crate=crate,
        identifier="#test_encrypted_meta",
        properties = {"name":"test_encrypted_meta"},
        pubkey_fingerprints =[test_gpg_key.fingerprint],
    )
    crate.add(encrypted_entity)
    out_path = tmpdir / "ro_crate_out"
    crate.write(out_path)
    crate = ROCrate(source=out_path, gpg_passphrase=test_passphrase)
    decrypted_result = crate.dereference("#test_encrypted_meta")
    print(decrypted_result)
    assert isinstance(decrypted_result, EncryptedContextEntity)
    assert decrypted_result.as_jsonld() == encrypted_entity.as_jsonld()

def test_re_encrypt(tmpdir, test_gpg_key:GenKey, test_passphrase):
    """Test a cycle of writing, reading and re-writing an RO-Crate with
        Encrypted metadata to confirm encrypted entities remain re-encrytped
        without loss of data or keys
    """
    crate = ROCrate(pubkey_fingerprints=[test_gpg_key.fingerprint])
    encrypted_entity = EncryptedContextEntity(
        crate=crate,
        identifier="#test_encrypted_meta",
        properties = {"name":"test_encrypted_meta"},
        pubkey_fingerprints =None,
    )
    crate.add(encrypted_entity)
    out_path = tmpdir / "ro_crate_out"
    crate.write(out_path)
    crate = ROCrate(source=out_path, gpg_passphrase=test_passphrase)
    decrypted_result = crate.dereference("#test_encrypted_meta")
    assert isinstance(decrypted_result, EncryptedContextEntity)
    #assert decrypted_result.pubkey_fingerprints == ""
    out_path = tmpdir / "ro_crate_out_again"
    crate.write(out_path)
    crate = ROCrate(source=out_path, gpg_passphrase=test_passphrase)
    decrypted_result = crate.dereference("#test_encrypted_meta")
    print(decrypted_result)
    assert isinstance(decrypted_result, EncryptedContextEntity)
    assert decrypted_result.as_jsonld() == encrypted_entity.as_jsonld()


def test_multiple_keys(
    test_gpg_key:GenKey,
    test_gpg_key_2:GenKey,
    test_fingerprint_no_secret:str,
    tmpdir:Path,
    test_passphrase:str):
    """Test the encryption and decryption of an RO-Crate using multiple separate private keys"""
    crate = ROCrate(pubkey_fingerprints=[test_fingerprint_no_secret])
    crate.add(EncryptedContextEntity(
        crate=crate,
        identifier="#test_encrypted_meta_a",
        properties = {"name":"test_encrypted_meta_a"},
        pubkey_fingerprints =[test_gpg_key.fingerprint],
    ))
    crate.add(EncryptedContextEntity(
        crate=crate,
        identifier="#test_encrypted_meta_b",
        properties = {"name":"test_encrypted_meta_b"},
        pubkey_fingerprints =[test_gpg_key_2.fingerprint],
    ))
    out_path = tmpdir / "ro_crate_out"
    crate.write(out_path)
    GPG(crate.gpg_binary).delete_keys(test_gpg_key.fingerprint, True, passphrase=test_passphrase)
    crate = ROCrate(source=out_path, gpg_passphrase=test_passphrase)
    assert not crate.dereference("#test_encrypted_meta_a")
    assert crate.dereference("#test_encrypted_meta_b")
