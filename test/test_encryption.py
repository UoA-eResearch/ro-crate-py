"""Tests the encryption of elements in the RO-Crate"""
from pathlib import Path

import pytest
import mock
import warnings
from gnupg import GPG, GenKey, ImportResult

from rocrate.encryption_utils import (
    MissingMemberException,
    NoValidKeysError,
    combine_recipient_keys
    )
from rocrate.model.contextentity import ContextEntity
from rocrate.model.encryptedcontextentity import EncryptedContextEntity
from rocrate.model.keyholder import Keyholder, PubkeyObject, split_uid, NO_VALID_EMAIL, KeyserverWarning
from rocrate.rocrate import ROCrate


def test_confrim_gpg_binary():
    crate = ROCrate()
    assert crate.gpg_binary is not None

@pytest.fixture
def test_keyserver() -> str:
    return "keyserver.ubuntu.com"

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
     key_usage='sign encrypt',
     Name_Real = "Joe Tester",
     Name_Email = "joe@foo.bar")
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
        uids=["Josiah Carberry <jcarberry@potterymail.com>", "<test@email.com>", "name noemail"]
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

def test_split_uid(test_gpg_key_2:GenKey, test_gpg_object):
    key_data = test_gpg_object.list_keys().key_map.get(test_gpg_key_2.fingerprint)
    assert key_data is not None
    key_from_gpg = PubkeyObject(method = key_data["algo"], key=test_gpg_key_2.fingerprint, uids=key_data["uids"])
    assert key_from_gpg.uids == ["Joe Tester <joe@foo.bar>"]
    assert split_uid(key_from_gpg.uids[0]) == ("Joe Tester", "joe@foo.bar")

def test_split_uid_list(test_pubkey_nosecret):
    names, emails = zip(*[split_uid(uid) for uid in test_pubkey_nosecret.uids])
    assert names == ("Josiah Carberry", "test@email.com", "name noemail")
    assert emails == ("jcarberry@potterymail.com", "test@email.com", NO_VALID_EMAIL)

@pytest.fixture
def test_gpg_import_fail(test_pubkey_nosecret) ->ImportResult:
    crate = ROCrate()
    result = ImportResult(gpg=crate.gpg_binary)
    result.fingerprints = [test_pubkey_nosecret.key]
    result.returncode = 2
    result.results.append({'fingerprint': test_pubkey_nosecret.key, 'problem': '0', 'text': 'Other failure'})
    return result

@pytest.fixture
def test_gpg_import_missing(test_pubkey_nosecret) ->ImportResult:
    crate = ROCrate()
    result = ImportResult(gpg=crate.gpg_binary)
    result.returncode = 2
    result.results.append({'fingerprint': None, 'problem': '0', 'text': 'No valid data found'})
    return result

@pytest.fixture
def test_gpg_import_nothing(test_pubkey_nosecret) ->ImportResult:
    crate = ROCrate()
    result = ImportResult(gpg=crate.gpg_binary)
    result.returncode = 0
    return result

@pytest.fixture
def test_gpg_import_sucess(test_pubkey_nosecret) ->ImportResult:
    crate = ROCrate()
    result = ImportResult(gpg=crate.gpg_binary)
    result.fingerprints = [test_pubkey_nosecret.key]
    result.returncode = 0
    result.results.append({'fingerprint': test_pubkey_nosecret.key, 'ok': '1', 'text': 'Entirely new key'})
    return result

@mock.patch.object(GPG, "recv_keys")
def test_receive_keys(test_recv_keys,test_gpg_import_nothing, test_gpg_import_missing,test_gpg_import_sucess, test_gpg_import_fail, test_pubkey_nosecret, test_keyserver:str):
    crate = ROCrate()
    test_keyholder = Keyholder(crate, pubkey_fingerprint=test_pubkey_nosecret,keyserver=test_keyserver)
    gpg = GPG(crate.gpg_binary)
    test_recv_keys.return_value = test_gpg_import_nothing
    result = test_keyholder.retreive_keys(gpg)
    assert result == None
    #f"invalid response from keyserver for keys {test_pubkey_nosecret.key}: Other failure"
    with pytest.warns(KeyserverWarning) as warned:
        test_recv_keys.return_value = test_gpg_import_fail
        result = test_keyholder.retreive_keys(gpg)
        assert result == [test_pubkey_nosecret.key]



    with warnings.catch_warnings():
        test_recv_keys.return_value = test_gpg_import_sucess
        result = test_keyholder.retreive_keys(gpg)
        assert result == [test_pubkey_nosecret.key]

    with pytest.raises(Exception):
        test_keyholder = Keyholder(crate, pubkey_fingerprint=[],keyserver=test_keyserver)
    test_keyholder.pubkey_fingerprints = []
    with pytest.warns(KeyserverWarning) as warned:
        test_recv_keys.return_value = test_gpg_import_missing
        result = test_keyholder.retreive_keys(gpg)
        assert result == []
