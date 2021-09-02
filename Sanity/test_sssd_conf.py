# author: Pavel Yadlouski <pyadlous@redhat.com>
import SCAutolib.src.utils as utils
from fixtures import *
import pytest


@pytest.mark.parametrize("file_path,section,key,value,restore,restart",
                         [("/etc/sssd/sssd.conf", "pam", "p11_uri",
                           "pkcs11:slot-description=Virtual%20PCD%2000%2000", True,
                           ["sssd"])])
def test_su_login_p11_uri_slot_description(user, edit_config):
    """Test login with PIN to the system with p11_uri specified on specific
    slot in sssd.conf."""
    user.su_login_local_with_sc()


@pytest.mark.parametrize("file_path,section,key,value,restore,restart",
                         [("/etc/sssd/sssd.conf", "pam", "p11_uri",
                           "pkcs11:slot-description=Virtual%20PCD%2000%2001", True,
                           ["sssd"])])
def test_su_login_p11_uri_wrong_slot_description(user, edit_config):
    """Test login with password to the system with wrong p11_uri with wrong
    slot description in sssd.conf."""
    user.su_login_local_with_passwd()


@pytest.mark.parametrize("file_path,section,key,value,restore,restart",
                         [("/etc/sssd/sssd.conf", f"certmap/shadowutils/{user().USERNAME_LOCAL}",
                          "matchrule", "<SUBJECT>.*CN=testuser.*", True, ["sssd"])])
def test_user_mismatch(user, edit_config):
    """Test smart card login fail when sssd.conf do not contain user from
    the smart card (wrong user in matchrule)"""
    user.su_login_local_with_passwd()


@pytest.mark.parametrize("file_path,section,key,value,restore,restart",
                         [("/etc/sssd/sssd.conf", f"certmap/shadowutils/{user().USERNAME_LOCAL}",
                          "matchrule", f"UID={user().USERNAME_LOCAL}", True, ["sssd"])])
def test_wrong_subject_in_matchrule(user, edit_config):
    """Test smart card login fail when sssd.conf contain wrong subject in
    the matchrule."""
    user.su_login_local_with_passwd()
