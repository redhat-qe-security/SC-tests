# author: Pavel Yadlouski <pyadlous@redhat.com>
import SCAutolib.src.utils as utils
from shutil import copy2
from os import remove
from fixtures import *
import pytest


@pytest.skip()
def test_wrong_issuer_cert(user):
    """Test failed smart card login when root certificate has different
    issuer then certificate on the smart card."""
    @utils.backup("sssd", file_path="/etc/sssd/pki/sssd_auth_ca_db.pem", restore=True)
    def test():
        user.new_cert, user.new_key = utils.generate_cert()
    test()
    copy2(user.new_cert, "/etc/sssd/pki/sssd_auth_ca_db.pem")
    user.su_login_local_with_sc()
    remove(user.new_cert)
    remove(user.new_key)
