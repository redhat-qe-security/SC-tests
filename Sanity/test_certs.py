# author: Pavel Yadlouski <pyadlous@redhat.com>
from os import remove
from subprocess import run

import pytest
from SCAutolib.src import utils
from SCAutolib.src.env import run
from fixtures import *
from SCAutolib.src.exceptions import PatternNotFound


@pytest.mark.parametrize("file_path,restore,restart",
                         [("/etc/sssd/pki/sssd_auth_ca_db.pem", True, ["sssd"])])
def test_wrong_issuer_cert(user, backup):
    """Test failed smart card login when root certificate has different
    issuer then certificate on the smart card."""

    new_cert, new_key = utils.generate_cert()

    with open("/etc/sssd/pki/sssd_auth_ca_db.pem", "w") as f:
        with open(new_cert, "r") as f_new:
            f.write(f_new.read())

    run(['restorecon', "-v", "/etc/sssd/pki/sssd_auth_ca_db.pem"])

    with pytest.raises(PatternNotFound):
        user.su_login_local_with_sc()
    user.su_login_local_with_passwd()

    remove(new_cert)
    remove(new_key)
