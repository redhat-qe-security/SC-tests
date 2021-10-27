# author: Pavel Yadlouski <pyadlous@redhat.com>
from os import remove
from subprocess import run

from SCAutolib.src import utils
from SCAutolib.src.env import run
from fixtures import *
from SCAutolib.src.exceptions import PatternNotFound


@pytest.mark.parametrize("file_path,restore,restart",
                         [("/etc/sssd/pki/sssd_auth_ca_db.pem", True, ["sssd"])])
def test_wrong_issuer_cert(user, backup):
    """Test failed smart card login when root certificate stored in the
     /etc/sssd/pki/sssd_auth_ca_db.pem file has different
    issuer then certificate on the smart card.

    Setup
        1. Create a card with certificate from root CA
        2. Create a new root CA certificate and put it into
           /etc/sssd/pki/sssd_auth_ca_db.pem
        3. Restore SELinux context on /etc/sssd/pki/sssd_auth_ca_db.pem
        4. Set authselect: authselect select sssd with-smartcard
        5. Insert the card
        6. Try to switch the user (su command) to smart card user

    Expected result
        - Certificate is not recognized
        - The user isn't asked for the PIN, but for password
        - User can login with a password
    """

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
