# author: Pavel Yadlouski <pyadlous@redhat.com>
from os import remove
from pathlib import Path

from subprocess import run

from fixtures import *
from SCAutolib.models.authselect import Authselect
from SCAutolib.models.file import File, OpensslCnf
from SCAutolib.utils import ca_factory, user_factory


@pytest.mark.parametrize("user,sssd_db", [
    (user_factory("local-user"),File("/etc/sssd/pki/sssd_auth_ca_db.pem"))])
def test_wrong_issuer_cert(user, sssd_db, user_shell, tmp_path):
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

    sssd_db.backup()
    sssd_db.path.unlink()
    ca_factory(tmp_path.joinpath("ca"))
    run(['restorecon', "-v", "/etc/sssd/pki/sssd_auth_ca_db.pem"])

    with Authselect():
        with user.card(insert=True):
            cmd = f'su {user.username} -c "whoami"'
            user_shell.sendline(cmd)
            user_shell.expect_exact(f"Password:")
            user_shell.sendline(user.password)
            user_shell.expect_exact(user.username)

    sssd_db.restore()
    run(['restorecon', "-v", "/etc/sssd/pki/sssd_auth_ca_db.pem"])
