import pytest

from SCAutolib.models.authselect import Authselect
from SCAutolib.isDistro import isDistro


@pytest.mark.parametrize(
    "required,lock_on_removal", [(True, True), (True, False), (False, True), (False, False),]
)
def test_change_local_user_passwd(local_user, user_shell, required, lock_on_removal):
    """Run 'passwd' command when smartcard login is enforced and after user is
    authenticated in with a smartcard.

    Setup
        1. Create local CA
        2. Create virtual smart card with certs signed by created CA
        3. Update /etc/sssd/sssd.conf so it contains following fields
            [sssd]
            debug_level = 9
            services = nss, pam,
            domains = shadowutils
            certificate_verification = no_ocsp

            [pam]
            debug_level = 9
            pam_cert_auth = True

            [domain/shadowutils]
            debug_level = 9
            id_provider = files

            [certmap/shadowutils/username]
            matchrule = <SUBJECT>.*CN=username.*
        4. Setup authselect: authselect select sssd with-smartcard with-smartcard-required
        5. Login to the smart card user
        6. Run 'passwd'


    Expected result
        - Users is asked to change it local password
        - No mentioning of the smart card
    """
    with Authselect(required=required, lock_on_removal=lock_on_removal):
        with local_user.card(insert=True):
            cmd = f"su {local_user.username} -c 'passwd'"
            user_shell.sendline(cmd)
            user_shell.expect_exact(f"PIN for {local_user.username}:")
            user_shell.sendline(local_user.pin)
            if isDistro(['rhel', 'centos'], '>=10') or isDistro('fedora', '>=40'):
                user_shell.expect_exact(f"Current password")
            else:
                user_shell.expect_exact(f"Changing password for user {local_user.username}.")
