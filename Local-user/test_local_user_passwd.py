import pytest
from SCAutolib.src.authselect import Authselect
from SCAutolib.src.virt_card import VirtCard
from fixtures import user_indirect, user_shell


@pytest.mark.parametrize("required", [True, False])
def test_change_local_user_passwd(user, user_shell, required):
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
    with Authselect(required=required):
        with VirtCard(user.USERNAME_LOCAL, insert=True):
            cmd = f"su {user.USERNAME_LOCAL} -c 'passwd'"
            user_shell.sendline(cmd)
            user_shell.expect_exact(f"PIN for {user.USERNAME_LOCAL}:")
            user_shell.sendline(user.PIN_LOCAL)
            user_shell.expect_exact(f"Changing password for user {user.USERNAME_LOCAL}.")
