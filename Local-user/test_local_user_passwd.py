import pytest
from SCAutolib.models.authselect import Authselect
from SCAutolib.utils import user_factory


@pytest.mark.parametrize("required,user", [(True, user_factory("local-user")),
                                           (False, user_factory("local-user"))],
                         scope="session")
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
        with user.card(insert=True):
            cmd = f"su {user.username} -c 'passwd'"
            user_shell.sendline(cmd)
            user_shell.expect_exact(f"PIN for {user.username}:")
            user_shell.sendline(user.pin)
            user_shell.expect_exact(f"Changing password for user {user.username}.")
