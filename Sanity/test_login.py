"""Note: as all tests are executed from root user, first login to any user
do not require any credentials!
"""
import pytest
from SCAutolib.models.authselect import Authselect
from SCAutolib.utils import run_cmd, check_output


@pytest.mark.parametrize("name", ["local-user"], scope="session")
def test_su_login_with_sc(user):
    """Basic su login to the user with a smart card.

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
        4. Setup authselect: authselect select sssd with-smartcard
        5. Insert the card
        6. Try to switch user (su login) to the smartcard user


    Expected result
        - Users is asked for smartcard PIN
        - User insert correct PIN
        - User is successfully logged in
    """

    with Authselect(required=False):
        with user.card:
            cmd = f'su - {user.username} -c "su - {user.username}"'
            output = run_cmd(cmd, passwd=user.pin, pin=True)
            check_output(output, expect=["su: Authentication failure"],
                         zero_rc=False, check_rc=True)


@pytest.mark.parametrize("name", ["local-user"], scope="session")
def test_su_login_with_sc_wrong(user):
    """Basic su login to the user with a smartcard when user inters wrong PIN.

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
    4. Setup authselect: authselect select sssd with-smartcard
    5. Insert the card
    6. Try to switch user (su login) to the smartcard user


    Expected result
        - Users is asked for smartcard PIN
        - User inserts wrong PIN
        - User is not logged in and error message is written to the console
    """
    with Authselect(required=False):
        with user.card:
            cmd = f'su - {user.username} -c "su - {user.username}"'
            output = run_cmd(cmd, passwd=user.password, pin=True)
            check_output(output, expect=["su: Authentication failure"],
                         zero_rc=False, check_rc=True)


@pytest.mark.parametrize("name", ["local-user"], scope="session")
def test_gdm_login_sc_required(user):
    """GDM login to the user when smart card is required. Point is to check
    that GDM prompts to insert the smart card if it is not inserted

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
        6. Run 'sssctl user-checks -s gdm-smartcard username -a auth'

    Expected result
        - Users is asked to insert the card
        - User inserts the card
        - User is asked to insert the PIN
        - User inserts correct PIN
        - Authentication is succeed

    """
    with Authselect(required=True):
        with user.card as sc:
            cmd = f'sssctl user-checks -s gdm-smartcard {user.username} -a auth'
            shell = run_cmd(cmd, return_val="shell")
            shell.expect("Please insert smart card")
            sc.insert()
            shell.expect(f"PIN for {user.username}")
            shell.sendline(user.pin)
            check_output(shell.read(), expect=["pam_authenticate.*Success"])
#
#
# def test_su_login_without_sc(user):
#     """SU login with user password, smartcard is not required.
#
#     Setup
#         1. Update /etc/sssd/sssd.conf so it contains following fields
#             [sssd]
#             debug_level = 9
#             services = nss, pam,
#             domains = shadowutils
#             certificate_verification = no_ocsp
#
#             [pam]
#             debug_level = 9
#             pam_cert_auth = True
#
#             [domain/shadowutils]
#             debug_level = 9
#             id_provider = files
#
#             [certmap/shadowutils/username]
#             matchrule = <SUBJECT>.*CN=username.*
#         2. Setup authselect: authselect select sssd with-smartcard
#         4. Try to switch user (su login) to the smartcard user
#
#
#     Expected result
#         - Users is asked insert the password
#         - User inserts correct password
#         - User is successfully logged in
#     """
#     with Authselect():
#         cmd = f'su - {user.USERNAME_LOCAL} -c "su - {user.USERNAME_LOCAL} -c whoami"'
#         output = run_cmd(cmd, pin=False, passwd=user.PASSWD_LOCAL)
#         check_output(output, expect=[user.USERNAME_LOCAL])
#
#
# def test_su_to_root(user, user_shell):
#     """Test for smartcard login to the local user and then switching to root (su -).
#
#     Setup
#         1. Create local CA
#         2. Create virtual smart card with certs signed by created CA
#         3. Update /etc/sssd/sssd.conf so it contains following fields
#             [sssd]
#             debug_level = 9
#             services = nss, pam,
#             domains = shadowutils
#             certificate_verification = no_ocsp
#
#             [pam]
#             debug_level = 9
#             pam_cert_auth = True
#
#             [domain/shadowutils]
#             debug_level = 9
#             id_provider = files
#
#             [certmap/shadowutils/username]
#             matchrule = <SUBJECT>.*CN=username.*
#         4. Setup authselect: authselect select sssd with-smartcard
#         5. Insert the card
#         6. Switch user with 'su' command to the smartcard user
#         7. User is asked for smartcard PIN -> insert correct PIN
#         8. After successful login, try to switch to root user with 'su -'
#
#     Expected result
#         - Users is asked for root password
#         - User insert correct root password
#         - User is switched to the root user
#     """
#     with Authselect():
#         with VirtCard(user.USERNAME_LOCAL, insert=True) as sc:
#             user_shell.sendline(f"su - {user.USERNAME_LOCAL}")
#             user_shell.expect(f"PIN for {user.USERNAME_LOCAL}:")
#             user_shell.sendline(user.PIN_LOCAL)
#             user_shell.sendline("whoami")
#             user_shell.expect(user.USERNAME_LOCAL)
#             user_shell.sendline('su - root -c "whoami"')
#             user_shell.sendline(user.ROOT_PASSWD)
#             user_shell.expect("root")
