"""Note: as all tests are executed from root user, first login to any user
do not require any credentials!
"""
from SCAutolib.models.authselect import Authselect


def test_su_login_with_sc(local_user, user_shell):
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
        with local_user.card(insert=True):
            cmd = f'su {local_user.username} -c "whoami"'
            user_shell.sendline(cmd)
            user_shell.expect_exact(f"PIN for {local_user.username}:")
            user_shell.sendline(local_user.pin)
            user_shell.expect_exact(local_user.username)


def test_su_login_with_sc_wrong(local_user, user_shell):
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
        with local_user.card(insert=True):
            cmd = f'su {local_user.username} -c "whoami"'
            user_shell.sendline(cmd)
            user_shell.expect_exact(f"PIN for {local_user.username}:")
            user_shell.sendline("wrong")
            user_shell.expect(f"su: Authentication failure")


def test_gdm_login_sc_required(local_user, root_shell):
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
        - Authentication is succeeded

    """
    with Authselect(required=True):
        with local_user.card as sc:
            cmd = f'sssctl user-checks -s gdm-smartcard {local_user.username} -a auth'
            root_shell.sendline(cmd)
            root_shell.expect_exact("Please insert smart card")
            sc.insert()
            root_shell.expect_exact(f"PIN for {local_user.username}")
            root_shell.sendline(local_user.pin)
            root_shell.expect("pam_authenticate.*Success")


def test_su_login_without_sc(local_user, user_shell):
    """SU login with user password, smartcard is not required.

    Setup
        1. Update /etc/sssd/sssd.conf so it contains following fields
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
        2. Setup authselect: authselect select sssd with-smartcard
        4. Try to switch user (su login) to the smartcard user


    Expected result
        - Users is asked insert the password
        - User inserts correct password
        - User is successfully logged in
    """
    with Authselect():
        cmd = f"su - {local_user.username} -c whoami"
        user_shell.sendline(cmd)
        user_shell.expect_exact(f"Password:")
        user_shell.sendline(local_user.password)
        user_shell.expect_exact(local_user.username)


def test_su_to_root(local_user, user_shell, root_user):
    """Test for smartcard login to the local user and then switching to root (su -).

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
        6. Switch user with 'su' command to the smartcard user
        7. User is asked for smartcard PIN -> insert correct PIN
        8. After successful login, try to switch to root user with 'su -'

    Expected result
        - Users is asked for root password
        - User insert correct root password
        - User is switched to the root user
    """
    with Authselect():
        with local_user.card(insert=True):
            user_shell.sendline(f"su - {local_user.username}")
            user_shell.expect_exact(f"PIN for {local_user.username}:")
            user_shell.sendline(local_user.pin)
            user_shell.expect_exact(local_user.username)
            user_shell.sendline("whoami")
            user_shell.expect_exact(local_user.username)
            user_shell.sendline('su - root -c "whoami"')
            user_shell.expect_exact("Password:")
            user_shell.sendline(root_user.password)
            user_shell.expect_exact("root")
