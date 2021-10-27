from SCAutolib.src.authselect import Authselect
from SCAutolib.src.virt_card import VirtCard
from fixtures import ipa_user_indirect, user_shell


def test_kerberos_change_passwd_sc_login(ipa_user, user_shell):
    """Kerberos user tries to change it kerberos password after user is logged
    in to the system with smartcard when smartcard is not required for login.

    Setup
        1. General setup
        2. Setup authselect: authselect select sssd with-smartcard
        3. Switch to kerberos user (su kerberos_username)
        4. Insert the card
        5. Login with smartcard PIN
        6. Try to change the password by 'passwd'

    Expected result
        - Message about changing the password is written to the console
     """
    with Authselect():
        with VirtCard(ipa_user.USERNAME, insert=True) as f:
            cmd = f"su {ipa_user.USERNAME} -c 'passwd'"
            user_shell.sendline(cmd)
            user_shell.expect_exact(f"PIN for {ipa_user.USERNAME}:")
            user_shell.sendline(ipa_user.PIN)
            user_shell.expect_exact(f"Changing password for user {ipa_user.USERNAME}.")


def test_kerberos_change_passwd_sc_login_required(ipa_user, user_shell):
    """Kerberos user tries to change it kerberos password after user is logged
    in to the system with smartcard when smartcard is required for login.

    Setup
        1. General setup
        2. Setup authselect: authselect select sssd with-smartcard with-smartcard-required
        3. Switch to kerberos user (su kerberos_username)
        4. Insert the card
        5. Login to the system with smartcard PIN
        6. Try to change the password by 'passwd'

    Expected result
        - Message about changing the password is written to the console
     """
    with Authselect():
        with VirtCard(ipa_user.USERNAME, insert=True) as f:
            cmd = f"su {ipa_user.USERNAME} -c 'passwd'"
            user_shell.sendline(cmd)
            user_shell.expect_exact(f"PIN for {ipa_user.USERNAME}:")
            user_shell.sendline(ipa_user.PIN)
            user_shell.expect_exact(f"Changing password for user {ipa_user.USERNAME}.")


def test_kerberos_change_passwd_password_login_required(ipa_user, user_shell):
    """Kerberos user tries to change it kerberos password after user is logged
    in to the system with password when smartcard is required for login.

    Setup
        1. General setup
        2. Setup authselect: authselect select sssd with-smartcard with-smartcard-required
        3. Login to kerberos user with smart card (su kerberos_username)
        4. Insert smartcard
        5. Put correct smart card pin
        6. Try to change the password by 'passwd'

    Expected result
        - Message about changing the password is written to the console
     """
    with Authselect(required=True):
        with VirtCard(ipa_user.USERNAME, insert=False) as sc:
            cmd = f"su {ipa_user.USERNAME} -c 'passwd'"
            user_shell.sendline(cmd)
            user_shell.expect_exact(f"Please insert smart card")
            sc.insert()
            user_shell.expect_exact(f"PIN for {ipa_user.USERNAME}:")
            user_shell.sendline(ipa_user.PIN)
            user_shell.expect_exact(f"Changing password for user {ipa_user.USERNAME}.")


def test_kerberos_change_passwd_password_login(ipa_user, user_shell):
    """Kerberos user tries to change it kerberos password after user is logged
    in to the system with password when smartcard is not required for login.

    Setup
        1. General setup
        2. Setup authselect: authselect select sssd with-smartcard
        3. Login to kerberos user with password (su kerberos_username)
        4. Try to change the password by 'passwd'

    Expected result
        - Message about changing the password is written to the console
     """
    with Authselect():
            cmd = f"su {ipa_user.USERNAME} -c 'passwd'"
            user_shell.sendline(cmd)
            user_shell.expect_exact(f"Password:")
            user_shell.sendline(ipa_user.PASSWD)
            user_shell.expect_exact(f"Changing password for user {ipa_user.USERNAME}.")


# @pytest.mark.skip(reason="Need fix due to specific password changing with IPA server")
def test_kerberos_change_passwd(ipa_user, user_shell):
    """Kerberos user tries to change it kerberos password after user is logged
    in to the system with smartcard

    Setup
        1. General setup
        2. Setup authselect: authselect select sssd with-smartcard
        3. Switch to kerberos user (su kerberos_username)
        4. Insert the card
        5. Try to change the password by 'passwd'

    Expected result
        - Message about changing the password is written to the console
     """
    # FIXME: test fails due to IPA password policies, so it is not stable
    with Authselect():
        with VirtCard(ipa_user.USERNAME, insert=True) as f:
            cmd = f"su {ipa_user.USERNAME} -c 'passwd'"
            user_shell.sendline(cmd)
            user_shell.expect_exact(f"PIN for {ipa_user.USERNAME}:")
            user_shell.sendline(ipa_user.PIN)
            user_shell.expect_exact(f"Changing password for user {ipa_user.USERNAME}.")
