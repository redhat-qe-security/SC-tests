import pytest
from SCAutolib.src.authselect import Authselect
from SCAutolib.src.virt_card import VirtCard

from fixtures import ipa_user_, ipa_user, user_shell


@pytest.mark.parametrize("required,insert,expect,secret",
                         [(False, False, "Password:", ipa_user_().PASSWD),
                          (False, True, f"PIN for {ipa_user_().USERNAME}:",
                           ipa_user_().PIN),
                          (True, False, "Password:", ipa_user_().PASSWD),
                          (True, True, f"PIN for {ipa_user_().USERNAME}:",
                           ipa_user_().PIN)])
def test_kerberos_change_passwd(ipa_user, user_shell, required, insert, expect,
                                secret):
    """Kerberos user tries to change it kerberos password after he is logged
    in to the system.

    This test runs 4 times with different set of parameters. Sets are:
        - smart card is not required, smart card is not inserted, expecting 'Password:'
          on the stdout, passing correct user password.
        - smart card is not required, smart card is inserted, expecting
          'PIN for user_name:', passing correct smart card PIN.

        - smart card is required, smart card is not inserted, expecting 'Password:'
          on the stdout, passing correct user password.
        - smart card is required, smart card is inserted, expecting
          'PIN for user_name:', passing correct smart card PIN.

    In this way we test 4 scenarios in one test:
        - testing that user can login with the password and change the password
        - testing that user can login with the smart card and change the
          password
        - testing that smart card is not enforced for 'su' command by setting
          with-smartcard-required parameter to authselect, so user can still
          login with a password and change his password without using the smart card.
        - testing that smart card is not mentioned when user change password
          after he logged in with smart card and smart card is required for the
          login (with-smartcard-required parameter to authselect)

    As expected behaviour form user site looks similar, scenarios with same
    insert, expect and secret parts are using similar description
    Setup
        1. General setup
        2. Setup authselect: authselect select sssd with-smartcard with-smartcard-required

    Scenario 1, 3:
        1. Do not insert the smart card
        2. Try to switch the user to kerberos user (su kerberos_user -c 'passwd')
           from the normal user
    Expected result:
        - User is asked for password
        - After correct password is inserted, user is successfully logged in
        - Warning about changing the password is shown

    Scenario 2, 4:
        1. User insert the card
        2. Try to switch the user to kerberos user (su kerberos_user -c 'passwd')
           from the normal user
    Expected result:
        - User is asked for smart card PIN
        - After correct PIN is inserted, user is successfully logged in
        - Warning about changing the password is shown
     """
    with Authselect(required=required):
        with VirtCard(ipa_user.USERNAME, insert=insert) as f:
            cmd = f"su {ipa_user.USERNAME} -c 'passwd'"
            user_shell.sendline(cmd)
            user_shell.expect_exact(expect)
            user_shell.sendline(secret)
            user_shell.expect_exact(f"Changing password for user {ipa_user.USERNAME}.")
