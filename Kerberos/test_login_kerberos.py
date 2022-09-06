import pexpect
import pytest

from SCAutolib import run
from SCAutolib.models.authselect import Authselect
from SCAutolib.utils import user_factory, ipa_factory

ipa_username = "rhel-86-regression"
ipa_server = ipa_factory()
ipa_user = user_factory(ipa_username, ipa_server=ipa_server)


@pytest.mark.parametrize("user", [ipa_user], scope="session")
def test_smart_card_gdm_login_enforcing(user, root_shell):
    """Test kerberos user tries to login to the GDM with smart card. Smart
    card is enforced.

    Setup
        1. General setup
        2. Setup authselect: authselect select sssd with-smartcard with-smartcard-required
        3. Try to run 'sssctl user-checks -s gdm-smartcard kerberos_username -a auth'

    Expected result
        - User is asked to insert the smartcard
        - User inserts the smartcard
        - User is asked to insert smartcard PIN
        - User inserts correct smartcard PIN
        - Authentication is succeed.
    """
    with Authselect(lock_on_removal=True, mk_homedir=True, required=True):
        with user.card(insert=False) as sc:
            cmd = f"sssctl user-checks -s gdm-smartcard {user.username} -a auth"
            root_shell.sendline(cmd)
            root_shell.expect(r"Please (insert|enter) smart card", timeout=10)
            sc.insert()
            root_shell.expect(f"PIN for {user.username}:")
            root_shell.sendline(user.pin)
            root_shell.expect(rf"pam_authenticate for user \[{user.username}\]: Success")


@pytest.mark.parametrize("user", [ipa_user], scope="session")
def test_kerberos_login_to_root(user, user_shell, root_user):
    """Kerberos user tries to switch to the root user with root password after
    kerberos user is logged in with smart card. Smart card is required.

    Setup
        1. General setup
        2. Setup authselect: authselect select sssd with-smartcard with-smartcard-required
        3. Insert the card
        4. Switch to kerberos user (su kerberos_username)
        5. System asks for smartcard PIN -> insert correct smartcard PIN
        6. User is successfully logged in
        7. Try to switch to root (su -)

    Expected result
        - User is asked to insert root password
        - User inserts root password
        - User is switched to the root user
    """
    with Authselect(required=True):
        with user.card(insert=True):
            user_shell.sendline(f"su - {user.username}")
            user_shell.expect(f"PIN for {user.username}", timeout=10)
            user_shell.sendline(user.pin)
            user_shell.sendline("su - -c 'whoami'")
            user_shell.expect("Password")
            user_shell.sendline(root_user.password)
            user_shell.expect("root")


@pytest.mark.parametrize("user", [ipa_user], scope="session")
def test_krb_user_su_to_root_wrong_passwd_sc_required_no_sc(user, user_shell):
    """Kerberos user tries to switch to the root user with root password after
       kerberos user is logged in with smart card. Smart card is required.

       Setup
           1. General setup
           2. Setup authselect: authselect select sssd with-smartcard with-smartcard-required
           3. Insert the card
           4. Switch to kerberos user (su kerberos_username)
           5. System asks for smartcard PIN -> insert correct smartcard PIN
           6. User is successfully logged in
           7. Try to switch to root (su -)

       Expected result
           1. User is asked to insert root password
           2. User inserts wrong root password
           3. User is not switched to the root user, corresponding message is
              written to the output
       """
    with Authselect(required=True):
        with user.card(insert=True) as sc:
            cmd = f"su - {user.username}"
            user_shell.sendline(cmd)
            user_shell.expect_exact(f"PIN for {user.username}:")
            user_shell.sendline(user.pin)
            cmd = "whoami"
            user_shell.sendline(cmd)
            user_shell.expect_exact(user.username)
            sc.remove()

            cmd = "su -"
            user_shell.sendline(cmd)
            user_shell.expect_exact("Password:")
            user_shell.sendline("wrong_password")
            user_shell.expect_exact("su: Authentication failure")


@pytest.mark.parametrize("user", [ipa_user], scope="session")
def test_kerberos_user_sudo_wrong_password(user, user_shell):
    """Kerberos user tries to use sudo to access some application and mistype
    the password. Smartcard is required and used for user login and removed
    after login.

    Setup
        1. General setup
        2. Setup authselect: authselect select sssd with-smartcard with-smartcard-required
        3. Insert the card
        4. Switch to kerberos user (su kerberos_username)
        5. System asks for smartcard PIN -> insert correct smartcard PIN
        6. User is successfully logged in
        7. Try to run sudo command 'sudo ls /'

    Expected result
        - User is asked to insert the password
        - User inserts wrong password
        - Password is not accepted and user is asked to insert the password again
    """

    with Authselect(required=True):
        with user.card(insert=True) as sc:
            cmd = f"su - {user.username} -c 'sudo -S ls /'"
            user_shell.sendline(cmd)
            user_shell.expect_exact(f"PIN for {user.username}:")
            user_shell.sendline(user.pin)

            cmd = "whoami"
            user_shell.sendline(cmd)
            user_shell.expect_exact(user.username)

            sc.remove()

            cmd = "sudo -S ls /"
            user_shell.sendline(cmd)
            user_shell.expect_exact(f"[sudo] password for {user.username}:")
            user_shell.sendline("098765432")
            user_shell.expect("Sorry, try again.")


@pytest.mark.parametrize("user", [ipa_user], scope="session")
def test_krb_user_sudo_correct_password_sc_required_no_sc(user, user_shell):
    with Authselect(required=True, sudo=True):
        with user.card(insert=True) as sc:
            output = pexpect.run("ls /", encoding="utf-8")
            cmd = f"su - {user.username}"
            user_shell.sendline(cmd)
            user_shell.expect_exact(f"PIN for {user.username}:")
            user_shell.sendline(user.pin)

            cmd = "whoami"
            user_shell.sendline(cmd)
            user_shell.expect_exact(user.username)

            sc.remove()

            cmd = "sudo -S ls /"
            user_shell.sendline(cmd)
            user_shell.expect(rf"\[sudo\] password for {user.username}:")
            user_shell.sendline(user.password)
            user_shell.expect(output)


@pytest.mark.parametrize("user", [ipa_user], scope="session")
def test_krb_user_su_correct_password(user, user_shell):
    """Kerberos' user login with command su using correct password.

    Setup:
        1. General setup
        2. Smart card is NOT required for login
        3. Smart card is NOT inserted
        4. Run su ipa-user

    Expected result:
        - user is prompted to insert kerberos password
        - after inserting the password, user is successfully authenticated
    """
    with Authselect():
        cmd = f"su {user.username}"
        user_shell.sendline(cmd)
        user_shell.expect_exact("Password:")
        user_shell.sendline(user.password)
        user_shell.sendline("whoami")
        user_shell.expect_exact(user.username)
        user_shell.close()


@pytest.mark.parametrize("user", [ipa_user], scope="session")
def test_krb_user_ldap_mapping(user, user_shell, sssd):
    """Test for LDAP mapping of Kerberos user provided by IPA server"""
    changes = ({"section": f"domain/{ipa_server.domain}",
                "key": "id_provider",
                "val": "ldap"},
               {"section": f"certmap/{ipa_server.domain}/{user.username}",
                "key": "matchrule",
                "val": f"<SUBJECT>.*CN={user.username}.*"},
               {"section": f"certmap/{ipa_server.domain}/{user.username}",
                "key": "maprule",
                "val": "(userCertificate;binary={cert!bin})"})
    with sssd as conf:
        for item in changes:
            conf.set(key=item["key"],
                     value=item["val"],
                     section=item["section"])
        conf.save()

        run(["systemctl", "restart", "sssd"], sleep=5)

        with Authselect(), user.card(insert=True):
            cmd = f"su {user.username} -c 'whoami'"
            user_shell.sendline(cmd)
            user_shell.expect_exact(f"PIN for {user.username}:")
            user_shell.sendline(user.pin)
            user_shell.expect_exact(user.username)
