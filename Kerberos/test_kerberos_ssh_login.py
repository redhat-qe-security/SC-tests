from os.path import isfile

import pexpect
import pytest

from SCAutolib.models.authselect import Authselect


def test_krb_user_ssh(ipa_user, user_shell):
    with Authselect(required=False), ipa_user.card(insert=True):
        user_shell.sendline(f"ssh -o StrictHostKeyChecking=no {ipa_user.username}@localhost")
        user_shell.expect_exact("Password")
        user_shell.sendline(ipa_user.password)
        user_shell.sendline("whoami")
        user_shell.expect_exact(ipa_user.username)


def test_krb_user_scp(ipa_user, user_shell):
    with Authselect(required=False), ipa_user.card(insert=True):
        user_shell.sendline('touch /tmp/scp_test_file')
        _, retcode = pexpect.run(
            f'scp -o StrictHostKeyChecking=no '
            f'/tmp/scp_test_file {ipa_user.username}@localhost:/tmp/scp_test_file_copied',
            events={'(?i)password': ipa_user.password + '\n'},
            # If we are prompted for password, enter ipa password + enter
            withexitstatus=1)
        assert isfile('/tmp/scp_test_file_copied')
        assert retcode == 0


def test_krb_user_ssh_required(ipa_user, user_shell):
    with Authselect(required=True), ipa_user.card(insert=True):
        user_shell.sendline(f"ssh -o StrictHostKeyChecking=no {ipa_user.username}@localhost")
        user_shell.expect_exact("Password")
        user_shell.sendline(ipa_user.password)
        # When smart card is required, SSH will fail even if we provide
        # the correct password and will ask for password again.
        user_shell.expect_exact("Password")  # Expect the second Password prompt.
        user_shell.sendcontrol('c')  # Send control-C to exit the prompt


def test_krb_user_scp_required(ipa_user, user_shell):
    with Authselect(required=True), ipa_user.card(insert=True):
        user_shell.sendline('touch /tmp/scp_test_file1')
        user_shell.sendline(
            f'scp -o StrictHostKeyChecking=no -o ConnectTimeout=5 '
            f'/tmp/scp_test_file1 {ipa_user.username}@localhost:/tmp/scp_test_file_copied1')
        user_shell.expect_exact("Password")
        user_shell.sendline(ipa_user.password)
        # When smart card is required, SCP will fail even if we provide
        # the correct password and will ask for password again.
        user_shell.expect_exact("Password")  # Expect the second Password prompt.
        user_shell.sendcontrol('c')  # Send control-C to exit the prompt
        assert not isfile('/tmp/scp_test_file_copied1')


@pytest.mark.parametrize("ipa_login", [True, False])
def test_krb_change_passwd_ssh(ipa_user, user_shell, ipa_login):
    with Authselect(required=False), ipa_user.card(insert=True):
        if ipa_login:
            user_shell.sendline(f"su - {ipa_user.username}")
            user_shell.expect(f"PIN for {ipa_user.username}", timeout=10)
            user_shell.sendline(ipa_user.pin)
        user_shell.sendline(f"ssh -o StrictHostKeyChecking=no {ipa_user.username}@localhost")
        user_shell.expect_exact("Password")
        user_shell.sendline(ipa_user.password)
        user_shell.sendline("whoami")
        user_shell.expect_exact(ipa_user.username)
        user_shell.sendline("passwd")
        user_shell.expect_exact(f"Changing password for user {ipa_user.username}.")


# Login with kerberos user using a smart card and then check if we can still ssh into the system
# with different user.
def test_different_user_ssh(ipa_user, base_user, user_shell):
    with Authselect(required=False):
        with ipa_user.card(insert=True):
            user_shell.sendline(f"su - {ipa_user.username}")
            user_shell.expect(f"PIN for {ipa_user.username}", timeout=10)
            user_shell.sendline(ipa_user.pin)
            user_shell.sendline(f"ssh -o StrictHostKeyChecking=no {base_user.username}@localhost")
            user_shell.expect_exact("Password")
            user_shell.sendline(base_user.password)
            user_shell.sendline("whoami")
            user_shell.expect_exact(base_user.username)
