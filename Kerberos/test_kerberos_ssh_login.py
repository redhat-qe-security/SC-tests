import sys
import pexpect
import pytest
from SCAutolib.src.authselect import Authselect
from SCAutolib.src.utils import run_cmd
from SCAutolib.src.virt_card import VirtCard
from fixtures import user_shell, ipa_user
from os.path import isfile


def test_krb_user_ssh(ipa_user, user_shell):
    with Authselect(required=False):
        with VirtCard(username=ipa_user.USERNAME, insert=True) as sc:
            user_shell.sendline(f"ssh -o StrictHostKeyChecking=no {ipa_user.USERNAME}@localhost")
            user_shell.expect_exact(f"Password")
            user_shell.sendline(ipa_user.PASSWD)
            user_shell.sendline(f"whoami")
            user_shell.expect_exact(ipa_user.USERNAME)


def test_krb_user_scp(ipa_user, user_shell):
    with Authselect(required=False):
        with VirtCard(username=ipa_user.USERNAME, insert=True) as sc:
            user_shell.sendline('touch /tmp/scp_test_file')
            _, retcode = pexpect.run(f'scp -o StrictHostKeyChecking=no /tmp/scp_test_file {ipa_user.USERNAME}@localhost:/tmp/scp_test_file_copied',
                                    events={'(?i)password': ipa_user.PASSWD + '\n'}, #If we are prompted for password, enter ipa password + enter
                                    withexitstatus=1)
            assert isfile('/tmp/scp_test_file_copied')
            assert retcode == 0


def test_krb_user_ssh_required(ipa_user, user_shell):
    with Authselect(required=True):
        with VirtCard(username=ipa_user.USERNAME, insert=True) as sc:
            user_shell.sendline(f"ssh -o StrictHostKeyChecking=no {ipa_user.USERNAME}@localhost")
            user_shell.expect_exact(f"Password")
            user_shell.sendline(ipa_user.PASSWD)
            # When smart card is required, SSH will fail even if we provide
            # the correct password and will ask for password again.
            user_shell.expect_exact(f"Password") # Expect the second Password prompt.
            user_shell.sendcontrol('c') # Send control-C to exit the prompt


def test_krb_user_scp_required(ipa_user, user_shell):
    with Authselect(required=True):
        with VirtCard(username=ipa_user.USERNAME, insert=True) as sc:
            user_shell.sendline('touch /tmp/scp_test_file1')
            user_shell.sendline(f'scp -o StrictHostKeyChecking=no -o ConnectTimeout=5 /tmp/scp_test_file1 {ipa_user.USERNAME}@localhost:/tmp/scp_test_file_copied1')
            user_shell.expect_exact(f"Password")
            user_shell.sendline(ipa_user.PASSWD)
            # When smart card is required, SCP will fail even if we provide
            # the correct password and will ask for password again.
            user_shell.expect_exact(f"Password") # Expect the second Password prompt.
            user_shell.sendcontrol('c') # Send control-C to exit the prompt
            assert not isfile('/tmp/scp_test_file_copied1')
