import re
import sys
from time import sleep

import pytest
from fixtures import ipa_user, https_server, root_shell, ipa_meta_client
from subprocess import check_output
from SCAutolib.src import virt_card


@pytest.mark.parametrize('principal,ca', [("https-server", "ipa")])
def test_access_secure_webpage_on_https(ipa_user, https_server, root_shell, tmpdir):
    check_output(["certutil", "-N", "-d", tmpdir, "--empty-password"], encoding="utf-8")

    check_output(["certutil", "-A", "-n", "ipa-ca", "-t", 'TC,C,T', "-d", tmpdir,
                 "-i", "/etc/ipa/ca.crt"], encoding="utf-8")

    server_addr = f"127.0.0.1 {https_server}\n"
    with open("/etc/hosts", "r") as f:
        content = f.read()
    if server_addr not in content:
        # NSS client requires that name of requested server is the same as the
        # CN from the server certificate. To fulfill this requirement,
        # principal name should be added to the /etc/hosts as it is the
        with open("/etc/hosts", "a") as f:
            f.write(f"\n{server_addr}")

    with virt_card.VirtCard(ipa_user.USERNAME, insert=True):
        out = check_output(["modutil", "-list", "-dbdir", tmpdir], encoding="utf-8")
        uri = re.findall(rf"uri:\s(.*{ipa_user.USERNAME}.*)\n", out)
        assert len(uri) == 1, f"Only one URI should be present in the " \
                              f"database. Found URIs: {uri}"
        uri = uri[0]
        nss_client = "/usr/lib64/nss/unsupported-tools/tstclnt"

        cmd = f'{nss_client} -n "{uri}" -d {tmpdir} -p 8888 -h {https_server} -V tls1.2: -Q'
        root_shell.sendline(cmd)
        root_shell.expect_exact(f'Enter Password or Pin for "{ipa_user.USERNAME}":', timeout=20)
        root_shell.sendline(ipa_user.PIN)
        root_shell.expect_exact("Received 0 Cert Status items (OCSP stapled data)", timeout=20)
