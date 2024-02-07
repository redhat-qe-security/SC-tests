from http import server
import re
import ssl
import threading
from subprocess import check_output
from time import sleep

import pytest

from SCAutolib.models.file import File
from SCAutolib.models.user import IPAUser
from SCAutolib.models.card import VirtualCard
from SCAutolib.utils import _gen_private_key
from SCAutolib.exceptions import SCAutolibException
from conftest import ipa_server


def _https_server(user_cert, user_key):
    server_address = ("127.0.0.1", 8888)
    httpd = server.HTTPServer(server_address, server.SimpleHTTPRequestHandler)
    httpd.socket = ssl.wrap_socket(httpd.socket,
                                   server_side=True,
                                   certfile=str(user_cert),
                                   keyfile=str(user_key),
                                   ca_certs="/etc/ipa/ca.crt",
                                   ssl_version=ssl.PROTOCOL_TLSv1_2,
                                   cert_reqs=ssl.CERT_REQUIRED,
                                   do_handshake_on_connect=True)
    httpd.serve_forever()


@pytest.fixture
def https_server(tmp_path):
    https_user_card = VirtualCard({
        "name": "virt-card-2",
        "pin": "123456",
        "cardholder": "https-server",
        "CN": "https-server",
        "UID": "",
        "card_type": "virtual",
        "ca_name": "ipa"
    }, card_dir=tmp_path)

    https_user = IPAUser(ipa_server,
                         username="https-server",
                         password="SECret.123")

    https_user_card.user = https_user

    try:
        https_user.add_user()
    except SCAutolibException:
        pass
    key = tmp_path.joinpath("https-server-key.pem")
    _gen_private_key(key)
    https_user_card.key = key
    csr = https_user_card.gen_csr()
    cert_out = tmp_path.joinpath("cert.pem")
    ipa_server.request_cert(csr, https_user.username, cert_out)

    hosts = File("/etc/hosts")
    with hosts.path.open("a") as f:
        f.write(f"127.0.0.1 {https_user.username}")
    try:
        server_t = threading.Thread(name='daemon_server',
                                    args=(cert_out, https_user_card.key),
                                    daemon=True,
                                    target=_https_server)
        server_t.start()

        sleep(5)
        yield https_user.username
        server_t.join(timeout=1)
    finally:
        ipa_server.del_user(https_user)


def test_access_secure_webpage_on_https(ipa_user, https_server, root_shell, tmpdir):
    """Test that kerberos user is asked for PIN when accessing a secure webpage"""
    check_output(["certutil", "-N", "-d", tmpdir, "--empty-password"], encoding="utf-8")

    check_output(["certutil", "-A", "-n", "ipa-ca", "-t", 'TC,C,T', "-d", tmpdir,
                 "-i", "/etc/ipa/ca.crt"], encoding="utf-8")

    with ipa_user.card(insert=True):
        out = check_output(["modutil", "-list", "-dbdir", tmpdir], encoding="utf-8")
        uri = re.findall(rf"uri:\s(.*{ipa_user.username}.*)\n", out)
        assert len(uri) == 1, f"Only one URI should be present in the " \
                              f"database. Found URIs: {uri}"
        uri = uri[0]
        nss_client = "/usr/lib64/nss/unsupported-tools/tstclnt"

        cmd = f'{nss_client} -n "{uri}" -d {tmpdir} -p 8888 -h {https_server} -V tls1.2: -Q'
        root_shell.sendline(cmd)
        root_shell.expect_exact(f'Enter Password or Pin for "{ipa_user.username}":', timeout=20)
        root_shell.sendline(ipa_user.pin)
        root_shell.expect_exact("Received 0 Cert Status items (OCSP stapled data)", timeout=20)
