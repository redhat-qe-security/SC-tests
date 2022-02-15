import http.server
import ssl
import subprocess as subp
import sys
import threading
from time import sleep

import pexpect
import pytest
import python_freeipa as pipa
from SCAutolib.src import read_config, LIB_CERTS, LIB_KEYS
from SCAutolib.src.authselect import Authselect
from SCAutolib.src.utils import (run_cmd, check_output, edit_config_,
                                 restart_service, backup_, restore_file_)
from SCAutolib.src.virt_card import VirtCard
import python_freeipa as pipa


class User:
    ROOT_PASSWD = read_config("root_passwd")
    USERNAME_LOCAL = None
    PASSWD_LOCAL = None
    PIN_LOCAL = None

    def su_login_local_with_sc(self):
        with Authselect(required=False):
            with VirtCard(self.USERNAME_LOCAL, insert=True):
                cmd = f'su - {self.USERNAME_LOCAL} -c "su - ' \
                      f'{self.USERNAME_LOCAL} -c whoami"'
                output = run_cmd(cmd, passwd=self.PIN_LOCAL, pin=True)
                check_output(output, expect=self.USERNAME_LOCAL,
                             zero_rc=True, check_rc=True)

    def su_login_local_with_passwd(self):
        with Authselect(required=False):
            with VirtCard(self.USERNAME_LOCAL, insert=True):
                cmd = f'su - {self.USERNAME_LOCAL} -c "su - ' \
                      f'{self.USERNAME_LOCAL} -c whoami"'
                output = run_cmd(cmd, passwd=self.PASSWD_LOCAL, pin=False)
                check_output(output, expect=self.USERNAME_LOCAL,
                             zero_rc=True, check_rc=True)


class LocalUser(User):
    def __init__(self):
        self.USERNAME_LOCAL = read_config("local_user.name")
        self.PASSWD_LOCAL = read_config("local_user.passwd")
        self.PIN_LOCAL = read_config("local_user.pin")


class IPAUser(User):
    def __init__(self):
        self.USERNAME = read_config("ipa_user.name")
        self.PASSWD = read_config("ipa_user.passwd")
        self.PIN = read_config("ipa_user.pin")


@pytest.fixture()
def edit_config(file_path, section, key, value, restore, restart):
    """Used for editing given configuration file. Arguments are based through
    the pytest.mark.parametrize decorator"""
    destination_path = backup_(file_path)
    if type(section) == str:
        section = [section]
    if type(key) == str:
        key = [key]
    if type(value) != list:
        value = [value]

    if len(section) != len(key) != len(value):
        raise ValueError(
            "Length of parameters section, key, value has to be the same. "
            f"len(section) = {len(section)}; "
            f"len(key) = {len(key)}; "
            f"len(value) = {len(value)}")

    for s, k, v in zip(section, key, value):
        edit_config_(file_path, s, k, v)

    for service in restart:
        restart_service(service)

    yield

    if restore:
        restore_file_(destination_path, file_path)
        for service in restart:
            restart_service(service)


def local_user():
    return LocalUser()


def ipa_user_():
    return IPAUser()


@pytest.fixture(name="user")
def user_indirect():
    """Returns an object of local user"""
    return local_user()


@pytest.fixture()
def ipa_user():
    """Returns an object of IPA user"""
    return ipa_user_()


@pytest.fixture()
def backup(file_path, restore, restart):
    assert type(file_path) == str
    assert type(restore) == bool
    assert (type(restart) == list) or (type(restart) == str)
    target = backup_(file_path)
    if type(restart) == str:
        restart = [restart]

    for service in restart:
        restart_service(service)

    yield

    if restore:
        restore_file_(target, file_path)
        for service in restart:
            restart_service(service)


@pytest.fixture(scope="function")
def user_shell():
    """Creates shell with some local user as a starting point for test."""
    shell = pexpect.spawn("/usr/bin/sh -c 'su base-user'", encoding="utf-8")
    shell.logfile = sys.stdout
    return shell


@pytest.fixture(scope="function")
def root_shell():
    """Creates root shell."""
    shell = pexpect.spawn("/usr/bin/sh ", encoding="utf-8")
    shell.logfile = sys.stdout
    return shell


@pytest.fixture
def ipa_meta_client():
    """Ready-to-user admin Meta Client for IPA server."""
    hostname, passwd = read_config("ipa_server_hostname", "ipa_server_admin_passwd")
    client = pipa.ClientMeta(hostname, verify_ssl=False)
    client.login("admin", passwd)
    return client


def _https_server(principal, ca, ipa_meta_client, *args, **kwargs):
    server_address = ("127.0.0.1", 8888)
    key = f"{LIB_KEYS}/key-{principal}.pem"
    csr = f"{LIB_CERTS}/{principal}.csr"
    cert_path = f"{LIB_CERTS}/cert-{principal}.pem"

    subp.check_output(["openssl", "req", "-new", "-days", "365",
                       "-nodes", "-newkey", "rsa:4096", "-keyout", key,
                       "-out", csr, "-subj", f"/CN={principal}"],
                      encoding='utf-8')
    with open(csr, "r") as f:
        csr_content = f.read()

    ca_cert = None
    if ca == "ipa":
        ca_cert = "/etc/ipa/ca.crt"
        resp = ipa_meta_client.cert_request(a_csr=csr_content, o_principal=principal)
        cert = resp["result"]["certificate"]
        begin = "-----BEGIN CERTIFICATE-----"
        end = "-----END CERTIFICATE-----"
        cert = f"{begin}\n{cert}\n{end}"
        with open(cert_path, "w") as f:
            f.write(cert)
    else:
        raise Exception("Other then IPA CA is not implemented yet")

    httpd = http.server.HTTPServer(server_address, http.server.SimpleHTTPRequestHandler)

    httpd.socket = ssl.wrap_socket(httpd.socket,
                                   server_side=True,
                                   certfile=cert_path,
                                   keyfile=key,
                                   ca_certs=ca_cert,
                                   ssl_version=ssl.PROTOCOL_TLSv1_2,
                                   cert_reqs=ssl.CERT_REQUIRED,
                                   do_handshake_on_connect=True)
    httpd.serve_forever()


@pytest.fixture
def https_server(principal, ca, ipa_meta_client):
    """Start HTTPS server """
    try:
        ipa_meta_client.user_add(principal, "https", "server", principal,
                                 o_userpassword='redhat')
    except pipa.exceptions.DuplicateEntry:
        pass

    server_t = threading.Thread(name='daemon_server',
                                args=(principal, ca, ipa_meta_client,),
                                daemon=True,
                                target=_https_server)
    server_t.start()

    sleep(5)
    yield principal

    server_t.join(timeout=1)
    resp = ipa_meta_client.cert_find(user=principal)["result"]
    assert len(resp) == 1, "Only one certificate should be matched. " \
                           f"Number of matched certs is {len(resp)}"
    resp = resp[0]
    assert resp["status"].lower() == "valid", "Certificate is not valid"
    assert not resp["revoked"], "Certificate is revoked"
    cert_base64 = resp["certificate"]
    ipa_meta_client.user_remove_cert(a_uid=principal,
                                     o_usercertificate=cert_base64)
