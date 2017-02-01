#!/usr/local/bin/python

"""
Usage:
    ./openvpn_chrome.py <filename.ovpn> ...
    - The filenames should be OpenVPN credentials files (.ovpn)
    - For example: ./openvpn_config.py joe-shmoe.ovpn joe-bloe.ovpn joe-public.ovpn
    - output is:
        - a .p12 file, to be imported into Certificates
        - a .onc file, to be imported into Chrome "net-internals"

Notes:
    - assumes openssl is installed and is on the PATH
    - the password on the .p12 will be blank (just hit Enter when prompted)
"""

import argparse
import distutils.spawn
import json
import os.path
import re
import subprocess
import sys
import uuid

parser = argparse.ArgumentParser("parse filenames")
parser.add_argument(
    "filenames",
    metavar="filename",
    type=argparse.FileType("rU"),
    nargs='+',
    help="One or more .ovpn files"
)
args = parser.parse_args()
if not args.filenames:
    parser.print_help()
    sys.exit()

print("Checking dependencies...")
openssl = distutils.spawn.find_executable('openssl')
if not openssl:
    print("openssl must be installed in order to use this tool")
    print("Ask your local sysadmin!")
    sys.exit()

count = 0
for ovpn_file in args.filenames:
    filename, file_extension = os.path.splitext(ovpn_file.name)
    if not ".ovpn" == file_extension:
        print("{} is not a .ovpn file, skipping".format(ovpn_file.name))
        continue

    print("Processing {}...".format(ovpn_file.name))

    ca = cert = key = tls_key = ""
    crt_filename = filename + ".crt"
    key_filename = filename + ".key"
    p12_filename = filename + ".p12"
    encoded_p12_filename = p12_filename + ".enc"
    onc_filename = filename + ".onc"

    host = slug = ""
    with ovpn_file as f:
        contents = f.read()
        username, host = re.search(r'# OVPN_ACCESS_SERVER_PROFILE=(.*)', contents).group(1).split(
            '@')
        ca = re.search(r'<ca>(.*)</ca>', contents, re.DOTALL).group(1).strip()
        cert = re.search(r'<cert>(.*)</cert>', contents, re.DOTALL).group(1).strip()
        key = re.search(r'<key>(.*)</key>', contents, re.DOTALL).group(1).strip()
        verbose_tls_key = re.search(r'<tls-auth>(.*)</tls-auth>', contents, re.DOTALL).group(
            1).strip()
        tls_key = ''.join(verbose_tls_key.partition('-----')[1:3]).strip()  # ditch the comments
        slug = '{}-{}'.format(username, uuid.uuid4())

    print("Writing keys and certs for {}...".format(slug))
    with open(crt_filename, "w") as f:
        f.write(cert)
    with open(key_filename, "w") as f:
        f.write(key)

    print('Generating .p12 file: {}...'.format(p12_filename))
    subprocess.call(['openssl', 'pkcs12', '-export',
                     '-in', crt_filename,
                     '-inkey', key_filename,
                     '-out', p12_filename,
                     '-password', 'pass:'])  # TODO: ???

    print('Base64-encoding {} for import...'.format(p12_filename))
    subprocess.call(
        "openssl enc -base64 -in {} -out {}".format(p12_filename, encoded_p12_filename), shell=True)

    cert = ""
    with open(encoded_p12_filename, 'r') as f:
        cert = f.read()

    print("Cleaning up files...")
    os.remove(crt_filename)
    os.remove(key_filename)
    os.remove(encoded_p12_filename)

    print("Building .onc file: {}...".format(onc_filename))
    cacert_value = "{{cacert{}}}".format(slug)
    servercert_value = "{{servercert{}}}".format(slug)
    clientcert_value = "{{clientcert{}}}".format(slug)
    onc = dict(
        Type="UnencryptedConfiguration",
        NetworkConfigurations=[dict(
            GUID=str(uuid.uuid4()),
            Name="WPOpenVPN",
            Type="VPN",
            VPN=dict(
                Type="OpenVPN",
                Host=host,
                OpenVPN=dict(
                    Auth="SHA1",
                    ClientCertType="Ref",
                    CompLZO="true",  # yes, this must be a string...
                    Cipher="BF-CBC",
                    NsCertType="server",
                    RemoteCertTLS="none",
                    KeyDirection="1",
                    Port=443,
                    Proto="tcp",
                    Username="",
                    Password="",
                    SaveCredentials=True,  # ... and this must not be a string
                    StaticChallenge="Google Auth",
                    ServerCARef=cacert_value,
                    ClientCertRef=clientcert_value,
                    Verb="3",
                    ServerPollTimeout=360,
                    RenegSec=0,
                    TLSAuthContents=tls_key  # don't strip the newlines
                )
            )
        )],
        Certificates=[dict(
            GUID=cacert_value,
            Type="Authority",
            X509=ca.replace('\n', '')
        ), dict(
            GUID=clientcert_value,
            Type="Client",
            PKCS12=cert.replace('\n', '')
        )]
    )

    with open(onc_filename, 'w') as f:
        f.write(json.dumps(onc, indent=4))

    print('Processed {}! Generated:'.format(ovpn_file.name))
    print('- {}'.format(p12_filename))
    print('- {}'.format(onc_filename))

    count += 1

print("Done! Processed {} .ovpn file(s)!".format(count))
