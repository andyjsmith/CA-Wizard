# CA Wizard
#
# Copyright (c) 2022 Andy Smith
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

import datetime
import os.path
import pathlib
import re
import subprocess
import argparse

from dateutil.relativedelta import relativedelta
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from prompt_toolkit import prompt
from prompt_toolkit.shortcuts import confirm
from prompt_toolkit.validation import Validator, ValidationError
from colorama import Fore, Style


class ChoiceValidator(Validator):
    def __init__(self, num_opts: int, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)

        self.num_opts: int = num_opts

    def validate(self, document):
        text = document.text

        try:
            num = int(text)
        except ValueError:
            raise ValidationError(message="Enter a number")

        if num < 1 or num > self.num_opts:
            raise ValidationError(message="Choice must be one of the given options")


class PasswordValidator(Validator):
    def __init__(self, *args, required=False, **kwargs) -> None:
        super().__init__(*args, **kwargs)

        self.required = required

    def validate(self, document):
        text = document.text

        try:
            text.encode("utf-8")
        except:
            raise ValidationError(message="Password could not be encoded")

        if self.required:
            if len(text) < 4:
                raise ValidationError(message="Password must be 4+ characters")
        else:
            if 0 < len(text) < 4:
                raise ValidationError(
                    message="Password must be either blank or 4+ characters"
                )


class TextValidatorNoEmpty(Validator):
    def validate(self, document):
        text = document.text

        if len(text) == 0:
            raise ValidationError(message="Input cannot be blank")

        try:
            text.encode("utf-8")
        except:
            raise ValidationError(message="Input could not be encoded")


def print_info(text, *args, **kwargs):
    print(f"[{Fore.GREEN}+{Style.RESET_ALL}] {text}", *args, **kwargs)


def print_warning(text, *args, **kwargs):
    print(f"[{Fore.YELLOW}WARNING{Style.RESET_ALL}] {text}", *args, **kwargs)


def print_error(text, *args, **kwargs):
    print(f"[{Fore.RED}ERROR{Style.RESET_ALL}] {text}", *args, **kwargs)


def get_password(
    subject="key", required=False
) -> serialization.KeySerializationEncryption:
    while True:
        password = prompt(
            f"Enter a password to encrypt the {subject}: ",
            validator=PasswordValidator(required=required),
            is_password=True,
        )

        if len(password) == 0:
            print_warning(f"{subject} will be saved unencrypted")
            return serialization.NoEncryption()

        password_repeat = prompt(
            "Enter the password again: ",
            validator=PasswordValidator(required=required),
            is_password=True,
        )

        if password == password_repeat:
            break

        print_error("Passwords don't match!")

    return serialization.BestAvailableEncryption(password.encode("utf-8"))


def get_read_password(subject="key") -> bytes:
    password = prompt(
        f"Enter the password you used to encrypt the {subject}: ",
        validator=PasswordValidator(),
        is_password=True,
    )

    return password.encode("utf-8")


def get_name(subject="subject", common_name_eg="eg, YOUR name") -> x509.Name:
    print(f"Enter the {subject} details. All values are optional.")
    country = prompt("Country Name (2 letter code): ")
    state_or_province = prompt("State or Province Name (full name): ")
    locality = prompt("Locality Name (eg, city): ")
    organization = prompt("Organization Name (eg, company): ")
    organizational_unit = prompt("Organizational Unit Name (eg, section): ")
    common_name = prompt(f"Common Name ({common_name_eg}): ")
    email_address = prompt("Email Address: ")

    name_args: "list[x509.NameAttribute]" = []
    if country:
        name_args.append(x509.NameAttribute(NameOID.COUNTRY_NAME, country))
    if state_or_province:
        name_args.append(
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, state_or_province)
        )
    if locality:
        name_args.append(x509.NameAttribute(NameOID.LOCALITY_NAME, locality))
    if organization:
        name_args.append(x509.NameAttribute(NameOID.ORGANIZATION_NAME, organization))
    if organizational_unit:
        name_args.append(
            x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, organizational_unit)
        )
    if common_name:
        name_args.append(x509.NameAttribute(NameOID.COMMON_NAME, common_name))
    if email_address:
        name_args.append(x509.NameAttribute(NameOID.EMAIL_ADDRESS, email_address))

    return x509.Name(name_args)


def get_validity_timedelta() -> relativedelta:
    while True:
        validity_str = prompt(
            "How long should the certificate be valid? Enter either in months or years (e.g. 6m or 10y): "
        ).lower()

        if re.match("^[0-9]+[ym]$", validity_str):
            break

        print_error("Your time did not match the specified format")

    months = 0
    years = 0
    if validity_str.endswith("m"):
        months = int(validity_str[:-1])
    if validity_str.endswith("y"):
        years = int(validity_str[:-1])

    return relativedelta(months=months, years=years)


def init(path):
    global BASE_DIR
    global ROOT_DIR
    global INTERMEDIATE_DIR
    global ROOT_KEY_PATH
    global ROOT_CERT_PATH
    global INTERMEDIATE_KEY_PATH
    global INTERMEDIATE_CERT_PATH
    global WEBSITE_DIR
    global CLIENT_DIR
    global CODE_SIGNING_DIR

    if path:
        BASE_DIR = os.path.realpath(path)
    else:
        BASE_DIR = os.path.realpath(os.path.curdir)
    ROOT_DIR = pathlib.Path(BASE_DIR).joinpath("root")
    ROOT_DIR.mkdir(exist_ok=True)
    ROOT_KEY_PATH = ROOT_DIR.joinpath("root.pem")
    ROOT_CERT_PATH = ROOT_DIR.joinpath("root.crt")
    INTERMEDIATE_DIR = pathlib.Path(BASE_DIR).joinpath("intermediate")
    INTERMEDIATE_DIR.mkdir(exist_ok=True)
    INTERMEDIATE_KEY_PATH = INTERMEDIATE_DIR.joinpath("intermediate.key")
    INTERMEDIATE_CERT_PATH = INTERMEDIATE_DIR.joinpath("intermediate.crt")
    WEBSITE_DIR = pathlib.Path(BASE_DIR).joinpath("webserver")
    WEBSITE_DIR.mkdir(exist_ok=True)
    CLIENT_DIR = pathlib.Path(BASE_DIR).joinpath("client")
    CLIENT_DIR.mkdir(exist_ok=True)
    CODE_SIGNING_DIR = pathlib.Path(BASE_DIR).joinpath("codesigning")
    CODE_SIGNING_DIR.mkdir(exist_ok=True)

    global root_name
    global root_key
    global root_cert
    global intermediate_name
    global intermediate_key
    global intermediate_cert

    root_name = None
    root_key = None
    root_cert = None
    intermediate_name = None
    intermediate_key = None
    intermediate_cert = None


def root_exists(all=False) -> bool:
    if all:
        return os.path.isfile(ROOT_KEY_PATH) and os.path.isfile(ROOT_CERT_PATH)
    else:
        return os.path.isfile(ROOT_KEY_PATH) or os.path.isfile(ROOT_CERT_PATH)


def intermediate_exists(all=False) -> bool:
    if all:
        return os.path.isfile(INTERMEDIATE_KEY_PATH) and os.path.isfile(
            INTERMEDIATE_CERT_PATH
        )
    else:
        return os.path.isfile(INTERMEDIATE_KEY_PATH) or os.path.isfile(
            INTERMEDIATE_CERT_PATH
        )


def load_certs(root=False, intermediate=True):
    """
    Load root and/or intermediate keys/certificates from disk if they aren't already in memory.
    If root is True, root certs will be loaded as well.
    """
    global root_name
    global root_key
    global root_cert
    global intermediate_name
    global intermediate_key
    global intermediate_cert

    if root:
        if (
            root_cert is not None
            and root_key is not None
            and intermediate_cert is not None
            and intermediate_key is not None
        ):
            return
    if intermediate:
        if intermediate_cert is not None and intermediate_key is not None:
            return

    if root:
        # Load root key
        with open(ROOT_KEY_PATH, "rb") as f:
            raw_root_key = f.read()

        try:
            root_key = serialization.load_pem_private_key(raw_root_key, password=None)
        except TypeError:
            while True:
                try:
                    root_key = serialization.load_pem_private_key(
                        raw_root_key,
                        password=get_read_password("root CA key"),
                        backend=default_backend(),
                    )
                    break
                except (ValueError, TypeError):
                    print_error("Password for the key was incorrect. Try again.")

        # Load root cert
        with open(ROOT_CERT_PATH, "rb") as f:
            root_cert = x509.load_pem_x509_certificate(f.read())

        # Load root name
        root_name = root_cert.subject

    if intermediate:
        # Load intermediate key
        with open(INTERMEDIATE_KEY_PATH, "rb") as f:
            raw_intermediate_key = f.read()

        try:
            intermediate_key = serialization.load_pem_private_key(
                raw_intermediate_key, password=None
            )
        except TypeError:
            while True:
                try:
                    intermediate_key = serialization.load_pem_private_key(
                        raw_intermediate_key,
                        password=get_read_password("intermediate CA key"),
                        backend=default_backend(),
                    )
                    break
                except (ValueError, TypeError):
                    print_error("Password for the key was incorrect. Try again.")

        # Load intermediate cert
        with open(INTERMEDIATE_CERT_PATH, "rb") as f:
            intermediate_cert = x509.load_pem_x509_certificate(f.read())

        # Load intermediate name
        intermediate_name = intermediate_cert.subject


def create_root_ca() -> bool:
    """Generate the root CA key and certificate"""
    global root_name
    global root_key
    global root_cert
    print("-" * 20)

    if root_exists():
        if not confirm(
            "Root CA key or certificate already exists. Do you want to overwrite?"
        ):
            return False
        print_warning("Existing root key and certificate will be DELETED")

    # Generate root CA certificate
    root_key = ec.generate_private_key(ec.SECP384R1)

    root_encryption_algorithm = get_password("Root CA key")

    with open(ROOT_KEY_PATH, "wb") as f:
        f.write(
            root_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=root_encryption_algorithm,
            )
        )

    root_name = get_name(subject="root CA", common_name_eg="eg, Example Root CA")

    root_cert = (
        x509.CertificateBuilder()
        .subject_name(root_name)
        .issuer_name(root_name)
        .public_key(root_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.utcnow())
        .not_valid_after(datetime.datetime.utcnow() + get_validity_timedelta())
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(root_key.public_key()),
            critical=False,
        )
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                key_cert_sign=True,
                crl_sign=True,
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                key_agreement=False,
                data_encipherment=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.ExtendedKeyUsage(
                [
                    x509.OID_SERVER_AUTH,
                    x509.OID_CLIENT_AUTH,
                    x509.OID_CODE_SIGNING,
                    x509.OID_EMAIL_PROTECTION,
                    x509.OID_TIME_STAMPING,
                    x509.OID_OCSP_SIGNING,
                ]
            ),
            critical=False,
        )
    ).sign(root_key, hashes.SHA256())

    with open(ROOT_CERT_PATH, "wb") as f:
        f.write(root_cert.public_bytes(serialization.Encoding.PEM))

    return True


def create_intermediate_ca() -> bool:
    """Generate the intermediate CA key and certificate, which is signed by the root CA"""
    global intermediate_name
    global intermediate_key
    global intermediate_cert
    print("-" * 20)
    print("[Intermediate Certificate Generation]")

    if intermediate_exists():
        if not confirm(
            "Intermediate CA key or certificate already exists. Do you want to overwrite?"
        ):
            return False
        print_warning("Existing intermediate key and certificate will be DELETED")

    # Generate root CA certificate
    intermediate_key = ec.generate_private_key(ec.SECP384R1)

    intermediate_encryption_algorithm = get_password("Intermediate CA key")

    with open(INTERMEDIATE_KEY_PATH, "wb") as f:
        f.write(
            intermediate_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=intermediate_encryption_algorithm,
            )
        )

    intermediate_name = get_name(
        subject="intermediate CA", common_name_eg="eg, Example Intermediate CA"
    )

    while True:
        not_valid_after = datetime.datetime.utcnow() + get_validity_timedelta()
        if not_valid_after < root_cert.not_valid_after:
            break

        print_error(
            "Intermediate certificate validity should not be longer than root certificate validity"
        )

    intermediate_cert = (
        x509.CertificateBuilder()
        .subject_name(intermediate_name)
        .issuer_name(root_name)
        .public_key(intermediate_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.utcnow())
        .not_valid_after(not_valid_after)
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(intermediate_key.public_key()),
            critical=False,
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(root_cert.public_key()),
            critical=False,
        )
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(
            x509.KeyUsage(
                key_cert_sign=True,
                crl_sign=True,
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                key_agreement=False,
                data_encipherment=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.ExtendedKeyUsage(
                [
                    x509.OID_SERVER_AUTH,
                    x509.OID_CLIENT_AUTH,
                    x509.OID_CODE_SIGNING,
                    x509.OID_EMAIL_PROTECTION,
                    x509.OID_TIME_STAMPING,
                    x509.OID_OCSP_SIGNING,
                ]
            ),
            critical=False,
        )
    ).sign(root_key, hashes.SHA256())

    with open(INTERMEDIATE_CERT_PATH, "wb") as f:
        f.write(intermediate_cert.public_bytes(serialization.Encoding.PEM))

    return True


def create_website():
    """Generate a website certificate"""

    print("-" * 20)
    print("[Website Certificate Generation]")

    friendly_name = prompt(
        f"Enter a friendly name for the website (e.g. example.com, Example, etc.): ",
        validator=TextValidatorNoEmpty(),
    )

    website_key = ec.generate_private_key(ec.SECP384R1)

    with open(WEBSITE_DIR.joinpath(f"{friendly_name}.key"), "wb") as f:
        f.write(
            website_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )

    website_subject = get_name(subject="website", common_name_eg="eg, example.com")

    san = []
    print(
        "Now enter DNS names the certificate should be valid for, one per line. These are the domains your certificate should be valid for (e.g. example.com, *.example.com, test123.example.com). When you're done, leave it blank and press enter."
    )
    while True:
        input_name = prompt("DNS Name: ")
        if input_name == "":
            break

        try:
            san.append(x509.DNSName(input_name))
        except ValueError as err:
            print_error(err)

    while True:
        not_valid_after = datetime.datetime.utcnow() + get_validity_timedelta()
        if not_valid_after < intermediate_cert.not_valid_after:
            break

        print_error(
            "Website certificate validity should not be longer than intermediate certificate validity"
        )

    website_cert = (
        x509.CertificateBuilder()
        .subject_name(website_subject)
        .issuer_name(intermediate_name)
        .public_key(website_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.utcnow())
        .not_valid_after(not_valid_after)
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(website_key.public_key()),
            critical=False,
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(
                intermediate_cert.public_key()
            ),
            critical=False,
        )
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                key_cert_sign=False,
                crl_sign=False,
                digital_signature=True,
                content_commitment=False,
                key_encipherment=True,
                key_agreement=False,
                data_encipherment=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.SubjectAlternativeName(san),
            critical=False,
        )
        .add_extension(
            x509.ExtendedKeyUsage([x509.OID_SERVER_AUTH]),
            critical=False,
        )
        .sign(intermediate_key, hashes.SHA256())
    )

    with open(WEBSITE_DIR.joinpath(f"{friendly_name}.crt"), "wb") as f:
        f.write(website_cert.public_bytes(serialization.Encoding.PEM))

    with open(WEBSITE_DIR.joinpath(f"{friendly_name}_fullchain.crt"), "wb") as f:
        f.write(website_cert.public_bytes(serialization.Encoding.PEM))
        f.write(intermediate_cert.public_bytes(serialization.Encoding.PEM))


def create_client():
    """Generate a client certificate"""

    print("-" * 20)
    print("[Client Certificate Generation]")

    friendly_name = prompt(
        f"Enter a friendly name for the client (e.g. John Doe, john.doe@example.com, etc.): ",
        validator=TextValidatorNoEmpty(),
    )

    client_key = ec.generate_private_key(ec.SECP384R1)

    client_encryption_algorithm = get_password("client key", required=True)

    with open(CLIENT_DIR.joinpath(f"{friendly_name}.key"), "wb") as f:
        f.write(
            client_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=client_encryption_algorithm,
            )
        )

    client_subject = get_name(
        subject="client",
        common_name_eg="eg, John Doe, john.doe@example.com, John's Phone, DESKTOP-XXXXXX, etc.",
    )

    while True:
        not_valid_after = datetime.datetime.utcnow() + get_validity_timedelta()
        if not_valid_after < intermediate_cert.not_valid_after:
            break

        print_error(
            "Client certificate validity should not be longer than intermediate certificate validity"
        )

    client_cert = (
        x509.CertificateBuilder()
        .subject_name(client_subject)
        .issuer_name(intermediate_name)
        .public_key(client_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.utcnow())
        .not_valid_after(not_valid_after)
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(client_key.public_key()),
            critical=False,
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(
                intermediate_cert.public_key()
            ),
            critical=False,
        )
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                key_cert_sign=False,
                crl_sign=False,
                digital_signature=True,
                content_commitment=True,
                key_encipherment=True,
                key_agreement=False,
                data_encipherment=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.ExtendedKeyUsage([x509.OID_CLIENT_AUTH, x509.OID_EMAIL_PROTECTION]),
            critical=False,
        )
        .sign(intermediate_key, hashes.SHA256())
    )

    with open(CLIENT_DIR.joinpath(f"{friendly_name}.crt"), "wb") as f:
        f.write(client_cert.public_bytes(serialization.Encoding.PEM))

    # Save PFX for easy Windows installation
    with open(CLIENT_DIR.joinpath(f"{friendly_name}.pfx"), "wb") as f:
        f.write(
            serialization.pkcs12.serialize_key_and_certificates(
                friendly_name.encode("utf-8"),
                client_key,
                client_cert,
                [intermediate_cert],
                client_encryption_algorithm,
            )
        )


def create_code_signing():
    """Generate a code signing certificate"""

    print("-" * 20)
    print("[Code Signing Certificate Generation]")

    friendly_name = prompt(
        f"Enter a friendly name for the code signing certificate (e.g. example.com, Example, etc.): ",
        validator=TextValidatorNoEmpty(),
    )

    code_signing_key = ec.generate_private_key(ec.SECP384R1)

    with open(CODE_SIGNING_DIR.joinpath(f"{friendly_name}.key"), "wb") as f:
        f.write(
            code_signing_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )

    print(
        "Below, common name should usually be your name or your company's name (e.g. Example LLC, John Doe, etc.)"
    )
    code_signing_subject = get_name(
        subject="code signing",
        common_name_eg="your name or your company's name, e.g. Example LLC, John Doe, etc.",
    )

    while True:
        not_valid_after = datetime.datetime.utcnow() + get_validity_timedelta()
        if not_valid_after < intermediate_cert.not_valid_after:
            break

        print_error(
            "Code signing certificate validity should not be longer than intermediate certificate validity"
        )

    code_signing_cert = (
        x509.CertificateBuilder()
        .subject_name(code_signing_subject)
        .issuer_name(intermediate_name)
        .public_key(code_signing_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.utcnow())
        .not_valid_after(not_valid_after)
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(code_signing_key.public_key()),
            critical=False,
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(
                intermediate_cert.public_key()
            ),
            critical=False,
        )
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                key_cert_sign=False,
                crl_sign=False,
                digital_signature=True,
                content_commitment=False,
                key_encipherment=True,
                key_agreement=False,
                data_encipherment=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.ExtendedKeyUsage([x509.OID_CODE_SIGNING]),
            critical=False,
        )
        .sign(intermediate_key, hashes.SHA256())
    )

    with open(CODE_SIGNING_DIR.joinpath(f"{friendly_name}.crt"), "wb") as f:
        f.write(code_signing_cert.public_bytes(serialization.Encoding.PEM))

    # Save PFX for easy Windows installation
    with open(CODE_SIGNING_DIR.joinpath(f"{friendly_name}.pfx"), "wb") as f:
        f.write(
            serialization.pkcs12.serialize_key_and_certificates(
                friendly_name.encode("utf-8"),
                code_signing_key,
                code_signing_cert,
                [intermediate_cert],
                serialization.NoEncryption(),
            )
        )


def install_root():
    print("-" * 20)
    print("Attempting to install root CA certificate...")
    process = subprocess.run(
        ["certutil.exe", "-user", "-addstore", "Root", ROOT_CERT_PATH]
    )
    if process.returncode == 0:
        print_info("Installed root CA successfully")
    else:
        print_error("An error occurred when installing the root CA")


def main():
    parser = argparse.ArgumentParser(description="Certificate Authority Wizard")
    parser.add_argument(
        "-d",
        "--dir",
        type=pathlib.Path,
        help="directory containing the CA files, default is current directory",
    )
    args = parser.parse_args()

    init(args.dir)

    # If root certs don't exist, then program was never run so run the wizards
    # to create root and intermediate CAs
    if not intermediate_exists(all=True) and not root_exists(all=True):
        print(
            "It looks like there aren't any existing certificates. Let's create new ones now."
        )

        if not create_root_ca():
            return
        if not create_intermediate_ca():
            return
    elif not intermediate_exists(all=True):
        print_warning(
            "It looks like you have root certificates but are missing an intermediate certificate. Let's generate an intermediate certificate."
        )

        load_certs(root=True, intermediate=False)
        if not create_intermediate_ca():
            return

    while True:
        options = [
            "Create a website certificate",
            "Create a client certificate",
            "Create a code signing certificate",
            "Install root certificate (Windows ONLY)",
            "Regenerate intermediate CA",
            "Exit",
        ]

        print("What would you like to do?")

        for i, option in enumerate(options):
            print(f"{i+1}) {option}")

        choice = int(prompt("Choice: ", validator=ChoiceValidator(len(options))))

        if choice == 1:
            load_certs()
            create_website()
        elif choice == 2:
            load_certs()
            create_client()
        elif choice == 3:
            load_certs()
            create_code_signing()
        elif choice == 4:
            install_root()
        elif choice == 5:
            load_certs(root=True)
            if not create_intermediate_ca():
                return
        else:
            print_info("Exiting")
            return


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print_error("Heard Ctrl-C, Exiting")
