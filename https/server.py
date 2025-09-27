"""
https.server - SimpleHTTPServer wrapped in TLS"
"""
__version__ = "1.0.1"
__all__ = ["HTTPSServer", "ThreadingHTTPSServer", "generate_cert", "extract_client_cert"]

import os
import ssl
import argparse
import socketserver
import tempfile
import random
import datetime
import ipaddress
from http.server import HTTPServer, SimpleHTTPRequestHandler
from functools import partial
from cryptography import x509
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization


class HTTPSServer(HTTPServer):
    """
    HTTPServer Class, with its socket wrapped in TLS
    using ssl.wrap_socket
    """

    def __init__(self, cert_path, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # Wrap Socket using TLS cert
        self.cert_path = cert_path
        self.context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.context.load_cert_chain(cert_path)
        self.socket = self.context.wrap_socket(
            self.socket, server_side=True
        )


class ThreadingHTTPSServer(socketserver.ThreadingMixIn, HTTPSServer):
    """
    ThreadedHTTPServer Class, with its socket wrapped in TLS
    using ssl.wrap_socket
    """

    daemon_threads = True


def run_server(bind, port, directory, cert_path):
    """
    Start HTTPSServer. Code based upon code in 'http.server'
    """
    handler_class = partial(SimpleHTTPRequestHandler, directory=directory)
    server_address = (bind, port)

    with ThreadingHTTPSServer(cert_path, server_address, handler_class) as httpd:
        sa = httpd.socket.getsockname()
        serve_message = (
            "Serving HTTPS on {host} port {port} (https://{host}:{port}/) ..."
        )
        print(serve_message.format(host=sa[0], port=sa[1]))
        print(f"Using TLS Cert: {cert_path}")
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\nKeyboard interrupt received, exiting.")


def generate_cert(cert_path, bind_address="localhost"):
    """
    Use pyca/cryptography to create a new Cert and Key with proper Subject Alternative Names
    for client verification
    """
    import socket

    # create the SAN list
    san_list = [
        x509.DNSName("localhost"),
        x509.IPAddress(ipaddress.IPv4Address("127.0.0.1")),
        x509.IPAddress(ipaddress.IPv6Address("::1")),
    ]

    # Add the bind address if it's different from localhost
    if bind_address and bind_address not in ["localhost", "127.0.0.1", ""]:
        # Check if it's an IPv4 address
        try:
            parts = bind_address.split(".")
            if len(parts) == 4 and all(part.isdigit() and 0 <= int(part) <= 255 for part in parts):
                san_list.append(x509.IPAddress(ipaddress.IPv4Address(bind_address)))
            else:
                san_list.append(x509.DNSName(bind_address))
        except (ValueError, AttributeError):
            san_list.append(x509.DNSName(bind_address))

    # Try to add the actual hostname
    try:
        hostname = socket.gethostname()
        if hostname not in ["localhost"] and x509.DNSName(hostname) not in san_list:
            san_list.append(x509.DNSName(hostname))
    except:
        pass


    # create a key pair
    key = rsa.generate_private_key(public_exponent=65537, key_size=4096)

    # create a self-signed cert
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Python HTTPS Server"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, "Local"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Python HTTPS Server"),
        x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "Development"),
        x509.NameAttribute(NameOID.COMMON_NAME, bind_address if bind_address else "localhost"),
    ])
    cert = (
        x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.datetime.now(datetime.timezone.utc))
            .not_valid_after(datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=365))
            .add_extension(x509.SubjectAlternativeName(san_list), critical=False)
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=True,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ), critical=True)
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=True)
            .sign(key, hashes.SHA256())
    )

    cert_pem = cert.public_bytes(encoding=serialization.Encoding.PEM).decode()
    key_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    ).decode()

    # Write to file if needed
    if cert_path is not None:
        with open(cert_path, "w") as f:
            f.write(key_pem)
            f.write(cert_pem)

    # Return cert and key if required
    return cert_pem, key_pem


def extract_client_cert(cert_path, client_cert_path):
    """
    Extract just the certificate portion (without private key) for client verification
    """
    try:
        with open(cert_path, "r") as f:
            content = f.read()
        
        # Extract only the certificate part
        cert_start = content.find("-----BEGIN CERTIFICATE-----")
        cert_end = content.find("-----END CERTIFICATE-----") + len("-----END CERTIFICATE-----")
        
        if cert_start == -1 or cert_end == -1:
            raise ValueError("Certificate not found in file")
        
        cert_only = content[cert_start:cert_end]
        
        with open(client_cert_path, "w") as f:
            f.write(cert_only)
        
        return cert_only
    except Exception as e:
        raise Exception(f"Failed to extract client certificate: {e}")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--bind",
        "-b",
        default="",
        metavar="ADDRESS",
        help="Specify alternate bind address " "[default: all interfaces]",
    )
    parser.add_argument(
        "--directory",
        "-d",
        default=os.getcwd(),
        help="Specify alternative directory " "[default:current directory]",
    )
    parser.add_argument(
        "port",
        action="store",
        default=8443,
        type=int,
        nargs="?",
        help="Specify alternate port [default: 8000]",
    )
    parser.add_argument(
        "--existing-cert",
        "-e",
        dest="existing_cert",
        help="Specify an existing cert to use "
        "instead of auto-generating one. File must contain "
        "both PEM-encoded cert and private key",
    )
    parser.add_argument(
        "--save-cert",
        "-s",
        dest="save_cert",
        action="store_true",
        help="Save certificate file in current directory",
    )
    parser.add_argument(
        "--client-cert",
        "-c",
        dest="client_cert",
        action="store_true",
        help="Also save a client certificate file (cert only, no private key) for client verification",
    )
    args = parser.parse_args()

    # If supplied cert use that
    if args.existing_cert is not None:
        cert_path = args.existing_cert
        # Extract client cert if requested
        if args.client_cert:
            client_cert_path = os.path.join(os.getcwd(), "client-cert.pem")
            try:
                extract_client_cert(cert_path, client_cert_path)
                print(f"Client certificate saved to: {client_cert_path}")
            except Exception as e:
                print(f"Warning: Could not extract client certificate: {e}")
        run_server(args.bind, args.port, args.directory, cert_path)
    # Else generate a cert and key pair and use that
    elif args.save_cert:
        cert_path = os.path.join(os.getcwd(), "cert.pem")
        bind_addr = args.bind if args.bind else "localhost"
        generate_cert(cert_path, bind_addr)
        print(f"Server certificate saved to: {cert_path}")
        
        # Extract client cert if requested
        if args.client_cert:
            client_cert_path = os.path.join(os.getcwd(), "client-cert.pem")
            try:
                extract_client_cert(cert_path, client_cert_path)
                print(f"Client certificate saved to: {client_cert_path}")
                print("\nTo use with requests python library:")
                print("  import requests")
                print("  response = requests.get('https://{bind_addr}:{args.port}', verify='{client_cert_path}')")
            except Exception as e:
                print(f"Warning: Could not extract client certificate: {e}")
        
        run_server(args.bind, args.port, args.directory, cert_path)
    else:
        with tempfile.TemporaryDirectory(prefix="pythonHTTPS_") as tmp_dir:
            cert_path = os.path.join(tmp_dir, "cert.pem")
            bind_addr = args.bind if args.bind else "localhost"
            generate_cert(cert_path, bind_addr)
            run_server(args.bind, args.port, args.directory, cert_path)


if __name__ == "__main__":
    main()
