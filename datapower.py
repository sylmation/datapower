import requests
from requests.exceptions import RequestException
from requests.auth import HTTPBasicAuth
import os
from datetime import datetime
from cryptography import x509
from cryptography.hazmat.backends import default_backend

class DataPowerCertUpdater:
    def __init__(self, host, username, password):
        self.host = host
        self.username = username
        self.password = password
        self.session = requests.Session()
        self.session.auth = HTTPBasicAuth(self.username, self.password)

    def update_cert(self, cert_path, key_path, cert_label):
        try:
            #check file format 
            cert_type = os.path.splitext(cert_path)[1]
            if cert_type in ('.pem', '.crt'):
                cert_data = open(cert_path, 'rb').read()
                cert = x509.load_pem_x509_certificate(cert_data, default_backend())
            elif cert_type == '.der':
                cert_data = open(cert_path, 'rb').read()
                cert = x509.load_der_x509_certificate(cert_data, default_backend())
            else:
                raise ValueError(f"Invalid certificate format {cert_type}. Only PEM, CRT and DER formats are supported.")

            key_data = open(key_path, 'rb').read()

            url = f"https://{self.host}/service/mgmt/current/import?fromlocal=cert&file={cert_label}.crt&encoding=binary"
            response = self.session.put(url, data=cert_data)
            response.raise_for_status()

            url = f"https://{self.host}/service/mgmt/current/import?fromlocal=key&file={cert_label}.key&encoding=binary"
            response = self.session.put(url, data=key_data)
            response.raise_for_status()

            url = f"https://{self.host}/service/mgmt/current/config/default/CertificateAuthorityFile/{cert_label}"
            response = self.session.put(url)
            response.raise_for_status()
        except FileNotFoundError as e:
            print(f'Could not find certificate or key file. Error: {e}')
        except ValueError as e:
            print(f'{e}')
        except RequestException as e:
            print(f'Error while updating certificate: {e}')
    
    def delete_cert(self, cert_label):
        try:
            url = f"https://{self.host}/service/mgmt/current/config/default/CertificateAuthorityFile/{cert_label}"
            response = self.session.delete(url)
            response.raise_for_status()
            print(f"Certificate with label {cert_label} deleted successfully.")
        except RequestException as e:
            print(f'Error while deleting certificate: {e}')
    
    def validate_cert(self, cert_path):
        try:
            cert_type = os.path.splitext(cert_path)[1]
            if cert_type in ('.pem', '.crt'):
                cert_data = open(cert_path, 'rb').read()
                cert = x509.load_pem_x509_certificate(cert_data, default_backend())
            elif cert_type == '.der':
                cert_data = open(cert_path, 'rb').read()
                cert = x509.load_der_x509_certificate(cert_data, default_backend())
            else:
                raise ValueError(f"Invalid certificate format {cert_type}. Only PEM, CRT and DER formats are supported.")
            now = datetime.now()
            cert.public_key().verify(cert.signature, cert.tbs_certificate_bytes, cert.signature_hash_algorithm)
            if cert.not_valid_before <= now <= cert.not_valid_after:
                print("The certificate is valid.")
            else:
                raise ValueError("The certificate is not yet valid or has expired.")
        except Exception as e:
            print("The certificate is not valid, reason: ", e)
