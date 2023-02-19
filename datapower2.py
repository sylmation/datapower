import requests
import os
import time
import xml.etree.ElementTree as ET

class DataPowerCertUpdater:
    def __init__(self, dp_hostname, dp_username, dp_password):
        self.dp_hostname = dp_hostname
        self.dp_username = dp_username
        self.dp_password = dp_password

    def update_certificate(self, cert_path, cert_label, domain):
        with open(cert_path, 'rb') as f:
            cert_data = f.read()

        update_url = f'https://{self.dp_hostname}:5554/rest/{domain}/CryptoCertificate/{cert_label}'
        headers = {'Content-Type': 'application/pkix-cert', 'Accept': 'application/xml'}

        response = requests.put(update_url, data=cert_data, headers=headers, auth=(self.dp_username, self.dp_password), verify=False)

        if response.status_code != 200:
            print(f"Error updating certificate. Status code: {response.status_code}")
        else:
            print("Certificate updated successfully.")

    def delete_certificate(self, cert_label, domain):
        delete_url = f'https://{self.dp_hostname}:5554/rest/{domain}/CryptoCertificate/{cert_label}'
        response = requests.delete(delete_url, auth=(self.dp_username, self.dp_password), verify=False)

        if response.status_code != 200:
            print(f"Error deleting certificate. Status code: {response.status_code}")
        else:
            print("Certificate deleted successfully.")

    def validate_certificate(self, cert_label, domain):
        query_url = f'https://{self.dp_hostname}:5554/rest/{domain}/CryptoCertificate/{cert_label}'
        response = requests.get(query_url, auth=(self.dp_username, self.dp_password), verify=False)

        if response.status_code != 200:
            print(f"Error querying certificate. Status code: {response.status_code}")
        else:
            cert_data = response.content
            cert = x509.load_pem_x509_certificate(cert_data, default_backend())
            print(f"Certificate subject: {cert.subject}")
            print(f"Certificate issuer: {cert.issuer}")
            print(f"Certificate version: {cert.version}")
            print(f"Certificate serial number: {cert.serial_number}")
            print(f"Certificate not valid before: {cert.not_valid_before}")
            print(f"Certificate not valid after: {cert.not_valid_after}")

    def create_and_upload_xml_file(self, xml_content, xml_filename, domain):
        # Create the XML file on the local machine
        with open(xml_filename, 'w') as f:
            f.write(xml_content)

        # Prepare the HTTP request to upload the XML file to DataPower
        upload_url = f'https://{self.dp_hostname}:5554/rest/{domain}/config'
        files = {'file': (xml_filename, open(xml_filename, 'rb'), 'application/xml')}
        headers = {'Content-Type': 'application/xml', 'Accept': 'application/xml'}

        # Make the HTTP POST request to upload the XML file to DataPower
        response = requests.post(upload_url, files=files, headers=headers, auth=(self.dp_username, self.dp_password), verify=False)

        if response.status_code != 200:
            print(f"Error uploading XML file to DataPower. Status code: {response.status_code}")
        else:
            print("XML file uploaded successfully to DataPower.")

        # Delete the local XML file
        os.remove(xml_filename)

    def update_xml_file(self, xml_file_path, xpath, new_value, domain):
        # Parse the XML file
        tree = ET.parse(xml_file_path)
        root = tree.getroot()

        # Find the element(s) to update using the provided XPath
        for element in root.findall(xpath):
            element.text = new_value

        # Convert the updated XML tree back to a string
        updated_xml = ET.tostring(root, encoding='unicode')

        # Upload the updated XML file to DataPower
        self.create_and_upload_xml_file(updated_xml, 'updated_file.xml', domain)
