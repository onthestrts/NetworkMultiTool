import re
from ipwhois import IPWhois
import subprocess
import requests

def extract_ips(text):
    # Regex to match both IPv4 and IPv6 addresses
    ipv4_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
    ipv6_pattern = r'\b(?:[a-fA-F0-9:]+:+)+[a-fA-F0-9]+\b'
    ips = re.findall(f'{ipv4_pattern}|{ipv6_pattern}', text)
    return ips

def lookup_ip(ip):
    try:
        obj = IPWhois(ip)
        res = obj.lookup_rdap()
        location = res['asn_country_code']
        return {
            'asn': res.get('asn', 'N/A'),
            'country': res.get('asn_country_code', 'N/A'),
            'city': res.get('network', {}).get('city', 'N/A'),
            'isp': res.get('network', {}).get('name', 'N/A'),
            'nslookup': nslookup(ip),
            'ping': ping(ip)
        }
    except Exception as e:
        return {'error': str(e)}

def nslookup(ip):
    try:
        result = subprocess.run(["nslookup", ip], capture_output=True, text=True)
        return result.stdout.strip().replace('\n', '<br>')
    except Exception as e:
        return f"Error: {str(e)}"

def ping(ip):
    try:
        result = subprocess.run(["ping", "-c", "4", ip], capture_output=True, text=True)
        return result.stdout.strip().replace('\n', '<br>')
    except Exception as e:
        return f"Error: {str(e)}"

def create_textile_table(ip_data):
    header = "|_. IP Address |_. ASN |_. Country |_. City |_. ISP |_. NSLookup |_. Ping |\n"
    rows = ""
    for ip, data in ip_data.items():
        nslookup_result = data.get('nslookup', 'N/A')
        ping_result = data.get('ping', 'N/A')
        rows += "| {} | {} | {} | {} | {} | {} | {} |\n".format(
            ip,
            data.get('asn', 'N/A'),
            data.get('country', 'N/A'),
            data.get('city', 'N/A'),
            data.get('isp', 'N/A'),
            nslookup_result,
            ping_result
        )
    return header + rows

def main(input_text):
    ips = extract_ips(input_text)
    ip_data = {}
    for ip in ips:
        ip_data[ip] = lookup_ip(ip)
    textile_table = create_textile_table(ip_data)
    print(textile_table)

if __name__ == "__main__":
    input_text = input("Paste your text here: ")
    main(input_text)