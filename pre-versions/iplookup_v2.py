import re
from ipwhois import IPWhois
import subprocess
import tkinter as tk
from tkinter import scrolledtext, messagebox

def extract_ips(text):
    ipv4_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
    ipv6_pattern = r'\b(?:[a-fA-F0-9:]+:+)+[a-fA-F0-9]+\b'
    ips = re.findall(f'{ipv4_pattern}|{ipv6_pattern}', text)
    return ips

def lookup_ip(ip):
    try:
        obj = IPWhois(ip)
        res = obj.lookup_rdap()
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
    except subprocess.CalledProcessError as e:
        return f"NSLookup failed: {str(e)}"
    except Exception as e:
        return f"Unexpected error: {str(e)}"

def ping(ip):
    try:
        result = subprocess.run(["ping", "-c", "4", ip], capture_output=True, text=True)
        return result.stdout.strip().replace('\n', '<br>')
    except subprocess.CalledProcessError as e:
        return f"Ping failed: {str(e)}"
    except Exception as e:
        return f"Unexpected error: {str(e)}"

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

def run_analysis(input_text):
    ips = extract_ips(input_text)
    ip_data = {}
    for ip in ips:
        ip_data[ip] = lookup_ip(ip)
    textile_table = create_textile_table(ip_data)
    return textile_table

def display_results():
    input_text = text_area.get("1.0", tk.END).strip()
    if input_text:
        results = run_analysis(input_text)
        result_text_area.delete("1.0", tk.END)
        result_text_area.insert(tk.END, results)
    else:
        messagebox.showwarning("Input Error", "Please enter some text to analyze.")

# GUI Setup
root = tk.Tk()
root.title("IP Address Analyzer")

# Frame for Text Input
input_frame = tk.Frame(root, padx=10, pady=10)
input_frame.pack(fill=tk.BOTH, expand=True)

tk.Label(input_frame, text="Enter text with IP addresses:").pack(anchor="w")

text_area = scrolledtext.ScrolledText(input_frame, wrap=tk.WORD, height=10)
text_area.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

# Frame for Buttons
button_frame = tk.Frame(root, padx=10, pady=10)
button_frame.pack(fill=tk.BOTH)

analyze_button = tk.Button(button_frame, text="Analyze", command=display_results)
analyze_button.pack(pady=5)

# Frame for Result Display
result_frame = tk.Frame(root, padx=10, pady=10)
result_frame.pack(fill=tk.BOTH, expand=True)

tk.Label(result_frame, text="Results:").pack(anchor="w")

result_text_area = scrolledtext.ScrolledText(result_frame, wrap=tk.WORD, height=15)
result_text_area.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

root.mainloop()