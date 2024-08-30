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
            'isp': res.get('network', {}).get('name', 'N/A')
        }
    except Exception as e:
        return {'error': str(e)}

def ping(ip):
    try:
        result = subprocess.run(["ping", "-c", "4", ip], capture_output=True, text=True)
        return result.stdout.strip().replace('\n', '<br>')
    except subprocess.CalledProcessError as e:
        return f"Ping failed: {str(e)}"
    except Exception as e:
        return f"Unexpected error: {str(e)}"

def create_textile_table(ip_data):
    header = "| IP Address | ASN | Country | City | ISP |\n"
    rows = ""
    for ip, data in ip_data.items():
        rows += "| {} | {} | {} | {} | {} |\n".format(
            ip,
            data.get('asn', 'N/A'),
            data.get('country', 'N/A'),
            data.get('city', 'N/A'),
            data.get('isp', 'N/A')
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
        result_text_area.config(state=tk.NORMAL)
        result_text_area.delete("1.0", tk.END)
        result_text_area.insert(tk.END, results)
        result_text_area.config(state=tk.DISABLED)
    else:
        messagebox.showwarning("Input Error", "Please enter some text to analyze.")

def nslookup_option():
    input_text = text_area.get("1.0", tk.END).strip()
    if input_text:
        ips = extract_ips(input_text)
        nslookup_results = ""
        for ip in ips:
            nslookup_results += f"NSLookup for {ip}:\n" + nslookup(ip) + "\n\n"
        result_text_area.config(state=tk.NORMAL)
        result_text_area.delete("1.0", tk.END)
        result_text_area.insert(tk.END, nslookup_results)
        result_text_area.config(state=tk.DISABLED)
    else:
        messagebox.showwarning("Input Error", "Please enter some text to analyze.")

def ping_option():
    input_text = text_area.get("1.0", tk.END).strip()
    if input_text:
        ips = extract_ips(input_text)
        ping_results = ""
        for ip in ips:
            ping_results += f"Ping for {ip}:\n" + ping(ip) + "\n\n"
        result_text_area.config(state=tk.NORMAL)
        result_text_area.delete("1.0", tk.END)
        result_text_area.insert(tk.END, ping_results)
        result_text_area.config(state=tk.DISABLED)
    else:
        messagebox.showwarning("Input Error", "Please enter some text to analyze.")

# GUI Setup
root = tk.Tk()
root.title("IP Address Analyzer")

# Set a minimum window size for better layout
root.minsize(600, 400)

# Configure the grid layout
root.rowconfigure(0, weight=1)
root.columnconfigure(0, weight=1)
root.columnconfigure(1, weight=1)

# Frame for Text Input
input_frame = tk.Frame(root, padx=10, pady=10)
input_frame.grid(row=0, column=0, sticky="nsew")

tk.Label(input_frame, text="Enter text with IP addresses:").pack(anchor="w")

text_area = scrolledtext.ScrolledText(input_frame, wrap=tk.WORD, height=10, bg="white", fg="black", insertbackground="black")
text_area.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

# Frame for Result Display
result_frame = tk.Frame(root, padx=10, pady=10)
result_frame.grid(row=0, column=1, sticky="nsew")

tk.Label(result_frame, text="Results:").pack(anchor="w")

result_text_area = scrolledtext.ScrolledText(result_frame, wrap=tk.WORD, height=15, bg="white", fg="black", insertbackground="black")
result_text_area.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
result_text_area.config(state=tk.DISABLED)  # Disable editing of results

# Frame for Buttons
button_frame = tk.Frame(root, padx=10, pady=10)
button_frame.grid(row=1, column=0, columnspan=2, sticky="ew")

analyze_button = tk.Button(button_frame, text="Analyze", command=display_results)
analyze_button.pack(pady=5, side=tk.LEFT)

nslookup_button = tk.Button(button_frame, text="NSLookup", command=nslookup_option)
nslookup_button.pack(pady=5, side=tk.LEFT)

ping_button = tk.Button(button_frame, text="Ping", command=ping_option)
ping_button.pack(pady=5, side=tk.LEFT)

root.mainloop()

