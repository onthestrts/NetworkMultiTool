import re
import requests
from ipwhois import IPWhois
import subprocess
import tkinter as tk
from tkinter import scrolledtext, messagebox, filedialog
import csv
import datetime

# Creator Information
CREATOR_NAME = "Flurin Kärcher"
CREATION_DATE = datetime.datetime.now().strftime("%Y-%m-%d")
EMAIL = "[blank]"
VERSION = 7.1  # Incremented version number for a minor change

def extract_ips(text):
    ipv4_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
    ipv6_pattern = r'\b(?:[a-fA-F0-9:]+:+)+[a-fA-F0-9]+\b'
    ips = re.findall(f'{ipv4_pattern}|{ipv6_pattern}', text)
    return ips

def geolocate_ip(ip):
    try:
        response = requests.get(f"https://ipinfo.io/{ip}/json")
        data = response.json()
        return {
            'city': data.get('city', 'N/A'),
            'region': data.get('region', 'N/A'),
            'country': data.get('country', 'N/A'),
            'postal_code': data.get('postal', 'N/A'),
            'latitude': data.get('loc', 'N/A').split(',')[0],
            'longitude': data.get('loc', 'N/A').split(',')[1] if 'loc' in data else 'N/A'
        }
    except Exception as e:
        return {'error': str(e)}

def lookup_ip(ip):
    try:
        obj = IPWhois(ip)
        res = obj.lookup_rdap()
        geolocation = geolocate_ip(ip)
        return {
            'asn': res.get('asn', 'N/A'),
            'asn_name': res.get('asn_description', 'N/A'),
            'country': res.get('asn_country_code', geolocation.get('country', 'N/A')),
            'region': res.get('network', {}).get('state', geolocation.get('region', 'N/A')),
            'city': res.get('network', {}).get('city', geolocation.get('city', 'N/A')),
            'postal_code': res.get('network', {}).get('postal_code', geolocation.get('postal_code', 'N/A')),
            'latitude': res.get('network', {}).get('latitude', geolocation.get('latitude', 'N/A')),
            'longitude': res.get('network', {}).get('longitude', geolocation.get('longitude', 'N/A')),
            'isp': res.get('network', {}).get('name', 'N/A'),
            'category': "Internet Technology"
        }
    except Exception as e:
        return {'error': str(e)}

def nslookup(ip):
    try:
        result = subprocess.run(["nslookup", ip], capture_output=True, text=True)
        return result.stdout.strip()
    except subprocess.CalledProcessError as e:
        return f"NSLookup failed: {str(e)}"
    except Exception as e:
        return f"Unexpected error: {str(e)}"

def create_textile_table(ip_data):
    header = "| IP Address | ASN | AS Name | Category | Country | Region | City | ZIP/Postal Code | Latitude | Longitude | ISP |\n"
    rows = ""
    for ip, data in ip_data.items():
        rows += "| {} | {} | {} | {} | {} | {} | {} | {} | {} | {} | {} |\n".format(
            ip,
            data.get('asn', 'N/A'),
            data.get('asn_name', 'N/A'),
            data.get('category', 'N/A'),
            data.get('country', 'N/A'),
            data.get('region', 'N/A'),
            data.get('city', 'N/A'),
            data.get('postal_code', 'N/A'),
            data.get('latitude', 'N/A'),
            data.get('longitude', 'N/A'),
            data.get('isp', 'N/A')
        )
    return header + rows

def run_analysis(input_text):
    ips = extract_ips(input_text)
    ip_data = {}
    for ip in ips:
        ip_data[ip] = lookup_ip(ip)
    textile_table = create_textile_table(ip_data)
    return textile_table, ip_data

def display_results():
    input_text = text_area.get("1.0", tk.END).strip()
    if input_text:
        results, ip_data = run_analysis(input_text)
        result_text_area.config(state=tk.NORMAL)
        result_text_area.delete("1.0", tk.END)
        result_text_area.insert(tk.END, results)
        result_text_area.config(state=tk.DISABLED)
        return ip_data
    else:
        messagebox.showwarning("Input Error", "Please enter some text to analyze.")
        return None

def nslookup_option():
    ip_data = display_results()
    if ip_data:
        nslookup_results = ""
        for ip in ip_data.keys():
            nslookup_results += f"NSLookup for {ip}:\n" + nslookup(ip) + "\n\n"
        result_text_area.config(state=tk.NORMAL)
        result_text_area.insert(tk.END, nslookup_results)
        result_text_area.config(state=tk.DISABLED)

def ping_option():
    ip_data = display_results()
    if ip_data:
        ping_results = ""
        for ip in ip_data.keys():
            ping_results += f"Ping for {ip}:\n" + ping(ip) + "\n\n"
        result_text_area.config(state=tk.NORMAL)
        result_text_area.insert(tk.END, ping_results)
        result_text_area.config(state=tk.DISABLED)

def export_csv(ip_data):
    if ip_data:
        filepath = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV files", "*.csv")])
        if filepath:
            with open(filepath, mode='w', newline='') as file:
                writer = csv.writer(file)
                writer.writerow(["IP Address", "ASN", "AS Name", "Category", "Country", "Region", "City", "ZIP/Postal Code", "Latitude", "Longitude", "ISP"])
                for ip, data in ip_data.items():
                    writer.writerow([
                        ip,
                        data.get('asn', 'N/A'),
                        data.get('asn_name', 'N/A'),
                        data.get('category', 'N/A'),
                        data.get('country', 'N/A'),
                        data.get('region', 'N/A'),
                        data.get('city', 'N/A'),
                        data.get('postal_code', 'N/A'),
                        data.get('latitude', 'N/A'),
                        data.get('longitude', 'N/A'),
                        data.get('isp', 'N/A')
                    ])
            messagebox.showinfo("Export Complete", f"Data exported to {filepath}")

def quit_app():
    root.quit()

def on_enter(e):
    e.widget.config(background='gray', foreground='white')

def on_leave(e):
    e.widget.config(background='SystemButtonFace', foreground='black')

# GUI Setup
root = tk.Tk()
root.title("IP Address Analyzer")

# Set a minimum window size for better layout
root.minsize(800, 600)

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

result_text_area = scrolledtext.ScrolledText(result_frame, wrap=tk.WORD, height=20, bg="white", fg="black", insertbackground="black")
result_text_area.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
result_text_area.config(state=tk.DISABLED)  # Disable editing of results

# Frame for Buttons
button_frame = tk.Frame(root, padx=10, pady=10)
button_frame.grid(row=1, column=0, columnspan=2, sticky="ew")

# Buttons with hover effects
analyze_button = tk.Button(button_frame, text="Analyze", command=display_results)
analyze_button.pack(pady=5, side=tk.LEFT)
analyze_button.bind("<Enter>", on_enter)
analyze_button.bind("<Leave>", on_leave)

nslookup_button = tk.Button(button_frame, text="NSLookup", command=nslookup_option)
nslookup_button.pack(pady=5, side=tk.LEFT)
nslookup_button.bind("<Enter>", on_enter)
nslookup_button.bind("<Leave>", on_leave)

ping_button = tk.Button(button_frame, text="Ping", command=ping_option)
ping_button.pack(pady=5, side=tk.LEFT)
ping_button.bind("<Enter>", on_enter)
ping_button.bind("<Leave>", on_leave)

export_button = tk.Button(button_frame, text="Export CSV", command=lambda: export_csv(display_results()))
export_button.pack(pady=5, side=tk.LEFT)
export_button.bind("<Enter>", on_enter)
export_button.bind("<Leave>", on_leave)

quit_button = tk.Button(button_frame, text="Quit", command=quit_app)
quit_button.pack(pady=5, side=tk.RIGHT)
quit_button.bind("<Enter>", on_enter)
quit_button.bind("<Leave>", on_leave)

# Display Creator Information
info_label = tk.Label(root, text=f"Creator: {CREATOR_NAME}\nDate: {CREATION_DATE}\nEmail: {EMAIL}\nVersion: {VERSION}", anchor="w", justify="left", padx=10, pady=10)
info_label.grid(row=2, column=0, columnspan=2, sticky="w")

root.mainloop()