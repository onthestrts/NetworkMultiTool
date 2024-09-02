import re
import requests
from ipwhois import IPWhois
import subprocess
import tkinter as tk
from tkinter import scrolledtext, messagebox, filedialog
import csv
import datetime
from tkinter import ttk
import socket
import threading
import os
import hashlib

# Setting up environment variables for password
os.environ['ADMIN_PASSWORD_HASH'] = hashlib.sha256(b'your_password').hexdigest()

# Creator Information
CREATOR_NAME = "Flurin Kärcher"
CREATION_DATE = datetime.datetime.now().strftime("%Y-%m-%d")
EMAIL = "fkaercher@baggenstos.ch"
VERSION = 1.1  # Incremented version number for a minor change

# CSV Converter Function
def csv_to_textile(csv_file_path):
    try:
        with open(csv_file_path, 'r', newline='', encoding='utf-8') as csv_file:
            reader = csv.reader(csv_file)
            rows = list(reader)

            if not rows:
                messagebox.showinfo("Info", "The CSV file is empty.")
                return ""

            textile_content = []
            # Write header row as a Textile table header
            header = rows[0]
            header_textile = '|_. ' + ' |_. '.join(header) + ' |'
            textile_content.append(header_textile)

            # Write the rest of the rows as Textile table rows
            for row in rows[1:]:
                row_textile = '| ' + ' | '.join(row) + ' |'
                textile_content.append(row_textile)

        return "\n".join(textile_content)
    except Exception as e:
        messagebox.showerror("Error", f"An error occurred: {str(e)}")
        return ""

# Function to handle file selection and conversion
def convert_csv():
    csv_file_path = filedialog.askopenfilename(title="Select CSV File", filetypes=[("CSV files", "*.csv")])
    if not csv_file_path:
        return

    textile_content = csv_to_textile(csv_file_path)
    if textile_content:
        result_text_area_csv.config(state=tk.NORMAL)
        result_text_area_csv.delete("1.0", tk.END)
        result_text_area_csv.insert(tk.END, textile_content)
        result_text_area_csv.config(state=tk.DISABLED)
        messagebox.showinfo("Success", "CSV file has been successfully converted to Textile format.")

# IP Address Analyzer Functions
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

# IP Scanner Functions
COMMON_PORTS = {
    21: 'FTP',
    22: 'SSH',
    23: 'Telnet',
    25: 'SMTP',
    53: 'DNS',
    80: 'HTTP',
    110: 'POP3',
    143: 'IMAP',
    443: 'HTTPS',
    3389: 'RDP'
}

def is_host_up(ip):
    try:
        socket.gethostbyname(ip)
        return True
    except socket.error:
        return False

def scan_port(ip, port):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(1)
            result = sock.connect_ex((ip, port))
            if result == 0:
                service = COMMON_PORTS.get(port, 'Unknown Service')
                return f"Port {port} ({service}): Open"
            else:
                return f"Port {port}: Closed"
    except Exception as e:
        return f"Port {port}: Error - {str(e)}"

def scan_ip(ip, ports, output_text):
    if is_host_up(ip):
        output_text.insert(tk.END, f"\nScanning {ip}...\n")
        for port in ports:
            result = scan_port(ip, port)
            output_text.insert(tk.END, result + "\n")
    else:
        output_text.insert(tk.END, f"{ip} is down or unreachable.\n")

def start_scan(start_ip, end_ip, ports, output_text):
    output_text.delete(1.0, tk.END)  # Clear the output text area

    start_ip_parts = list(map(int, start_ip.split('.')))
    end_ip_parts = list(map(int, end_ip.split('.')))

    for i in range(start_ip_parts[-1], end_ip_parts[-1] + 1):
        ip = f"{start_ip_parts[0]}.{start_ip_parts[1]}.{start_ip_parts[2]}.{i}"
        threading.Thread(target=scan_ip, args=(ip, ports, output_text)).start()

def on_enter(e):
    e.widget.config(background='#d0d0d0')  # Light gray background on hover
    e.widget.config(font=('Helvetica', 10, 'bold'))

def on_leave(e):
    e.widget.config(background='SystemButtonFace')  # Default background
    e.widget.config(font=('Helvetica', 10, 'normal'))

def show_about():
    about_window = tk.Toplevel(root)
    about_window.title("About")
    about_window.geometry("400x300")
    about_window.resizable(False, False)
    about_window.configure(bg='#2b2b2b')  # Darker background

    about_label = tk.Label(about_window, text="About This Application", font=('Helvetica', 14, 'bold'), fg='white', bg='#2b2b2b')
    about_label.pack(pady=10)

    info_text = f"Creator: {CREATOR_NAME}\n" \
                f"Creation Date: {CREATION_DATE}\n" \
                f"Email: {EMAIL}\n" \
                f"Version: {VERSION}\n\n" \
                "This application is designed for network analysis and scanning.\n" \
                "It provides basic functionalities similar to nmap, including port scanning and IP address analysis.\n" \
                "For more advanced features, please contact the creator."

    info_label = tk.Label(about_window, text=info_text, justify=tk.LEFT, padx=10, pady=10, fg='white', bg='#2b2b2b', wraplength=380)
    info_label.pack(fill=tk.BOTH, expand=True)

    close_button = tk.Button(about_window, text="Close", command=about_window.destroy, bg='#3c3f41', fg='white', bd=0, padx=10, pady=5)
    close_button.pack(pady=10)

def admin_login():
    def verify_password():
        entered_password = password_entry.get()
        entered_password_hash = hashlib.sha256(entered_password.encode()).hexdigest()
        if entered_password_hash == os.environ['ADMIN_PASSWORD_HASH']:
            messagebox.showinfo("Access Granted", "You have entered the admin backend.")
            backend_window.destroy()
            open_admin_backend()
        else:
            messagebox.showerror("Access Denied", "Incorrect password. Please try again.")

    backend_window = tk.Toplevel(root)
    backend_window.title("Admin Login")
    backend_window.geometry("300x150")
    backend_window.resizable(False, False)

    tk.Label(backend_window, text="Enter Admin Password:", font=('Helvetica', 12)).pack(pady=10)
    password_entry = tk.Entry(backend_window, show="*")
    password_entry.pack(pady=5)
    login_button = tk.Button(backend_window, text="Login", command=verify_password)
    login_button.pack(pady=10)

def open_admin_backend():
    admin_window = tk.Toplevel(root)
    admin_window.title("Admin Backend")
    admin_window.geometry("400x300")
    admin_window.resizable(False, False)

    tk.Label(admin_window, text="Admin Backend", font=('Helvetica', 14, 'bold')).pack(pady=10)

    # Add admin functionalities here (e.g., update version, change settings, etc.)

    close_button = tk.Button(admin_window, text="Close", command=admin_window.destroy)
    close_button.pack(pady=10)

# Main GUI Application
root = tk.Tk()
root.title("Network Tools")

# Set a minimum window size for better layout
root.minsize(800, 600)

# Create the Notebook (tabs)
notebook = ttk.Notebook(root)
notebook.pack(expand=True, fill='both')

# CSV Converter Tab
csv_converter_tab = tk.Frame(notebook)
notebook.add(csv_converter_tab, text="CSV Converter")

# CSV Converter UI
csv_button = tk.Button(csv_converter_tab, text="Convert CSV to Textile", command=convert_csv)
csv_button.pack(pady=10)

# Result Display for CSV Conversion
result_text_area_csv = scrolledtext.ScrolledText(csv_converter_tab, wrap=tk.WORD, height=20, bg="white", fg="black", insertbackground="black")
result_text_area_csv.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
result_text_area_csv.config(state=tk.DISABLED)

# IP Address Analyzer Tab
analyzer_tab = tk.Frame(notebook)
notebook.add(analyzer_tab, text="IP Address Analyzer")

# Configure grid layout for the analyzer tab
analyzer_tab.grid_rowconfigure(0, weight=1)
analyzer_tab.grid_columnconfigure(0, weight=1)
analyzer_tab.grid_columnconfigure(1, weight=1)

# Frame for Text Input
input_frame = tk.Frame(analyzer_tab, padx=10, pady=10)
input_frame.grid(row=0, column=0, sticky="nsew")

tk.Label(input_frame, text="Enter text with IP addresses:").pack(anchor="w")

text_area = scrolledtext.ScrolledText(input_frame, wrap=tk.WORD, height=10, bg="white", fg="black", insertbackground="black")
text_area.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

# Frame for Result Display
result_frame = tk.Frame(analyzer_tab, padx=10, pady=10)
result_frame.grid(row=0, column=1, sticky="nsew")

tk.Label(result_frame, text="Results:").pack(anchor="w")

result_text_area = scrolledtext.ScrolledText(result_frame, wrap=tk.WORD, height=20, bg="white", fg="black", insertbackground="black")
result_text_area.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
result_text_area.config(state=tk.DISABLED)  # Disable editing of results

# Frame for Buttons
button_frame = tk.Frame(analyzer_tab, padx=10, pady=10)
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

quit_button = tk.Button(button_frame, text="Quit", command=root.quit)
quit_button.pack(pady=5, side=tk.RIGHT)
quit_button.bind("<Enter>", on_enter)
quit_button.bind("<Leave>", on_leave)

# IP Scanner Tab
scanner_tab = tk.Frame(notebook)
notebook.add(scanner_tab, text="IP Scanner")

# Configure grid layout for the scanner tab
scanner_tab.grid_rowconfigure(3, weight=1)
scanner_tab.grid_columnconfigure(1, weight=1)

# IP Scanner GUI elements
tk.Label(scanner_tab, text="Start IP:").grid(row=0, column=0, padx=5, pady=5, sticky="e")
start_ip_entry = tk.Entry(scanner_tab)
start_ip_entry.grid(row=0, column=1, padx=5, pady=5, sticky="ew")

tk.Label(scanner_tab, text="End IP:").grid(row=1, column=0, padx=5, pady=5, sticky="e")
end_ip_entry = tk.Entry(scanner_tab)
end_ip_entry.grid(row=1, column=1, padx=5, pady=5, sticky="ew")

tk.Label(scanner_tab, text="Ports (comma separated):").grid(row=2, column=0, padx=5, pady=5, sticky="e")
ports_entry = tk.Entry(scanner_tab)
ports_entry.grid(row=2, column=1, padx=5, pady=5, sticky="ew")

output_text = scrolledtext.ScrolledText(scanner_tab, width=50, height=15)
output_text.grid(row=3, column=0, columnspan=2, padx=5, pady=5, sticky="nsew")

def on_start():
    start_ip = start_ip_entry.get()
    end_ip = end_ip_entry.get()
    ports = [int(port.strip()) for port in ports_entry.get().split(",")]
    threading.Thread(target=start_scan, args=(start_ip, end_ip, ports, output_text)).start()

start_button = tk.Button(scanner_tab, text="Start Scan", command=on_start)
start_button.grid(row=4, column=0, columnspan=2, padx=5, pady=5)

# About Button
about_button = tk.Button(root, text="About", command=show_about)
about_button.pack(side=tk.RIGHT, padx=10, pady=5)

# Admin Button
admin_button = tk.Button(root, text="Admin", command=admin_login)
admin_button.pack(side=tk.RIGHT, padx=10, pady=5)

root.mainloop()