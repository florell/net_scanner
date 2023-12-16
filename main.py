import socket
import ipwhois
import tkinter as tk
from tkinter import scrolledtext
from tkinter import messagebox
import requests
from scapy.all import getmacbyip
import nmap
import concurrent.futures # для многопоточности

def scan_ports(ip, start_port, end_port):
    open_ports = []
    if start_port == 0 and end_port == 0:
        # Сканирование всех портов с 1 по 65535
        start_port = 1
        end_port = 65535

    for port in range(start_port, end_port + 1):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((ip, port))
        if result == 0:
            open_ports.append(port)
        sock.close()
    return open_ports

# def scan_all_ports_nmap(ip):
#     open_ports = []

#     nm = nmap.PortScanner()
#     nm.scan(ip, arguments='-p 1-65535 --open')

#     for host in nm.all_hosts():
#         for proto in nm[host].all_protocols():
#             lport = nm[host][proto].keys()
#             open_ports.extend(list(lport))

#     return open_ports

def scan_specific_ports(ip, ports):
    open_ports = []
    for port in ports:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((ip, port))
        if result == 0:
            open_ports.append(port)
        sock.close()
    return open_ports

def scan_specific_ips(ips, ports):
    open_ports_dict = {}
    for ip in ips:
        open_ports = scan_specific_ports(ip, ports)
        open_ports_dict[ip] = open_ports
    return open_ports_dict

def get_service_info(port):
    try:
        service_info = socket.getservbyport(port)
        return service_info
    except (socket.error, socket.herror, socket.gaierror, socket.timeout, socket.error):
        return "Unknown service"

def get_host_info(ip):
    try:
        obj = ipwhois.IPWhois(ip)
        result = obj.lookup_rdap()

        mac_address = getmacbyip(ip)
        if mac_address is None:
            mac_address = "Not available"


        ipinfo_response = requests.get(f'https://ipinfo.io/{ip}/json')
        ipinfo_data = ipinfo_response.json()
        country = ipinfo_data.get('country', '')
        provider = ipinfo_data.get('org', '')

        network_info = result.get('network', {})
        organization = network_info.get('name', '')

        host_info = {
            'IP Address': ip,
            'MAC Address': mac_address,
            'Organization': organization,
            'Country': country,
            'Provider': provider,
        }

        return host_info
    except Exception as e:
        return f"Error: {str(e)}"


class PortScannerApp:
    def __init__(self, master):
        self.master = master
        master.title("Port Scanner")

        self.create_widgets()
        self.update_widgets_visibility()

    def create_widgets(self):
        self.ip_label = tk.Label(self.master, text="IP Address:")
        self.ip_label.grid(row=0, column=0)

        self.ip_entry = tk.Entry(self.master)
        self.ip_entry.grid(row=0, column=1)

        self.ports_label = tk.Label(self.master, text="Ports (comma-separated):")
        self.ports_label.grid(row=1, column=0, sticky=tk.E)

        self.ports_entry = tk.Entry(self.master)
        self.ports_entry.grid(row=1, column=1)

        self.scan_type_label = tk.Label(self.master, text="Scan Type:")
        self.scan_type_label.grid(row=2, column=0, sticky=tk.E)

        self.scan_type_var = tk.StringVar()
        self.scan_type_var.set("All Ports")  # значение по умолчанию

        self.scan_type_menu = tk.OptionMenu(self.master, self.scan_type_var, "All Ports", "Specific Ports", "Specific IPs")
        self.scan_type_menu.grid(row=2, column=1)

        self.result_text = scrolledtext.ScrolledText(self.master, width=40, height=10)
        self.result_text.grid(row=4, column=0, columnspan=2)

        self.specific_ports_label = tk.Label(self.master, text="Specific Ports:")
        self.specific_ports_label.grid(row=3, column=0, sticky=tk.E)

        self.specific_ports_entry = tk.Entry(self.master)
        self.specific_ports_entry.grid(row=3, column=1)

        self.specific_ips_label = tk.Label(self.master, text="Specific IPs (comma-separated):")
        self.specific_ips_label.grid(row=3, column=0, sticky=tk.E)

        self.specific_ips_entry = tk.Entry(self.master)
        self.specific_ips_entry.grid(row=3, column=1)

        self.scan_button = tk.Button(self.master, text="Scan", command=self.scan_ports)
        self.scan_button.grid(row=5, column=0, columnspan=2)

        self.scan_type_var.trace_add("write", self.update_widgets_visibility)

    def update_widgets_visibility(self, *args):
        scan_type = self.scan_type_var.get()

        if scan_type == "All Ports":
            self.ports_label.grid_remove()
            self.ports_entry.grid_remove()
            self.specific_ports_label.grid_remove()
            self.specific_ports_entry.grid_remove()
            self.specific_ips_label.grid_remove()
            self.specific_ips_entry.grid_remove()
            self.ip_label.grid()
            self.ip_entry.grid()
        elif scan_type == "Specific Ports":
            self.ports_label.grid()
            self.ports_entry.grid()
            self.specific_ports_label.grid_remove()
            self.specific_ports_entry.grid_remove()
            self.specific_ips_label.grid_remove()
            self.specific_ips_entry.grid_remove()
            self.ip_label.grid()
            self.ip_entry.grid()
        elif scan_type == "Specific IPs":
            self.ports_label.grid()
            self.ports_entry.grid()
            self.specific_ports_label.grid()
            self.specific_ports_entry.grid()
            self.specific_ips_label.grid()
            self.specific_ips_entry.grid()
            self.ip_label.grid_remove()
            self.ip_entry.grid_remove()
        else:
            messagebox.showerror("Error", "Invalid scan type selected.")

    def scan_ports(self):
        self.result_text.delete(1.0, tk.END)
        ip = self.ip_entry.get()
        scan_type = self.scan_type_var.get()

        try:
            if scan_type == "All Ports":
                open_ports = scan_ports(ip, 0, 0)
            elif scan_type == "Specific Ports":
                ports = [int(port.strip()) for port in self.ports_entry.get().split(",")]
                open_ports = scan_specific_ports(ip, ports)
            elif scan_type == "Specific IPs":
                ips = [ip.strip() for ip in self.specific_ips_entry.get().split(",")]
                open_ports_dict = scan_specific_ips(ips, [])
                self.display_specific_ips_results(open_ports_dict)
                return
            else:
                messagebox.showerror("Error", "Invalid scan type selected.")
                return

            self.result_text.insert(tk.END, f"Open ports on {ip}:\n")
            for port in open_ports:
                service_info = get_service_info(port)
                self.result_text.insert(tk.END, f"Port {port} is open, Service: {service_info}\n")

            host_info = get_host_info(ip)
            self.display_host_info(host_info)
        except Exception as e:
            messagebox.showerror("Error", f"An error occurred: {str(e)}")



    def display_host_info(self, host_info):
        self.result_text.insert(tk.END, "\nHost information:\n")
        for key, value in host_info.items():
            self.result_text.insert(tk.END, f"{key}: {value}\n")

    def display_specific_ips_results(self, open_ports_dict):
        self.result_text.insert(tk.END, "\nResults for Specific IPs:\n")
        for ip, open_ports in open_ports_dict.items():
            self.result_text.insert(tk.END, f"Open ports on {ip}:\n")
            for port in open_ports:
                service_info = get_service_info(port)
                self.result_text.insert(tk.END, f"Port {port} is open, Service: {service_info}\n")
            host_info = get_host_info(ip)
            self.display_host_info(host_info)

# Запуск GUI
root = tk.Tk()
app = PortScannerApp(root)
root.mainloop()
