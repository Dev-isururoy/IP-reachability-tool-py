import threading
import subprocess
import scapy.all as scapy
import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext


class PythonBasedIPReachabilityAnalysisTool:
    def __init__(self):
        self.results = {}

    def ping(self, ip, name):
        response = subprocess.run(['ping', '-n', '1', ip], stdout=subprocess.PIPE)
        return response.returncode == 0

    def trace_route(self, ip):
        response = subprocess.run(['tracert', ip], stdout=subprocess.PIPE)
        return response.stdout.decode('utf-8')

    def icmp_analysis(self, ip):
        try:
            icmp = scapy.IP(dst=ip) / scapy.ICMP()
            response = scapy.sr1(icmp, timeout=1, verbose=False)
            if response:
                return True, response.time
            else:
                return False, None
        except Exception:
            return False, None

    def analyze(self, ip, name):
        self.results[name] = {}
        self.results[name]['Ping'] = self.ping(ip, name)
        self.results[name]['Trace Route'] = self.trace_route(ip)
        icmp_status, icmp_response_time = self.icmp_analysis(ip)
        self.results[name]['ICMP Analysis'] = {
            'Status': icmp_status,
            'Response Time': icmp_response_time
        }


class GUI:
    def __init__(self, master):
        self.master = master
        self.master.title("IP Reachability Analyzer")
        self.master.geometry("800x600")
        self.analyzer = PythonBasedIPReachabilityAnalysisTool()

        self.ip_name_mapping = {
            "8.8.8.8": "Google DNS",
            "192.168.5.2": "Firewall",
            "192.168.10.1": "Core 01",
            "192.168.10.3": "Switch 01 Aruba POE",
            "192.168.10.4": "Switch 02 HP 01",
            "192.168.10.5": "Switch 03 HP 02",
            "192.168.10.6": "Switch 04 Service Floor",
            "192.168.10.7": "Switch 05 Service Floor",
            "192.168.10.8": "Switch 06 Engineering",
            "192.168.10.9": "Switch 07 Canteen",
            "192.168.10.10": "Switch 08 Power House",
            "192.168.10.12": "Switch 10 Boiler Site",
            "192.168.10.13": "Switch 11 Locker Room",
            "192.168.50.250": "NVR 01",
            "192.168.50.251": "NVR 02",
            "192.168.30.233": "Primary Domain Server",
            "192.168.30.190": "Secondary Domain Server",
            "192.168.30.234": "HRM Server",
            "192.168.30.232": "Domain Server NAS",
            "192.168.20.200": "BMS Server",
            "192.168.30.199": "NTP Server",
            "192.168.40.250": "WIFI NVR",
            "192.168.70.100": "Locker Room Fingerprint Machine",
            "192.168.70.28": "Server Room Fingerprint Machine",
            "192.168.30.191": "Production Office Printer",
            "192.168.30.195": "P&A Black & White Printer",
            "192.168.30.197": "Color Printer",
            "192.168.30.242": "Engineering Office",
            "192.168.30.196": "QC Black & White",
            "192.168.30.239": "QC color Printer Smart Tank",
            "192.168.30.170": "Mr. Parag Printer",
            "192.168.30.207": "QA Black & White Printer",
            "192.168.30.189": "QA Color Printer",
            "192.168.30.114": "QA Color Printer Smart Tank",
        }

        self.create_widgets()

    def create_widgets(self):
        ttk.Label(self.master, text="Select Device/IP:", font=('Arial', 12)).pack(pady=10)

        self.selected_ip = tk.StringVar()
        self.dropdown = ttk.Combobox(
            self.master,
            textvariable=self.selected_ip,
            values=[f"{v} ({k})" for k, v in self.ip_name_mapping.items()],
            state="readonly",
            width=60
        )
        self.dropdown.pack(pady=5)

        ttk.Button(self.master, text="Run Analysis", command=self.run_analysis).pack(pady=10)

        self.output_box = scrolledtext.ScrolledText(self.master, width=90, height=25, font=("Courier", 10))
        self.output_box.pack(padx=10, pady=10)

    def run_analysis(self):
        selected = self.selected_ip.get()
        if not selected:
            messagebox.showwarning("Selection Error", "Please select a device/IP.")
            return

        thread = threading.Thread(target=self._analyze_ip, args=(selected,))
        thread.start()

    def _analyze_ip(self, selected):
        ip = selected.split('(')[-1].strip(')')
        name = self.ip_name_mapping[ip]

        self.output_box.after(0, lambda: self.output_box.delete(1.0, tk.END))
        self.output_box.after(0, lambda: self.output_box.insert(tk.END, f"Running analysis for: {name} ({ip})...\n\n"))

        self.analyzer.analyze(ip, name)
        result = self.analyzer.results[name]

        output_lines = [
            f"Ping Status: {'✅ Reachable' if result['Ping'] else '❌ Unreachable'}",
            f"ICMP Status: {'✅ Success' if result['ICMP Analysis']['Status'] else '❌ Failed'}"
        ]

        if result['ICMP Analysis']['Response Time']:
            output_lines.append(f"ICMP Response Time: {result['ICMP Analysis']['Response Time']:.4f} sec")

        output_lines.append("\nTraceroute Output:\n")
        output_lines.append(result['Trace Route'])

        final_output = "\n".join(output_lines)
        self.output_box.after(0, lambda: self.output_box.insert(tk.END, final_output))


if __name__ == "__main__":
    root = tk.Tk()
    app = GUI(root)
    root.mainloop()
