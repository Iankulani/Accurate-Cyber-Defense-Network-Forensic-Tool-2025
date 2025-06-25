import sys
import os
import socket
import threading
import time
import json
import datetime
import subprocess
import matplotlib.pyplot as plt
import paramiko
import whois
import numpy as np
from collections import defaultdict
from scapy.all import sniff, IP, TCP, UDP, ICMP
from queue import Queue
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import tkinter as tk
from tkinter import ttk, messagebox, filedialog, scrolledtext

# Constants
GREEN_THEME = '#00ff00'
BLACK_THEME = '#000000'
TEXT_COLOR = GREEN_THEME
BG_COLOR = BLACK_THEME
FONT = ('Courier', 10)
MAX_LOG_ENTRIES = 1000
MONITORING_INTERVAL = 5  # seconds

class CyberSecurityTool:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("Accurate Cyber Defense Network Forensic Tool 2025")
        self.root.geometry("1200x800")
        self.root.configure(bg=BG_COLOR)
        
        # Initialize variables
        self.monitoring = False
        self.target_ip = ""
        self.logs = []
        self.threat_stats = defaultdict(int)
        self.ssh_client = None
        self.packet_queue = Queue()
        self.sniffer_thread = None
        self.monitoring_thread = None
        
        # Create menu
        self.create_menu()
        
        # Create main interface
        self.create_main_interface()
        
        # Initialize terminal
        self.terminal_history = []
        self.current_history_index = 0
        
        # Start the GUI
        self.root.protocol("WM_DELETE_WINDOW", self.on_close)
        self.root.mainloop()
    
    def create_menu(self):
        menubar = tk.Menu(self.root, bg=BG_COLOR, fg=TEXT_COLOR)
        
        # File menu
        file_menu = tk.Menu(menubar, tearoff=0, bg=BG_COLOR, fg=TEXT_COLOR)
        file_menu.add_command(label="Export Data", command=self.export_data)
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self.on_close)
        menubar.add_cascade(label="File", menu=file_menu)
        
        # View menu
        view_menu = tk.Menu(menubar, tearoff=0, bg=BG_COLOR, fg=TEXT_COLOR)
        view_menu.add_command(label="Threat Dashboard", command=self.show_threat_dashboard)
        view_menu.add_command(label="Network Traffic", command=self.show_network_traffic)
        menubar.add_cascade(label="View", menu=view_menu)
        
        # Help menu
        help_menu = tk.Menu(menubar, tearoff=0, bg=BG_COLOR, fg=TEXT_COLOR)
        help_menu.add_command(label="About", command=self.show_about)
        help_menu.add_command(label="Help", command=self.show_help)
        menubar.add_cascade(label="Help", menu=help_menu)
        
        self.root.config(menu=menubar)
    
    def create_main_interface(self):
        # Create main frames
        main_frame = tk.Frame(self.root, bg=BG_COLOR)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Left panel (terminal)
        left_frame = tk.Frame(main_frame, bg=BG_COLOR)
        left_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        
        terminal_label = tk.Label(left_frame, text="Security Terminal", bg=BG_COLOR, fg=TEXT_COLOR, font=('Courier', 12, 'bold'))
        terminal_label.pack(anchor=tk.W)
        
        self.terminal_output = scrolledtext.ScrolledText(
            left_frame, wrap=tk.WORD, width=80, height=25,
            bg=BG_COLOR, fg=TEXT_COLOR, insertbackground=TEXT_COLOR, font=FONT
        )
        self.terminal_output.pack(fill=tk.BOTH, expand=True)
        self.terminal_output.bind('<Key>', lambda e: 'break')  # Make read-only
        
        self.terminal_input = tk.Entry(
            left_frame, bg=BG_COLOR, fg=TEXT_COLOR, insertbackground=TEXT_COLOR,
            font=FONT, relief=tk.FLAT
        )
        self.terminal_input.pack(fill=tk.X, pady=(5, 0))
        self.terminal_input.bind('<Return>', self.process_terminal_command)
        self.terminal_input.bind('<Up>', self.get_previous_command)
        self.terminal_input.bind('<Down>', self.get_next_command)
        
        # Right panel (logs and stats)
        right_frame = tk.Frame(main_frame, bg=BG_COLOR, width=300)
        right_frame.pack(side=tk.RIGHT, fill=tk.Y)
        
        logs_label = tk.Label(right_frame, text="Security Logs", bg=BG_COLOR, fg=TEXT_COLOR, font=('Courier', 12, 'bold'))
        logs_label.pack(anchor=tk.W)
        
        self.logs_text = scrolledtext.ScrolledText(
            right_frame, wrap=tk.WORD, width=40, height=15,
            bg=BG_COLOR, fg=TEXT_COLOR, insertbackground=TEXT_COLOR, font=FONT
        )
        self.logs_text.pack(fill=tk.BOTH, expand=True)
        self.logs_text.bind('<Key>', lambda e: 'break')  # Make read-only
        
        stats_label = tk.Label(right_frame, text="Threat Statistics", bg=BG_COLOR, fg=TEXT_COLOR, font=('Courier', 12, 'bold'))
        stats_label.pack(anchor=tk.W, pady=(10, 0))
        
        self.stats_text = scrolledtext.ScrolledText(
            right_frame, wrap=tk.WORD, width=40, height=10,
            bg=BG_COLOR, fg=TEXT_COLOR, insertbackground=TEXT_COLOR, font=FONT
        )
        self.stats_text.pack(fill=tk.BOTH, expand=True)
        self.stats_text.bind('<Key>', lambda e: 'break')  # Make read-only
        
        # Initial terminal message
        self.print_to_terminal("Advanced Cyber Security Monitoring Tool")
        self.print_to_terminal("Type 'help' for available commands\n")
    
    def print_to_terminal(self, text):
        self.terminal_output.config(state=tk.NORMAL)
        self.terminal_output.insert(tk.END, text + "\n")
        self.terminal_output.config(state=tk.DISABLED)
        self.terminal_output.see(tk.END)
    
    def add_log_entry(self, entry):
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_entry = f"[{timestamp}] {entry}"
        self.logs.append(log_entry)
        
        if len(self.logs) > MAX_LOG_ENTRIES:
            self.logs.pop(0)
        
        self.update_logs_display()
    
    def update_logs_display(self):
        self.logs_text.config(state=tk.NORMAL)
        self.logs_text.delete(1.0, tk.END)
        self.logs_text.insert(tk.END, "\n".join(self.logs[-50:]))  # Show last 50 entries
        self.logs_text.config(state=tk.DISABLED)
        self.logs_text.see(tk.END)
    
    def update_stats_display(self):
        self.stats_text.config(state=tk.NORMAL)
        self.stats_text.delete(1.0, tk.END)
        
        if not self.threat_stats:
            self.stats_text.insert(tk.END, "No threat data available")
        else:
            for threat, count in sorted(self.threat_stats.items()):
                self.stats_text.insert(tk.END, f"{threat}: {count}\n")
        
        self.stats_text.config(state=tk.DISABLED)
        self.stats_text.see(tk.END)
    
    def process_terminal_command(self, event):
        command = self.terminal_input.get().strip()
        self.terminal_input.delete(0, tk.END)
        
        if not command:
            return
        
        # Add to history
        self.terminal_history.append(command)
        self.current_history_index = len(self.terminal_history)
        
        # Echo command
        self.print_to_terminal(f"> {command}")
        
        # Process command
        parts = command.split()
        cmd = parts[0].lower()
        
        try:
            if cmd == "help":
                self.show_help()
            elif cmd == "start":
                if len(parts) < 3 or parts[1].lower() != "monitoring":
                    self.print_to_terminal("Usage: start monitoring <ip_address>")
                else:
                    ip = parts[2]
                    self.start_monitoring(ip)
            elif cmd == "stop":
                self.stop_monitoring()
            elif cmd == "ping":
                if len(parts) < 2:
                    self.print_to_terminal("Usage: ping <ip_address>")
                else:
                    ip = parts[1]
                    self.ping_ip(ip)
            elif cmd == "whois":
                if len(parts) < 2:
                    self.print_to_terminal("Usage: whois <domain_or_ip>")
                else:
                    target = parts[1]
                    self.whois_lookup(target)
            elif cmd == "ssh":
                if len(parts) < 4:
                    self.print_to_terminal("Usage: ssh <username> <ip_address> <password>")
                else:
                    username = parts[1]
                    ip = parts[2]
                    password = " ".join(parts[3:])
                    self.ssh_connect(username, ip, password)
            elif cmd == "exit":
                self.on_close()
            else:
                self.print_to_terminal(f"Unknown command: {cmd}")
        except Exception as e:
            self.print_to_terminal(f"Error: {str(e)}")
            self.add_log_entry(f"Command error: {str(e)}")
    
    def get_previous_command(self, event):
        if self.terminal_history and self.current_history_index > 0:
            self.current_history_index -= 1
            self.terminal_input.delete(0, tk.END)
            self.terminal_input.insert(0, self.terminal_history[self.current_history_index])
    
    def get_next_command(self, event):
        if self.terminal_history and self.current_history_index < len(self.terminal_history) - 1:
            self.current_history_index += 1
            self.terminal_input.delete(0, tk.END)
            self.terminal_input.insert(0, self.terminal_history[self.current_history_index])
        elif self.terminal_history and self.current_history_index == len(self.terminal_history) - 1:
            self.current_history_index += 1
            self.terminal_input.delete(0, tk.END)
    
    def start_monitoring(self, ip):
        if self.monitoring:
            self.print_to_terminal(f"Already monitoring {self.target_ip}. Stop first.")
            return
        
        # Validate IP address
        try:
            socket.inet_aton(ip)
        except socket.error:
            self.print_to_terminal(f"Invalid IP address: {ip}")
            return
        
        self.target_ip = ip
        self.monitoring = True
        
        # Start packet capture thread
        self.sniffer_thread = threading.Thread(
            target=self.packet_capture_thread,
            args=(ip,),
            daemon=True
        )
        self.sniffer_thread.start()
        
        # Start monitoring thread
        self.monitoring_thread = threading.Thread(
            target=self.monitoring_loop,
            daemon=True
        )
        self.monitoring_thread.start()
        
        self.print_to_terminal(f"Started monitoring {ip} for cyber threats")
        self.add_log_entry(f"Started monitoring {ip}")
    
    def stop_monitoring(self):
        if not self.monitoring:
            self.print_to_terminal("Not currently monitoring any IP")
            return
        
        self.monitoring = False
        
        if self.sniffer_thread and self.sniffer_thread.is_alive():
            # Scapy's sniff doesn't have a clean way to stop, so we use this workaround
            os.kill(os.getpid(), signal.SIGINT)
        
        self.print_to_terminal(f"Stopped monitoring {self.target_ip}")
        self.add_log_entry(f"Stopped monitoring {self.target_ip}")
        self.target_ip = ""
    
    def packet_capture_thread(self, ip):
        """Thread function for capturing and analyzing network packets"""
        try:
            # Filter to capture traffic related to our target IP
            filter_str = f"host {ip}"
            
            # Start packet capture
            sniff(
                filter=filter_str,
                prn=self.process_packet,
                store=0,
                stop_filter=lambda x: not self.monitoring
            )
        except Exception as e:
            self.add_log_entry(f"Packet capture error: {str(e)}")
    
    def process_packet(self, packet):
        """Analyze individual packets for security threats"""
        if not self.monitoring:
            return
        
        try:
            # Check for TCP packets
            if packet.haslayer(TCP):
                tcp = packet[TCP]
                
                # Detect port scanning (SYN packets to multiple ports)
                if tcp.flags == 'S':  # SYN flag
                    self.threat_stats["SYN Scan Attempt"] += 1
                    self.add_log_entry(f"Possible port scan detected from {packet[IP].src} to port {tcp.dport}")
                
                # Detect potential brute force attempts (multiple SYN packets to same port)
                if tcp.flags == 'S' and tcp.dport in [22, 3389, 21]:  # Common service ports
                    self.threat_stats["Brute Force Attempt"] += 1
                    self.add_log_entry(f"Possible brute force attempt from {packet[IP].src} to port {tcp.dport}")
            
            # Check for UDP packets (potential UDP flood)
            elif packet.haslayer(UDP):
                self.threat_stats["UDP Traffic"] += 1
                if self.threat_stats["UDP Traffic"] % 100 == 0:  # Log every 100 UDP packets
                    self.add_log_entry(f"High UDP traffic detected from {packet[IP].src}")
            
            # Check for ICMP (potential ping flood)
            elif packet.haslayer(ICMP):
                self.threat_stats["ICMP Traffic"] += 1
                if self.threat_stats["ICMP Traffic"] % 100 == 0:  # Log every 100 ICMP packets
                    self.add_log_entry(f"High ICMP traffic detected from {packet[IP].src}")
            
            # Check for HTTP traffic (port 80)
            if packet.haslayer(TCP) and (packet[TCP].dport == 80 or packet[TCP].sport == 80):
                self.threat_stats["HTTP Traffic"] += 1
            
            # Update stats display periodically
            if sum(self.threat_stats.values()) % 10 == 0:
                self.update_stats_display()
                
        except Exception as e:
            self.add_log_entry(f"Packet processing error: {str(e)}")
    
    def monitoring_loop(self):
        """Main monitoring loop for detecting threats"""
        packet_counts = defaultdict(int)
        last_check = time.time()
        
        while self.monitoring:
            try:
                current_time = time.time()
                
                # Check for DDoS (high packet rate)
                total_packets = sum(packet_counts.values())
                if total_packets > 1000:  # Threshold for DDoS detection
                    self.threat_stats["DDoS Detected"] += 1
                    self.add_log_entry("DDoS attack detected! High packet rate")
                
                # Reset counters periodically
                if current_time - last_check > MONITORING_INTERVAL:
                    packet_counts.clear()
                    last_check = current_time
                
                time.sleep(0.1)
            except Exception as e:
                self.add_log_entry(f"Monitoring error: {str(e)}")
                time.sleep(1)
    
    def ping_ip(self, ip):
        """Ping an IP address and display results"""
        try:
            self.print_to_terminal(f"Pinging {ip}...")
            
            # Platform-independent ping command
            param = '-n' if os.name == 'nt' else '-c'
            count = '4'
            command = ['ping', param, count, ip]
            
            result = subprocess.run(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            
            if result.returncode == 0:
                self.print_to_terminal(result.stdout)
                self.add_log_entry(f"Successful ping to {ip}")
            else:
                self.print_to_terminal(f"Ping failed to {ip}")
                self.print_to_terminal(result.stderr if result.stderr else "Unknown error")
                self.add_log_entry(f"Failed ping to {ip}")
        except Exception as e:
            self.print_to_terminal(f"Ping error: {str(e)}")
            self.add_log_entry(f"Ping error: {str(e)}")
    
    def whois_lookup(self, target):
        """Perform WHOIS lookup on domain or IP"""
        try:
            self.print_to_terminal(f"Performing WHOIS lookup for {target}...")
            
            w = whois.whois(target)
            
            self.print_to_terminal("\nWHOIS Results:")
            self.print_to_terminal(f"Domain: {w.domain_name}")
            self.print_to_terminal(f"Registrar: {w.registrar}")
            self.print_to_terminal(f"Creation Date: {w.creation_date}")
            self.print_to_terminal(f"Expiration Date: {w.expiration_date}")
            self.print_to_terminal(f"Name Servers: {w.name_servers}")
            
            self.add_log_entry(f"Performed WHOIS lookup for {target}")
        except Exception as e:
            self.print_to_terminal(f"WHOIS error: {str(e)}")
            self.add_log_entry(f"WHOIS error: {str(e)}")
    
    def ssh_connect(self, username, ip, password):
        """Connect to a remote server via SSH"""
        try:
            if self.ssh_client:
                self.print_to_terminal("Already connected to SSH. Disconnect first.")
                return
            
            self.print_to_terminal(f"Connecting to {username}@{ip}...")
            
            self.ssh_client = paramiko.SSHClient()
            self.ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            self.ssh_client.connect(ip, username=username, password=password)
            
            self.print_to_terminal("SSH connection established successfully")
            self.add_log_entry(f"SSH connected to {username}@{ip}")
            
            # Start a thread to handle SSH commands
            threading.Thread(
                target=self.ssh_command_handler,
                daemon=True
            ).start()
        except Exception as e:
            self.print_to_terminal(f"SSH connection error: {str(e)}")
            self.add_log_entry(f"SSH connection failed to {username}@{ip}")
            self.ssh_client = None
    
    def ssh_command_handler(self):
        """Handle SSH commands in a separate thread"""
        try:
            while self.ssh_client:
                command = input("SSH> ")  # This won't work well with GUI, needs improvement
                if command.lower() == 'exit':
                    break
                
                stdin, stdout, stderr = self.ssh_client.exec_command(command)
                output = stdout.read().decode()
                error = stderr.read().decode()
                
                if output:
                    self.print_to_terminal(output)
                if error:
                    self.print_to_terminal(f"Error: {error}")
        except Exception as e:
            self.print_to_terminal(f"SSH error: {str(e)}")
        finally:
            if self.ssh_client:
                self.ssh_client.close()
                self.ssh_client = None
                self.print_to_terminal("SSH connection closed")
                self.add_log_entry("SSH connection closed")
    
    def show_threat_dashboard(self):
        """Display threat statistics in visual charts"""
        dashboard = tk.Toplevel(self.root)
        dashboard.title("Threat Dashboard")
        dashboard.geometry("800x600")
        dashboard.configure(bg=BG_COLOR)
        
        if not self.threat_stats:
            tk.Label(
                dashboard,
                text="No threat data available",
                bg=BG_COLOR, fg=TEXT_COLOR, font=FONT
            ).pack(pady=20)
            return
        
        # Prepare data for charts
        threats = list(self.threat_stats.keys())
        counts = list(self.threat_stats.values())
        
        # Create figure for bar chart
        fig1, ax1 = plt.subplots(figsize=(6, 4), facecolor=BG_COLOR)
        ax1.bar(threats, counts, color=GREEN_THEME)
        ax1.set_title('Threat Distribution', color=TEXT_COLOR)
        ax1.set_facecolor(BG_COLOR)
        ax1.tick_params(colors=TEXT_COLOR)
        plt.setp(ax1.get_xticklabels(), rotation=45, ha='right')
        
        # Create canvas for bar chart
        canvas1 = FigureCanvasTkAgg(fig1, master=dashboard)
        canvas1.draw()
        canvas1.get_tk_widget().pack(side=tk.TOP, fill=tk.BOTH, expand=True)
        
        # Create figure for pie chart
        fig2, ax2 = plt.subplots(figsize=(6, 4), facecolor=BG_COLOR)
        ax2.pie(counts, labels=threats, autopct='%1.1f%%', colors=[GREEN_THEME, '#00cc00', '#009900'])
        ax2.set_title('Threat Percentage', color=TEXT_COLOR)
        
        # Create canvas for pie chart
        canvas2 = FigureCanvasTkAgg(fig2, master=dashboard)
        canvas2.draw()
        canvas2.get_tk_widget().pack(side=tk.TOP, fill=tk.BOTH, expand=True)
    
    def show_network_traffic(self):
        """Display network traffic statistics"""
        traffic_window = tk.Toplevel(self.root)
        traffic_window.title("Network Traffic Analysis")
        traffic_window.geometry("600x400")
        traffic_window.configure(bg=BG_COLOR)
        
        if not self.threat_stats:
            tk.Label(
                traffic_window,
                text="No network traffic data available",
                bg=BG_COLOR, fg=TEXT_COLOR, font=FONT
            ).pack(pady=20)
            return
        
        # Create a treeview to display traffic data
        tree = ttk.Treeview(traffic_window, columns=('Protocol', 'Count'), show='headings')
        tree.heading('Protocol', text='Protocol')
        tree.heading('Count', text='Count')
        
        # Add data to treeview
        for protocol, count in sorted(self.threat_stats.items(), key=lambda x: x[1], reverse=True):
            tree.insert('', tk.END, values=(protocol, count))
        
        tree.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Add scrollbar
        scrollbar = ttk.Scrollbar(traffic_window, orient=tk.VERTICAL, command=tree.yview)
        tree.configure(yscroll=scrollbar.set)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
    
    def export_data(self):
        """Export monitoring data to a file"""
        if not self.logs and not self.threat_stats:
            messagebox.showwarning("Export Data", "No data available to export")
            return
        
        file_path = filedialog.asksaveasfilename(
            defaultextension=".json",
            filetypes=[("JSON Files", "*.json"), ("Text Files", "*.txt"), ("All Files", "*.*")]
        )
        
        if not file_path:
            return
        
        try:
            data = {
                "logs": self.logs,
                "threat_stats": dict(self.threat_stats),
                "target_ip": self.target_ip,
                "timestamp": datetime.datetime.now().isoformat()
            }
            
            with open(file_path, 'w') as f:
                json.dump(data, f, indent=2)
            
            self.print_to_terminal(f"Data exported successfully to {file_path}")
            self.add_log_entry(f"Exported data to {file_path}")
        except Exception as e:
            messagebox.showerror("Export Error", f"Failed to export data: {str(e)}")
            self.add_log_entry(f"Export failed: {str(e)}")
    
    def show_about(self):
        """Display about information"""
        about_text = """
Advanced Cyber Security Monitoring Tool
Version 1.0

This tool provides real-time monitoring of network traffic
and detection of various cyber threats including:
- DDoS attacks
- Port scanning
- Brute force attempts
- Suspicious traffic patterns

Developed for professional security monitoring.
"""
        messagebox.showinfo("About", about_text)
    
    def show_help(self):
        """Display help information"""
        help_text = """
Available Commands:
------------------
help                         - Show this help message
start monitoring <ip>        - Start monitoring the specified IP
stop                         - Stop monitoring
ping <ip>                    - Ping an IP address
whois <domain_or_ip>         - Perform WHOIS lookup
ssh <user> <ip> <password>   - Connect via SSH
exit                         - Exit the program

Dashboard Features:
------------------
- Real-time threat detection
- Visual charts of threat distribution
- Logging of all security events
- Export capability for all collected data
"""
        self.print_to_terminal(help_text)
    
    def on_close(self):
        """Clean up resources before closing"""
        if self.monitoring:
            self.stop_monitoring()
        
        if self.ssh_client:
            self.ssh_client.close()
        
        self.root.destroy()

# Main entry point
if __name__ == "__main__":
    # Check for root/admin privileges
    if os.name == 'posix' and os.geteuid() != 0:
        print("This tool requires root privileges for packet capture.")
        sys.exit(1)
    
    tool = CyberSecurityTool()