#!/usr/bin/env python3

import tkinter as tk
from tkinter import ttk, messagebox
from scapy.all import sniff
import threading
import time
import os
import subprocess

# Automatically install the Chicago95 font
def install_font():
    font_path = os.path.abspath("font/ChicagoFLF.ttf")
    fonts_dir = os.path.expanduser("~/.fonts")
    dest_path = os.path.join(fonts_dir, "ChicagoFLF.ttf")

    try:
        # Ensure the fonts directory exists
        os.makedirs(fonts_dir, exist_ok=True)

        # Copy the font if it doesn't already exist
        if not os.path.exists(dest_path):
            subprocess.run(["cp", font_path, dest_path], check=True)
            print(f"Font copied to {dest_path}")

        # Update the font cache
        subprocess.run(["fc-cache", "-f", "-v"], check=True)
        print("Font cache updated")

        # Verify if the font is installed
        result = subprocess.run(["fc-list"], capture_output=True, text=True)
        if "ChicagoFLF" not in result.stdout:
            print("Warning: ChicagoFLF font not found in the system font list.")
        else:
            print("ChicagoFLF font successfully installed and available.")

    except Exception as e:
        print(f"Error installing font: {e}")

# Global flags for sniffing control
sniffing = False
thread = None

# Main class for the user interface
class PacketSnifferGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Tralalero Sniffer")
        self.root.geometry("800x500")
        self.root.configure(bg="#C0C0C0")  # Windows 95 grey

        self.custom_font = ("ChicagoFLF", 10)
        self.title_font = ("ChicagoFLF", 14, "bold")

        self.filter_var = tk.StringVar(value="ALL")  # Default protocol filter

        self.create_widgets()  # Build the GUI components
        self.packet_count = 0  # Counter for packets

    def create_widgets(self):
        # Title bar
        title = tk.Label(self.root, text="TRALALERO TRALALA - Packet Sniffer",
                         font=self.title_font, bg="#000080", fg="white", pady=5)
        title.pack(fill=tk.X)

        # Control panel
        control_frame = tk.Frame(self.root, bg="#C0C0C0")
        control_frame.pack(pady=5)

        tk.Label(control_frame, text="Protocol Filter:", bg="#C0C0C0", font=self.custom_font).grid(row=0, column=0, padx=5)
        self.protocol_menu = ttk.Combobox(control_frame, textvariable=self.filter_var,
                                          values=["ALL", "TCP", "UDP", "ICMP"], width=10, state="readonly")
        self.protocol_menu.grid(row=0, column=1)

        self.start_btn = ttk.Button(control_frame, text="Start Sniffing", command=self.start_sniffing)
        self.start_btn.grid(row=0, column=2, padx=5)

        self.stop_btn = ttk.Button(control_frame, text="Stop", command=self.stop_sniffing, state="disabled")
        self.stop_btn.grid(row=0, column=3, padx=5)

        self.packet_table = ttk.Treeview(self.root, columns=("No", "Time", "Source", "Destination", "Protocol", "Length"),
                                         show="headings", height=15)
        self.packet_table.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)

        for col in self.packet_table["columns"]:
            self.packet_table.heading(col, text=col)
            self.packet_table.column(col, width=100, anchor=tk.CENTER)

        self.packet_table.bind("<<TreeviewSelect>>", self.show_packet_details)

        self.detail_text = tk.Text(self.root, height=5, bg="white", font=("Courier", 9))
        self.detail_text.pack(fill=tk.X, padx=10, pady=5)

    def start_sniffing(self):
        global sniffing, thread
        sniffing = True
        self.start_btn.config(state="disabled")
        self.stop_btn.config(state="normal")
        self.packet_table.delete(*self.packet_table.get_children())
        self.packet_count = 0
        thread = threading.Thread(target=self.sniff_packets)
        thread.daemon = True
        thread.start()

    def stop_sniffing(self):
        global sniffing
        sniffing = False
        self.start_btn.config(state="normal")
        self.stop_btn.config(state="disabled")

    def sniff_packets(self):
        def process_packet(packet):
            if not sniffing:
                return False

            self.packet_count += 1
            time_str = time.strftime("%H:%M:%S")
            src = packet[0][1].src if packet.haslayer(1) else "Unknown"
            dst = packet[0][1].dst if packet.haslayer(1) else "Unknown"
            proto = packet.summary().split()[0]
            length = len(packet)

            self.packet_table.insert("", "end", values=(self.packet_count, time_str, src, dst, proto, length))
            self.packet_table.update_idletasks()
            return sniffing

        protocol_filter = self.filter_var.get().lower()
        filter_str = protocol_filter if protocol_filter != "all" else ""

        sniff(prn=process_packet, store=False, filter=filter_str)

    def show_packet_details(self, event):
        selected = self.packet_table.selection()
        if not selected:
            return

        values = self.packet_table.item(selected[0])['values']
        self.detail_text.delete("1.0", tk.END)

        details = f"Packet #{values[0]}\nTime: {values[1]}\nSource: {values[2]}\nDestination: {values[3]}\nProtocol: {values[4]}\nLength: {values[5]}"
        self.detail_text.insert(tk.END, details)

# Main
if __name__ == "__main__":
    install_font()
    root = tk.Tk()
    app = PacketSnifferGUI(root)
    root.mainloop()
