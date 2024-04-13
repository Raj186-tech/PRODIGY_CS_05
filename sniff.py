import tkinter as tk
from tkinter import scrolledtext
import scapy.all as scapy
from threading import Thread

class PacketSnifferApp:
    def __init__(self, master):
        self.master = master
        master.title("Packet Sniffer")

        self.interface_label = tk.Label(master, text="Interface:")
        self.interface_label.grid(row=0, column=0, padx=10, pady=5)

        self.interface_entry = tk.Entry(master)
        self.interface_entry.grid(row=0, column=1, padx=10, pady=5)

        self.start_button = tk.Button(master, text="Start Sniffing", command=self.start_sniffing)
        self.start_button.grid(row=1, column=0, columnspan=2, padx=10, pady=5)

        self.log_text = scrolledtext.ScrolledText(master, width=60, height=20)
        self.log_text.grid(row=2, column=0, columnspan=2, padx=10, pady=5)

    def packet_sniffer(self, packet):
        if packet.haslayer(scapy.IP):
            source_ip = packet[scapy.IP].src
            destination_ip = packet[scapy.IP].dst
            protocol = packet[scapy.IP].proto

            log_msg = f"[*] Source IP: {source_ip} --> Destination IP: {destination_ip} Protocol: {protocol}\n"
            self.log_text.insert(tk.END, log_msg)

            if packet.haslayer(scapy.TCP):
                source_port = packet[scapy.TCP].sport
                destination_port = packet[scapy.TCP].dport
                log_msg = f"    [+] Source Port: {source_port} --> Destination Port: {destination_port}\n"
                self.log_text.insert(tk.END, log_msg)

                if packet.haslayer(scapy.Raw):
                    payload = packet[scapy.Raw].load
                    log_msg = f"    [+] Payload: {payload}\n"
                    self.log_text.insert(tk.END, log_msg)

    def start_sniffing(self):
        self.log_text.delete(1.0, tk.END)
        interface = self.interface_entry.get()
        if interface:
            self.log_text.insert(tk.END, f"[*] Starting packet sniffing on interface: {interface}\n")

            def sniff_packets():
                scapy.sniff(iface=interface, store=False, prn=self.packet_sniffer)

            t = Thread(target=sniff_packets)
            t.start()
        else:
            self.log_text.insert(tk.END, "[!] Please enter an interface to start sniffing.\n")

def main():
    root = tk.Tk()
    app = PacketSnifferApp(root)
    root.mainloop()

if __name__ == "__main__":
    main()
