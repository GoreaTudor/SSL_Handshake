import json
import socket
import threading
import tkinter as tk
from tkinter import ttk, scrolledtext

from client import SSLClient, read_config
from server import SSLServer

class SSLApp(tk.Tk):
    def __init__(self, config):
        super().__init__()

        self.config = config
        self.title("SSL Server & Client")
        self.geometry("1080x760")

        self.create_widgets()

    def create_widgets(self):
        self.create_server_frame()
        self.create_client_frame()
        self.create_output_frames()
        self.create_port_frame()
        self.create_clear_output_buttons()
        self.create_settings_output_frame()
        self.create_alg_frame()

    def create_alg_frame(self):
        frame = ttk.LabelFrame(self, text="Algorithms")
        frame.grid(column=0, row=5, columnspan=2, padx=10, pady=10, sticky="W")

        ttk.Label(frame, text="Key Exchange:").grid(column=0, row=0, sticky="W")
        self.ke_var = tk.StringVar()
        self.ke_var.set(self.config["pref_KE"])
        self.ke_dropdown = ttk.OptionMenu(frame, self.ke_var, self.config["pref_KE"], "RSA", "ECC")
        self.ke_dropdown.grid(column=1, row=0, padx=5, sticky="W")

        ttk.Label(frame, text="Symmetric:").grid(column=2, row=0, sticky="W")
        self.sym_var = tk.StringVar()
        self.sym_var.set(self.config["pref_SYM"])
        self.sym_dropdown = ttk.OptionMenu(frame, self.sym_var, self.config["pref_SYM"], "AES", "ARC2", "Blowfish", "CAST", "Salsa20")
        self.sym_dropdown.grid(column=3, row=0, padx=5, sticky="W")

        self.save_alg_button = ttk.Button(frame, text="Save Algorithms", command=self.save_algorithms)
        self.save_alg_button.grid(column=4, row=0, padx=5, sticky="W")

    def save_algorithms(self):
        new_ke = self.ke_var.get()
        new_sym = self.sym_var.get()

        # Load the current configuration
        with open("config.json", "r") as file:
            config = json.load(file)

        # Update the algorithm values
        config["pref_KE"] = new_ke
        config["pref_SYM"] = new_sym

        # Save the updated configuration
        with open("config.json", "w") as file:
            json.dump(config, file)

        self.settings_output_text.insert(tk.END, f"Key Exchange algorithm updated to: {new_ke}\n")
        self.settings_output_text.insert(tk.END, f"Symmetric algorithm updated to: {new_sym}\n")

    def create_clear_output_buttons(self):
        frame = ttk.Frame(self)
        frame.grid(column=0, row=3, columnspan=2, padx=10, pady=10, sticky="W")
        
        self.clear_server_output_button = ttk.Button(frame, text="Clear Server Output", command=self.clear_server_output)
        self.clear_server_output_button.grid(column=0, row=0)
        
        self.clear_client_output_button = ttk.Button(frame, text="Clear Client Output", command=self.clear_client_output)
        self.clear_client_output_button.grid(column=1, row=0)

    def clear_server_output(self):
        self.server_output_text.delete(1.0, tk.END)
    
    def clear_client_output(self):
        self.client_output_text.delete(1.0, tk.END)

    def create_settings_output_frame(self):
        frame = ttk.LabelFrame(self, text="Settings Output")
        frame.grid(column=0, row=4, columnspan=2, padx=10, pady=10, sticky="W")

        self.settings_output_text = scrolledtext.ScrolledText(frame, width=80, height=10, wrap=tk.WORD)
        self.settings_output_text.grid(column=0, row=0)

    def create_server_frame(self):
        frame = ttk.LabelFrame(self, text="Server")
        frame.grid(column=0, row=0, padx=10, pady=10, sticky="W")

        self.start_server_button = ttk.Button(frame, text="Start Server", command=self.start_server)
        self.start_server_button.grid(column=0, row=0)

    def create_client_frame(self):
        frame = ttk.LabelFrame(self, text="Client")
        frame.grid(column=1, row=0, padx=10, pady=10, sticky="W")

        self.start_client_button = ttk.Button(frame, text="Start Client", command=self.start_client)
        self.start_client_button.grid(column=0, row=0)

    def create_output_frames(self):
        self.create_server_output_frame()
        self.create_client_output_frame()

    def create_server_output_frame(self):
        frame = ttk.LabelFrame(self, text="Server Output")
        frame.grid(column=0, row=1, padx=10, pady=10, sticky="W")

        self.server_output_text = scrolledtext.ScrolledText(frame, width=40, height=20, wrap=tk.WORD)
        self.server_output_text.grid(column=0, row=0)

    def create_client_output_frame(self):
        frame = ttk.LabelFrame(self, text="Client Output")
        frame.grid(column=1, row=1, padx=10, pady=10, sticky="W")

        self.client_output_text = scrolledtext.ScrolledText(frame, width=40, height=20, wrap=tk.WORD)
        self.client_output_text.grid(column=0, row=0)

    def create_port_frame(self):
        frame = ttk.LabelFrame(self, text="Port")
        frame.grid(column=0, row=2, columnspan=2, padx=10, pady=10, sticky="W")

        ttk.Label(frame, text="Port Number:").grid(column=0, row=0, sticky="W")
        self.port_entry = ttk.Entry(frame, width=10)
        self.port_entry.insert(0, str(self.config["port"]))
        self.port_entry.grid(column=1, row=0, padx=5, sticky="W")

        self.save_port_button = ttk.Button(frame, text="Save Port", command=self.save_port)
        self.save_port_button.grid(column=2, row=0, padx=5, sticky="W")

    def start_server(self):
        server_thread = threading.Thread(target=self.run_server, daemon=True)
        server_thread.start()

    def start_client(self):
        client_thread = threading.Thread(target=self.run_client, daemon=True)
        client_thread.start()

    def run_server_thread(self):
        config = read_config()
        host = socket.gethostname()
        port = config["port"]
        ssl_server = SSLServer(host, port, self.update_server_output)
        ssl_server.set_preffered_algs(str(config["pref_KE"]), str(config["pref_SYM"]))
        ssl_server.run()

    def run_server(self):
        self.update_server_output("Starting server...")
        server_thread = threading.Thread(target=self.run_server_thread, daemon=True)
        server_thread.start()

    def run_client(self):
        config = read_config()
        host = socket.gethostname()
        port = config["port"]
        ssl_client = SSLClient(host, port, self.update_client_output)
        ssl_client.run()

    def update_server_output(self, text):
        self.server_output_text.insert(tk.END, text + "\n")
        self.server_output_text.see(tk.END)

    def update_client_output(self, text):
        self.client_output_text.insert(tk.END, text + "\n")
        self.client_output_text.see(tk.END)

    def save_port(self):
        try:
            new_port = int(self.port_entry.get())

            # Load the current configuration
            with open("config.json", "r") as file:
                config = json.load(file)

            # Update the port value
            config["port"] = new_port

            # Save the updated configuration
            with open("config.json", "w") as file:
                json.dump(config, file)

            self.settings_output_text.insert(tk.END, f"Port number updated to: {new_port}\n")
        except ValueError:
            self.settings_output_text.insert(tk.END, "Invalid port number. Please enter a valid integer.\n")

def main():
    config = read_config()
    app = SSLApp(config)
    app.mainloop()

if __name__ == "__main__":
    main()
