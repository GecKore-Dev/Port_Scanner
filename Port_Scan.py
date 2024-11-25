#  _____           _   __               
# |  __ \         | | / /               
# | |  \/ ___  ___| |/ /  ___  _ __ ___ 
# | | __ / _ \/ __|    \ / _ \| '__/ _ \
# | |_\ \  __/ (__| |\  \ (_) | | |  __/
#  \____/\___|\___\_| \_/\___/|_|  \___|
#                                       
# Nom du fichier : port_scanner.py
# Version       : 1.0.8
# Auteur        : GecKore-Dev
# GitHub        : https://github.com/GecKore-Dev
#

import socket
import tkinter as tk
from tkinter import messagebox, ttk, Checkbutton, IntVar, Scrollbar, RIGHT, Y, END
from PIL import Image, ImageTk
import threading
import os
import sys

# Fonction pour obtenir le chemin des ressources (logo inclus dans le .exe)
def get_resource_path(relative_path):
    """Obtenir le chemin absolu d'un fichier même après la compilation avec PyInstaller."""
    try:
        base_path = sys._MEIPASS  # Lorsqu'on exécute l'exécutable compilé
    except AttributeError:
        base_path = os.path.abspath(".")  # Lorsqu'on exécute le script directement
    return os.path.join(base_path, relative_path)

# Informations du projet
VERSION = "1.0.8"
AUTHOR = "GecKore-Dev"
GITHUB_URL = "https://github.com/GecKore-Dev"

# Chemin des ressources
logo_path = get_resource_path("Geckore/Logo-GecKore.png")
icon_path = get_resource_path("Geckore/Icon-GecKore.ico")

# Variable pour stopper le scan
stop_scan_flag = False

# Fonction pour scanner les ports
def scan_ports(target_ip, selected_ports, result_list):
    """Scanne les ports sélectionnés ou une plage de ports."""
    global stop_scan_flag
    open_ports = []
    for port in selected_ports:
        if stop_scan_flag:
            result_list.insert(END, "Scan interrompu.")
            result_list.see(END)
            return
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(0.5)
                if s.connect_ex((target_ip, port)) == 0:
                    open_ports.append(port)
                    result_list.insert(END, f" - Port {port}: Ouvert")
                else:
                    result_list.insert(END, f" - Port {port}: Fermé")
        except Exception as e:
            result_list.insert(END, f" - Port {port}: Erreur ({e})")
        result_list.see(END)

    # Résumé des résultats
    result_list.insert(END, f"\nScan terminé pour {target_ip}.")
    if open_ports:
        result_list.insert(END, f"Ports ouverts : {', '.join(map(str, open_ports))}")
    else:
        result_list.insert(END, "Aucun port ouvert trouvé.")
    result_list.see(END)

# Interface graphique
def create_gui():
    """Crée une interface graphique pour le port scanner."""
    root = tk.Tk()
    root.title("Port Scanner by GecKore")

    # Définir l'icône pour l'interface
    root.iconbitmap(icon_path)

    # Dimensions de l'interface
    root.geometry("700x700")

    # Ajout du logo
    try:
        img = Image.open(logo_path)
        img = img.resize((150, 150), Image.Resampling.LANCZOS)
        logo = ImageTk.PhotoImage(img)
        logo_label = tk.Label(root, image=logo)
        logo_label.image = logo
        logo_label.place(x=275, y=10)  # Placement centré en haut
    except Exception as e:
        print(f"Erreur lors du chargement du logo : {e}")
        messagebox.showerror("Erreur", f"Impossible de charger le logo : {e}")

    # Ajout des informations sur l'auteur
    info_label = tk.Label(root, text=f"Auteur : {AUTHOR}\nVersion : {VERSION}", font=("Arial", 12), justify="center")
    info_label.place(x=275, y=170)

    # Champ pour saisir l'adresse IP cible
    ip_label = tk.Label(root, text="Entrez l'adresse IP cible :", font=("Arial", 12))
    ip_label.place(x=20, y=220)
    ip_entry = ttk.Entry(root, font=("Arial", 12), width=30)
    ip_entry.place(x=200, y=220)

    # Champ pour la plage de ports
    range_label = tk.Label(root, text="Plage de ports :", font=("Arial", 12))
    range_label.place(x=20, y=260)
    port_start = ttk.Entry(root, font=("Arial", 12), width=10)
    port_start.place(x=140, y=260)
    port_start.insert(0, "1")
    range_to_label = tk.Label(root, text="à", font=("Arial", 12))
    range_to_label.place(x=240, y=260)
    port_end = ttk.Entry(root, font=("Arial", 12), width=10)
    port_end.place(x=270, y=260)
    port_end.insert(0, "1024")

    # Cases à cocher pour les ports communs
    ports_label = tk.Label(root, text="Ports communs :", font=("Arial", 12))
    ports_label.place(x=20, y=300)

    common_ports = {80: "HTTP", 443: "HTTPS", 21: "FTP", 22: "SSH", 25: "SMTP", 53: "DNS"}
    port_vars = {}
    y_offset = 330
    for i, (port, name) in enumerate(common_ports.items()):
        port_vars[port] = IntVar()
        cb = Checkbutton(root, text=f"{port} ({name})", variable=port_vars[port])
        cb.place(x=20 + (i % 3) * 150, y=y_offset + (i // 3) * 30)

    # Liste pour afficher les résultats avec barre de défilement
    result_frame = tk.Frame(root)
    result_frame.place(x=20, y=400, width=660, height=200)

    result_list = tk.Listbox(result_frame, font=("Arial", 10), width=80, height=10)
    scrollbar = Scrollbar(result_frame, orient=tk.VERTICAL)
    result_list.config(yscrollcommand=scrollbar.set)
    scrollbar.config(command=result_list.yview)
    scrollbar.pack(side=RIGHT, fill=Y)
    result_list.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

    # Bouton pour démarrer le scan
    def start_scan():
        """Démarre le scan en utilisant un thread."""
        global stop_scan_flag
        stop_scan_flag = False
        target_ip = ip_entry.get().strip()
        if not target_ip:
            messagebox.showerror("Erreur", "Veuillez entrer une adresse IP valide.")
            return

        # Ports sélectionnés
        selected_ports = [port for port, var in port_vars.items() if var.get() == 1]
        if not selected_ports:
            try:
                start = int(port_start.get())
                end = int(port_end.get())
                selected_ports = list(range(start, end + 1))
            except ValueError:
                messagebox.showerror("Erreur", "Veuillez entrer une plage de ports valide.")
                return

        result_list.delete(0, END)
        result_list.insert(END, f"Scan en cours pour {target_ip}...")
        threading.Thread(target=scan_ports, args=(target_ip, selected_ports, result_list), daemon=True).start()

    # Bouton pour arrêter le scan
    def stop_scan():
        """Arrête le scan en cours."""
        global stop_scan_flag
        stop_scan_flag = True

    # Boutons repositionnés sous la liste des résultats
    scan_button = tk.Button(root, text="Démarrer le scan", command=start_scan, bg="green", fg="white", font=("Arial", 12), width=15)
    scan_button.place(x=150, y=620)

    stop_button = tk.Button(root, text="Arrêter le scan", command=stop_scan, bg="red", fg="white", font=("Arial", 12), width=15)
    stop_button.place(x=400, y=620)

    root.mainloop()

# Lancer l'interface graphique
if __name__ == "__main__":
    create_gui()
