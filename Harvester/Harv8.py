# Tkinter pour l'interface graphique (GUI)
import tkinter as tk                # Fournit les classes pour créer une interface utilisateur graphique
from tkinter import messagebox       # Permet d'afficher des boîtes de message (ex. messages d'alerte)
from tkinter import ttk              # Pour les widgets supplémentaires de Tkinter (par exemple les menus déroulants)
from tkinter import filedialog       # Pour ouvrir des boîtes de dialogue pour choisir des fichiers

# Nmap pour l'analyse des réseaux # Librairie utilisée pour le scan réseau
import nmap                            

# Pour la gestion des fichiers et des répertoires
import os                            # Utilisé pour interagir avec le système de fichiers (par exemple vérifier si un fichier existe)

# Expressions régulières pour valider ou extraire des informations des chaînes de caractères
import re                            # Utilisé pour effectuer des recherches et des validations de texte avec des expressions régulières

# Pour ouvrir des URLs dans le navigateur par défaut
import webbrowser                    # Permet d'ouvrir une URL dans le navigateur

# Pour interagir avec le système d'exploitation 
import sys                           # Permet d'accéder aux arguments passés au programme ou de manipuler l'environnement

# SQLite pour gérer une base de données locale
import sqlite3                       # Bibliothèque pour interagir avec des bases de données SQLite (probablement pour stocker des informations locales)

# Importation du module pour la manipulation des images (si tu utilises des images dans  GUI)
from PIL import Image, ImageTk        # Utilisé pour manipuler des images et les afficher dans l'interface Tkinter

# Pour exécuter des commandes système ou externes depuis Python
import subprocess                     # Permet d'exécuter des commandes systèmes (par exemple ouvrir un terminal ou un autre programme)

# Pour le hachage de mots de passe dans les applications Flask
from werkzeug.security import generate_password_hash, check_password_hash  # Utilisé pour sécuriser les mots de passe des utilisateurs

# Pour manipuler les dates et heures
from datetime import datetime         # Permet de travailler avec les dates et heures (formatage des dates, calculs, etc.)

# Ajoute le dossier parent "prj-finale-réseau" dans sys.path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

# importe les modèles
from models import db, User, ScanResult
import time
import threading

class Database:
    def __init__(self, db_path):
        """
        Initialise la connexion à la base de données en spécifiant le chemin du fichier de base de données.
        
        :param db_path: chemin d'accès au fichier de base de données SQLite
        """
        self.db_path = db_path  # Définit l'emplacement du fichier de base de données

    def authenticate_user(self, username, password):
        """
        Authentifie un utilisateur en vérifiant son nom d'utilisateur et son mot de passe.
        Retourne l'ID de l'utilisateur et son rôle si l'authentification est réussie.
        
        :param username: nom d'utilisateur de l'utilisateur
        :param password: mot de passe de l'utilisateur
        :return: un tuple (user_id, role) si authentification réussie, sinon (None, None)
        """
        # Vérifie si les champs sont vides
        if not username or not password:
            messagebox.showwarning("Champs vides", "Veuillez remplir tous les champs.")  # Affiche un avertissement si les champs sont vides
            return None, None  # Retourne None, None pour indiquer une erreur

        try:
            # Connexion à la base de données SQLite
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()

            # Exécute une requête pour obtenir l'ID, le mot de passe haché et le rôle de l'utilisateur
            cursor.execute("SELECT id, password_hash, role FROM user WHERE username = ?", (username,))
            result = cursor.fetchone()  # Récupère le résultat de la requête (une seule ligne ou None)

            conn.close()  # Ferme la connexion à la base de données

            # Vérifie si un utilisateur a été trouvé
            if result:
                user_id, password_hash, role = result  # Décompose le résultat en variables
                # Vérifie si le mot de passe fourni correspond au mot de passe haché
                if check_password_hash(password_hash, password):
                    return user_id, role  # Retourne l'ID de l'utilisateur et son rôle si l'authentification réussit
            # Si l'authentification échoue, affiche un message d'erreur
            messagebox.showerror("Erreur", "Nom d'utilisateur ou mot de passe incorrect.")
            return None, None  # Retourne None, None pour indiquer une erreur d'authentification
        except sqlite3.Error as e:
            # Si une erreur de base de données se produit, affiche un message d'erreur
            messagebox.showerror("Erreur", f"Problème de base de données : {e}")
            return None, None  # Retourne None, None en cas d'erreur

# Classe pour gérer les actions réseau, comme l'ouverture des règles RGPD dans un navigateur
class Network:
    @staticmethod
    def open_rgpd():
        """
        Ouvre le lien des règles RGPD dans le navigateur.
        
        Cette méthode utilise la bibliothèque webbrowser pour ouvrir le lien
        vers les règles de protection des données personnelles (RGPD) sur le site de la CNIL.
        Si une erreur se produit lors de l'ouverture du lien, un message d'erreur est affiché à l'utilisateur.
        """
        try:
            # Essaye d'ouvrir le lien vers les règles RGPD de la CNIL dans le navigateur
            webbrowser.open("https://www.cnil.fr/fr/reglement-europeen-protection-donnees")
        except Exception as e:
            # Si une erreur se produit lors de l'ouverture du lien (par exemple, si le navigateur n'est pas disponible)
            # Affiche un message d'erreur avec les détails de l'exception
            messagebox.showerror("Erreur", f"Impossible d'ouvrir les règles RGPD : {e}")

class NetworkScanner:
    """Classe pour gérer le scan du réseau avec Nmap."""

    def __init__(self, network_range="192.168.193.0/24", progress_callback=None):
        """
        Constructeur de la classe. Initialise la plage réseau et l'outil Nmap pour le scan.
        
        :param network_range: Plage réseau à scanner (par défaut 192.168.193.0/24).
        """
        self.network_range = network_range
        self.scanner = nmap.PortScanner()  # Initialise l'outil Nmap pour le scan
        self.progress_callback = progress_callback  # Callback pour mettre à jour la barre de progression
    def set_network_range(self, network_range):
        """Met à jour la plage réseau à scanner."""
        self.network_range = network_range  # Mise à jour de la plage réseau

    def scan(self, target=None):
        """
        Effectue un scan du réseau sur la plage spécifiée ou sur une cible donnée.
        
        :param target: Plage réseau ou hôte spécifique à scanner (par défaut, utilise `network_range`).
        :return: Les résultats du scan Nmap ou None en cas d'erreur.
        """
        if not target:
            target = self.network_range  # Utilise la plage réseau par défaut si aucune cible n'est spécifiée
        if not target:
            messagebox.showerror("Erreur", "Veuillez spécifier une plage réseau valide.")  # Vérifie si la cible est valide
            return None

        try:
            print(f"Scanning network: {target}...")

            # Début du scan → Progression à 10%
            if self.progress_callback:
                self.progress_callback(10)

            # Simulation de la progression
            for progress in range(20, 101, 20):
                time.sleep(1)  # Pause pour simuler l'avancement
                if self.progress_callback:
                    self.progress_callback(progress)

            # Lancer le scan réel
            self.scanner.scan(hosts=target, arguments='-p 1-1024 -sV -Pn -O --osscan-guess')

            # Mise à jour finale de la progression
            if self.progress_callback:
                self.progress_callback(100)

            # Vérifie si des hôtes sont détectés
            if not self.scanner.all_hosts():
                print("Aucun hôte détecté.")
            else:
                print(f"Hôtes détectés : {', '.join(self.scanner.all_hosts())}")

            print("Scan terminé.")
            return self.scanner

        except Exception as e:
            print(f"Erreur pendant le scan : {e}")
            messagebox.showerror("Erreur", f"Une erreur est survenue pendant le scan : {e}")
            return None

    def get_wan_ping_latency(self, host):
        """
        Mesure la latence WAN en pingant un serveur distant (par exemple, 8.8.8.8).
        
        :param host: L'hôte pour lequel on souhaite mesurer la latence.
        :return: La latence mesurée ou "Inconnu" si une erreur survient.
        """
        try:
            # Utilisation de l'adresse Google DNS pour tester la latence WAN (8.8.8.8)
            ping_command = ["ping", "-n", "4", "8.8.8.8"] if os.name == 'nt' else ["ping", "-c", "4", "8.8.8.8"]
            
            # Exécute la commande ping
            result = subprocess.run(ping_command, capture_output=True, text=True)
            
            # Vérifie si la commande a réussi
            if result.returncode != 0:
                return "Inconnu"  # Si le ping échoue, retourne "Inconnu"
            
            output = result.stdout  # Récupère la sortie du ping
            
            # Debug: Afficher la sortie complète pour vérifier le format
            print("Ping output:", output)
            
            # Sur Windows, la latence moyenne se trouve après "Moyenne ="
            if os.name == 'nt' and "Moyenne" in output:
                latency = output.split("Moyenne =")[1].split("ms")[0].strip()  # Extraire la latence sur Windows
                return f"{latency} ms"
            
            # Sur Linux / macOS, la latence moyenne se trouve après "avg ="
            elif os.name != 'nt' and "avg" in output:
                latency = output.split("avg =")[1].split("/")[1].strip()  # Extraire la latence sur Linux/macOS
                return f"{latency} ms"
            
            else:
                return "Inconnu"  # Si la latence ne peut pas être déterminée, retourne "Inconnu"
    
        except Exception as e:
            print(f"Erreur lors du ping: {e}")  # Capture et affiche l'erreur du ping
            return "Inconnu"  # Retourne "Inconnu" en cas d'erreur


class App:
    """Classe principale pour gérer l'interface graphique et les résultats du scan."""
    
    def __init__(self, root, db_path):
        """
        Constructeur pour initialiser l'application avec la fenêtre principale et la base de données.
        
        :param root: La fenêtre principale de l'application Tkinter.
        :param db_path: Le chemin de la base de données SQLite.
        """
        self.root = root
        self.db_path = db_path
        self.database = Database(db_path)  # Crée une instance de la classe Database pour gérer la base de données
        self.network = Network()  # Crée une instance de la classe Network pour gérer les actions liées au réseau
        self.network_scanner = NetworkScanner()  # Crée une instance de la classe NetworkScanner pour effectuer des scans réseau
        
        # Définit l'icône de l'application à partir d'un fichier image
        self.root.iconphoto(False, tk.PhotoImage(file="Harvester/icon.png"))
        
        # Initialisation des variables pour les images de fond et de logo
        self.bg_photo = None
        self.logo_photo = None

        # Paramètres de la fenêtre principale
        self.root.title("Authentification")  # Définit le titre de la fenêtre
        self.root.geometry("500x600")  # Définit les dimensions de la fenêtre
        self.root.resizable(False, False)  # Désactive la possibilité de redimensionner la fenêtre
        
        # Initialisation de l'ID utilisateur (par défaut None)
        self.user_id = None
        self.scan_id_map = {}

        # Crée les widgets pour l'interface utilisateur
        self.create_widgets()
        
    def create_widgets(self):
        """Crée tous les widgets de l'interface utilisateur"""
        # Image de fond
        try:
            bg_image = Image.open("Harvester/image2.png").resize((500, 600))  # Charge et redimensionne l'image de fond
            self.bg_photo = ImageTk.PhotoImage(bg_image)  # Convertit l'image en un format compatible avec Tkinter
            canvas = tk.Canvas(self.root, width=500, height=600)  # Crée un canvas pour afficher l'image
            canvas.create_image(0, 0, image=self.bg_photo, anchor="nw")  # Affiche l'image de fond
            canvas.pack()  # Place le canvas dans la fenêtre
        except FileNotFoundError:
            messagebox.showerror("Erreur", "L'image de fond est introuvable.")  # Affiche un message d'erreur si l'image est introuvable
            self.root.destroy()  # Ferme l'application en cas d'erreur

        # Ajout du logo
        try:
            logo_image = Image.open("Harvester/image2.png").resize((100, 100))  # Charge et redimensionne l'image du logo
            self.logo_photo = ImageTk.PhotoImage(logo_image)  # Convertit l'image du logo en format compatible Tkinter
            logo_label = tk.Label(self.root, image=self.logo_photo, bg="#000000")  # Crée un label pour afficher le logo
            logo_label.place(relx=0.5, rely=0.2, anchor="center")  # Positionne le logo en haut de la fenêtre
        except FileNotFoundError:
            messagebox.showerror("Erreur", "Le logo est introuvable.")  # Affiche un message d'erreur si le logo est introuvable
            self.root.destroy()  # Ferme l'application en cas d'erreur

        # Création d'un cadre pour le formulaire d'authentification
        frame = tk.Frame(self.root, padx=30, pady=25, bg="#000000", bd=2, relief="groove")
        frame.place(relx=0.5, rely=0.5, anchor="center", width=400, height=300)  # Positionne le cadre au centre

        # Titre du formulaire
        tk.Label(
            frame,
            text="Se Connecter",  # Texte du titre
            font=("Arial", 16, "bold"),  # Police du titre
            bg="#000000",  # Couleur de fond
            fg="#ffffff"  # Couleur du texte
        ).grid(row=0, column=0, columnspan=2, pady=10)

        # Champ pour le nom d'utilisateur
        tk.Label(frame, text="Nom d'utilisateur", font=("Arial", 12), bg="#000000", fg="white").grid(row=1, column=0, sticky="w", pady=5)
        self.entry_username = tk.Entry(frame, font=("Arial", 12), width=30)  # Zone de saisie du nom d'utilisateur
        self.entry_username.grid(row=2, column=0, pady=5)

        # Champ pour le mot de passe
        tk.Label(frame, text="Mot de passe", font=("Arial", 12), bg="#000000", fg="white").grid(row=3, column=0, sticky="w", pady=5)
        self.entry_password = tk.Entry(frame, show="*", font=("Arial", 12), width=30)  # Zone de saisie du mot de passe (masqué)
        self.entry_password.grid(row=4, column=0, pady=5)

        # Bouton pour se connecter
        btn_login = tk.Button(frame, text="Se connecter", command=self.login, bg="#a41010", fg="white", font=("Arial", 14), width=20)
        btn_login.grid(row=5, column=0, pady=10)

        # Case à cocher pour le consentement
        self.consent_var = tk.BooleanVar(value=True)  # La case est censée être cochée par défaut
        consent_checkbox = tk.Checkbutton(
           frame,
           text="J'accepte que mes informations soient conservées pendant 30 jours",
           font=("Arial", 10),
           bg="#000000",
           fg="white",
           selectcolor="#222222",
           variable=self.consent_var,
           onvalue=True,
           offvalue=False
        )
        consent_checkbox.grid(row=6, column=0, pady=15, sticky="w")
        self.root.after(100, lambda: consent_checkbox.select())

        

        # Lien vers les règles RGPD
        link_label = tk.Label(self.root, text="Lire les règles RGPD", font=("Arial", 10, "underline"), fg="#a41010", bg="#000000", cursor="hand2")
        link_label.place(relx=0.5, rely=0.85, anchor="center")  # Lien centré
        link_label.bind("<Button-1>", lambda e: self.network.open_rgpd())  # Ouvre les règles RGPD dans le navigateur lors du clic

        # Footer de l'application
        footer = tk.Label(self.root, text="© 2025 Seahawks Monitoring", font=("Arial", 10), bg="#000000", fg="#a41010")
        footer.place(relx=0.5, rely=0.95, anchor="center")  # Texte de bas de page centré
        
    def login(self):
        """Effectue l'authentification de l'utilisateur"""
        username = self.entry_username.get().strip()  # Récupère le nom d'utilisateur
        password = self.entry_password.get().strip()  # Récupère le mot de passe
        save_info = self.consent_var.get()  # Récupère l'état de la case à cocher pour le consentement

        # Vérification si les champs sont vides
        if not username or not password:
            messagebox.showwarning("Champs vides", "Veuillez remplir tous les champs.")
            return

        # Vérification du consentement RGPD
        if not save_info:
            messagebox.showwarning("Consentement requis", "Vous devez accepter les règles RGPD pour vous connecter.")
            return

        try:
            # Tentative d'authentification
            user_id, role = self.database.authenticate_user(username, password)  # Récupère l'ID utilisateur et le rôle
        except Exception as e:
            messagebox.showerror("Erreur", f"Erreur lors de l'authentification : {e}")
            return

        # Vérification du rôle de l'utilisateur
        if role == 'client':
            authenticated_user_id = user_id  # Stocke l'ID utilisateur pour l'utiliser dans le dashboard
            self.user_id = authenticated_user_id  # Ajoute l'ID utilisateur à l'instance

            # Logiciel de consentement (si activé)
            if save_info:
                messagebox.showinfo("Consentement", "Vos informations seront sauvegardées pendant 30 jours.")
            else:
                messagebox.showinfo("Consentement", "Vos informations ne seront pas sauvegardées.")

            messagebox.showinfo("Succès", "Authentification réussie.")  # Affiche un message de succès
            
            # Ferme la fenêtre de login et ouvre le tableau de bord
            self.root.destroy()
              # Ouvre le tableau de bord avec le nom d'utilisateur
            self.dashboard(username, user_id) 
        elif role is None:
            messagebox.showerror("Erreur", "Nom d'utilisateur ou mot de passe incorrect.")

        elif role != 'client':
            messagebox.showerror("Accès refusé", "Seuls les clients peuvent se connecter.")

    def dashboard(self, username, user_id):
       """Affiche le tableau de bord après une authentification réussie"""
    
       # Création d'une nouvelle fenêtre Tkinter pour le tableau de bord
       self.dash = tk.Tk()  # Création de la fenêtre principale du tableau de bord
       self.dash.title("harvestar Réseau")  # Titre de la fenêtre
       self.dash.geometry("1000x700")  # Dimensions de la fenêtre du tableau de bord
       self.dash.resizable(False, False)  # Désactivation du redimensionnement de la fenêtre
       # Création d'une instance de NetworkScanner pour effectuer des scans réseau
       self.dash.network_scanner = NetworkScanner() 
       # ✅ Met à jour la référence principale
       self.root = self.dash  

       self.username = username  # Stocke le nom d'utilisateur
       self.user_id = user_id  # Stocke l'ID utilisateur

       # Définition de l'icône de l'application dans le tableau de bord
       self.dash.iconphoto(False, tk.PhotoImage(file="Harvester/icon.png"))
       # Création de l'arrière-plan (vous devez définir la méthode `create_background` pour cela)
       self.create_background()
       # Appel de la méthode pour afficher les résultats du scan du réseau
       self.dash_scan()  # Cette méthode devra afficher le scan réseau dans le tableau de bord
       # Lancement de la boucle principale de l'application Tkinter
       self.dash.mainloop()  # Démarre l'interface graphique du tableau de bord et attend les interactions
       
       
    def create_background(self):
        """Crée un fond avec une image sur le Canvas"""
    
        # Création du Canvas où l'image de fond sera affichée
        self.canvas = tk.Canvas(self.dash, width=1000, height=700)  # Crée un canvas avec les dimensions de la fenêtre du tableau de bord
        self.canvas.pack(fill="both", expand=True)  # Pack le Canvas et l'étend pour remplir tout l'espace disponible
    
        try:
          # Charger l'image de fond à partir du fichier spécifié
          self.bg_image = Image.open("Harvester/image2.png")  # Charge l'image à partir du chemin spécifié
          self.bg_image = self.bg_image.resize((1000, 700), Image.Resampling.LANCZOS)  # Redimensionne l'image pour s'ajuster à la fenêtre du tableau de bord
          self.bg_photo = ImageTk.PhotoImage(self.bg_image)  # Convertit l'image en un format compatible avec Tkinter
       
          # Afficher l'image sur le Canvas en utilisant la position (0,0) pour le coin supérieur gauche
          self.canvas.create_image(0, 0, image=self.bg_photo, anchor="nw")  # Place l'image dans le coin supérieur gauche du Canvas
        except FileNotFoundError:
          # Si l'image n'est pas trouvée, afficher une erreur et fermer l'application
          messagebox.showerror("Erreur", "L'image de fond est introuvable.")
          self.dash.destroy()

    def dash_scan(self):
     """Créer les widgets de l'application."""
     self.progress = ttk.Progressbar(self.dash, orient="horizontal", length=400, mode="determinate")
     self.canvas.create_window(500, 550, window=self.progress)  # Positionner la barre de progression sur le canvas
    
     # Titre principal de l'application
     title_label = tk.Label(
        text="Analyseur Réseau",
        font=("Helvetica", 24, "bold"),  # Police et taille du titre
        fg="#005a9e",  # Couleur bleue pour attirer l'attention
        bg="#000000"  # Fond noir
     )
     self.canvas.create_window(500, 50, window=title_label)  # Positionner le label sur le canvas à (500, 50)
    
     # Cadre pour les champs de saisie (adresse IP et plage)
     input_frame = tk.Frame(self.dash, bg="#000000")  # Cadre noir pour un alignement propre
     self.canvas.create_window(500, 150, window=input_frame)  # Positionner le cadre sur le canvas à (500, 150)
    
     # Champ de saisie pour l'adresse IP
     ip_label = tk.Label(
        input_frame,
        text="Adresse IP :",  # Texte du label pour l'adresse IP
        font=("Helvetica", 14),  # Police et taille du texte
        fg="white",  # Texte en blanc
        bg="#000000"  # Fond noir
     )
     ip_label.grid(row=0, column=0, padx=5, pady=5)  # Positionner le label dans le cadre
     self.ip_entry = tk.Entry(input_frame, font=("Helvetica", 14), width=15)  # Champ de saisie pour l'adresse IP
     self.ip_entry.grid(row=0, column=1, padx=5, pady=5)  # Positionner le champ de saisie dans le cadre
    
     # Champ de saisie pour la plage CIDR
     range_label = tk.Label(
        input_frame,
        text="Plage (CIDR) :",  # Texte du label pour la plage CIDR
        font=("Helvetica", 14),
        fg="white",
        bg="#000000"
     )
     range_label.grid(row=0, column=2, padx=5, pady=5)  # Positionner le label dans le cadre
     self.range_entry = tk.Entry(input_frame, font=("Helvetica", 14), width=10)  # Champ de saisie pour la plage CIDR
     self.range_entry.grid(row=0, column=3, padx=5, pady=5)  # Positionner le champ de saisie dans le cadre

     # Bouton pour démarrer le scan réseau
     scan_button = tk.Button(
        text="Démarrer le Scan Réseau",
        font=("Helvetica", 14, "bold"),  # Texte du bouton avec police en gras
        bg="#004aad",  # Couleur de fond du bouton
        fg="white",  # Couleur du texte du bouton
        activebackground="#000000",  # Couleur de fond lorsque le bouton est actif
        activeforeground="white",  # Couleur du texte lorsque le bouton est actif
        relief="solid",  # Style du bouton
        bd=2,  # Bordure du bouton
        width=20,  # Largeur du bouton
        height=2,  # Hauteur du bouton
        command=lambda: self.start_scan_with_input(self.user_id)  # Action à effectuer lors du clic
     )
     self.canvas.create_window(500, 250, window=scan_button)  # Positionner le bouton sur le canvas à (500, 250)

     # Bouton pour afficher les latences WAN
     latency_button = tk.Button(
        text="Afficher les Temps de Latence WAN",
        font=("Helvetica", 14, "bold"),
        bg="#004aad",
        fg="white",
        activebackground="#000000",
        activeforeground="white",
        relief="solid",
        bd=2,
        width=28,
        height=2,
        command=self.display_latencies  # Action à effectuer lors du clic
     )
     self.canvas.create_window(500, 350, window=latency_button)  # Positionner le bouton sur le canvas à (500, 350)

     # Bouton pour accéder aux anciens scans
     history_button = tk.Button(
         self.dash,
        text="Accéder aux Anciens Scans",
        font=("Helvetica", 14, "bold"),
        bg="#004aad",
        fg="white",
        activebackground="#000000",
        activeforeground="white",
        relief="solid",
        bd=2,
        width=25,
        height=2,
        command=self.view_previous_scans  # Action à effectuer lors du clic
     )
     self.canvas.create_window(500, 450, window=history_button)  # Positionner le bouton sur le canvas à (500, 450)

    def save_scan_to_db(self, nm, user_id):
     """
     Enregistre les résultats du scan dans la base de données.
     Les informations sont insérées dans les tables scan_result, port et vulnerability.
     """
     # Connexion à la base de données SQLite
     conn = sqlite3.connect(self.db_path)
     cursor = conn.cursor()

     # Parcours de chaque hôte trouvé dans le scan
     for host in nm.all_hosts():
        # Récupérer le nom d'hôte (ou "Inconnu" si non disponible)
        hostname = nm[host].hostname() or "Inconnu"
        
        # Récupérer l'état de l'hôte (ex : "up" ou "down")
        state = nm[host]['status']['state'] if 'status' in nm[host] else "Inconnu"
        
        # Récupérer le fournisseur de l'hôte (vendor) pour déterminer s'il est virtuel
        vendor = nm[host].get("vendor", {})
        is_vm = any(vm_keyword in vendor.values() for vm_keyword in ["VMware", "VirtualBox", "QEMU"])
        
        # Déterminer le type de machine (Virtuelle ou Physique)
        machine_type = "Virtuelle" if is_vm else "Physique"
        
        # Extraire les informations sur le système d'exploitation de l'hôte
        os_match = self.extract_os_info(nm[host])
        
        # Extraire les ports ouverts et les vulnérabilités de l'hôte
        open_ports, vulnerabilities = self.extract_ports_and_vulnerabilities(nm[host])
        
        # Mesurer la latence WAN pour cet hôte
        wan_latency = self.network_scanner.get_wan_ping_latency(host)
        
        # Convertir la latence en nombre (exemple : "15 ms" -> 15.0)
        try:
            latency_value = float(wan_latency.replace(" ms", "")) if wan_latency != "Inconnu" else None
        except Exception:
            latency_value = None  # Si la conversion échoue, la latence est définie à None

        # Insertion des résultats du scan dans la table scan_result
        cursor.execute("""
            INSERT INTO scan_result (user_id, hostname, state, machine_type, os, wan_latency)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (user_id, hostname, state, machine_type, os_match, latency_value))
        
        # Récupérer l'ID du scan récemment inséré (utile pour lier d'autres données)
        scan_id = cursor.lastrowid  

        # Enregistrement des ports ouverts associés au scan dans la table "port"
        if open_ports:
            ports_list = open_ports.split("; ")  # Séparer les ports ouverts par un séparateur "; "
            for port in ports_list:
                if port.strip():  # Ignorer les entrées vides
                    cursor.execute("""
                        INSERT INTO port (scan_id, port_info)
                        VALUES (?, ?)
                    """, (scan_id, port.strip()))  # Enregistrer chaque port associé à l'ID du scan

        # Enregistrement des vulnérabilités associées au scan dans la table "vulnerability"
        if vulnerabilities:
            vuln_list = vulnerabilities.split("; ")  # Séparer les vulnérabilités par un séparateur "; "
            for vuln in vuln_list:
                if vuln.strip():  # Ignorer les entrées vides
                    cursor.execute("""
                        INSERT INTO vulnerability (scan_id, vulnerability_info)
                        VALUES (?, ?)
                    """, (scan_id, vuln.strip()))  # Enregistrer chaque vulnérabilité associée à l'ID du scan

     # Valider les changements (commit) dans la base de données
     conn.commit()
     # Fermer la connexion à la base de données
     conn.close()

    
    def start_scan_with_input(self, user_id):
     """Démarre le scan réseau avec les entrées de l'utilisateur."""
    
     # Récupération de l'adresse IP et de la plage CIDR saisies par l'utilisateur
     ip = self.ip_entry.get().strip()  # Obtenir l'adresse IP entrée
     cidr = self.range_entry.get().strip()  # Obtenir la plage CIDR entrée
    
     # Vérifier si l'adresse IP et la plage CIDR ont été saisies
     if not ip or not cidr:
        messagebox.showerror("Erreur", "Veuillez saisir une adresse IP et une plage valide.")
        return  # Quitte la fonction si les entrées sont invalides
    
     # Vérifier si l'ID utilisateur est valide (présent)
     if not user_id:
        messagebox.showerror("Erreur", "L'ID utilisateur est manquant. Impossible de sauvegarder le scan.")
        return  # Quitte la fonction si l'ID utilisateur est manquant
    
     # Créer la cible pour le scan (format "IP/plage")
     target = f"{ip}/{cidr}"
    
     try:
        # Afficher un message d'information indiquant que le scan va commencer
        messagebox.showinfo("Info", f"Lancement du scan sur : {target}")
        
        # Lancer le scan réseau en utilisant la méthode scan() de l'objet network_scanner
        nm = self.network_scanner.scan(target)
        
        # Vérifier si des résultats ont été obtenus pour le scan
        if nm:
            self.display_results(nm)  # Afficher les résultats du scan dans l'interface
            self.save_scan_to_db(nm, user_id)  # Enregistrer les résultats du scan dans la base de données
        else:
            messagebox.showerror("Erreur", "Aucun résultat pour le scan.")  # Afficher une erreur si aucun résultat n'est retourné
     except Exception as e:
        # Si une erreur survient, afficher un message d'erreur avec l'exception
        messagebox.showerror("Erreur", f"Une erreur est survenue : {e}")

    
    def start_scan(self, user_id):
     """Démarre le scan réseau."""
    
     # Vérifier si l'ID utilisateur est fourni
     if not user_id:
        # Si l'ID utilisateur est manquant, afficher un message d'erreur et arrêter la fonction
        messagebox.showerror("Erreur", "L'ID utilisateur est manquant. Impossible de sauvegarder le scan.")
        return  # Quitte la fonction si l'ID utilisateur n'est pas présent
    
     # Lancer le scan réseau sans paramètres supplémentaires
     nm = self.network_scanner.scan()
    
     # Vérifier si des résultats ont été obtenus après le scan
     if nm:
        # Si des résultats sont trouvés, afficher les résultats à l'utilisateur
        self.display_results(nm)
        
        # Sauvegarder les résultats du scan dans la base de données pour l'utilisateur
        self.save_scan_to_db(nm, user_id)  # Enregistrer les résultats dans la base de données
     else:
        # Si aucun résultat n'est trouvé ou si un problème survient pendant le scan, afficher un message d'erreur
        messagebox.showerror("Erreur", "Aucune machine détectée ou problème de scan.")

    
    
    def display_latencies(self):
     """Affiche les temps de latence WAN dans une nouvelle fenêtre."""
    
     # Lancer un scan réseau pour récupérer les hôtes détectés
     nm = self.network_scanner.scan()
    
     # Vérifier si aucun hôte n'a été détecté (aucun scan effectué)
     if not nm.all_hosts():
        # Si aucun hôte n'est trouvé, afficher un message d'information et arrêter la fonction
        messagebox.showinfo("Information", "Aucun scan n'a été effectué. Veuillez d'abord lancer un scan.")
        return  # Quitte la fonction si aucun hôte n'est détecté
    
     # Créer une nouvelle fenêtre pour afficher les latences WAN
     latency_window = tk.Toplevel(self.dash)  # Création d'une fenêtre secondaire (Toplevel)
     latency_window.title("Temps de Latence WAN")  # Définir le titre de la fenêtre
     latency_window.geometry("600x400")  # Définir les dimensions de la fenêtre
     latency_window.configure(bg="#202124")  # Définir la couleur de fond de la fenêtre
     latency_window.iconphoto(False, tk.PhotoImage(file="Harvester/icon.png"))  # Ajouter une icône à la fenêtre

     # Ajouter un label en haut de la fenêtre pour indiquer le titre
     tk.Label(
        latency_window,
        text="Temps de Latence WAN",
        font=("Helvetica", 18, "bold"),
        fg="white",  # Texte en blanc
        bg="#202124"  # Fond de label en couleur sombre pour correspondre au thème
     ).pack(pady=10)  # Ajouter un peu d'espace autour du label (pady=10)

     # Créer une liste (Listbox) pour afficher les latences des hôtes
     latency_listbox = tk.Listbox(
        latency_window,
        height=20,  # Hauteur de la liste (20 lignes visibles)
        width=80,   # Largeur de la liste
        font=("Helvetica", 12),  # Police et taille de texte
        bg="#2f2f2f",  # Fond sombre pour la liste
        fg="white"  # Texte en blanc pour une meilleure lisibilité
     )
     latency_listbox.pack(pady=10)  # Ajouter la liste à la fenêtre et un peu d'espace autour
    
     # Boucler à travers chaque hôte détecté et récupérer sa latence WAN
     for host in nm.all_hosts():
        # Utiliser la méthode get_wan_ping_latency pour obtenir la latence WAN de l'hôte
        latency = self.network_scanner.get_wan_ping_latency(host)
        
        # Ajouter une entrée dans la liste pour chaque hôte avec sa latence
        latency_listbox.insert(tk.END, f"Hôte: {host}, Latence WAN: {latency}")
    
     # Ajouter un bouton pour fermer la fenêtre de latences
     close_button = tk.Button(
        latency_window,
        text="Fermer",  # Texte du bouton
        font=("Helvetica", 12, "bold"),
        bg="#ff0000",  # Fond rouge pour attirer l'attention
        fg="white",  # Texte en blanc pour contraster avec le fond
        command=latency_window.destroy  # Fermer la fenêtre lorsque le bouton est cliqué
     )
     close_button.pack(pady=10)  # Ajouter le bouton et un peu d'espace autour

    
    def view_previous_scans(self):
     """Affiche les scans enregistrés dans la base de données SQLAlchemy."""
    
     # Récupérer tous les résultats de scan, triés par la date la plus récente
     scans = ScanResult.query.order_by(ScanResult.timestamp.desc()).all()
    
     # Vérifier si aucun scan n'est enregistré dans la base de données
     if not scans:
        messagebox.showinfo("Information", "Aucun scan enregistré.")  # Afficher un message si aucun scan
        return  # Quitter la fonction si aucun scan n'est trouvé

     # Créer une nouvelle fenêtre pour afficher les anciens scans
     history_window = tk.Toplevel(self.dash)  # Création d'une fenêtre secondaire (Toplevel)
     history_window.title("Anciens Scans")  # Définir le titre de la fenêtre
     history_window.geometry("600x400")  # Définir les dimensions de la fenêtre
     history_window.configure(bg="#202124")  # Définir la couleur de fond de la fenêtre

     # Créer une Listbox pour afficher les scans enregistrés
     scan_listbox = tk.Listbox(
        history_window,
        height=10,  # Hauteur de la liste
        width=80,   # Largeur de la liste
        font=("Helvetica", 12),  # Police et taille du texte
        bg="#2f2f2f",  # Fond sombre de la liste
        fg="white"  # Texte en blanc pour une meilleure lisibilité
     )
     scan_listbox.pack(pady=10)  # Ajouter la liste à la fenêtre avec un peu d'espace autour (pady=10)
    
     # Créer un dictionnaire pour associer les index de la liste aux IDs des scans dans la base de données
     scan_id_map = {}  # Mapping de l'index de la Listbox à l'ID du scan dans la base de données
    
     # Boucler à travers tous les scans récupérés de la base de données
     for index, scan in enumerate(scans):
        # Ajouter chaque scan à la Listbox avec son horodatage et le nom de l'hôte
        scan_listbox.insert(tk.END, f"{scan.timestamp} - {scan.hostname}")
        
        # Sauvegarder l'ID du scan dans le dictionnaire pour référence future
        scan_id_map[index] = scan.id  # L'index de la Listbox est mappé à l'ID du scan dans la base de données


     def show_selected_scan():
        selected_index = scan_listbox.curselection()
        if not selected_index:
            messagebox.showwarning("Avertissement", "Veuillez sélectionner un scan.")
            return
        scan_id = scan_id_map[selected_index[0]]
        self.show_scan_details(scan_id)

     details_button = tk.Button(
        history_window,
        text="Afficher les détails",
        font=("Helvetica", 12, "bold"),
        bg="#0078d4",
        fg="white",
        command=show_selected_scan
     )
     details_button.pack(pady=10)
    
    
    def display_results(self, nm):
     """Affiche les résultats du scan dans une nouvelle fenêtre."""

     # Créer une nouvelle fenêtre pour afficher les résultats du scan
     results_window = tk.Toplevel(self.dash)  # Crée une fenêtre secondaire
     results_window.title("Résultats du scan réseau")  # Définir le titre de la fenêtre
     results_window.geometry("1000x600")  # Définir la taille de la fenêtre
     results_window.configure(bg="#202124")  # Définir la couleur de fond sombre pour la fenêtre
     results_window.iconphoto(False, tk.PhotoImage(file="Harvester/icon.png"))  # Ajouter une icône à la fenêtre
 
     # Ajouter un label en haut de la fenêtre pour indiquer l'objectif (Machines détectées)
     tk.Label(
        results_window,
        text="Machines détectées",
        font=("Helvetica", 18, "bold"),
        fg="white",  # Couleur du texte
        bg="#202124"  # Couleur de fond en accord avec le thème
     ).pack(pady=10)  # Ajouter le label avec un peu d'espace autour (pady=10)

     # Définir les colonnes pour le tableau des résultats
     columns = ("IP", "Nom", "État", "Type", "OS", "Ports", "Vulnérabilités", "Latence WAN")
    
     # Créer un widget Treeview pour afficher les résultats sous forme de tableau
     tree = ttk.Treeview(
        results_window,
        columns=columns,  # Colonnes du tableau
        show="headings",  # Ne montre que les en-têtes des colonnes
        height=20  # Nombre de lignes visibles
     )

     # Configuration de chaque colonne dans le tableau
     tree.column("IP", width=150, anchor="center")
     tree.column("Nom", width=150, anchor="center")
     tree.column("État", width=100, anchor="center")
     tree.column("Type", width=150, anchor="center")
     tree.column("OS", width=300, anchor="center")
     tree.column("Ports", width=300, anchor="w")
     tree.column("Vulnérabilités", width=300, anchor="w")
     tree.column("Latence WAN", width=150, anchor="center")

     # Ajouter les titres des colonnes dans le tableau
     for col in columns:
        tree.heading(col, text=col)

     # Parcourir tous les hôtes détectés dans le scan
     for host in nm.all_hosts():
        # Récupérer le nom de l'hôte (si disponible)
        hostname = nm[host].hostname() or "Inconnu"

        # Récupérer l'état de l'hôte (en ligne ou hors ligne)
        host_state = nm[host]['status']['state'] if 'status' in nm[host] else "inconnu"

        # Déterminer si l'hôte est une machine virtuelle ou physique
        vendor = nm[host].get("vendor", {})
        is_vm = any(vm_keyword in vendor.values() for vm_keyword in ["VMware", "VirtualBox", "QEMU"])
        machine_type = "Virtuelle" if is_vm else "Physique"

        # Extraire les informations sur le système d'exploitation
        os_match = self.extract_os_info(nm[host])

        # Extraire les ports ouverts et les vulnérabilités détectées
        open_ports, vulnerabilities = self.extract_ports_and_vulnerabilities(nm[host])
        
        # Affichage des vulnérabilités pour débogage
        print(f"Vulnérabilités pour l'hôte {host}: {vulnerabilities}")

        # Récupérer la latence WAN pour l'hôte
        wan_latency = self.network_scanner.get_wan_ping_latency(host)

        # Insérer les données dans le tableau (Treeview)
        tree.insert("", "end", values=(
            host, hostname, host_state, machine_type,
            os_match, open_ports, vulnerabilities, wan_latency
        ))

     # Afficher le tableau dans la fenêtre
     tree.pack(fill="both", expand=True, pady=20)

     # Ajouter un bouton pour afficher les détails d'un scan sélectionné
     details_button = tk.Button(
        results_window,
        text="Afficher les détails",  # Texte du bouton
        font=("Helvetica", 12, "bold"),
        bg="#0078d4",  # Couleur de fond du bouton
        fg="white",  # Couleur du texte du bouton
        command=lambda: self.show_selected_details(tree, nm)  # Fonction appelée au clic
     )
     details_button.pack(pady=10)  # Ajouter un peu d'espace autour du bouton (pady=10)


    def extract_os_info(self, host_data):
     """Extraire les informations sur le système d'exploitation."""
    
     # Vérifier si le champ 'osmatch' existe dans les données de l'hôte
     if 'osmatch' in host_data:
        os_matches = host_data['osmatch']  # Récupérer les correspondances du système d'exploitation
        if os_matches:
            # Si des correspondances sont trouvées, retourner le nom du système d'exploitation et sa précision
            return f"{os_matches[0]['name']} (Précision : {os_matches[0]['accuracy']}%)"
    
     # Si aucune information sur l'OS n'est trouvée, retourner "Inconnu"
     return "Inconnu"


    def extract_ports_and_vulnerabilities(self, host_data):
     """Extraire les informations sur les ports ouverts et les vulnérabilités potentielles."""
    
     # Initialisation des listes pour stocker les détails des ports et des vulnérabilités
     port_details = []
     vulnerabilities = []

     # Parcours de chaque protocole trouvé sur l'hôte
     for protocol in host_data.all_protocols():
        # Tri des ports par ordre croissant
        for port in sorted(host_data[protocol].keys()):
            port_info = host_data[protocol][port]  # Détails du port
            # Extraction des informations disponibles sur le port
            service_name = port_info.get('name', 'Inconnu')
            version = port_info.get('version', 'Inconnue')
            product = port_info.get('product', 'N/A')
            port_state = port_info.get('state', 'Inconnu')

            # Création d'une chaîne décrivant le port
            port_details.append(f"Port {port}/{protocol}: {service_name} (Version: {version}, Produit: {product}, État: {port_state})")

            # Debugging pour afficher les services et leurs versions
            print(f"Service: {service_name}, Version: {version}, Produit: {product}, Port: {port}/{protocol}")

            # Vérification des vulnérabilités potentielles en fonction des services
            if 'OpenSSH' in service_name and ('8' in version or version == 'Inconnue'):
                vulnerabilities.append(f"OpenSSH version {version} vulnérable à CVE-XXXX-YYYY")
            elif 'Apache' in service_name and '2.4.49' in version:
                vulnerabilities.append(f"Apache version {version} vulnérable à CVE-XXXX-YYYY")
            elif 'VMware' in service_name:  # Cas spécifique pour VMware
                vulnerabilities.append(f"Service VMware Authentication Daemon vulnérable à CVE-XXXX-ZZZZ")
            elif 'netbios' in service_name.lower():  # Cas pour Netbios
                vulnerabilities.append(f"Service NetBIOS potentiel problème de sécurité")

     # Affichage des vulnérabilités détectées pour l'hôte (utilisé pour le débogage)
     print(f"Vulnérabilités détectées: {vulnerabilities}")

     # Retourner les détails des ports et les vulnérabilités trouvées, ou des messages par défaut
     return "; ".join(port_details) if port_details else "Aucun port détecté", "; ".join(vulnerabilities) if vulnerabilities else "Aucune vulnérabilité détectée"

   
    def show_selected_details(self, tree, nm):
     """Affiche les détails de la machine sélectionnée."""

     # Récupérer l'élément sélectionné dans le tableau
     selected_item = tree.selection()
     if not selected_item:
        messagebox.showwarning("Avertissement", "Veuillez sélectionner une machine.")
        return  # Si aucune machine n'est sélectionnée, afficher un avertissement et sortir de la fonction.

     # Récupérer l'adresse IP de l'hôte sélectionné dans le tableau
     host = tree.item(selected_item, "values")[0]
     host_data = nm[host]  # Récupérer les données du scan pour l'hôte sélectionné

     # Création d'une nouvelle fenêtre pour afficher les détails de l'hôte sélectionné
     details_window = tk.Toplevel(self.dash)
     details_window.title(f"Détails de la machine : {host}")
     details_window.geometry("800x600")  # Taille de la fenêtre
     details_window.configure(bg="#202124")  # Fond de la fenêtre
     details_window.iconphoto(False, tk.PhotoImage(file="Harvester/icon.png"))  # Icône de la fenêtre

     # Cadre pour les informations principales de la machine
     frame = tk.Frame(details_window, bg="#202124")
     frame.pack(pady=20)  # Ajouter le cadre avec des marges en haut et en bas

     # Affichage du titre principal avec le nom de l'hôte
     tk.Label(
        frame,
        text=f"Détails pour : {host}",
        font=("Helvetica", 16, "bold"),
        fg="white",
        bg="#202124"
     ).grid(row=0, column=0, pady=10)

     # Extraction des informations détaillées pour l'hôte
     hostname = host_data.hostname() or "Inconnu"  # Nom d'hôte ou "Inconnu" s'il n'est pas trouvé
     state = host_data['status']['state'] if 'status' in host_data else "inconnu"  # État de l'hôte
     os_info = self.extract_os_info(host_data)  # Informations sur le système d'exploitation
     open_ports, vulnerabilities = self.extract_ports_and_vulnerabilities(host_data)  # Détails des ports et vulnérabilités

     # Préparer les informations sous forme de texte à afficher dans le label
     details_text = f"""
Nom : {hostname}
État : {state.capitalize()}
OS : {os_info}
Vulnérabilités : {vulnerabilities}
"""
     # Affichage des informations détaillées dans un label
     tk.Label(
        frame,
        text=details_text,
        font=("Helvetica", 12),
        bg="#202124",
        fg="white",
        justify="left",
        anchor="nw"  # Alignement du texte en haut à gauche
     ).grid(row=1, column=0, pady=10, padx=10, sticky="w")

     # Titre pour la section des ports ouverts
     tk.Label(
        frame,
        text="Détails des Ports Ouverts:",
        font=("Helvetica", 14, "bold"),
        fg="white",
        bg="#202124"
     ).grid(row=2, column=0, pady=10, padx=10, sticky="w")

     # Liste déroulante (Listbox) pour afficher les ports ouverts
     ports_listbox = tk.Listbox(
        frame,
        height=10,  # Hauteur de la liste
        width=80,  # Largeur de la liste
        font=("Helvetica", 12),
        bg="#2f2f2f",  # Couleur de fond de la liste
        fg="white",  # Couleur du texte dans la liste
        selectmode=tk.SINGLE  # Permet la sélection d'un seul élément
     )
     ports_listbox.grid(row=3, column=0, pady=10, padx=10, sticky="w")  # Ajouter la liste dans le cadre

     # Ajouter chaque détail de port dans la listbox
     for port_detail in open_ports.split("; "):
        ports_listbox.insert(tk.END, port_detail)  # Insérer chaque détail de port dans la listbox

     # Ajout d'une barre de défilement verticale pour la listbox
     scrollbar = tk.Scrollbar(frame, orient=tk.VERTICAL, command=ports_listbox.yview)
     scrollbar.grid(row=3, column=1, sticky="ns")  # Placer la barre de défilement à côté de la liste
     ports_listbox.config(yscrollcommand=scrollbar.set)  # Lier la listbox à la scrollbar

     # Bouton pour fermer la fenêtre des détails
     close_button = tk.Button(
        details_window,
        text="Fermer",
        font=("Helvetica", 12, "bold"),
        bg="#ff0000",  # Couleur de fond du bouton (rouge)
        fg="white",
        command=details_window.destroy  # Fermer la fenêtre lorsqu'on clique sur ce bouton
     )
     close_button.pack(pady=10)  # Placer le bouton avec une marge verticale

    def show_scan_details(self, scan_id):
     """Affiche les détails d'un scan depuis la base de données SQLAlchemy."""

     # Récupérer le scan correspondant à l'ID fourni depuis la base de données
     scan = ScanResult.query.get(scan_id)

     if not scan:
        messagebox.showerror("Erreur", "Scan introuvable dans la base de données.")
        return  # Si aucun scan n'est trouvé, afficher une erreur et quitter la fonction.

     # Création d'une nouvelle fenêtre pour afficher les détails du scan
     details_window = tk.Toplevel(self.dash)
     details_window.title(f"Détails du scan: {scan.hostname}")  # Titre de la fenêtre avec le nom d'hôte
     details_window.geometry("1000x600")  # Définir la taille de la fenêtre
     details_window.configure(bg="#202124")  # Couleur de fond de la fenêtre
     details_window.iconphoto(False, tk.PhotoImage(file="Harvester/icon.png"))  # Ajouter une icône à la fenêtre

     # Ajouter un label pour afficher la date et l'hôte du scan
     tk.Label(
        details_window,
        text=f"Détails du scan effectué le {scan.timestamp} sur {scan.hostname}",
        font=("Helvetica", 18, "bold"),
        fg="white",
        bg="#202124"
     ).pack(pady=10)  # Le label est placé avec une marge verticale de 10 pixels

     # Création du tableau pour afficher les résultats du scan
     columns = ("Nom", "État", "Type", "OS", "Ports", "Vulnérabilités", "Latence WAN")
     tree = ttk.Treeview(
        details_window,
        columns=columns,
        show="headings",
        height=20  # Définir le nombre de lignes visibles
     )

     # Configuration des colonnes du tableau
     for col in columns:
        tree.heading(col, text=col)  # Définir le titre des colonnes
        tree.column(col, width=150, anchor="center")  # Définir la largeur et l'alignement des colonnes

     # Ajouter les données du scan dans le tableau
     tree.insert("", "end", values=(
        scan.hostname,  # Nom d'hôte du scan
        scan.state,  # État de la machine lors du scan
        scan.machine_type,  # Type de machine (Virtuelle ou Physique)
        scan.os,  # Système d'exploitation détecté
        scan.open_ports,  # Ports ouverts détectés
        scan.vulnerabilities,  # Vulnérabilités détectées
        f"{scan.wan_latency} ms" if scan.wan_latency else "Inconnu"  # Latence WAN, si disponible
     ))

     tree.pack(fill="both", expand=True, pady=20)  # Ajouter le tableau à la fenêtre et permettre à l'interface de s'étendre

    
    def delete_scan(self):
     """Supprime un scan sélectionné depuis la base de données SQLAlchemy."""

     # Récupérer l'index de l'élément sélectionné dans la Listbox
     selected_index = scan_listbox.curselection()
    
     # Si aucun élément n'est sélectionné, afficher un message d'avertissement et retourner
     if not selected_index:
        messagebox.showwarning("Avertissement", "Veuillez sélectionner un scan à supprimer.")
        return

     # Récupérer l'ID du scan correspondant à l'élément sélectionné
     scan_id = scan_id_map[selected_index[0]]  # Récupère l'ID associé à l'index sélectionné

     # Rechercher l'objet scan dans la base de données en utilisant l'ID
     scan = ScanResult.query.get(scan_id)

     # Si aucun scan n'est trouvé, afficher un message d'erreur
     if not scan:
        messagebox.showerror("Erreur", "Scan introuvable dans la base de données.")
        return

     try:
        # Essayer de supprimer le scan de la base de données
        db.session.delete(scan)  # Supprime l'objet de la session
        db.session.commit()  # Applique les modifications en base de données
        messagebox.showinfo("Succès", "Scan supprimé avec succès.")  # Affiche un message de succès

        # Supprime le scan de la Listbox affichée
        scan_listbox.delete(selected_index)  # Retire l'élément de la Listbox de l'interface utilisateur

     except Exception as e:
        # Si une erreur se produit lors de la suppression, annuler les changements
        db.session.rollback()
        # Afficher un message d'erreur avec l'exception capturée
        messagebox.showerror("Erreur", f"Erreur lors de la suppression : {e}")
    
    
   

    def view_previous_scans(self):
        """Affiche uniquement les scans de l'utilisateur connecté."""
        
        if not self.user_id:
            messagebox.showerror("Erreur", "Aucun utilisateur connecté !")
            return  

        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()

        query = """
        SELECT id, hostname, strftime('%Y-%m-%d %H:%M', timestamp) as scan_time
        FROM scan_result
        WHERE user_id = ?  
        ORDER BY timestamp DESC
        """
        cursor.execute(query, (self.user_id,))
        rows = cursor.fetchall()
        conn.close()

        if not rows:
            messagebox.showinfo("Info", "Aucun scan trouvé pour cet utilisateur.")
            return

        grouped_scans = {}
        for row in rows:
            scan_time = row[2]  
            if scan_time not in grouped_scans:
                grouped_scans[scan_time] = []
            grouped_scans[scan_time].append(row)

        history_window = tk.Toplevel(self.dash)  
        history_window.title("Anciens Scans")
        history_window.geometry("600x400")
        history_window.configure(bg="#202124")

        tk.Label(
            history_window, text="Sélectionnez un scan :", 
            font=("Helvetica", 14, "bold"), fg="white", bg="#202124"
        ).pack(pady=10)

        self.scan_listbox = tk.Listbox(
            history_window,
            height=10, width=80,
            font=("Helvetica", 12),
            bg="#2f2f2f", fg="white"
        )
        self.scan_listbox.pack(pady=10)  

        self.scan_id_map = {}  # ✅ Initialisation correcte

        for index, (time, scans) in enumerate(grouped_scans.items()):
            self.scan_listbox.insert(tk.END, f"{time} ({len(scans)} Machines)")  
            self.scan_id_map[index] = scans  # ✅ Associe l'index à la liste des scans  

        detail_button = tk.Button(
            history_window,
            text="Voir Détails",
            font=("Helvetica", 12, "bold"),
            bg="#004aad", fg="white",
            activebackground="#000000",
            activeforeground="white",
            command=self.show_scan_details  
        )
        detail_button.pack(pady=5)

    def show_scan_details(self):
     """Affiche un tableau des machines détectées dans le scan sélectionné."""

     selected_index = self.scan_listbox.curselection()
     if not selected_index:
        messagebox.showwarning("Attention", "Veuillez sélectionner un scan.")
        return

     selected_index = selected_index[0]

     if selected_index not in self.scan_id_map:
        messagebox.showerror("Erreur", "Erreur interne : Scan non trouvé.")
        return

     selected_scans = self.scan_id_map[selected_index]  # ✅ Liste des machines détectées dans ce scan

     # Ouvrir une nouvelle fenêtre pour afficher les machines
     machine_window = tk.Toplevel(self.dash)
     machine_window.title("Machines détectées")
     machine_window.geometry("900x400")  # Augmenter la taille pour afficher plus d'infos
     machine_window.configure(bg="#202124")

     tk.Label(
        machine_window, text="Machines détectées :", 
        font=("Helvetica", 14, "bold"), fg="white", bg="#202124"
     ).pack(pady=10)

     # ✅ Ajout de nouvelles colonnes : Type, OS, Latence
     columns = ("ID", "Hôte", "Type", "OS", "Latence", "Date")
     self.machine_table = ttk.Treeview(machine_window, columns=columns, show="headings", height=10)

     # ✅ Définition des colonnes
     for col in columns:
        self.machine_table.heading(col, text=col)
        self.machine_table.column(col, anchor="center")

     # ✅ Ajout des machines dans le tableau
     self.machine_id_map = {}
     for idx, scan in enumerate(selected_scans):
        machine_id, hostname, scan_time = scan
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        
        # Récupérer type, OS et latence
        cursor.execute("""
            SELECT machine_type, os, wan_latency FROM scan_result WHERE id = ?
        """, (machine_id,))
        machine_info = cursor.fetchone()
        conn.close()

        machine_type = machine_info[0] if machine_info and machine_info[0] else "Inconnu"
        os = machine_info[1] if machine_info and machine_info[1] else "Inconnu"
        latence = f"{machine_info[2]} ms" if machine_info and machine_info[2] else "N/A"

        # Insérer les données avec les nouvelles colonnes
        self.machine_table.insert("", tk.END, values=(machine_id, hostname, machine_type, os, latence, scan_time))
        self.machine_id_map[idx] = scan  # ✅ Associer l'index au scan

     self.machine_table.pack(pady=10, fill=tk.BOTH, expand=True)

    # ✅ Bouton pour afficher les détails
     detail_button = tk.Button(
        machine_window,
        text="Voir Détails",
        font=("Helvetica", 12, "bold"),
        bg="#004aad", fg="white",
        activebackground="#000000",
        activeforeground="white",
        command=self.show_machine_details  
     )
     detail_button.pack(pady=5)

    def show_machine_details(self):
     """Affiche les détails de la machine sélectionnée dans un scan."""

     selected_item = self.machine_table.selection()  # ✅ Récupère l'élément sélectionné
     if not selected_item:
        messagebox.showwarning("Attention", "Veuillez sélectionner une machine.")
        return

     selected_values = self.machine_table.item(selected_item, "values")  # ✅ Récupère les valeurs de la ligne sélectionnée
     if not selected_values:
        messagebox.showerror("Erreur", "Erreur interne : Machine non trouvée.")
        return

     machine_id = selected_values[0]  # ✅ L'ID de la machine est stocké en première colonne

     conn = sqlite3.connect(DB_PATH)
     cursor = conn.cursor()

     # 🔹 Récupérer les détails de la machine
     cursor.execute("""
        SELECT hostname, state, machine_type, os, wan_latency, strftime('%Y-%m-%d %H:%M', timestamp)
        FROM scan_result WHERE id = ?
     """, (machine_id,))
     machine_details = cursor.fetchone()

     if not machine_details:
        conn.close()
        messagebox.showerror("Erreur", "Aucune donnée trouvée pour cette machine.")
        return

     # 🔹 Récupérer les ports ouverts
     cursor.execute("SELECT port_info FROM port WHERE scan_id = ?", (machine_id,))
     ports = [row[0] for row in cursor.fetchall()]

     # 🔹 Récupérer les vulnérabilités
     cursor.execute("SELECT vulnerability_info FROM vulnerability WHERE scan_id = ?", (machine_id,))
     vulnerabilities = [row[0] for row in cursor.fetchall()]

     conn.close()
 
     # ✅ Fenêtre pour afficher les détails
     details_window = tk.Toplevel(self.dash)
     details_window.title(f"Détails de {machine_details[0]}")
     details_window.geometry("700x500")
     details_window.configure(bg="#202124")

     scrollbar = tk.Scrollbar(details_window)
     scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

     details_text = tk.Text(
        details_window, font=("Helvetica", 12), bg="#2f2f2f", fg="white",
        yscrollcommand=scrollbar.set
     )
     details_text.pack(padx=10, pady=10, fill=tk.BOTH, expand=True)
     scrollbar.config(command=details_text.yview)

     # 🔹 Ajouter les détails à la fenêtre
     details_text.insert(tk.END, f"🔹 **Nom d'hôte**: {machine_details[0]}\n")
     details_text.insert(tk.END, f"🔹 **État**: {machine_details[1]}\n")
     details_text.insert(tk.END, f"🔹 **Type de Machine**: {machine_details[2]}\n")
     details_text.insert(tk.END, f"🔹 **OS**: {machine_details[3] if machine_details[3] else 'Inconnu'}\n")
     details_text.insert(tk.END, f"🔹 **Latence WAN**: {machine_details[4] if machine_details[4] else 'N/A'} ms\n")
     details_text.insert(tk.END, f"🔹 **Date du Scan**: {machine_details[5]}\n\n")

     details_text.insert(tk.END, "🚪 **Ports Ouverts:**\n")
     if ports:
        for port in ports:
            details_text.insert(tk.END, f"  - {port}\n")
     else:
        details_text.insert(tk.END, "  Aucun port ouvert détecté.\n")

     details_text.insert(tk.END, "\n⚠️ **Vulnérabilités:**\n")
     if vulnerabilities:
        for vuln in vulnerabilities:
            details_text.insert(tk.END, f"  - {vuln}\n")
     else:
        details_text.insert(tk.END, "  Aucune vulnérabilité détectée.\n")

     details_text.config(state=tk.DISABLED)

# Lancement de l'application
if __name__ == "__main__":
    BASE_DIR = os.path.dirname(os.path.abspath(__file__))
    DB_PATH = os.path.join(BASE_DIR, '../instance/users.db')  # Chemin d'accès à la base de données
    root = tk.Tk()
    app = App(root, DB_PATH)  # Création de l'application
    root.mainloop()  # Lancement de la boucle principale de l'application