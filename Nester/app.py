import os
import sys
from flask import Flask, render_template, redirect, url_for, request, flash, session, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_socketio import SocketIO
from werkzeug.security import check_password_hash, generate_password_hash
from sqlalchemy import extract
from datetime import datetime
from waitress import serve
from flask_migrate import Migrate

# Ajouter le dossier parent dans sys.path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

# Importation des modèles
from models import db, User, ScanResult

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///../instance/users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db.init_app(app)
migrate = Migrate(app, db)  # Ajout de Flask-Migrate pour la gestion des migrations
socketio = SocketIO(app, cors_allowed_origins="*")

# Création des tables si elles n'existent pas
with app.app_context():
    db.create_all()

# ------------------------- ROUTES -------------------------

@app.route('/')
def home():
    if 'user_id' in session:
        user = User.query.get(session['user_id'])
        if user and user.role == 'admin':
            return redirect(url_for('admin_dashboard'))
        return render_template('home.html')
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()

        if user and check_password_hash(user.password_hash, password):
            session['user_id'] = user.id
            flash("Login successful", "success")
            return redirect(url_for('home'))
        else:
            flash("Invalid username or password", "danger")

    return render_template('login.html')

@app.route('/logout', methods=['POST'])
def logout():
    session.clear()
    flash("Vous avez été déconnecté avec succès.", "info")
    return redirect(url_for('login'))

# ------------------- Gestion des utilisateurs -------------------
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        name = request.form.get('name')
        username = request.form.get('username')
        password = request.form.get('password')
        role = request.form.get('role', 'client')  # Par défaut, le rôle est "client"

        # Vérification des champs
        if not username or not password:
            flash("Le nom d'utilisateur et le mot de passe ne peuvent pas être vides.", "danger")
            return redirect(url_for('register'))

        # Vérification de l'existence de l'utilisateur
        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            flash("Le nom d'utilisateur existe déjà. Choisissez-en un autre.", "danger")
            return redirect(url_for('register'))

        hashed_password = generate_password_hash(password)
        new_user = User(name=name, username=username, password_hash=hashed_password, role=role)

        try:
            db.session.add(new_user)
            db.session.commit()
            flash("Inscription réussie.", "success")
            return redirect(url_for('admin_dashboard'))
        except Exception as e:
            db.session.rollback()
            app.logger.error(f"Erreur lors de l'inscription : {e}")
            flash("Une erreur s'est produite lors de l'inscription.", "danger")

    return render_template('register.html')

@app.route('/delete_user/<int:id>', methods=['POST'])
def delete_user(id):
    user = User.query.get_or_404(id)
    if user.id == session.get('user_id'):
        flash("You cannot delete your own account.", "danger")
        return redirect(url_for('admin_dashboard'))

    db.session.delete(user)
    db.session.commit()
    flash("User deleted successfully", "danger")
    return redirect(url_for('admin_dashboard'))

# ------------------- Gestion des scans -------------------
@app.route('/scan/<int:client_id>')
def scan_client(client_id):
    client = User.query.get_or_404(client_id)

    new_scan = ScanResult(
        user_id=client.id,
        hostname="192.168.1.1",
        state="Actif",
        machine_type="Serveur",
        os="Linux Ubuntu 22.04",
        wan_latency=12.5
    )

    db.session.add(new_scan)
    db.session.commit()
    return redirect(url_for('client_profile', id=client.id))

@app.route('/send_notification')
def send_notification():
    dernier_scan = ScanResult.query.order_by(ScanResult.id.desc()).first()
    if not dernier_scan:
        return "Aucun scan trouvé en base de données."

    user = User.query.get(dernier_scan.user_id)
    username = user.username if user else "Utilisateur inconnu"
    message = f"🔔 Un nouveau scan de {username} est reçu !"
    
    socketio.emit('new_scan', {'message': message})
    return message

@app.route('/client_profile/<int:id>')
def client_profile(id):
    client = User.query.get_or_404(id)

    last_scan = ScanResult.query.filter(
        ScanResult.user_id == client.id
    ).order_by(ScanResult.timestamp.desc()).first()

    scans = []
    if last_scan:
        scans = ScanResult.query.filter(
            extract('hour', ScanResult.timestamp) == last_scan.timestamp.hour,
            extract('minute', ScanResult.timestamp) == last_scan.timestamp.minute
        ).all()

    return render_template('client_profile.html', client=client, scans=scans, last_scan=last_scan)

@app.route('/clients')
def clients():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    current_user = User.query.get(session['user_id'])
    if not current_user or current_user.role != 'admin':
        flash("Vous n'êtes pas autorisé à accéder à cette page.", "danger")
        return redirect(url_for('home'))

    users = User.query.filter_by(role='client').all()
    return render_template('clients.html', users=users)

@app.route('/admin_dashboard')
def admin_dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    current_user = User.query.get(session['user_id'])
    if not current_user or current_user.role != 'admin':
        flash("Vous n'êtes pas autorisé à accéder à cette page.", "danger")
        return redirect(url_for('home'))

    users = User.query.filter_by(role='client').all()
    return render_template('admin_dashboard.html', users=users, current_user=current_user)

# ------------------- Exécution du serveur -------------------
if __name__ == '__main__':
    socketio.run(app, host='0.0.0.0', port=5000, debug=True)
