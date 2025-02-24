import os
from flask import Flask, render_template, redirect, url_for, request, flash, session
from flask_sqlalchemy import SQLAlchemy
import sys
from werkzeug.security import check_password_hash
from werkzeug.security import generate_password_hash
from flask import request, jsonify

# Ajoute le dossier parent "prj-finale-réseau" dans sys.path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from models import db, User, ScanResult

from flask_migrate import Migrate

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db.init_app(app)
migrate = Migrate(app, db)

# api = Api(app)

# # Ajouter les ressources à l'API
# api.add_resource(UserResource, '/api/user/<int:user_id>')
# api.add_resource(ScanResultResource, '/api/scan/<int:scan_id>')
# api.add_resource(UserListResource, '/api/users')

# Route d'accueil
@app.route('/')
def home():
    if 'user_id' in session:
        user = User.query.get(session['user_id'])
        if user and user.role == 'admin':
            return redirect(url_for('admin_dashboard'))
        return render_template('home.html')
    return redirect(url_for('login'))

@app.route('/search_by_username')
def search_by_username():
    keyword = request.args.get('username', '').lower()

    if not keyword:
        return jsonify([])  # Retourne une liste vide si aucun mot-clé

    # Recherche des utilisateurs dont le 'username' contient le mot-clé (insensible à la casse)
    users = User.query.filter(User.username.ilike(f'%{keyword}%')).all()

    # Retourner les résultats sous forme de liste JSON
    results = [{'username': user.username, 'id': user.id} for user in users]

    return jsonify(results)  # Retourner les résultats en JSON

# Route de connexion
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

@app.route('/clients')
def clients():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    # Assurez-vous que l'utilisateur connecté est un admin
    current_user = User.query.get(session['user_id'])
    if not current_user or current_user.role != 'admin':
        flash("Vous n'êtes pas autorisé à accéder à cette page.", "danger")
        return redirect(url_for('home'))

    # Récupérer tous les utilisateurs avec le rôle 'client'
    users = User.query.filter_by(role='client').all()

    # Récupérer pour chaque client son dernier résultat de scan
    for user in users:
        last_scan = ScanResult.query.filter_by(user_id=user.id).order_by(ScanResult.timestamp.desc()).first()
        user.last_scan_os = last_scan.os if last_scan else 'Non disponible'

    return render_template('clients.html', users=users)


# Route d'inscription
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        name = request.form.get('name')
        username = request.form.get('username')
        password = request.form.get('password')
        role = request.form.get('role', 'client')  # Par défaut, le rôle est "client"

        # Validation des champs
        if not username or not password:
            flash("Le nom d'utilisateur et le mot de passe ne peuvent pas être vides.", "danger")
            return redirect(url_for('register'))

        # Vérifie si l'utilisateur existe déjà
        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            flash("Le nom d'utilisateur existe déjà. Choisissez-en un autre.", "danger")
            return redirect(url_for('register'))

        # Hachage du mot de passe et création de l'utilisateur
        hashed_password = generate_password_hash(password)

        try:
            new_user = User(name=name, username=username, password_hash=hashed_password, role=role)
            db.session.add(new_user)
            db.session.commit()
            flash("Inscription réussie.", "success")
            return redirect(url_for('admin_dashboard'))  # Redirige vers le tableau de bord admin
        except Exception as e:
            db.session.rollback()  # Annule en cas d'erreur
            app.logger.error(f"Erreur lors de l'inscription : {e}")  # Ajout de log pour l'erreur
            flash("Une erreur s'est produite lors de l'inscription.", "danger")

    return render_template('register.html')



@app.route('/client_profile/<int:id>')
def client_profile(id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    current_user = db.session.get(User, session['user_id'])
    if not current_user or current_user.role != 'admin':
        flash("Vous n'êtes pas autorisé à accéder à cette page.", "danger")
        return redirect(url_for('home'))
    
    client = User.query.get_or_404(id)
    last_scan = ScanResult.query.filter_by(user_id=id).order_by(ScanResult.timestamp.desc()).first()

    return render_template('client_profile.html', client=client, last_scan=last_scan)

# Route pour récupérer les utilisateurs (admin uniquement)
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

# Route pour afficher le profil
@app.route('/profile')
def profile():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    current_user = User.query.get(session['user_id'])
    return render_template('profile.html', current_user=current_user)

# Route de déconnexion
@app.route('/logout', methods=['POST'])
def logout():
    session.clear()
    flash("Vous avez été déconnecté avec succès.", "info")
    return redirect(url_for('login'))

# Route pour supprimer un utilisateur (admin uniquement)
@app.route('/delete_user/<int:id>', methods=['GET', 'POST'])
def delete_user(id):
    user = User.query.get_or_404(id)
    if user.id == session.get('user_id'):
        flash("You cannot delete your own account.", "danger")
        return redirect(url_for('admin_dashboard'))

    db.session.delete(user)
    db.session.commit()
    flash("User deleted successfully", "danger")
    return redirect(url_for('admin_dashboard'))

if __name__ == '__main__':
    app.run(debug=True)
