# app.py - Application Flask principale améliorée
from flask import Flask, request, jsonify, session
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from flask_mail import Mail, Message as MailMessage
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
import logging
import json
import uuid
import re
import os
from functools import wraps

# Configuration
app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'votre-cle-secrete-ici')
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'mysql+pymysql://root:@localhost/chatbot_iam')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['JWT_SECRET_KEY'] = os.environ.get('JWT_SECRET_KEY', 'jwt-secret-string')
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(hours=24)

# Configuration email
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = os.environ.get('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.environ.get('MAIL_PASSWORD')
app.config['MAIL_DEFAULT_SENDER'] = 'IAM Chatbot <noreply@iam.td>'

# Extensions
CORS(app)
db = SQLAlchemy(app)
jwt = JWTManager(app)
mail = Mail(app)

# Logger
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Modèles de base de données
class Role(db.Model):
    __tablename__ = 'roles'
    id = db.Column(db.Integer, primary_key=True)
    nom = db.Column(db.String(50), unique=True, nullable=False)
    description = db.Column(db.Text)
    permissions = db.Column(db.JSON)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    nom = db.Column(db.String(100), nullable=False)
    prenom = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(255), unique=True, nullable=False)
    telephone = db.Column(db.String(20))
    password = db.Column(db.String(255))
    role_id = db.Column(db.Integer, db.ForeignKey('roles.id'), default=1)
    statut = db.Column(db.Enum('actif', 'inactif', 'suspendu'), default='actif')
    code_etudiant = db.Column(db.String(20), unique=True)
    date_inscription = db.Column(db.Date)
    last_login = db.Column(db.DateTime)
    email_verified = db.Column(db.Boolean, default=False)
    verification_token = db.Column(db.String(255))
    reset_token = db.Column(db.String(255))
    reset_token_expires = db.Column(db.DateTime)
    avatar = db.Column(db.String(255))
    preferences = db.Column(db.JSON)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    role = db.relationship('Role', backref='users')

class Formation(db.Model):
    __tablename__ = 'formations'
    id = db.Column(db.Integer, primary_key=True)
    nom = db.Column(db.String(200), nullable=False)
    code = db.Column(db.String(20), unique=True)
    description = db.Column(db.Text)
    description_courte = db.Column(db.String(500))
    duree = db.Column(db.String(50))
    niveau = db.Column(db.Enum('Bachelor', 'Master', 'MBA', 'Certification'))
    prix_mensuel = db.Column(db.Numeric(10, 2))
    prix_total = db.Column(db.Numeric(10, 2))
    modalites_paiement = db.Column(db.Text)
    prerequisites = db.Column(db.Text)
    debouches = db.Column(db.Text)
    programme = db.Column(db.JSON)  # Structure du programme
    image = db.Column(db.String(255))
    statut = db.Column(db.Enum('active', 'inactive', 'bientot'), default='active')
    capacite_max = db.Column(db.Integer)
    places_disponibles = db.Column(db.Integer)
    date_debut = db.Column(db.Date)
    date_fin_inscription = db.Column(db.Date)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

class ChatSession(db.Model):
    __tablename__ = 'chat_sessions'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    user_type = db.Column(db.Enum('prospect', 'etudiant', 'admin'), default='prospect')
    session_token = db.Column(db.String(255), unique=True)
    statut = db.Column(db.Enum('active', 'fermee'), default='active')
    ip_address = db.Column(db.String(45))
    user_agent = db.Column(db.String(500))
    satisfaction_score = db.Column(db.Integer)  # 1-5
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    ended_at = db.Column(db.DateTime)
    
    user = db.relationship('User', backref='chat_sessions')

class Message(db.Model):
    __tablename__ = 'messages'
    id = db.Column(db.Integer, primary_key=True)
    session_id = db.Column(db.Integer, db.ForeignKey('chat_sessions.id'), nullable=False)
    sender_type = db.Column(db.Enum('user', 'bot', 'admin'), nullable=False)
    sender_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    content = db.Column(db.Text, nullable=False)
    message_type = db.Column(db.Enum('text', 'form', 'file', 'notification', 'quick_reply'), default='text')
    message_metadata = db.Column(db.JSON)
    is_read = db.Column(db.Boolean, default=False)
    response_time = db.Column(db.Float)  # Temps de réponse en secondes
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    session = db.relationship('ChatSession', backref='messages')
    sender = db.relationship('User', backref='sent_messages')

class BotResponse(db.Model):
    __tablename__ = 'bot_responses'
    id = db.Column(db.Integer, primary_key=True)
    mots_cles = db.Column(db.Text, nullable=False)  # JSON array
    reponse = db.Column(db.Text, nullable=False)
    contexte = db.Column(db.Enum('general', 'prospect', 'etudiant', 'admin'), default='general')
    categorie = db.Column(db.String(100))
    priorite = db.Column(db.Integer, default=1)  # Plus élevé = plus prioritaire
    actif = db.Column(db.Boolean, default=True)
    nombre_utilisations = db.Column(db.Integer, default=0)
    taux_satisfaction = db.Column(db.Float, default=0.0)
    actions = db.Column(db.JSON)  # Actions à effectuer après la réponse
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

class Inscription(db.Model):
    __tablename__ = 'inscriptions'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    formation_id = db.Column(db.Integer, db.ForeignKey('formations.id'))
    type_inscription = db.Column(db.Enum('pre_inscription', 'inscription_definitive'), default='pre_inscription')
    statut = db.Column(db.Enum('en_attente', 'acceptee', 'refusee', 'confirmee'), default='en_attente')
    documents_fournis = db.Column(db.JSON)
    documents_manquants = db.Column(db.JSON)
    commentaires = db.Column(db.Text)
    motivation = db.Column(db.Text)
    experience_professionnelle = db.Column(db.Text)
    date_inscription = db.Column(db.DateTime, default=datetime.utcnow)
    date_traitement = db.Column(db.DateTime)
    traite_par = db.Column(db.Integer, db.ForeignKey('users.id'))
    
    user = db.relationship('User', foreign_keys=[user_id], backref='inscriptions')
    formation = db.relationship('Formation', backref='inscriptions')
    admin = db.relationship('User', foreign_keys=[traite_par])

class Note(db.Model):
    __tablename__ = 'notes'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    formation_id = db.Column(db.Integer, db.ForeignKey('formations.id'), nullable=False)
    matiere = db.Column(db.String(100), nullable=False)
    type_evaluation = db.Column(db.Enum('controle', 'examen', 'projet', 'oral'), nullable=False)
    note = db.Column(db.Numeric(4, 2), nullable=False)
    note_max = db.Column(db.Numeric(4, 2), default=20.00)
    coefficient = db.Column(db.Numeric(3, 2), default=1.00)
    commentaire = db.Column(db.Text)
    date_evaluation = db.Column(db.Date)
    publiee = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    user = db.relationship('User', backref='notes')
    formation = db.relationship('Formation', backref='notes')

class Reclamation(db.Model):
    __tablename__ = 'reclamations'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    type_reclamation = db.Column(db.Enum('technique', 'administrative', 'pedagogique', 'financiere'), nullable=False)
    priorite = db.Column(db.Enum('basse', 'normale', 'haute', 'urgente'), default='normale')
    sujet = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text, nullable=False)
    statut = db.Column(db.Enum('ouverte', 'en_cours', 'resolue', 'fermee'), default='ouverte')
    reponse = db.Column(db.Text)
    assignee_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    date_limite = db.Column(db.DateTime)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    resolved_at = db.Column(db.DateTime)
    
    user = db.relationship('User', foreign_keys=[user_id], backref='reclamations')
    assignee = db.relationship('User', foreign_keys=[assignee_id])

class Paiement(db.Model):
    __tablename__ = 'paiements'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    formation_id = db.Column(db.Integer, db.ForeignKey('formations.id'), nullable=False)
    montant = db.Column(db.Numeric(10, 2), nullable=False)
    type_paiement = db.Column(db.Enum('inscription', 'mensualite', 'rattrapage'), nullable=False)
    methode_paiement = db.Column(db.String(50))
    reference_transaction = db.Column(db.String(100), unique=True)
    statut = db.Column(db.Enum('en_attente', 'confirme', 'echec', 'rembourse'), default='en_attente')
    date_echeance = db.Column(db.Date)
    date_paiement = db.Column(db.DateTime)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    user = db.relationship('User', backref='paiements')
    formation = db.relationship('Formation', backref='paiements')

# Service Chatbot Amélioré
class ChatbotService:
    @staticmethod
    def get_user_context(user_id=None):
        """Détermine le contexte de l'utilisateur"""
        if not user_id:
            return 'prospect'
        
        user = User.query.get(user_id)
        if not user:
            return 'prospect'
            
        role_name = user.role.nom if user.role else 'prospect'
        context_mapping = {
            'prospect': 'prospect',
            'etudiant': 'etudiant',
            'admin': 'admin',
            'administrateur': 'admin'
        }
        return context_mapping.get(role_name, 'prospect')
    
    @staticmethod
    def find_best_response(message, context='general', user_id=None):
        """Trouve la meilleure réponse basée sur le message et le contexte avec IA améliorée"""
        message_lower = message.lower()
        
        # Nettoyer le message
        message_clean = re.sub(r'[^\w\s]', ' ', message_lower)
        words = message_clean.split()
        
        # Récupérer les réponses appropriées au contexte
        responses = BotResponse.query.filter(
            BotResponse.actif == True,
            BotResponse.contexte.in_([context, 'general'])
        ).order_by(BotResponse.priorite.desc()).all()
        
        best_match = None
        max_score = 0
        
        for response in responses:
            mots_cles = json.loads(response.mots_cles)
            score = 0
            
            # Calcul du score amélioré
            for mot_cle in mots_cles:
                mot_cle_lower = mot_cle.lower()
                if mot_cle_lower in message_lower:
                    score += 3  # Correspondance exacte
                elif any(mot_cle_lower in word for word in words):
                    score += 2  # Correspondance partielle
                elif any(word in mot_cle_lower for word in words if len(word) > 3):
                    score += 1  # Correspondance inverse
            
            # Bonus pour la priorité
            score += response.priorite * 0.5
            
            if score > max_score:
                max_score = score
                best_match = response
        
        if best_match and max_score > 0:
            # Incrémenter le compteur d'utilisation
            best_match.nombre_utilisations += 1
            db.session.commit()
            
            # Traiter les actions si présentes
            actions = json.loads(best_match.actions) if best_match.actions else []
            
            return {
                'content': best_match.reponse,
                'actions': actions,
                'type': 'text'
            }
        
        return ChatbotService.get_default_response(context, message)
    
    @staticmethod
    def get_default_response(context, message=""):
        """Réponse par défaut selon le contexte avec suggestions intelligentes"""
        message_lower = message.lower()
        
        # Suggestions basées sur le contenu du message
        suggestions = []
        if any(word in message_lower for word in ['formation', 'cours', 'programme']):
            suggestions.append("Voir toutes nos formations")
            suggestions.append("Comparer les formations")
        elif any(word in message_lower for word in ['prix', 'coût', 'tarif']):
            suggestions.append("Consulter les tarifs")
            suggestions.append("Modalités de paiement")
        elif any(word in message_lower for word in ['inscription', 'candidature']):
            suggestions.append("Commencer une pré-inscription")
            suggestions.append("Documents requis")
        
        defaults = {
            'prospect': {
                'content': "Bienvenue ! Je peux vous renseigner sur nos formations, les prix, les modalités d'inscription et bien plus. Que souhaitez-vous savoir ?",
                'suggestions': suggestions or ["Voir les formations", "Tarifs et paiement", "Processus d'inscription", "Nous contacter"]
            },
            'etudiant': {
                'content': "Bonjour ! Je peux vous aider avec vos notes, réclamations, paiements ou questions administratives. Comment puis-je vous aider ?",
                'suggestions': ["Consulter mes notes", "Mes paiements", "Faire une réclamation", "Support technique"]
            },
            'admin': {
                'content': "Interface d'administration disponible. Vous pouvez gérer les utilisateurs, consulter les statistiques ou configurer le chatbot.",
                'suggestions': ["Tableau de bord", "Gérer les utilisateurs", "Statistiques", "Configuration"]
            },
            'general': {
                'content': "Comment puis-je vous aider aujourd'hui ?",
                'suggestions': ["Informations générales", "Nous contacter"]
            }
        }
        
        response = defaults.get(context, defaults['general'])
        return {
            'content': response['content'],
            'type': 'text',
            'suggestions': response['suggestions']
        }
    
    @staticmethod
    def handle_special_requests(message, user_id, context):
        """Gère les demandes spéciales avec logique métier avancée"""
        message_lower = message.lower()
        
        if context == 'prospect':
            # Gestion des inscriptions
            if any(word in message_lower for word in ['inscription', 'inscrire', 'candidature', 'postuler']):
                formations = Formation.query.filter_by(statut='active').all()
                formations_data = []
                
                for f in formations:
                    formations_data.append({
                        "id": f.id,
                        "nom": f.nom,
                        "niveau": f.niveau,
                        "duree": f.duree,
                        "prix_mensuel": float(f.prix_mensuel) if f.prix_mensuel else None,
                        "prix_total": float(f.prix_total) if f.prix_total else None,
                        "places_disponibles": f.places_disponibles,
                        "description_courte": f.description_courte
                    })
                
                return {
                    "type": "form",
                    "content": "Je peux vous aider avec votre pré-inscription. Voici nos formations disponibles :",
                    "data": {
                        "form_type": "pre_inscription",
                        "formations": formations_data
                    }
                }
            
            # Informations sur les prix
            elif any(word in message_lower for word in ['prix', 'coût', 'tarif', 'paiement']):
                formations = Formation.query.filter_by(statut='active').all()
                tarifs = []
                
                for f in formations:
                    tarifs.append({
                        "formation": f.nom,
                        "niveau": f.niveau,
                        "prix_mensuel": float(f.prix_mensuel) if f.prix_mensuel else None,
                        "prix_total": float(f.prix_total) if f.prix_total else None,
                        "modalites": f.modalites_paiement
                    })
                
                return {
                    "type": "pricing",
                    "content": "Voici nos tarifs et modalités de paiement :",
                    "data": tarifs
                }
        
        elif context == 'etudiant':
            # Consultation des notes
            if any(word in message_lower for word in ['note', 'resultat', 'bulletin', 'moyenne']):
                if user_id:
                    notes = Note.query.filter_by(user_id=user_id, publiee=True).all()
                    notes_data = []
                    
                    for note in notes:
                        notes_data.append({
                            "matiere": note.matiere,
                            "type_evaluation": note.type_evaluation,
                            "note": float(note.note),
                            "note_max": float(note.note_max),
                            "coefficient": float(note.coefficient),
                            "date_evaluation": note.date_evaluation.isoformat() if note.date_evaluation else None
                        })
                    
                    return {
                        "type": "notes",
                        "content": "Voici vos dernières notes :",
                        "data": notes_data
                    }
            
            # Réclamations
            elif any(word in message_lower for word in ['reclamation', 'probleme', 'plainte', 'support']):
                return {
                    "type": "form",
                    "content": "Je peux vous aider à déposer une réclamation. Quel est le type de problème ?",
                    "data": {
                        "form_type": "reclamation",
                        "types": ["technique", "administrative", "pedagogique", "financiere"]
                    }
                }
            
            # Paiements
            elif any(word in message_lower for word in ['paiement', 'facture', 'mensualite', 'dette']):
                if user_id:
                    paiements = Paiement.query.filter_by(user_id=user_id).order_by(Paiement.created_at.desc()).limit(5).all()
                    paiements_data = []
                    
                    for p in paiements:
                        paiements_data.append({
                            "montant": float(p.montant),
                            "type": p.type_paiement,
                            "statut": p.statut,
                            "date_echeance": p.date_echeance.isoformat() if p.date_echeance else None,
                            "date_paiement": p.date_paiement.isoformat() if p.date_paiement else None
                        })
                    
                    return {
                        "type": "payments",
                        "content": "Voici l'état de vos paiements :",
                        "data": paiements_data
                    }
        
        return None

# Décorateur pour vérifier les rôles
def role_required(roles):
    def decorator(f):
        @wraps(f)
        @jwt_required()
        def decorated_function(*args, **kwargs):
            current_user_id = get_jwt_identity()
            user = User.query.get(current_user_id)
            
            if not user or user.role.nom not in roles:
                return jsonify({"error": "Accès non autorisé"}), 403
            
            return f(*args, **kwargs)
        return decorated_function
    return decorator

# Routes d'authentification
@app.route("/api/auth/register", methods=["POST"])
def register():
    try:
        data = request.get_json()
        
        # Validation des données
        required_fields = ['nom', 'prenom', 'email', 'telephone']
        for field in required_fields:
            if field not in data:
                return jsonify({"error": f"Le champ {field} est requis"}), 400
        
        # Vérifier si l'email existe déjà
        if User.query.filter_by(email=data['email']).first():
            return jsonify({"error": "Un compte avec cet email existe déjà"}), 400
        
        # Validation email
        email_regex = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        if not re.match(email_regex, data['email']):
            return jsonify({"error": "Format d'email invalide"}), 400
        
        # Créer l'utilisateur
        user = User(
            nom=data['nom'],
            prenom=data['prenom'],
            email=data['email'],
            telephone=data['telephone'],
            verification_token=str(uuid.uuid4())
        )
        
        # Si un mot de passe est fourni
        if 'password' in data and data['password']:
            user.password = generate_password_hash(data['password'])
        
        db.session.add(user)
        db.session.commit()
        
        # Envoyer email de vérification
        send_verification_email(user)
        
        return jsonify({
            "message": "Compte créé avec succès. Vérifiez votre email.",
            "user_id": user.id
        }), 201
        
    except Exception as e:
        logger.error(f"Erreur lors de l'inscription: {str(e)}")
        return jsonify({"error": "Erreur interne du serveur"}), 500

@app.route("/api/auth/login", methods=["POST"])
def login():
    try:
        data = request.get_json()
        
        if not data.get('email') or not data.get('password'):
            return jsonify({"error": "Email et mot de passe requis"}), 400
        
        user = User.query.filter_by(email=data['email']).first()
        
        if user and check_password_hash(user.password, data['password']):
            if user.statut != 'actif':
                return jsonify({"error": "Compte suspendu ou inactif"}), 403
            
            # Mettre à jour la dernière connexion
            user.last_login = datetime.utcnow()
            db.session.commit()
            
            # Créer le token JWT
            access_token = create_access_token(
                identity=user.id,
                additional_claims={
                    'role': user.role.nom if user.role else 'prospect',
                    'email': user.email
                }
            )
            
            return jsonify({
                "access_token": access_token,
                "user": {
                    "id": user.id,
                    "nom": user.nom,
                    "prenom": user.prenom,
                    "email": user.email,
                    "role": user.role.nom if user.role else 'prospect',
                    "avatar": user.avatar
                }
            }), 200
        
        return jsonify({"error": "Email ou mot de passe incorrect"}), 401
        
    except Exception as e:
        logger.error(f"Erreur lors de la connexion: {str(e)}")
        return jsonify({"error": "Erreur interne du serveur"}), 500

# Routes du chatbot
@app.route("/api/chat/start", methods=["POST"])
def start_chat():
    try:
        data = request.get_json() or {}
        user_id = data.get('user_id')
        
        # Créer une nouvelle session de chat
        session = ChatSession(
            user_id=user_id,
            user_type=ChatbotService.get_user_context(user_id),
            session_token=str(uuid.uuid4()),
            ip_address=request.remote_addr,
            user_agent=request.headers.get('User-Agent', '')
        )
        
        db.session.add(session)
        db.session.commit()
        
        # Message de bienvenue
        welcome_response = ChatbotService.get_default_response(session.user_type)
        
        welcome_message = Message(
            session_id=session.id,
            sender_type='bot',
            content=welcome_response['content'],
            message_type='text',
            metadata={
                'suggestions': welcome_response.get('suggestions', [])
            }
        )
        
        db.session.add(welcome_message)
        db.session.commit()
        
        return jsonify({
            "session_token": session.session_token,
            "user_type": session.user_type,
            "welcome_message": {
                "content": welcome_response['content'],
                "suggestions": welcome_response.get('suggestions', [])
            }
        }), 200
        
    except Exception as e:
        logger.error(f"Erreur lors du démarrage du chat: {str(e)}")
        return jsonify({"error": "Erreur interne du serveur"}), 500

@app.route("/api/chat/send", methods=["POST"])
def send_message():
    try:
        data = request.get_json()
        session_token = data.get('session_token')
        message_content = data.get('message')
        
        if not session_token or not message_content:
            return jsonify({"error": "Token de session et message requis"}), 400
        
        # Récupérer la session
        session = ChatSession.query.filter_by(session_token=session_token).first()
        if not session:
            return jsonify({"error": "Session non trouvée"}), 404
        
        start_time = datetime.utcnow()
        
        # Enregistrer le message utilisateur
        user_message = Message(
            session_id=session.id,
            sender_type='user',
            sender_id=session.user_id,
            content=message_content,
            message_type='text'
        )
        
        db.session.add(user_message)
        db.session.commit()
        
        # Vérifier les demandes spéciales
        special_response = ChatbotService.handle_special_requests(
            message_content, session.user_id, session.user_type
        )
        
        if special_response:
            bot_response = special_response
        else:
            # Rechercher la meilleure réponse
            bot_response = ChatbotService.find_best_response(
                message_content, session.user_type, session.user_id
            )
        
        # Calculer le temps de réponse
        response_time = (datetime.utcnow() - start_time).total_seconds()
        
        # Enregistrer la réponse du bot
        bot_message = Message(
            session_id=session.id,
            sender_type='bot',
            content=bot_response['content'],
            message_type=bot_response.get('type', 'text'),
            metadata=bot_response.get('data') or bot_response.get('suggestions'),
            response_time=response_time
        )
        
        db.session.add(bot_message)
        db.session.commit()
        
        return jsonify({
            "response": bot_response,
            "message_id": bot_message.id,
            "response_time": response_time
        }), 200
        
    except Exception as e:
        logger.error(f"Erreur lors de l'envoi du message: {str(e)}")
        return jsonify({"error": "Erreur interne du serveur"}), 500

@app.route("/api/chat/history/<session_token>", methods=["GET"])
def get_chat_history(session_token):
    try:
        session = ChatSession.query.filter_by(session_token=session_token).first()
        if not session:
            return jsonify({"error": "Session non trouvée"}), 404
        
        messages = Message.query.filter_by(session_id=session.id)\
            .order_by(Message.created_at.asc()).all()
        
        history = []
        for msg in messages:
            history.append({
                "id": msg.id,
                "sender_type": msg.sender_type,
                "content": msg.content,
                "message_type": msg.message_type,
                "metadata": msg.metadata,
                "created_at": msg.created_at.isoformat()
            })
        
        return jsonify({"history": history}), 200
        
    except Exception as e:
        logger.error(f"Erreur lors de la récupération de l'historique: {str(e)}")
        return jsonify({"error": "Erreur interne du serveur"}), 500

# Routes pour les étudiants
@app.route("/api/student/notes", methods=["GET"])
@jwt_required()
def get_student_notes():
    try:
        user_id = get_jwt_identity()
        
        notes = Note.query.filter_by(user_id=user_id, publiee=True)\
            .order_by(Note.date_evaluation.desc()).all()
        
        notes_data = []
        total_points = 0
        total_coefficients = 0
        
        for note in notes:
            note_data = {
                "id": note.id,
                "matiere": note.matiere,
                "type_evaluation": note.type_evaluation,
                "note": float(note.note),
                "note_max": float(note.note_max),
                "coefficient": float(note.coefficient),
                "pourcentage": float(note.note / note.note_max * 100),
                "date_evaluation": note.date_evaluation.isoformat() if note.date_evaluation else None,
                "commentaire": note.commentaire
            }
            notes_data.append(note_data)
            
            # Calcul de la moyenne générale
            total_points += float(note.note * note.coefficient)
            total_coefficients += float(note.coefficient)
        
        moyenne_generale = round(total_points / total_coefficients, 2) if total_coefficients > 0 else 0
        
        return jsonify({
            "notes": notes_data,
            "moyenne_generale": moyenne_generale,
            "total_evaluations": len(notes_data)
        }), 200
        
    except Exception as e:
        logger.error(f"Erreur lors de la récupération des notes: {str(e)}")
        return jsonify({"error": "Erreur interne du serveur"}), 500

@app.route("/api/student/payments", methods=["GET"])
@jwt_required()
def get_student_payments():
    try:
        user_id = get_jwt_identity()
        
        paiements = Paiement.query.filter_by(user_id=user_id)\
            .order_by(Paiement.created_at.desc()).all()
        
        paiements_data = []
        total_paye = 0
        total_en_attente = 0
        
        for paiement in paiements:
            paiement_data = {
                "id": paiement.id,
                "montant": float(paiement.montant),
                "type_paiement": paiement.type_paiement,
                "statut": paiement.statut,
                "methode_paiement": paiement.methode_paiement,
                "reference_transaction": paiement.reference_transaction,
                "date_echeance": paiement.date_echeance.isoformat() if paiement.date_echeance else None,
                "date_paiement": paiement.date_paiement.isoformat() if paiement.date_paiement else None,
                "formation": paiement.formation.nom if paiement.formation else None
            }
            paiements_data.append(paiement_data)
            
            if paiement.statut == 'confirme':
                total_paye += float(paiement.montant)
            elif paiement.statut == 'en_attente':
                total_en_attente += float(paiement.montant)
        
        return jsonify({
            "paiements": paiements_data,
            "total_paye": total_paye,
            "total_en_attente": total_en_attente,
            "nombre_paiements": len(paiements_data)
        }), 200
        
    except Exception as e:
        logger.error(f"Erreur lors de la récupération des paiements: {str(e)}")
        return jsonify({"error": "Erreur interne du serveur"}), 500

@app.route("/api/student/reclamations", methods=["GET", "POST"])
@jwt_required()
def handle_reclamations():
    try:
        user_id = get_jwt_identity()
        
        if request.method == "GET":
            reclamations = Reclamation.query.filter_by(user_id=user_id)\
                .order_by(Reclamation.created_at.desc()).all()
            
            reclamations_data = []
            for reclamation in reclamations:
                reclamation_data = {
                    "id": reclamation.id,
                    "type_reclamation": reclamation.type_reclamation,
                    "priorite": reclamation.priorite,
                    "sujet": reclamation.sujet,
                    "description": reclamation.description,
                    "statut": reclamation.statut,
                    "reponse": reclamation.reponse,
                    "created_at": reclamation.created_at.isoformat(),
                    "resolved_at": reclamation.resolved_at.isoformat() if reclamation.resolved_at else None
                }
                reclamations_data.append(reclamation_data)
            
            return jsonify({"reclamations": reclamations_data}), 200
        
        elif request.method == "POST":
            data = request.get_json()
            
            required_fields = ['type_reclamation', 'sujet', 'description']
            for field in required_fields:
                if field not in data:
                    return jsonify({"error": f"Le champ {field} est requis"}), 400
            
            reclamation = Reclamation(
                user_id=user_id,
                type_reclamation=data['type_reclamation'],
                priorite=data.get('priorite', 'normale'),
                sujet=data['sujet'],
                description=data['description']
            )
            
            db.session.add(reclamation)
            db.session.commit()
            
            # Notifier les administrateurs
            notify_admins_new_reclamation(reclamation)
            
            return jsonify({
                "message": "Réclamation créée avec succès",
                "reclamation_id": reclamation.id
            }), 201
        
    except Exception as e:
        logger.error(f"Erreur lors de la gestion des réclamations: {str(e)}")
        return jsonify({"error": "Erreur interne du serveur"}), 500

# Routes pour les formations
@app.route("/api/formations", methods=["GET"])
def get_formations():
    try:
        formations = Formation.query.filter_by(statut='active').all()
        
        formations_data = []
        for formation in formations:
            formation_data = {
                "id": formation.id,
                "nom": formation.nom,
                "code": formation.code,
                "description": formation.description,
                "description_courte": formation.description_courte,
                "duree": formation.duree,
                "niveau": formation.niveau,
                "prix_mensuel": float(formation.prix_mensuel) if formation.prix_mensuel else None,
                "prix_total": float(formation.prix_total) if formation.prix_total else None,
                "modalites_paiement": formation.modalites_paiement,
                "prerequisites": formation.prerequisites,
                "debouches": formation.debouches,
                "programme": formation.programme,
                "image": formation.image,
                "places_disponibles": formation.places_disponibles,
                "date_debut": formation.date_debut.isoformat() if formation.date_debut else None,
                "date_fin_inscription": formation.date_fin_inscription.isoformat() if formation.date_fin_inscription else None
            }
            formations_data.append(formation_data)
        
        return jsonify({"formations": formations_data}), 200
        
    except Exception as e:
        logger.error(f"Erreur lors de la récupération des formations: {str(e)}")
        return jsonify({"error": "Erreur interne du serveur"}), 500

@app.route("/api/formations/<int:formation_id>", methods=["GET"])
def get_formation_details(formation_id):
    try:
        formation = Formation.query.get_or_404(formation_id)
        
        formation_data = {
            "id": formation.id,
            "nom": formation.nom,
            "code": formation.code,
            "description": formation.description,
            "description_courte": formation.description_courte,
            "duree": formation.duree,
            "niveau": formation.niveau,
            "prix_mensuel": float(formation.prix_mensuel) if formation.prix_mensuel else None,
            "prix_total": float(formation.prix_total) if formation.prix_total else None,
            "modalites_paiement": formation.modalites_paiement,
            "prerequisites": formation.prerequisites,
            "debouches": formation.debouches,
            "programme": formation.programme,
            "image": formation.image,
            "places_disponibles": formation.places_disponibles,
            "date_debut": formation.date_debut.isoformat() if formation.date_debut else None,
            "date_fin_inscription": formation.date_fin_inscription.isoformat() if formation.date_fin_inscription else None,
            "nombre_inscrits": len([i for i in formation.inscriptions if i.statut in ['acceptee', 'confirmee']])
        }
        
        return jsonify({"formation": formation_data}), 200
        
    except Exception as e:
        logger.error(f"Erreur lors de la récupération de la formation: {str(e)}")
        return jsonify({"error": "Erreur interne du serveur"}), 500

# Routes pour les inscriptions
@app.route("/api/inscriptions", methods=["POST"])
def create_inscription():
    try:
        data = request.get_json()
        
        required_fields = ['nom', 'prenom', 'email', 'telephone', 'formation_id']
        for field in required_fields:
            if field not in data:
                return jsonify({"error": f"Le champ {field} est requis"}), 400
        
        # Vérifier si la formation existe et est disponible
        formation = Formation.query.get(data['formation_id'])
        if not formation or formation.statut != 'active':
            return jsonify({"error": "Formation non disponible"}), 400
        
        # Vérifier les places disponibles
        if formation.places_disponibles is not None and formation.places_disponibles <= 0:
            return jsonify({"error": "Plus de places disponibles pour cette formation"}), 400
        
        # Créer ou récupérer l'utilisateur
        user = User.query.filter_by(email=data['email']).first()
        if not user:
            user = User(
                nom=data['nom'],
                prenom=data['prenom'],
                email=data['email'],
                telephone=data['telephone'],
                verification_token=str(uuid.uuid4())
            )
            db.session.add(user)
            db.session.flush()  # Pour obtenir l'ID
            
            # Envoyer email de vérification
            send_verification_email(user)
        
        # Vérifier si une inscription existe déjà
        existing_inscription = Inscription.query.filter_by(
            user_id=user.id,
            formation_id=formation.id
        ).first()
        
        if existing_inscription:
            return jsonify({"error": "Vous avez déjà une demande d'inscription pour cette formation"}), 400
        
        # Créer l'inscription
        inscription = Inscription(
            user_id=user.id,
            formation_id=formation.id,
            type_inscription='pre_inscription',
            motivation=data.get('motivation'),
            experience_professionnelle=data.get('experience_professionnelle')
        )
        
        db.session.add(inscription)
        
        # Décrémenter les places disponibles
        if formation.places_disponibles is not None:
            formation.places_disponibles -= 1
        
        db.session.commit()
        
        # Envoyer email de confirmation
        send_inscription_confirmation_email(user, formation)
        
        # Notifier les administrateurs
        notify_admins_new_inscription(inscription)
        
        return jsonify({
            "message": "Pré-inscription créée avec succès",
            "inscription_id": inscription.id,
            "user_id": user.id
        }), 201
        
    except Exception as e:
        db.session.rollback()
        logger.error(f"Erreur lors de la création de l'inscription: {str(e)}")
        return jsonify({"error": "Erreur interne du serveur"}), 500

# Routes d'administration
@app.route("/api/admin/dashboard", methods=["GET"])
@role_required(['admin', 'administrateur'])
def admin_dashboard():
    try:
        # Statistiques générales
        total_users = User.query.count()
        total_students = User.query.join(Role).filter(Role.nom == 'etudiant').count()
        total_prospects = User.query.join(Role).filter(Role.nom == 'prospect').count()
        total_formations = Formation.query.filter_by(statut='active').count()
        
        # Inscriptions récentes
        recent_inscriptions = Inscription.query.filter_by(statut='en_attente')\
            .order_by(Inscription.date_inscription.desc()).limit(5).all()
        
        # Réclamations en attente
        pending_reclamations = Reclamation.query.filter_by(statut='ouverte').count()
        
        # Sessions de chat actives
        active_sessions = ChatSession.query.filter_by(statut='active').count()
        
        # Messages du jour
        today = datetime.utcnow().date()
        messages_today = Message.query.filter(
            db.func.date(Message.created_at) == today
        ).count()
        
        # Formations populaires
        popular_formations = db.session.query(
            Formation.nom,
            db.func.count(Inscription.id).label('inscriptions_count')
        ).join(Inscription).group_by(Formation.id).order_by(
            db.func.count(Inscription.id).desc()
        ).limit(5).all()
        
        dashboard_data = {
            "total_users": total_users,
            "total_students": total_students,
            "total_prospects": total_prospects,
            "total_formations": total_formations,
            "pending_reclamations": pending_reclamations,
            "active_sessions": active_sessions,
            "messages_today": messages_today,
            "recent_inscriptions": [{
                "id": i.id,
                "user_name": f"{i.user.prenom} {i.user.nom}",
                "formation_name": i.formation.nom,
                "date": i.date_inscription.isoformat()
            } for i in recent_inscriptions],
            "popular_formations": [{
                "nom": f.nom,
                "inscriptions": f.inscriptions_count
            } for f in popular_formations]
        }
        
        return jsonify(dashboard_data), 200
        
    except Exception as e:
        logger.error(f"Erreur lors de la récupération du dashboard admin: {str(e)}")
        return jsonify({"error": "Erreur interne du serveur"}), 500

# Services d'email
def send_verification_email(user):
    try:
        msg = MailMessage(
            'Vérification de votre compte IAM',
            recipients=[user.email]
        )
        
        verification_url = f"https://votre-domaine.com/verify/{user.verification_token}"
        
        msg.html = f"""
        <h2>Bienvenue à l'Institut IAM !</h2>
        <p>Bonjour {user.prenom} {user.nom},</p>
        <p>Merci de vous être inscrit. Pour activer votre compte, cliquez sur le lien ci-dessous :</p>
        <a href="{verification_url}" style="background-color: #007bff; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px;">
            Vérifier mon compte
        </a>
        <p>Si vous n'avez pas créé ce compte, ignorez cet email.</p>
        <p>Cordialement,<br>L'équipe IAM</p>
        """
        
        mail.send(msg)
        logger.info(f"Email de vérification envoyé à {user.email}")
        
    except Exception as e:
        logger.error(f"Erreur lors de l'envoi de l'email de vérification: {str(e)}")

def send_inscription_confirmation_email(user, formation):
    try:
        msg = MailMessage(
            'Confirmation de votre pré-inscription',
            recipients=[user.email]
        )
        
        msg.html = f"""
        <h2>Pré-inscription confirmée !</h2>
        <p>Bonjour {user.prenom} {user.nom},</p>
        <p>Votre pré-inscription pour la formation <strong>{formation.nom}</strong> a été reçue avec succès.</p>
        <p><strong>Prochaines étapes :</strong></p>
        <ul>
            <li>Notre équipe va examiner votre dossier</li>
            <li>Vous recevrez une réponse sous 48-72h</li>
            <li>En cas d'acceptation, vous recevrez les instructions pour finaliser votre inscription</li>
        </ul>
        <p>Cordialement,<br>L'équipe IAM</p>
        """
        
        mail.send(msg)
        logger.info(f"Email de confirmation d'inscription envoyé à {user.email}")
        
    except Exception as e:
        logger.error(f"Erreur lors de l'envoi de l'email de confirmation: {str(e)}")

def notify_admins_new_inscription(inscription):
    # Logique pour notifier les administrateurs d'une nouvelle inscription
    logger.info(f"Nouvelle inscription: {inscription.id}")

def notify_admins_new_reclamation(reclamation):
    # Logique pour notifier les administrateurs d'une nouvelle réclamation
    logger.info(f"Nouvelle réclamation: {reclamation.id}")

# Initialisation de la base de données
@app.before_first_request
def create_tables():
    db.create_all()
    
    # Créer les rôles par défaut s'ils n'existent pas
    if not Role.query.first():
        roles = [
            Role(nom='prospect', description='Visiteur intéressé par les formations'),
            Role(nom='etudiant', description='Étudiant inscrit'),
            Role(nom='admin', description='Administrateur du système')
        ]
        
        for role in roles:
            db.session.add(role)
        
        db.session.commit()
        logger.info("Rôles par défaut créés")

# Gestion des erreurs
@app.errorhandler(404)
def not_found(error):
    return jsonify({"error": "Ressource non trouvée"}), 404

@app.errorhandler(500)
def internal_error(error):
    return jsonify({"error": "Erreur interne du serveur"}), 500

@app.errorhandler(403)
def forbidden(error):
    return jsonify({"error": "Accès interdit"}), 403

if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)