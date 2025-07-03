from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
import json
import uuid

db = SQLAlchemy()

class Room(db.Model):
    __tablename__ = 'rooms'
    
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    name = db.Column(db.String(100), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    is_active = db.Column(db.Boolean, default=True)
    max_users = db.Column(db.Integer, default=10)
    password_hash = db.Column(db.String(255), nullable=True)  # For private rooms
    
    # Relationships
    documents = db.relationship('Document', backref='room', lazy=True, cascade='all, delete-orphan')
    sessions = db.relationship('UserSession', backref='room', lazy=True, cascade='all, delete-orphan')
    
    def to_dict(self):
        return {
            'id': self.id,
            'name': self.name,
            'created_at': self.created_at.isoformat(),
            'updated_at': self.updated_at.isoformat(),
            'is_active': self.is_active,
            'max_users': self.max_users,
            'has_password': bool(self.password_hash)
        }

class Document(db.Model):
    __tablename__ = 'documents'
    
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    room_id = db.Column(db.String(36), db.ForeignKey('rooms.id'), nullable=False)
    content = db.Column(db.Text, default='')
    language = db.Column(db.String(50), default='javascript')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    version = db.Column(db.Integer, default=1)
    
    # Relationships
    revisions = db.relationship('DocumentRevision', backref='document', lazy=True, cascade='all, delete-orphan')
    
    def to_dict(self):
        return {
            'id': self.id,
            'room_id': self.room_id,
            'content': self.content,
            'language': self.language,
            'created_at': self.created_at.isoformat(),
            'updated_at': self.updated_at.isoformat(),
            'version': self.version
        }
    
    def create_revision(self, user_id, change_type='edit'):
        """Create a revision snapshot of the current document"""
        revision = DocumentRevision(
            document_id=self.id,
            content=self.content,
            language=self.language,
            version=self.version,
            user_id=user_id,
            change_type=change_type
        )
        db.session.add(revision)
        self.version += 1
        return revision

class DocumentRevision(db.Model):
    __tablename__ = 'document_revisions'
    
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    document_id = db.Column(db.String(36), db.ForeignKey('documents.id'), nullable=False)
    content = db.Column(db.Text, nullable=False)
    language = db.Column(db.String(50), nullable=False)
    version = db.Column(db.Integer, nullable=False)
    user_id = db.Column(db.String(36), db.ForeignKey('users.id'), nullable=True)
    change_type = db.Column(db.String(20), default='edit')  # edit, language_change, create
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    def to_dict(self):
        return {
            'id': self.id,
            'document_id': self.document_id,
            'content': self.content,
            'language': self.language,
            'version': self.version,
            'user_id': self.user_id,
            'change_type': self.change_type,
            'created_at': self.created_at.isoformat()
        }

class User(db.Model):
    __tablename__ = 'users'
    
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    username = db.Column(db.String(50), nullable=False)
    email = db.Column(db.String(100), nullable=True, unique=True)
    password_hash = db.Column(db.String(255), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_active = db.Column(db.DateTime, default=datetime.utcnow)
    is_guest = db.Column(db.Boolean, default=True)
    
    # Relationships
    sessions = db.relationship('UserSession', backref='user', lazy=True, cascade='all, delete-orphan')
    revisions = db.relationship('DocumentRevision', backref='user', lazy=True)
    
    def to_dict(self):
        return {
            'id': self.id,
            'username': self.username,
            'email': self.email,
            'created_at': self.created_at.isoformat(),
            'last_active': self.last_active.isoformat(),
            'is_guest': self.is_guest
        }

class UserSession(db.Model):
    __tablename__ = 'user_sessions'
    
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = db.Column(db.String(36), db.ForeignKey('users.id'), nullable=False)
    room_id = db.Column(db.String(36), db.ForeignKey('rooms.id'), nullable=False)
    socket_id = db.Column(db.String(100), nullable=False)
    joined_at = db.Column(db.DateTime, default=datetime.utcnow)
    left_at = db.Column(db.DateTime, nullable=True)
    is_active = db.Column(db.Boolean, default=True)
    cursor_position = db.Column(db.Text, nullable=True)  # JSON string
    
    def to_dict(self):
        return {
            'id': self.id,
            'user_id': self.user_id,
            'room_id': self.room_id,
            'socket_id': self.socket_id,
            'joined_at': self.joined_at.isoformat(),
            'left_at': self.left_at.isoformat() if self.left_at else None,
            'is_active': self.is_active,
            'cursor_position': json.loads(self.cursor_position) if self.cursor_position else None
        }
    
    def set_cursor_position(self, line, ch):
        """Set cursor position as JSON"""
        self.cursor_position = json.dumps({'line': line, 'ch': ch})
    
    def get_cursor_position(self):
        """Get cursor position as dict"""
        return json.loads(self.cursor_position) if self.cursor_position else None

class RoomStats(db.Model):
    __tablename__ = 'room_stats'
    
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    room_id = db.Column(db.String(36), db.ForeignKey('rooms.id'), nullable=False)
    date = db.Column(db.Date, default=datetime.utcnow().date)
    unique_users = db.Column(db.Integer, default=0)
    total_sessions = db.Column(db.Integer, default=0)
    total_edits = db.Column(db.Integer, default=0)
    avg_session_duration = db.Column(db.Float, default=0.0)  # in minutes
    
    # Composite unique constraint
    __table_args__ = (db.UniqueConstraint('room_id', 'date'),)
    
    def to_dict(self):
        return {
            'id': self.id,
            'room_id': self.room_id,
            'date': self.date.isoformat(),
            'unique_users': self.unique_users,
            'total_sessions': self.total_sessions,
            'total_edits': self.total_edits,
            'avg_session_duration': self.avg_session_duration
        }

# Database utility functions
def init_db():
    """Initialize database tables"""
    db.create_all()

def get_or_create_room(room_id, name=None):
    """Get existing room or create new one"""
    room = Room.query.filter_by(id=room_id).first()
    if not room:
        room = Room(id=room_id, name=name)
        db.session.add(room)
        db.session.commit()
    return room

def get_or_create_user(username, socket_id, email=None):
    """Get existing user or create new guest user"""
    # For guest users, create a new user each time
    user = User(
        username=username,
        email=email,
        is_guest=True
    )
    db.session.add(user)
    db.session.commit()
    return user

def get_or_create_document(room_id, initial_content='', language='javascript'):
    """Get existing document or create new one for room"""
    document = Document.query.filter_by(room_id=room_id).first()
    if not document:
        document = Document(
            room_id=room_id,
            content=initial_content,
            language=language
        )
        db.session.add(document)
        db.session.commit()
    return document

def create_user_session(user_id, room_id, socket_id):
    """Create new user session"""
    # End any existing active sessions for this user in this room
    existing_sessions = UserSession.query.filter_by(
        user_id=user_id, 
        room_id=room_id, 
        is_active=True
    ).all()
    
    for session in existing_sessions:
        session.is_active = False
        session.left_at = datetime.utcnow()
    
    # Create new session
    session = UserSession(
        user_id=user_id,
        room_id=room_id,
        socket_id=socket_id
    )
    db.session.add(session)
    db.session.commit()
    return session

def end_user_session(socket_id):
    """End user session when they disconnect"""
    session = UserSession.query.filter_by(socket_id=socket_id, is_active=True).first()
    if session:
        session.is_active = False
        session.left_at = datetime.utcnow()
        db.session.commit()
    return session

def get_active_room_users(room_id):
    """Get all active users in a room"""
    sessions = UserSession.query.filter_by(room_id=room_id, is_active=True).all()
    users = []
    for session in sessions:
        user_data = session.user.to_dict()
        user_data['session'] = session.to_dict()
        users.append(user_data)
    return users

def update_room_stats(room_id):
    """Update daily statistics for a room"""
    today = datetime.utcnow().date()
    
    # Get or create stats entry for today
    stats = RoomStats.query.filter_by(room_id=room_id, date=today).first()
    if not stats:
        stats = RoomStats(room_id=room_id, date=today)
        db.session.add(stats)
    
    # Calculate stats
    today_sessions = UserSession.query.filter(
        UserSession.room_id == room_id,
        db.func.date(UserSession.joined_at) == today
    ).all()
    
    stats.total_sessions = len(today_sessions)
    stats.unique_users = len(set(session.user_id for session in today_sessions))
    
    # Calculate average session duration
    completed_sessions = [s for s in today_sessions if s.left_at]
    if completed_sessions:
        durations = [(s.left_at - s.joined_at).total_seconds() / 60 for s in completed_sessions]
        stats.avg_session_duration = sum(durations) / len(durations)
    
    db.session.commit()
    return stats

def cleanup_old_data(days_to_keep=30):
    """Clean up old data to prevent database bloat"""
    cutoff_date = datetime.utcnow() - timedelta(days=days_to_keep)
    
    # Delete old revisions
    old_revisions = DocumentRevision.query.filter(
        DocumentRevision.created_at < cutoff_date
    ).delete()
    
    # Delete old inactive sessions
    old_sessions = UserSession.query.filter(
        UserSession.left_at < cutoff_date,
        UserSession.is_active == False
    ).delete()
    
    # Delete old guest users with no active sessions
    old_guests = User.query.filter(
        User.is_guest == True,
        User.last_active < cutoff_date,
        ~User.sessions.any(UserSession.is_active == True)
    ).delete()
    
    db.session.commit()
    return {
        'revisions_deleted': old_revisions,
        'sessions_deleted': old_sessions,
        'guests_deleted': old_guests
    }