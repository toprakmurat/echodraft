import os
import shutil
import logging
from flask import current_app
from datetime import datetime
from models import db, init_db, cleanup_old_data

class DatabaseConfig:
    def __init__(self):
        self.database_url = self._get_database_url()
        self.engine_options = self._get_engine_options()

    def _get_database_url(self):
        """Return SQLite database URL"""
        return os.getenv('DATABASE_URL')

    def _get_engine_options(self):
        """Return engine options for SQLite"""
        return {
            'pool_pre_ping': True,
            'pool_timeout': 20,
            'pool_recycle': -1
        }

def configure_database(app):
    """Configure database for Flask app"""
    config = DatabaseConfig()
    app.config['SQLALCHEMY_DATABASE_URI'] = config.database_url
    app.config['SQLALCHEMY_ENGINE_OPTIONS'] = config.engine_options
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    db.init_app(app)

    with app.app_context():
        init_db()

    logging.info(f"Database configured: {config.database_url}")

def get_database_info():
    """Get SQLite database connection info"""
    try:
        result = db.session.execute(db.text('SELECT 1')).fetchone()
        if result:
            return {
                'status': 'connected',
                'type': 'SQLite',
                'url': current_app.config.get('SQLALCHEMY_DATABASE_URI', '')
            }
    except Exception as e:
        return {
            'status': 'error',
            'error': str(e)
        }

def backup_database():
    """Create SQLite database backup"""
    try:
        database_url = current_app.config.get('SQLALCHEMY_DATABASE_URI', '')
        db_path = database_url.replace('sqlite:///', '')
        backup_path = f"{db_path}.backup_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        shutil.copy2(db_path, backup_path)
        return {'status': 'success', 'backup_path': backup_path}
    except Exception as e:
        return {'status': 'error', 'error': str(e)}

def run_maintenance():
    """Run maintenance tasks for SQLite"""
    try:
        cleanup_stats = cleanup_old_data(days_to_keep=30)
        db.session.execute(db.text('VACUUM'))
        db.session.commit()

        return {
            'status': 'success',
            'cleanup_stats': cleanup_stats,
            'maintenance_completed': datetime.utcnow().isoformat()
        }
    except Exception as e:
        return {'status': 'error', 'error': str(e)}

def get_database_stats():
    """Return basic SQLite database statistics"""
    try:
        from models import Room, Document, User, UserSession, DocumentRevision, RoomStats

        stats = {
            'rooms': {
                'total': Room.query.count(),
                'active': Room.query.filter_by(is_active=True).count()
            },
            'documents': {
                'total': Document.query.count(),
                'by_language': {}
            },
            'users': {
                'total': User.query.count(),
                'guests': User.query.filter_by(is_guest=True).count(),
                'registered': User.query.filter_by(is_guest=False).count()
            },
            'sessions': {
                'total': UserSession.query.count(),
                'active': UserSession.query.filter_by(is_active=True).count(),
                'today': UserSession.query.filter(
                    db.func.date(UserSession.joined_at) == datetime.utcnow().date()
                ).count()
            },
            'revisions': {
                'total': DocumentRevision.query.count(),
                'today': DocumentRevision.query.filter(
                    db.func.date(DocumentRevision.created_at) == datetime.utcnow().date()
                ).count()
            }
        }

        language_stats = db.session.query(
            Document.language,
            db.func.count(Document.id)
        ).group_by(Document.language).all()

        stats['documents']['by_language'] = {lang: count for lang, count in language_stats}
        return stats

    except Exception as e:
        return {'error': str(e)}

def check_database_health():
    """Check SQLite health"""
    try:
        start_time = datetime.utcnow()
        result = db.session.execute(db.text('SELECT 1')).fetchone()
        from models import Room
        room_count = Room.query.count()
        end_time = datetime.utcnow()
        return {
            'status': 'healthy',
            'response_time_seconds': (end_time - start_time).total_seconds(),
            'table_access': 'ok',
            'room_count': room_count
        }
    except Exception as e:
        return {
            'status': 'unhealthy',
            'error': str(e)
        }

def create_indexes():
    """Create indexes for SQLite"""
    try:
        indexes = [
            'CREATE INDEX IF NOT EXISTS idx_rooms_created_at ON rooms(created_at)',
            'CREATE INDEX IF NOT EXISTS idx_rooms_is_active ON rooms(is_active)',
            'CREATE INDEX IF NOT EXISTS idx_documents_room_id ON documents(room_id)',
            'CREATE INDEX IF NOT EXISTS idx_documents_updated_at ON documents(updated_at)',
            'CREATE INDEX IF NOT EXISTS idx_user_sessions_room_id ON user_sessions(room_id)',
            'CREATE INDEX IF NOT EXISTS idx_user_sessions_user_id ON user_sessions(user_id)',
            'CREATE INDEX IF NOT EXISTS idx_user_sessions_is_active ON user_sessions(is_active)',
            'CREATE INDEX IF NOT EXISTS idx_user_sessions_joined_at ON user_sessions(joined_at)',
            'CREATE INDEX IF NOT EXISTS idx_document_revisions_document_id ON document_revisions(document_id)',
            'CREATE INDEX IF NOT EXISTS idx_document_revisions_created_at ON document_revisions(created_at)',
            'CREATE INDEX IF NOT EXISTS idx_users_is_guest ON users(is_guest)',
            'CREATE INDEX IF NOT EXISTS idx_users_last_active ON users(last_active)',
            'CREATE INDEX IF NOT EXISTS idx_room_stats_room_id ON room_stats(room_id)',
            'CREATE INDEX IF NOT EXISTS idx_room_stats_date ON room_stats(date)'
        ]

        for sql in indexes:
            db.session.execute(db.text(sql))
        db.session.commit()
        return {'status': 'success', 'indexes_created': len(indexes)}
    except Exception as e:
        return {'status': 'error', 'error': str(e)}