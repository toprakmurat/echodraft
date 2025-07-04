from flask import Flask, render_template, request, jsonify
from flask import send_from_directory, redirect, url_for, flash, session
from flask_socketio import SocketIO, emit, join_room, leave_room
from sqlalchemy import or_ # Import for OR queries

from dotenv import load_dotenv
from datetime import datetime
import uuid
import json
import logging
import os

load_dotenv()

from database import configure_database, get_database_info, get_database_stats, run_maintenance
from models import (
    db, Room, Document, User, UserSession, DocumentRevision, RoomStats,
    get_or_create_room, get_or_create_user, get_or_create_document,
    create_user_session, end_user_session, get_active_room_users,
    update_room_stats
)

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Create and configure the app instance
app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')
configure_database(app)

socketio = SocketIO(app, cors_allowed_origins="*")

active_connections = {}  # socket_id -> {'room_id': str, 'user_id': str}

# Supported languages with their file extensions and syntax highlighting modes
SUPPORTED_LANGUAGES = {
    'python': {'extension': '.py', 'mode': 'python'},
    'javascript': {'extension': '.js', 'mode': 'javascript'},
    'html': {'extension': '.html', 'mode': 'htmlmixed'},
    'css': {'extension': '.css', 'mode': 'css'},
    'java': {'extension': '.java', 'mode': 'text/x-java'},
    'cpp': {'extension': '.cpp', 'mode': 'text/x-c++src'},
    'c': {'extension': '.c', 'mode': 'text/x-csrc'},
    'go': {'extension': '.go', 'mode': 'text/x-go'},
    'rust': {'extension': '.rs', 'mode': 'text/x-rustsrc'},
    'php': {'extension': '.php', 'mode': 'application/x-httpd-php'},
    'ruby': {'extension': '.rb', 'mode': 'text/x-ruby'},
    'sql': {'extension': '.sql', 'mode': 'text/x-sql'},
    'json': {'extension': '.json', 'mode': 'application/json'},
    'xml': {'extension': '.xml', 'mode': 'application/xml'},
    'yaml': {'extension': '.yaml', 'mode': 'text/x-yaml'},
    'markdown': {'extension': '.md', 'mode': 'text/x-markdown'},
    'shell': {'extension': '.sh', 'mode': 'text/x-sh'},
    'typescript': {'extension': '.ts', 'mode': 'text/typescript'},
    'kotlin': {'extension': '.kt', 'mode': 'text/x-kotlin'},
    'swift': {'extension': '.swift', 'mode': 'text/x-swift'}
}

# @app.route('/')
# def index():
#     return render_template('joinEditor.html', languages=SUPPORTED_LANGUAGES)

@app.route('/')
def home():
    """
    Home page. Redirects to login if not authenticated, otherwise shows dashboard.
    """
    if 'user_id' not in session:
        return render_template('home.html')

    user_id = session['user_id']
    user = User.query.get(user_id)
    if user:
        return render_template('joinEditor.html', languages=SUPPORTED_LANGUAGES, user=user)
    else:
        # User ID in session but user not found (e.g., deleted)
        session.pop('user_id', None)
        session.pop('username', None)
        flash('Your session is invalid. Please log in again.', 'danger')
        return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    """
    Handles user login.
    GET: Displays the login form.
    POST: Processes the form submission, authenticates the user.
    """
    if 'user_id' in session: # If already logged in, redirect to home
        return redirect(url_for('home'))

    if request.method == 'POST':
        email_or_username = request.form.get('email_or_username')
        password = request.form.get('password')

        if not email_or_username or not password:
            flash('Please enter your email/username and password.', 'danger')
            return render_template('login.html', email_or_username=email_or_username)

        # Try to find user by email or username
        user = User.query.filter(or_(User.email == email_or_username, User.username == email_or_username)).first()

        if user and user.check_password(password):
            session['user_id'] = user.id
            session['username'] = user.username # Store username for display
            session['is_guest'] = False;
            flash(f'Welcome back, {user.username}!', 'success')
            return redirect(url_for('home'))
        else:
            flash('Invalid email/username or password.', 'danger')
            return render_template('login.html', email_or_username=email_or_username)

    return render_template('login.html')

@app.route('/logout')
def logout():
    """
    Logs out the current user by clearing the session.
    """
    session.pop('user_id', None)
    session.pop('username', None)
    session.pop('is_guest', None)
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    """
    Handles user registration (signup).
    GET: Displays the signup form.
    POST: Processes the form submission, creates a new user.
    """
    if 'user_id' in session: # If already logged in, redirect to home
        return redirect(url_for('home'))

    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')

        if not all([username, email, password, confirm_password]):
            flash('All fields are required!', 'danger')
            return render_template('signup.html', username=username, email=email)

        if password != confirm_password:
            flash('Passwords do not match!', 'danger')
            return render_template('signup.html', username=username, email=email)

        if len(password) < 6:
            flash('Password must be at least 6 characters long.', 'danger')
            return render_template('signup.html', username=username, email=email)

        # Check if username or email already exists
        existing_user = User.query.filter(or_(User.username == username, User.email == email)).first()
        if existing_user:
            if existing_user.username == username:
                flash('Username already taken. Please choose a different one.', 'danger')
            else:
                flash('Email already registered. Please use a different email or log in.', 'danger')
            return render_template('signup.html', username=username, email=email)

        try:
            # Create a new user (let the model handle the UUID)
            new_user = User(username=username, email=email, is_guest=False)
            new_user.set_password(password)
            db.session.add(new_user)
            db.session.commit()
            
            flash('Account created successfully! Please log in.', 'success')
            return redirect(url_for('login'))
        except Exception as e:
            db.session.rollback()
            # Do not expose the actual error, instead log the error 
            flash('An error occurred during registration. Please try again.', 'danger')
            logger.error(f"Error during registration: {e}")
            return render_template('signup.html', username=username, email=email)

    return render_template('signup.html')

@app.route('/editor/<room_id>')
def editor(room_id):
    username = request.args.get('username') or f"Guest-{str(uuid.uuid4())[:6]}"
    language = request.args.get('language')
    
    room = get_or_create_room(room_id, language=language)
    user = get_or_create_user(username)

    # If the room exists but the URL has no language, redirect to add it
    if not language:
        return redirect(url_for('editor', room_id=room.id, username=user.username, language=room.language))

    # If the language in the URL doesn't match the room's language, redirect with correct one
    if language != room.language:
        return redirect(url_for('editor', room_id=room.id, username=user.username, language=room.language))

    # Proceed to render editor page with consistent language
    return render_template('editor.html',
                            room_id=room_id,
                            room=room, 
                            username=user.username, 
                            language=room.language,
                            supported_languages=SUPPORTED_LANGUAGES)

@app.route('/api/rooms/<room_id>')
def get_room_info(room_id):
    """Get room information and statistics"""
    try:
        room = get_or_create_room(room_id)
        document = get_or_create_document(room_id)
        active_users = get_active_room_users(room_id)
        
        return jsonify({
            'room': room.to_dict(),
            'document': document.to_dict(),
            'active_users': [user for user in active_users],
            'user_count': len(active_users)
        })
    except Exception as e:
        logger.error(f"Error getting room info: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/rooms/<room_id>/history')
def get_room_history(room_id):
    """Get document revision history for a room"""
    try:
        document = get_or_create_document(room_id)
        revisions = DocumentRevision.query.filter_by(
            document_id=document.id
        ).order_by(DocumentRevision.created_at.desc()).limit(50).all()
        
        return jsonify({
            'revisions': [revision.to_dict() for revision in revisions]
        })
    except Exception as e:
        logger.error(f"Error getting room history: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/database/info')
def database_info():
    """Get database connection information"""
    return jsonify(get_database_info())

@app.route('/api/database/stats')
def database_stats():
    """Get database statistics"""
    return jsonify(get_database_stats())

@app.route('/api/database/maintenance', methods=['POST'])
def database_maintenance():
    """Run database maintenance tasks"""
    return jsonify(run_maintenance())

@socketio.on('connect')
def on_connect():
    logger.info(f'Client connected: {request.sid}')

@socketio.on('disconnect')
def on_disconnect():
    logger.info(f'Client disconnected: {request.sid}')
    
    try:
        # End user session in database
        user_session = end_user_session(request.sid)
        
        if user_session and request.sid in active_connections:
            room_id = active_connections[request.sid]['room_id']
            user_id = active_connections[request.sid]['user_id']
            
            # Remove from active connections
            del active_connections[request.sid]
            
            # Get updated active users list
            active_users = get_active_room_users(room_id)
            
            # Notify other users in the room
            emit('user_left', {
                'user_id': user_id,
                'active_users': len(active_users),
                'users': [user for user in active_users]
            }, room=room_id)
            
            # Update room statistics
            update_room_stats(room_id)
            
            # Delete if the user is guest
            user = User.query.get(user_id)

            if not user:
                return f"User with ID {user_id} not found.", 404

            if user.is_guest:
                db.session.delete(user)
                db.session.commit()

    except Exception as e:
        logger.error(f"Error handling disconnect: {str(e)}")

@socketio.on('join_room')
def on_join_room(data):
    try:
        room_id = data['room_id']
        username = data.get('username', f'User_{request.sid[:8]}')
        language = data.get('language', 'javascript')

        # Get or create room
        room = get_or_create_room(room_id)
        
        # Get or create user
        # user = get_or_create_user(username, request.sid)
        user = get_or_create_user(username)

        # Create user session
        session = create_user_session(user.id, room_id, request.sid)
        
        # Join socket room
        join_room(room_id)
        
        # Store connection info
        active_connections[request.sid] = {
            'room_id': room_id,
            'user_id': user.id
        }
        
        # Get or create document
        document = get_or_create_document(
            room_id,
            initial_content='# Welcome to the collaborative editor!\n# Start typing to begin...',
            language=language
        )
        
        # Get active users in room
        active_users = get_active_room_users(room_id)
        
        # Send current document state to the new user
        emit('document_state', {
            'content': document.content,
            'language': document.language,
            'version': document.version,
            'room_info': room.to_dict(),
            'active_users': [user_data for user_data in active_users]
        })
        
        # Notify other users about the new user
        emit('user_joined', {
            'user_id': user.id,
            'username': username,
            'active_users': len(active_users),
            'users': [user_data for user_data in active_users]
        }, room=room_id)
        
        logger.info(f'User {username} joined room {room_id}')
        
    except Exception as e:
        logger.error(f"Error joining room: {str(e)}")
        emit('error', {'message': 'Failed to join room'})

@socketio.on('leave_room')
def on_leave_room(data):
    try:
        room_id = data['room_id']
        leave_room(room_id)
        
        if request.sid in active_connections:
            user_id = active_connections[request.sid]['user_id']
            
            # End user session
            end_user_session(request.sid)
            
            # Remove from active connections
            del active_connections[request.sid]
            
            # Get updated active users
            active_users = get_active_room_users(room_id)
            
            # Notify other users
            emit('user_left', {
                'user_id': user_id,
                'active_users': len(active_users),
                'users': [user_data for user_data in active_users]
            }, room=room_id)

            # Delete if the user is guest
            user = User.query.get(user_id)

            if not user:
                return f"User with ID {user_id} not found.", 404

            if user.is_guest:
                db.session.delete(user)
                db.session.commit()
            
    except Exception as e:
        logger.error(f"Error leaving room: {str(e)}")

@socketio.on('text_change')
def on_text_change(data):
    try:
        room_id = data['room_id']
        content = data['content']
        
        if request.sid not in active_connections:
            emit('error', {'message': 'Not connected to room'})
            return
        
        user_id = active_connections[request.sid]['user_id']
        
        # Get document
        document = get_or_create_document(room_id)
        
        # Create revision before updating
        document.create_revision(user_id, 'edit')
        
        # Update document content
        document.content = content
        document.updated_at = datetime.utcnow()
        db.session.commit()
        
        # Broadcast change to all other users in the room
        emit('text_change', {
            'content': content,
            'user_id': user_id,
            'version': document.version
        }, room=room_id, include_self=False)
        
    except Exception as e:
        logger.error(f"Error handling text change: {str(e)}")
        emit('error', {'message': 'Failed to save changes'})

@socketio.on('cursor_change')
def on_cursor_change(data):
    try:
        room_id = data['room_id']
        cursor_data = data['cursor']
        
        if request.sid not in active_connections:
            return
        
        user_id = active_connections[request.sid]['user_id']
        username = User.query.get(user_id).username
        # Update cursor position in session
        session = UserSession.query.filter_by(
            socket_id=request.sid,
            is_active=True
        ).first()
        
        if session:
            session.set_cursor_position(cursor_data.get('line', 0), cursor_data.get('ch', 0))
            db.session.commit()
            
            # Broadcast cursor position to all other users in the room
            emit('cursor_change', {
                'user_id': user_id,
                'username': username,
                'cursor': cursor_data
            }, room=room_id, include_self=False)
            
    except Exception as e:
        logger.error(f"Error handling cursor change: {str(e)}")

@socketio.on('language_change')
def on_language_change(data):
    try:
        room_id = data['room_id']
        language = data['language']
        
        if request.sid not in active_connections:
            emit('error', {'message': 'Not connected to room'})
            return
        
        if language not in SUPPORTED_LANGUAGES:
            emit('error', {'message': 'Unsupported language'})
            return
        
        user_id = active_connections[request.sid]['user_id']
        
        # Get document
        document = get_or_create_document(room_id)
        
        # Create revision before updating
        document.create_revision(user_id, 'language_change')
        
        # Update document language
        document.language = language
        document.updated_at = datetime.utcnow()
        db.session.commit()
        
        # Broadcast language change to all users in the room
        emit('language_change', {
            'language': language,
            'user_id': user_id,
            'version': document.version
        }, room=room_id, include_self=False)
        
    except Exception as e:
        logger.error(f"Error handling language change: {str(e)}")
        emit('error', {'message': 'Failed to change language'})

@socketio.on('get_document_info')
def on_get_document_info(data):
    try:
        room_id = data['room_id']
        
        # Get document and room info
        document = get_or_create_document(room_id)
        room = get_or_create_room(room_id)
        active_users = get_active_room_users(room_id)
        
        emit('document_info', {
            'language': document.language,
            'version': document.version,
            'last_modified': document.updated_at.isoformat(),
            'active_users': len(active_users),
            'room_info': room.to_dict(),
            'users': [user_data for user_data in active_users]
        })
        
    except Exception as e:
        logger.error(f"Error getting document info: {str(e)}")
        emit('error', {'message': 'Failed to get document info'})

@socketio.on('get_revision_history')
def on_get_revision_history(data):
    try:
        room_id = data['room_id']
        limit = data.get('limit', 20)
        
        # Get document
        document = get_or_create_document(room_id)
        
        # Get revisions
        revisions = DocumentRevision.query.filter_by(
            document_id=document.id
        ).order_by(DocumentRevision.created_at.desc()).limit(limit).all()
        
        emit('revision_history', {
            'revisions': [revision.to_dict() for revision in revisions]
        })
        
    except Exception as e:
        logger.error(f"Error getting revision history: {str(e)}")
        emit('error', {'message': 'Failed to get revision history'})

@socketio.on('restore_revision')
def on_restore_revision(data):
    try:
        room_id = data['room_id']
        revision_id = data['revision_id']
        
        if request.sid not in active_connections:
            emit('error', {'message': 'Not connected to room'})
            return
        
        user_id = active_connections[request.sid]['user_id']
        
        # Get revision
        revision = DocumentRevision.query.filter_by(id=revision_id).first()
        if not revision:
            emit('error', {'message': 'Revision not found'})
            return
        
        # Get document
        document = get_or_create_document(room_id)
        
        # Create revision before restoring
        document.create_revision(user_id, 'restore')
        
        # Restore content
        document.content = revision.content
        document.language = revision.language
        document.updated_at = datetime.utcnow()
        db.session.commit()
        
        # Broadcast restore to all users in the room
        emit('document_restored', {
            'content': document.content,
            'language': document.language,
            'version': document.version,
            'restored_from': revision.version
        }, room=room_id)
        
    except Exception as e:
        logger.error(f"Error restoring revision: {str(e)}")
        emit('error', {'message': 'Failed to restore revision'})

if __name__ == '__main__':
    socketio.run(app, debug=True, host='0.0.0.0', port=3000)