from flask import Blueprint, request, jsonify, session
from datetime import datetime
from bson import ObjectId  # Add this import
from bson.json_util import dumps  # For proper ObjectId serialization

chat_bp = Blueprint('chat', __name__)
chathistory = None

def init_chat(db):
    global chathistory
    chathistory = db['chathistory']
    chathistory.create_index("username")

@chat_bp.route('/send', methods=['POST'])
def send_message():
    if 'username' not in session:
        return jsonify({'error': 'Unauthorized'}), 401

    data = request.json
    user_msg = data.get('message', '').strip()
    if not user_msg:
        return jsonify({'error': 'Empty message'}), 400

    username = session['username']
    bot_response = f"You said: {user_msg}"  # dummy bot

    entry = {
        "_id": ObjectId(),  # Generate unique ID for each message
        "message": user_msg,  # Changed from "user" to match frontend
        "bot_response": bot_response,  # Changed from "bot" to match frontend
        "timestamp": datetime.utcnow()
    }

    try:
        chathistory.update_one(
            {'username': username},
            {'$push': {'messages': entry}},
            upsert=True
        )
        return jsonify({
            "_id": str(entry["_id"]),
            "message": entry["message"],
            "bot_response": entry["bot_response"],
            "timestamp": entry["timestamp"].isoformat()
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@chat_bp.route('/history', methods=['GET'])
def get_history():
    if 'username' not in session:
        return jsonify({'error': 'Unauthorized'}), 401

    try:
        user_data = chathistory.find_one({'username': session['username']})
        if not user_data:
            return jsonify([])
        
        # Convert ObjectId to string and datetime to ISO format
        messages = []
        for msg in user_data.get('messages', []):
            messages.append({
                "_id": str(msg["_id"]),
                "message": msg.get("message", ""),
                "bot_response": msg.get("bot_response", ""),
                "timestamp": msg["timestamp"].isoformat()
            })
        return jsonify(messages)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@chat_bp.route('/delete/<string:msg_id>', methods=['DELETE'])
def delete_entry(msg_id):
    if 'username' not in session:
        return jsonify({'error': 'Unauthorized'}), 401

    try:
        username = session['username']
        result = chathistory.update_one(
            {'username': username},
            {'$pull': {'messages': {'_id': ObjectId(msg_id)}}}
        )
        
        if result.modified_count == 0:
            return jsonify({'error': 'Message not found'}), 404
            
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@chat_bp.route('/update/<string:msg_id>', methods=['PUT'])
def update_entry(msg_id):
    if 'username' not in session:
        return jsonify({'error': 'Unauthorized'}), 401

    data = request.json
    new_message = data.get('message', '').strip()
    if not new_message:
        return jsonify({'error': 'Empty message'}), 400

    try:
        username = session['username']
        result = chathistory.update_one(
            {'username': username, 'messages._id': ObjectId(msg_id)},
            {'$set': {'messages.$.message': new_message}}
        )
        
        if result.modified_count == 0:
            return jsonify({'error': 'Message not found'}), 404
            
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'error': str(e)}), 500