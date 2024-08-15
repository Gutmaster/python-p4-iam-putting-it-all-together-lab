#!/usr/bin/env python3

from flask import request, session, make_response
from flask_restful import Resource
from sqlalchemy.exc import IntegrityError

from config import app, db, api
from models import User, Recipe

class Signup(Resource):
    def post(self):
        username = request.json.get('username')
        password = request.json.get('password')
        image_url = request.json.get('image_url')
        bio = request.json.get('bio')

        if not username or not password or not image_url or not bio:
            return {'error': 'Missing required fields'}, 422

        if User.query.filter_by(username=username).first():
            return {'error': 'Username already exists'}, 422

        user = User(username=username, image_url=image_url, bio=bio)
        
        user.password_hash = password

        db.session.add(user)
        db.session.commit()

        session['user_id'] = user.id
        return {'message': 'User created successfully'}, 201

class CheckSession(Resource):
    def get(self):
        if session.get('user_id'):
            user = User.query.filter_by(id=session['user_id']).first()
            return {'id': user.id, 'username': user.username, 'image_url': user.image_url, 'bio': user.bio}, 200
        else:
            return {'error': 'No active session'}, 401

class Login(Resource):
    def post(self):
        username = request.json.get('username')
        password = request.json.get('password')

        if not username or not password:
            return {'error': 'Missing required fields'}, 422

        user = User.query.filter_by(username=username).first()

        if user and user.authenticate(password):
            session['user_id'] = user.id
            return {'id': user.id, 'username': user.username, 'image_url': user.image_url, 'bio': user.bio}, 200
        else:
            return {'error': 'Invalid credentials'}, 401

class Logout(Resource):
    def delete(self):
        if session.get('user_id'):
            session['user_id'].pop()
            return {'message': 'Logged out successfully'}, 200
        else:
            return {'error': 'No active session'}, 401

class RecipeIndex(Resource):
    def get(self):
        if session.get('user_id'):
            recipes = Recipe.query.all()
            return make_response([{'title': recipe.title, 
                     'instructions': recipe.instructions, 
                     'minutes_to_complete': recipe.minutes_to_complete} for recipe in recipes], 200)
        else:
            return {'error': 'unauthorized'}, 401
        
    def post(self):
        if session.get('user_id'):
            title = request.json.get('title')
            instructions = request.json.get('instructions')
            minutes_to_complete = request.json.get('minutes_to_complete')

            if not title or not instructions or not minutes_to_complete:
                return {'error': 'Missing required fields'}, 422

            try:
                recipe = Recipe(title=title, instructions=instructions, minutes_to_complete=minutes_to_complete)
            except ValueError:
                return {'error': 'Invalid recipe data'}, 422
            
            recipe.user_id = session['user_id']
 
            db.session.add(recipe)
            db.session.commit()

            user = user = User.query.filter_by(id=session['user_id']).first()

            return {'title': recipe.title, 
                    'instructions': recipe.instructions,
                    'minutes_to_complete': recipe.minutes_to_complete,
                    'user': user.to_dict()}, 201
        else:
            return {'error': 'unauthorized'}, 401


api.add_resource(Signup, '/signup', endpoint='signup')
api.add_resource(CheckSession, '/check_session', endpoint='check_session')
api.add_resource(Login, '/login', endpoint='login')
api.add_resource(Logout, '/logout', endpoint='logout')
api.add_resource(RecipeIndex, '/recipes', endpoint='recipes')


if __name__ == '__main__':
    app.run(port=5555, debug=True)