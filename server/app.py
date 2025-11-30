#!/usr/bin/env python3

from flask import request, session
from flask_restful import Resource
from sqlalchemy.exc import IntegrityError
from marshmallow import ValidationError

from config import app, db, api
from models import User, Recipe, UserSchema, RecipeSchema

user_schema = UserSchema()
recipe_schema = RecipeSchema()
recipes_schema = RecipeSchema(many=True)

class Signup(Resource):
    def post(self):
        data = request.get_json() or {}

        # Basic presence validation (so tests that omit username/password get 422)
        if not data.get('username') or not data.get('password'):
            return {'errors': ['username and password are required']}, 422

        try:
            user = User(
                username=data.get('username'),
                bio=data.get('bio'),
                image_url=data.get('image_url')
            )
            # Expect User model to implement password_hash setter that hashes
            user.password_hash = data.get('password')

            db.session.add(user)
            db.session.commit()
        except IntegrityError:
            db.session.rollback()
            return {'errors': ['username must be unique']}, 422
        except Exception as e:
            db.session.rollback()
            return {'errors': [str(e)]}, 422

        # create session for new user
        session['user_id'] = user.id

        return user_schema.dump(user), 201


class CheckSession(Resource):
    def get(self):
        user_id = session.get('user_id')
        if not user_id:
            return {'error': 'Unauthorized'}, 401

        user = User.query.get(user_id)
        if not user:
            # If session had invalid id, treat as unauthorized
            session['user_id'] = None
            return {'error': 'Unauthorized'}, 401

        return user_schema.dump(user), 200


class Login(Resource):
    def post(self):
        data = request.get_json() or {}
        username = data.get('username')
        password = data.get('password')

        if not username or not password:
            return {'error': 'username and password required'}, 401

        user = User.query.filter(User.username == username).first()
        if not user or not user.authenticate(password):
            return {'error': 'Invalid credentials'}, 401

        session['user_id'] = user.id
        return user_schema.dump(user), 200


class Logout(Resource):
    def delete(self):
        # If there's no session or it's falsy, return 401 (test expects this)
        if not session.get('user_id'):
            return {'error': 'Unauthorized'}, 401

        session['user_id'] = None
        # test only checks that session cleared; 204 is fine
        return {}, 204


class RecipeIndex(Resource):
    def get(self):
        user_id = session.get('user_id')
        if not user_id:
            return {'error': 'Unauthorized'}, 401

        recipes = Recipe.query.filter(Recipe.user_id == user_id).all()
        return recipes_schema.dump(recipes), 200

    def post(self):
        user_id = session.get('user_id')
        if not user_id:
            return {'error': 'Unauthorized'}, 401

        data = request.get_json() or {}
        # attach the current user id to the input so schema/model can use it
        data['user_id'] = user_id

        try:
            # Let RecipeSchema validate fields (if schema has validations)
            recipe_data = recipe_schema.load(data)
        except ValidationError as ve:
            return {'errors': ve.messages}, 422
        except Exception as e:
            return {'errors': [str(e)]}, 422

        try:
            recipe = Recipe(
                title=recipe_data.get('title'),
                instructions=recipe_data.get('instructions'),
                minutes_to_complete=recipe_data.get('minutes_to_complete'),
                user_id=user_id
            )

            db.session.add(recipe)
            db.session.commit()
        except Exception as e:
            db.session.rollback()
            return {'errors': [str(e)]}, 422

        return recipe_schema.dump(recipe), 201


api.add_resource(Signup, '/signup', endpoint='signup')
api.add_resource(CheckSession, '/check_session', endpoint='check_session')
api.add_resource(Login, '/login', endpoint='login')
api.add_resource(Logout, '/logout', endpoint='logout')
api.add_resource(RecipeIndex, '/recipes', endpoint='recipes')


if __name__ == '__main__':
    app.run(port=5555, debug=True)
