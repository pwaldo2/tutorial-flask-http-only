from flask import Blueprint

auth_bp = Blueprint('auth_bp', __name__, url_prefix='/auth')

# Custom Views

@auth_bp.route('/')
def auth():
    return "Auth route!"