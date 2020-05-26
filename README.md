# Introduction

Welcome to a simple HTTP Only Cookie backend with Flask.

# Clone the repo

`git clone https://github.com/pwaldo2/tutorial-flask-http-only.git`

# Install a Virtual Environment for Python 3

```
cd tutorial-flask-http-only
python3 -m venv ./venv
```

# Activate the virtual environment

`source venv/bin/activate`

# Install the requirements

`pip install -r requirements.txt`

# Create your postgres

`createdb testusers`

# Update any environment variables

Edit the .env.example file and rename it to .env

You'll first want to change the first two to use the same secret

SECRET_KEY="MY-PRECIOUS"
JWT_SECRET_KEY="MY-PRECIOUS"

In your Python terminal do this to generate a random set of 24 numbers and characters:

```
>>> import secrets
>>> secrets.token_urlsafe(24)
'aaQYj72RKo4kc60B9fhkm5SmqTFEemFO'
```

Replace `MY-PRECIOUS` with the string generated in both cases.

Unless you used a different DB name, you do not need to change `DATABASE_URL`

# Initialize your data models

`python manage.py db upgrade`

# Initialize some data

```
flask initialize roles
flask initialize company
flask initialize user
```

Good luck! And remember...Read the source Luke!
