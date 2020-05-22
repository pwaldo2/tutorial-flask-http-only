import os
from api import create_app

app = create_app()
app.run(host='0.0.0.0',
        port=int(os.getenv('PORT', 5000)))