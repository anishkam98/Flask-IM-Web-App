def db(app):
      
      # This secret key is a placeholder and should not be used in deployment
      # Generate a random string to use for the secret key in deployment and store it somewhere safe
      # Ex. Can use secrets.token_urlsafe(16), secrets.token_hex(16), uuid.uuid4().hex, os.urandom(12), etc.
      app.secret_key = '1234'

      # Enter database connection details
      # For docker app container with docker database
      app.config['MYSQL_HOST'] = 'db'
      app.config['MYSQL_USER'] = 'root'
      app.config['MYSQL_PASSWORD'] = 'root'
      app.config['MYSQL_DB'] = 'chatapp'
      
      # For venv with docker database
      #app.config['MYSQL_HOST'] = '127.0.0.1'
      #app.config['MYSQL_USER'] = ''
      #app.config['MYSQL_PASSWORD'] = ''
      #app.config['MYSQL_DB'] = 'chatapp'