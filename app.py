from flask import Flask, render_template
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy
from flask_mail import Mail
from config import Config
from models.models import db  # ✅ Import `db` properly

mail = Mail()

def create_app():
    app = Flask(__name__, template_folder='template')
    app.config.from_object(Config)

    mail.init_app(app)  # ✅ Initialize mail
    db.init_app(app)  # ✅ Initialize database

    with app.app_context():  # ✅ Ensure tables are created within app context
        db.create_all()

    # ✅ Import Blueprints here (AFTER initializing app)
    from routes.auth_routes import auth, ui_feature, tables, samples  
    app.register_blueprint(auth)
    app.register_blueprint(ui_feature)
    app.register_blueprint(tables)
    app.register_blueprint(samples)

    CORS(app)

    @app.route("/")
    def home():
        return render_template("index.html")

    return app

if __name__ == "__main__":
    app = create_app()
    app.run(debug=True, port=5001)
