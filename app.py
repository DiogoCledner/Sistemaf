from flask import Flask, redirect, url_for, session, request, render_template, flash
from flask_sqlalchemy import SQLAlchemy
from authlib.integrations.flask_client import OAuth
import requests

app = Flask(__name__)
app.secret_key = '3345567778765'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
db = SQLAlchemy(app)
oauth = OAuth(app)

# Configurando OAuth do Facebook
facebook = oauth.register(
    name='facebook',
    client_id='570924121990330',
    client_secret='5cf096c37c477f59fcfee16',
    access_token_url='https://graph.facebook.com/oauth/access_token',
    authorize_url='https://www.facebook.com/dialog/oauth',
    authorize_params=None,
    api_base_url='https://graph.facebook.com/',
    client_kwargs={'scope': 'email,public_profile,publish_to_groups'},
)

# Modelo de usuário
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    facebook_token = db.Column(db.String(200))

# Rota inicial
@app.route('/')
def home():
    return render_template('home.html')

# Rota de cadastro
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        if User.query.filter_by(email=email).first():
            flash('Usuário já existe.')
            return redirect(url_for('signup'))
        user = User(username=username, email=email)
        db.session.add(user)
        db.session.commit()
        flash('Cadastro realizado com sucesso.')
        return redirect(url_for('home'))
    return render_template('signup.html')

# Rota de login com Facebook
@app.route('/login/facebook')
def login_facebook():
    redirect_uri = url_for('facebook_authorized', _external=True)
    return facebook.authorize_redirect(redirect_uri)

# Callback após autorização do Facebook
@app.route('/login/facebook/authorized')
def facebook_authorized():
    token = facebook.authorize_access_token()
    if token is None:
        flash('Acesso negado ao Facebook.')
        return redirect(url_for('home'))

    session['facebook_token'] = token

    # Obter dados do usuário do Facebook
    facebook_data = facebook.get('me?fields=id,name,email').json()

    # Atualiza o token do usuário no banco de dados
    user = User.query.filter_by(email=facebook_data['email']).first()
    if user:
        user.facebook_token = token['access_token']
        db.session.commit()
        flash('Conta do Facebook conectada com sucesso.')
    else:
        flash('Usuário não encontrado.')

    return redirect(url_for('home'))

# Rota para publicar no Facebook
@app.route('/post_to_facebook', methods=['POST'])
def post_to_facebook():
    message = request.form['message']
    user = User.query.first()  # Aqui simplificado, você pode implementar login real
    if user.facebook_token:
        url = f"https://graph.facebook.com/me/feed?message={message}&access_token={user.facebook_token}"
        r = requests.post(url)
        if r.status_code == 200:
            flash('Publicado com sucesso no Facebook!')
        else:
            flash('Falha ao publicar no Facebook.')
    else:
        flash('Nenhuma conta do Facebook conectada.')
    return redirect(url_for('home'))

if __name__ == '__main__':
    with app.app_context():  # Cria um contexto de aplicação
        db.create_all()  # Garante que db.create_all() seja executado dentro do contexto
    app.run(debug=True)

