from flask import Flask, render_template, request, jsonify, redirect, url_for, flash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from kubernetes import client, config
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import InputRequired, Length
 
app = Flask(__name__)
app.secret_key = '!@Dhiman09'
 
# Setup Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
 
# In-memory user store for demo purposes
users = {
        'admin': generate_password_hash('password123', method='pbkdf2:sha256')
}
 
# User model for Flask-Login
class User(UserMixin):
    def __init__(self, username):
       self.id = username
 
# Form for login
class LoginForm(FlaskForm):
    username = StringField('Username', validators=[InputRequired(), Length(min=4, max=15)])
    password = PasswordField('Password', validators=[InputRequired(), Length(min=8, max=80)])
    submit = SubmitField('Login')
 
# Flask-Login user loader
@login_manager.user_loader
def load_user(username):
    if username in users:
        return User(username)
    return None
 
# Route for login
@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data
 
        # Check if the user exists and the password matches
        if username in users and check_password_hash(users[username], password):
            user = User(username)
            login_user(user)
            flash('Logged in successfully!')
            return redirect(url_for('index'))
 
        flash('Invalid username or password')
        return redirect(url_for('login'))
 
    return render_template('login.html', form=form)
 
# Route for logout
@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.')
    return redirect(url_for('login'))
 
# Route to serve the dropdown form (requires login)
@app.route('/')
@login_required
def index():
    namespaces = get_namespaces()
    return render_template('index.html', namespaces=namespaces)
 
# Other routes (e.g., /api/deployments, /api/pods, /api/restart, /api/logs) remain unchanged
# ...

# Load Kubernetes config
config.load_kube_config()  # If running locally. Use config.load_incluster_config() when running inside the cluster
 
# Function to get namespaces
def get_namespaces():
    v1 = client.CoreV1Api()
    namespaces = v1.list_namespace().items
    namespace_list = [ns.metadata.name for ns in namespaces]
    return namespace_list
 
# Function to get deployments for a specific namespace
def get_deployments(namespace):
    apps_v1 = client.AppsV1Api()
    deployments = apps_v1.list_namespaced_deployment(namespace=namespace).items
    deployment_list = [deployment.metadata.name for deployment in deployments]
    return deployment_list
 
# Function to get pods based on the deployment name
def get_pods(namespace, deployment_name):
    v1 = client.CoreV1Api()
    pods = v1.list_namespaced_pod(namespace=namespace, label_selector=f'app={deployment_name}').items
    pod_list = [pod.metadata.name for pod in pods]
    return pod_list
 
# Function to restart pods for a deployment (scales down to 0 and then scales back up)
def restart_deployment(namespace, deployment_name):
    apps_v1 = client.AppsV1Api()
    # Get the deployment
    deployment = apps_v1.read_namespaced_deployment(deployment_name, namespace)
    # Scale down the deployment to 0
    replicas = deployment.spec.replicas
    apps_v1.patch_namespaced_deployment_scale(
        name=deployment_name,
        namespace=namespace,
        body={'spec': {'replicas': 0}}
    )
    # Scale back up to original number of replicas
    apps_v1.patch_namespaced_deployment_scale(
        name=deployment_name,
        namespace=namespace,
        body={'spec': {'replicas': replicas}}
    )
    return f"Deployment {deployment_name} restarted in namespace {namespace}"
 
# Function to get logs for a pod
def get_pod_logs(namespace, pod_name):
    v1 = client.CoreV1Api()
    logs = v1.read_namespaced_pod_log(name=pod_name, namespace=namespace)
    return logs
 
 
# API route to fetch deployments for the selected namespace via AJAX
@app.route('/api/deployments', methods=['POST'])
def api_deployments():
    namespace = request.json.get('namespace')
    deployments = get_deployments(namespace)
    return jsonify(deployments)
 
# API route to fetch pods for the selected deployment via AJAX
@app.route('/api/pods', methods=['POST'])
def api_pods():
    namespace = request.json.get('namespace')
    deployment = request.json.get('deployment')
    pods = get_pods(namespace, deployment)
    return jsonify(pods)
 
# API route to restart the selected deployment
@app.route('/api/restart', methods=['POST'])
def api_restart():
    namespace = request.form['namespace']
    deployment = request.form['deployment']
    result = restart_deployment(namespace, deployment)
    return result
 
# API route to download logs for a pod
@app.route('/api/logs', methods=['POST'])
def api_logs():
    namespace = request.form['namespace']
    pod = request.form['pod']
    logs = get_pod_logs(namespace, pod)
    
    # Return logs as a downloadable text file
    return Response(
        logs,
        mimetype='text/plain',
        headers={'Content-Disposition': f'attachment;filename={pod}_logs.txt'}
    )
if __name__ == '__main__':
   app.run(debug=True, host='0.0.0.0', port=5006)
   
