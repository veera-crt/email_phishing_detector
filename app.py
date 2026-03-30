from flask import Flask, render_template, request, redirect, url_for, flash, jsonify
from werkzeug.utils import secure_filename
import os
import json
from datetime import datetime
from config import Config
from email_analyzer import EmailAnalyzer

app = Flask(__name__)
app.config.from_object(Config)

# Ensure upload directory exists
if not os.path.exists(app.config['UPLOAD_FOLDER']):
    os.makedirs(app.config['UPLOAD_FOLDER'])

analyzer = EmailAnalyzer(Config)

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/upload', methods=['POST'])
def upload_file():
    if 'email_file' not in request.files:
        flash('No file part')
        return redirect(request.url)
    
    file = request.files['email_file']
    if file.filename == '':
        flash('No selected file')
        return redirect(request.url)
    
    if file and allowed_file(file.filename):
        # Clear uploads folder first to remove old files
        for f in os.listdir(app.config['UPLOAD_FOLDER']):
            os.remove(os.path.join(app.config['UPLOAD_FOLDER'], f))
            
        filename = secure_filename(file.filename)
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(filepath)
        
        # Analyze the email immediately
        results = analyzer.analyze_email(filepath)
        
        # Optional: delete the file after analysis to "not store here after"
        try:
            os.remove(filepath)
        except:
            pass
            
        return render_template('analyze.html', results=results, filename=filename)
    
    flash('Invalid file type')
    return redirect(url_for('index'))

@app.route('/analyze/<filename>')
def analyze_email(filename):
    # This route is now handled directly by /upload for immediate analysis
    return redirect(url_for('index'))

@app.route('/api/analyze', methods=['POST'])
def api_analyze():
    if 'email_file' not in request.files:
        return jsonify({'error': 'No file provided'}), 400
    
    file = request.files['email_file']
    if file.filename == '':
        return jsonify({'error': 'No selected file'}), 400
    
    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(filepath)
        
        # Analyze the email
        results = analyzer.analyze_email(filepath)
        
        return jsonify(results)
    
    return jsonify({'error': 'Invalid file type'}), 400

@app.route('/api/whitelist', methods=['GET', 'POST'])
def api_whitelist():
    if request.method == 'GET':
        return jsonify(analyzer.whitelist)
    else:
        try:
            new_whitelist = request.get_json()
            analyzer.whitelist = new_whitelist
            analyzer.save_whitelist()
            return jsonify({'status': 'success'})
        except Exception as e:
            return jsonify({'error': str(e)}), 400

if __name__ == '__main__':
    app.run(debug=True)
