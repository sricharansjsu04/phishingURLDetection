from flask import Flask, request, jsonify, send_from_directory
from extractFeatures import extract_features, predict_url

app = Flask(__name__)

@app.route('/')
def index():
    return send_from_directory('.', 'index.html')  # Ensure it serves the correct HTML file

@app.route('/api/predict', methods=['POST'])
def predict():
    data = request.get_json()
    url = data.get('url')
    if not url:
        return jsonify({'error': 'URL is required'}), 400

    # Extract features
    features = extract_features(url)
    feature_names = [
        'Have_IP', 'Have_At', 'URL_Length', 'URL_Depth', 'Redirection',
        'https_Domain', 'TinyURL', 'Prefix/Suffix', 'DNS_Record',
        'Web_Traffic', 'Domain_Age', 'Domain_End', 'iFrame',
        'Mouse_Over', 'Right_Click', 'Web_Forwards'
    ]
    feature_map = dict(zip(feature_names, features))

    # Get prediction
    prediction = predict_url(url)

    return jsonify({'features': feature_map, 'result': prediction})

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080, debug=True)
