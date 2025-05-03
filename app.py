from flask import Flask, render_template, request
import joblib
import feature_extractor  # Your custom module
import pandas as pd

app = Flask(__name__)
model = joblib.load('random_forest_model.pkl')  # Ensure model path is correct

@app.route('/')
def home():
    return render_template('index.html')

@app.route("/predict", methods=["POST"])
def predict():
    url = request.form["url"]
    
    # Extract features and meta information
    features, meta = feature_extractor.extract_features(url, return_meta=True)

    # Define column names as per model training
    columns = [
        'having_IP_Address', 'URL_Length', 'Shortining_Service', 'having_At_Symbol', 'double_slash_redirecting',
        'Prefix_Suffix', 'having_Sub_Domain', 'SSLfinal_State', 'Domain_registration_length', 'Favicon', 'port',
        'HTTPS_token', 'Request_URL', 'URL_of_Anchor', 'Links_in_tags', 'SFH', 'Submitting_to_email', 'Abnormal_URL',
        'Redirect', 'on_mouseover', 'RightClick', 'popUpWindow', 'Iframe', 'age_of_domain', 'DNSRecord', 'web_traffic',
        'Page_Rank', 'Google_Index', 'Links_pointing_to_page', 'Statistical_report'
    ]
    
    # Convert features to DataFrame
    X = pd.DataFrame([features], columns=columns)

    # Predict label and probability
    label = model.predict(X)[0]
    proba = model.predict_proba(X)[0]
    
    # Use label for main result
    prediction = "🔴Phishing" if label == -1 else "🟢Safe"
    confidence = proba[1] if label == 1 else proba[0]
    color = "green" if label == 1 else "red"

    # Optional risk level (not used in frontend anymore, but you can add it if needed)
    risk_level = "Low" if confidence >= 0.85 else "Medium" if confidence >= 0.6 else "High"

    return render_template(
        "index.html",
        prediction=prediction,
        url=url,
        color=color,
        confidence=confidence,
        risk_level=risk_level,
        domain=meta.get('domain', ''),
        issuer=meta.get('issuer', ''),
        cert_age=meta.get('cert_age', 'N/A'),
        domain_age=meta.get('domain_age', 'N/A'),
        red_flags=meta.get('red_flags', [])
    )

if __name__ == '__main__':
    app.run(debug=True)
