# 🔐 Phishing URL Detector – Machine Learning Based URL Classifier

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](./LICENSE)
[![Live Demo](https://img.shields.io/badge/Try%20It-Live-green)](https://phishing-url-detector-w4ih.onrender.com)
![Flask](https://img.shields.io/badge/Backend-Flask-lightgrey)
![ML Model](https://img.shields.io/badge/Model-RandomForest-orange)
![Accuracy](https://img.shields.io/badge/Accuracy-97%25-brightgreen)

This project is a machine learning-based web application that detects whether a given URL is **safe** or **phishing**. It uses a trained **Random Forest classifier** on a dataset of labeled URLs and is deployed with a Flask backend and a simple frontend built using Streamlit and HTML/CSS.

Created by: **Iffah Aafreen**  
As a part of MS AINSI Internship Capstone Project – 2025, conducted by Edunet Foundation.

## 📑 Table of Contents 
- [Features](#features)
- [Model Evaluation](#model-evaluation)
- [Technology Used](#technology-used)  
- [Local Installation Guide](#local-installation-guide)  
- [Try It Live](#try-it-live)
- [Citations](#citations)
- [License](#license)  
- [Contact](#contact)  

## Features

- 🔍 **URL Classification** – Detects phishing or legitimate URLs.
- 🧠 **ML Model Integration** – Random Forest model trained on labeled phishing dataset.
- 📊 **Model Accuracy** – Achieves ~97% accuracy on validation data.
- 🌐 **User Interface** – Clean and simple Streamlit + HTML frontend.
- ☁️ **Deployment** – Hosted using Render.

## Model Evaluation

### Confusion Matrix  
The confusion matrix shows true vs. predicted labels on the test set:

![Confusion Matrix](https://raw.githubusercontent.com/iffahaafreen/Phishing-URL-Detector/main/static/confusion_matrix_phishing_model.png)

### Classification Metrics  
Precision, recall and F1‑score for each class:

![Classification Metrics](https://raw.githubusercontent.com/iffahaafreen/Phishing-URL-Detector/main/static/classification_metrics_phishing_model.png)

## Technology Used
### Development
- **Backend** – Flask (Python)
- **Frontend** – HTML/CSS 
- **Machine Learning** – Scikit-learn (Random Forest)
- **Model Persistence** – joblib

### Hosting
- **Deployment** – Render

## Local Installation Guide
### Frontend
**Clone The Repository**
```bash
git clone https://github.com/iffahaafreen/Phishing-URL-Detector.git
cd Phishing-URL-Detector
```

**Create and activate a Virtual Environment**
```bash
# macOS/Linux
python3 -m venv venv
source venv/bin/activate

# Windows
python -m venv venv
venv\Scripts\activate
```

**Install Dependencies**
```bash
pip install -r requirements.txt
```

**Run the Flask App**
```bash
python app.py
```

## Try It Live
Check out the deployed app 👉 [https://phishing-url-detector-w4ih.onrender.com](https://phishing-url-detector-w4ih.onrender.com)

## Citations
Dataset : R. Mohammad and L. McCluskey. "Phishing Websites," UCI Machine Learning Repository, 2012. [Online]. Available: https://doi.org/10.24432/C51W2X.

## License
Licensed under the [MIT License](./LICENSE)
This project is built for the **4-week MS AINSI Internship Program by Edunet Foundation**

## Contact
For any inquiries, feel free to reach out:

GitHub: [iffahaafreen](https://github.com/iffahaafreen)
