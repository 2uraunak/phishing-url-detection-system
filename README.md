# Phishing URL Detection System using Machine Learning

## Overview
A comprehensive cybersecurity framework built with Python, Flask, and Machine Learning that detects malicious, deceptive, and phishing URLs in real-time. The system performs deep lexical feature analysis across domain structure, protocol security, character distributions, and redirection patterns.

## Features Analyzed
1. **IP Address in URL**: Flags numeric IP addresses masquerading as domain names.
2. **URL Length Detection**: Detects obfuscated and unusually long redirect chains (> 54 chars).
3. **URL Shortening Service**: Identifies masked links (bit.ly, tinyurl, t.co, etc.).
4. **Symbol '@' Detection**: Flags embedded credentials used to hijack web browsers.
5. **Double Slash Redirects**: Flags protocol redirection tricks.
6. **Hyphen (-) in Domain**: Flags typosquatting and impersonation attacks.
7. **Sub-Domain Depth**: Identifies multi-level phishing domains.
8. **SSL / TLS Verification**: Checks for HTTPS encryption standards.

## Project Structure
```
phishing-url-detection-system/
├── app.py                # Main Flask application and feature extraction pipeline
├── train_model.py        # Machine learning training and evaluation script
├── requirements.txt      # Python dependencies
├── templates/
│   └── index.html        # Interactive threat analysis dashboard
└── README.md             # Project documentation and setup guide
```

## How to Run Locally

### 1. Prerequisites
Ensure you have Python 3.8+ installed.

### 2. Install Dependencies
```bash
pip install -r requirements.txt
```

### 3. Start the Web Server
```bash
python app.py
```

### 4. Access the Application
Open your web browser and navigate to:
```
http://127.0.0.1:5000
```

## Authors & Academic Submission
Developed for B.Tech / BCA / MCA Final Year Project Presentation.
