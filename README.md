🛡️ PhishGuard – Cyber Security Tool

PhishGuard is a lightweight Flask-based web app that detects suspicious (phishing) URLs in real time.
It was built as part of Sustain-A-Thon 2025 (Sharda University – Infusion Student Club) under the theme: Cyber-Security & Digital Trust.

🚀 Features

✅ Detects common phishing patterns in URLs (IP addresses, @ trick, fake login pages, suspicious TLDs).

✅ Simple and user-friendly web interface.

✅ Built with Python & Flask (runs locally in VS Code or any IDE).

✅ Easy to extend with new phishing detection rules.

📂 Project Structure
phishguard/
│── app.py               # Main Flask app
│── requirements.txt     # Python dependencies
│── templates/
│    └── index.html      # Frontend (HTML template)

⚙️ Installation & Run Instructions
1. Clone the repo / download files
git clone https://github.com/HimanshuCY24/Phishguard.git
cd phishguard

2. Create virtual environment (recommended)
python -m venv venv
venv\Scripts\activate      # for Windows
# OR
source venv/bin/activate   # for Mac/Linux

3. Install dependencies
pip install -r requirements.txt

4. Run the project
python app.py


Open in browser:
👉 http://127.0.0.1:5000

🧪 Sample Test URLs
Safe URLs

https://www.google.com

https://github.com/login

https://stackoverflow.com

Suspicious URLs

http://192.168.0.1/login.php

http://secure-login.xyz

http://bank.ru/account

http://example.com@evil.com


📌 Future Improvements

Add ML-based phishing detection.

Integrate with a threat intelligence API.

Provide browser extension support.

Deploy on cloud (Heroku / AWS / Azure).

👨‍💻 Team

Team Name: HACKIN

Member 1 – Himanshu kumar singh
Member 2- kapil bedre
Member 3-Adish jain

Member 2 – [Teammate’s Name]

Member 3 – [Teammate’s Name]
