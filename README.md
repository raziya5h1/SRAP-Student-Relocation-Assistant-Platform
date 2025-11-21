# 🎓 SRAP — Student Resource Assistance Platform

SRAP (**Student Resource Assistance Platform**) is a centralized web portal designed to support students by connecting them with **NGOs, community services, donations, and document processing systems**.  
The platform ensures a structured workflow for **seeking help, participating in services, tracking donations, and managing institutional documents**.

---

## 🧭 Table of Contents

- [Overview](#overview)
- [Core Modules](#core-modules)
- [Technology Stack](#technology-stack)
- [Installation Guide](#installation-guide)
- [Environment Variables](#environment-variables)
- [Running the Project](#running-the-project)
- [Folder Structure](#folder-structure)
- [Security Features](#security-features)
- [Future Enhancements](#future-enhancements)
- [Contributors](#contributors)
- [License](#license)

---

## 📖 Overview

SRAP acts as a bridge between **students**, **NGOs**, and **institution-based community services**.  
Users can:

- Request help from NGOs
- Participate in services
- Donate resources
- Upload official documents
- Track and manage their requests

It automates support systems typically handled manually inside educational institutions.

---

## 🔧 Core Modules

### 🔐 Authentication
- Secure Login & Registration  
- BCrypt Password Hashing  
- Session-based Access  

---

### 🎗 NGO Module

🟣 Features:

- View available NGOs  
- Request support from any NGO  
- Track and manage request status  
- Admin can add new NGOs  

📌 NGO Details include:

| Field | Description |
|-------|------------|
| NGO Name | Organization title |
| Type | Profit / Non-Profit |
| Website | Official Link |
| Contact Details | Email / Phone |
| Areas of Support | What the NGO offers |

---

### 🛠 Service Management Module

🟩 Features:

- View all available services
- Create a new service event
- Participate in ongoing activities
- Track personal participation history
- Admin controls service status

📌 Service Form Includes:

| Field | Description |
|-------|------------|
| Event Name | Name of the service |
| Conducted By | NGO/Organization |
| Location | Venue |
| Schedule | Start & End Date/Time |

Statuses include:  
➡️ `Upcoming` → `Ongoing` → `Completed`

---

### 🎒 Donation Module

✔ Students can donate or request items  
✔ Items include books, materials, clothes, etc.  
✔ Accept / Reject & Collection workflow  

---

### 📁 Document Upload System

- Supports multiple file formats:  
  `.png, .jpg, .jpeg, .pdf, .doc, .docx, .txt`  
- Track uploaded submissions  
- Auto-store file metadata  

---

## 🧠 Technology Stack

| Layer | Tech Used |
|-------|-----------|
| Backend | Python Flask |
| Frontend | HTML, CSS, Bootstrap |
| Database | SQLite / PostgreSQL / MySQL |
| ORM | SQLAlchemy |
| Mail Service | Flask-Mail |
| Deployment Ready | AWS, Render, Heroku |

---

⚙️ Environment Variables

Create .env file:

SECRET_KEY=your-secret-key
MAIL_USERNAME=your-email
MAIL_PASSWORD=your-email-password
MAIL_SERVER=smtp.gmail.com
MAIL_PORT=587
DATABASE_URL=sqlite:///srap.db

---

▶ Run the Application
python app.py


Then open:

🔗 http://127.0.0.1:5000

---

🗂 Folder Structure
SRAP/
 ┣ app.py
 ┣ .env
 ┣ requirements.txt
 ┣ README.md
 ┣ /static
 ┣ /templates
 ┣ /uploads

 ---
🔐 Security Features

Hashed passwords using Werkzeug Security

Session-controlled routes

Secure filename handling

File validation to prevent harmful uploads

---

🚀 Future Enhancements

Push notifications for status updates

Whisper AI assistance for help-related requests

PWA mobile-ready version

Auto-generated certificates for service participation

---

👨‍💻 Contributors
Role	      Name
Developer	  Pinjari Raziya 

Support	Institution Admin / Faculty
📜 License 
College Name : Geethanjali College of Engineering and Technology

This project is licensed under the MIT License.

---

Note: An multiroom module is also included for group chat between colleges 


## 📦 Installation Guide

```bash
git clone https://github.com/<your-username>/SRAP.git
cd SRAP
pip install -r requirements.txt ```
