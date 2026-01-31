# 🏥 HealthSync - Smart Hospital Management System

<div align="center">

![HealthSync Logo](static/logo.png)

**A comprehensive, AI-powered, database-driven hospital management system with role-based access control**

[![Python](https://img.shields.io/badge/Python-3.11+-blue.svg)](https://python.org)
[![Flask](https://img.shields.io/badge/Flask-3.0.3-green.svg)](https://flask.palletsprojects.com)
[![PostgreSQL](https://img.shields.io/badge/PostgreSQL-13+-blue.svg)](https://postgresql.org)
[![License](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

[🚀 Quick Start](#-quick-start) • [📖 Features](#-features) • [🔧 Installation](#-installation) • [👥 Login](#-login-credentials) • [📚 Documentation](#-documentation)

</div>

---

## ✨ Overview

HealthSync is a modern, comprehensive hospital management system designed to streamline healthcare operations through intelligent automation and role-based access control. Built with Flask and PostgreSQL, it provides a complete solution for managing patients, appointments, prescriptions, lab results, and billing while incorporating cutting-edge AI features.

## 🎯 Key Features

### 🔐 Role-Based Access Control (RBAC)

| Role | Patient Records | Appointments | Prescriptions | Lab Results | Billing | User Management | System Settings |
|------|----------------|--------------|---------------|-------------|---------|-----------------|-----------------|
| **Admin** | ✅ Full Access | ✅ Full Access | ✅ Full Access | ✅ Full Access | ✅ Full Access | ✅ Full Access | ✅ Full Access |
| **Doctor** | ✅ Full Access | ✅ Full Access | ✅ Full Access | ✅ Full Access | ❌ No Access | ❌ No Access | ❌ No Access |
| **Nurse** | 🔶 Limited | ❌ No Access | 🔶 View Only | ❌ No Access | ❌ No Access | ❌ No Access | ❌ No Access |
| **Pharmacy Nurse** | ❌ No Access | ❌ No Access | ✅ Full Access | ❌ No Access | ❌ No Access | ❌ No Access | ❌ No Access |
| **Lab Assistant** | ❌ No Access | ❌ No Access | ❌ No Access | ✅ Full Access | ❌ No Access | ❌ No Access | ❌ No Access |
| **Receptionist** | 🔶 Limited | ✅ Full Access | ❌ No Access | ❌ No Access | ✅ Full Access | ❌ No Access | ❌ No Access |
| **Patient** | 🔶 Own Records | 🔶 Own Appointments | 🔶 Own Prescriptions | 🔶 Own Results | 🔶 Own Billing | ❌ No Access | ❌ No Access |

### 🚀 Core Modules

#### 👥 Patient Management
- Complete patient profiles with medical history
- Allergy and medication tracking
- Emergency contact management
- Insurance information storage
- Real-time patient search and filtering

#### 📅 Appointment Scheduling
- Calendar-based appointment system
- Doctor availability management
- Appointment rescheduling and cancellation
- Automated reminders and notifications
- Telemedicine integration support

#### 💊 Prescription Management
- Digital prescription creation and management
- Medication inventory tracking
- Prescription history and refill management
- Drug interaction checking
- Blockchain-based prescription verification

#### 🧪 Lab Test Management
- Test request management
- Result upload and storage
- Report generation and sharing
- Test history tracking
- Integration with lab equipment

#### 💰 Billing & Payment
- Comprehensive billing system
- Multiple payment methods
- Insurance claim processing
- Receipt generation
- Financial reporting and analytics

### 🤖 AI-Powered Features

#### 📊 Predictive Analytics
- Patient risk assessment
- Disease progression prediction
- Resource utilization forecasting
- Performance analytics and insights

#### 🧠 Smart Scheduling
- AI-optimized appointment scheduling
- Patient priority-based queuing
- Doctor workload balancing
- Emergency appointment handling

#### 💬 NLP Chatbot
- Website functionality assistance
- Patient query handling
- Real-time support and guidance
- Multi-language support capabilities

## 🛠️ Technology Stack

### Backend
- **Framework**: Flask 3.0.3
- **Language**: Python 3.11+
- **Database**: PostgreSQL 13+ (Primary) / SQLite (Development)
- **ORM**: SQLAlchemy
- **Authentication**: JWT (JSON Web Tokens)
- **Security**: Bcrypt password hashing

### Frontend
- **HTML5**: Semantic markup
- **CSS3**: Modern styling with Flexbox/Grid
- **Bootstrap 5**: Responsive design framework
- **JavaScript**: Interactive functionality
- **Chart.js**: Data visualization

### AI/ML Stack
- **scikit-learn**: Machine learning algorithms
- **pandas**: Data manipulation and analysis
- **numpy**: Numerical computing
- **transformers**: Natural language processing
- **torch**: Deep learning framework
- **NLTK**: Natural language toolkit

### Additional Tools
- **Web3.py**: Blockchain integration
- **BeautifulSoup**: Web scraping capabilities
- **Plotly**: Advanced data visualization
- **Dash**: Interactive web applications

## 📁 Project Structure

```
HealthSync/
├── app.py                      # Main Flask application (single file)
├── README.md                   # Project documentation
├── requirements.txt            # Python dependencies
├── .gitignore                  # Git ignore file
├── .venv/                      # Virtual environment
├── static/                     # Static assets
│   └── logo.png               # HealthSync logo
└── templates/                  # HTML templates
    ├── base.html              # Base template
    ├── index.html             # Homepage
    ├── login.html             # Login page
    ├── dashboard.html         # Main dashboard
    ├── admin_dashboard.html   # Admin dashboard
    ├── doctor_dashboard.html  # Doctor dashboard
    ├── nurse_dashboard.html   # Nurse dashboard
    ├── patient_dashboard.html # Patient dashboard
    ├── receptionist_dashboard.html # Receptionist dashboard
    ├── pharmacy_dashboard.html # Pharmacy dashboard
    ├── lab_dashboard.html     # Lab dashboard
    ├── ai_dashboard.html      # AI features dashboard
    ├── patients.html          # Patient management
    ├── appointments.html      # Appointment management
    ├── prescriptions.html     # Prescription management
    ├── lab_results.html       # Lab results management
    ├── billing.html           # Billing management
    ├── vital_monitoring.html  # Vital signs monitoring
    ├── medication_administration.html # Medication admin
    ├── shift_schedule.html    # Shift scheduling
    └── create_prescription.html # Prescription creation
```

## 🚀 Quick Start

### Prerequisites
- Python 3.11 or higher
- PostgreSQL 13+ (recommended) or SQLite
- pip (Python package manager)

### Installation

1. **Clone the repository**
   ```bash
   git clone <https://github.com/Dharaanishan-3105/Healthsync.git>
   cd HealthSync
   ```

2. **Create and activate virtual environment**
   ```bash
   # Create virtual environment
   python -m venv .venv
   
   # Activate virtual environment
   # Windows:
   .venv\Scripts\activate
   # Linux/Mac:
   source .venv/bin/activate
   ```

3. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

4. **Database Setup**
   
   **Option A: PostgreSQL (Recommended)**
   ```bash
   # Install PostgreSQL from: https://www.postgresql.org/download/
   # Create database 'healthsync'
   # Update connection string in app.py if needed
   ```
   
   **Option B: SQLite (Default)**
   ```bash
   # No additional setup required
   # SQLite database will be created automatically
   ```

5. **Run the application**
   ```bash
   python app.py
   ```

6. **Access the application**
   - Open your browser and go to: http://localhost:5000
   - Use the login credentials provided below

## 👥 Login Credentials

| Role | Email | Password | Access Level |
|------|-------|----------|--------------|
| **Admin** | ------- | ------ | Full system access |
| **Doctor** | doctor@healthsync.com | doctor123 | Medical operations |
| **Nurse** | nurse@healthsync.com | nurse123 | Patient care |
| **Patient** | patient@healthsync.com | patient123 | Personal records |
| **Receptionist** | receptionist@healthsync.com | receptionist123 | Front desk operations |
| **Lab Assistant** | lab@healthsync.com | lab123 | Laboratory management |
| **Pharmacy Nurse** | pharmacy@healthsync.com | pharmacy123 | Medication management |

## 🔧 Configuration

### Database Configuration
The application automatically detects and uses the best available database:

```python
# PostgreSQL (Primary)
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://postgres:password@localhost/healthsync'

# SQLite (Fallback)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///healthsync.db'
```

### Environment Variables
Create a `.env` file for production settings:

```env
SECRET_KEY=your-secret-key-here
JWT_SECRET_KEY=your-jwt-secret-key-here
DATABASE_URL=postgresql://user:password@localhost/healthsync
FLASK_ENV=production
```

## 📚 API Documentation

### Authentication Endpoints
- `POST /login` - User authentication
- `POST /logout` - User logout
- `POST /register` - User registration

### Patient Management
- `GET /api/patients` - List all patients
- `POST /api/patients` - Create new patient
- `GET /api/patients/<id>` - Get patient details
- `PUT /api/patients/<id>` - Update patient
- `DELETE /api/patients/<id>` - Delete patient

### Appointment Management
- `GET /api/appointments` - List appointments
- `POST /api/appointments` - Create appointment
- `PUT /api/appointments/<id>` - Update appointment
- `DELETE /api/appointments/<id>` - Cancel appointment

### Prescription Management
- `GET /api/prescriptions` - List prescriptions
- `POST /api/prescriptions` - Create prescription
- `PUT /api/prescriptions/<id>` - Update prescription
- `GET /api/prescriptions/<id>/dispense` - Dispense medication

### AI-Powered APIs
- `GET /api/predictive-analytics` - Get risk assessments
- `POST /api/predictive-analytics` - Generate predictions
- `GET /api/smart-scheduling` - Get scheduling suggestions
- `POST /api/chatbot` - Chatbot interaction

## 🔒 Security Features

- **Password Hashing**: Bcrypt encryption for secure password storage
- **JWT Authentication**: Token-based authentication with expiration
- **Role-Based Access Control**: Granular permissions based on user roles
- **Session Management**: Secure session handling with automatic timeout
- **Data Validation**: Input sanitization and validation
- **CSRF Protection**: Cross-site request forgery protection
- **SQL Injection Prevention**: Parameterized queries via SQLAlchemy
- **XSS Protection**: Output encoding and content security policies

## 🚀 Deployment

### Production Setup
1. Set up PostgreSQL database
2. Configure environment variables
3. Use a production WSGI server (Gunicorn, uWSGI)
4. Set up reverse proxy (Nginx)
5. Enable HTTPS/SSL
6. Configure firewall rules

### Docker Deployment
```dockerfile
FROM python:3.11-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt
COPY . .
EXPOSE 5000
CMD ["python", "app.py"]
```

## 🐛 Troubleshooting

### Common Issues

1. **Database Connection Error**
   - Ensure PostgreSQL is running
   - Check database credentials
   - Verify database exists

2. **Import Errors**
   - Activate virtual environment
   - Install requirements: `pip install -r requirements.txt`

3. **Port Already in Use**
   - Change port in app.py
   - Kill process using port 5000

4. **Permission Errors**
   - Run as administrator (Windows)
   - Check file permissions

### Getting Help
- Check application logs in terminal
- Review browser console for errors
- Verify database connectivity
- Ensure all dependencies are installed

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- Flask community for the excellent web framework
- PostgreSQL team for the robust database system
- Bootstrap team for the responsive UI framework
- All open-source contributors who made this project possible

## 📞 Support

For support and questions:
- Create an issue in the repository
- Check the documentation
- Review the troubleshooting section

---

<div align="center">

**Made with ❤️ for better healthcare management**

[![GitHub](https://img.shields.io/badge/GitHub-Repository-black.svg)](https://github.com)
[![Documentation](https://img.shields.io/badge/Documentation-Read%20More-blue.svg)](#)
[![Issues](https://img.shields.io/badge/Issues-Report%20Bug-red.svg)](https://github.com)

</div>