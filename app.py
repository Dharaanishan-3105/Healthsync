#!/usr/bin/env python3
"""
HealthSync - Smart Hospital Management System
Complete database-driven application with PostgreSQL
"""

import json
import requests
from bs4 import BeautifulSoup
from flask import Flask, request, jsonify, render_template, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import JWTManager, create_access_token, current_user, jwt_required, get_jwt_identity, get_jwt
from passlib.hash import bcrypt
from datetime import datetime, timedelta
from functools import wraps
import os
import hashlib

# Initialize Flask app
app = Flask(__name__)

# Configuration
app.config['SECRET_KEY'] = 'dev-secret-key-change-in-production'
app.config['JWT_SECRET_KEY'] = 'jwt-secret-key-change-in-production'

# Database Configuration
# PostgreSQL (Primary) - Connected successfully!
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://postgres:20052005@localhost/healthsync'

# SQLite (Fallback) - Comment out PostgreSQL line above if needed
# app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///healthsync.db'

app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Initialize extensions
db = SQLAlchemy(app)
jwt = JWTManager(app)

# Models
class UserRole:
    ADMIN = "admin"
    DOCTOR = "doctor"
    NURSE = "nurse"
    PHARMACY_NURSE = "pharmacy_nurse"
    LAB_ASSISTANT = "lab_assistant"
    RECEPTIONIST = "receptionist"
    PATIENT = "patient"

class User(db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    full_name = db.Column(db.String(120), nullable=False)
    role = db.Column(db.String(40), nullable=False, default=UserRole.PATIENT)
    password_hash = db.Column(db.String(255), nullable=False)
    is_active = db.Column(db.Boolean, default=True)
    phone = db.Column(db.String(20))
    department = db.Column(db.String(100))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_login = db.Column(db.DateTime)

    def set_password(self, password):
        self.password_hash = bcrypt.hash(password)

    def check_password(self, password):
        return bcrypt.verify(password, self.password_hash)

    def __repr__(self):
        return f"<User {self.email}>"

class Patient(db.Model):
    __tablename__ = "patients"
    id = db.Column(db.Integer, primary_key=True)
    patient_id = db.Column(db.String(50), unique=True, nullable=False)
    name = db.Column(db.String(120), nullable=False)
    age = db.Column(db.Integer)
    address = db.Column(db.String(255))
    phone = db.Column(db.String(20))
    gender = db.Column(db.String(10))
    emergency_contact = db.Column(db.String(120))
    insurance_provider = db.Column(db.String(100))
    medical_history = db.Column(db.Text)
    allergies = db.Column(db.Text)
    blood_type = db.Column(db.String(10))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    def __repr__(self):
        return f"<Patient {self.patient_id}>"

class Appointment(db.Model):
    __tablename__ = "appointments"
    id = db.Column(db.Integer, primary_key=True)
    patient_id = db.Column(db.Integer, db.ForeignKey("patients.id"), nullable=False)
    doctor_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    scheduled_for = db.Column(db.DateTime, nullable=False)
    appointment_type = db.Column(db.String(50))
    location = db.Column(db.String(100))
    notes = db.Column(db.Text)
    status = db.Column(db.String(30), default="scheduled")
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relationships
    patient = db.relationship('Patient', backref='appointments')
    doctor = db.relationship('User', backref='appointments')

    def __repr__(self):
        return f"<Appointment {self.id}>"

class Prescription(db.Model):
    __tablename__ = "prescriptions"
    id = db.Column(db.Integer, primary_key=True)
    patient_id = db.Column(db.Integer, db.ForeignKey("patients.id"), nullable=False)
    doctor_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    medication = db.Column(db.String(200), nullable=False)
    dosage = db.Column(db.String(100))
    instructions = db.Column(db.Text)
    status = db.Column(db.String(30), default="active")
    blockchain_hash = db.Column(db.String(255))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relationships
    patient = db.relationship('Patient', backref='prescriptions')
    doctor = db.relationship('User', backref='prescriptions')

    def __repr__(self):
        return f"<Prescription {self.id}>"

class LabResult(db.Model):
    __tablename__ = "lab_results"
    id = db.Column(db.Integer, primary_key=True)
    patient_id = db.Column(db.Integer, db.ForeignKey("patients.id"), nullable=False)
    test_name = db.Column(db.String(200), nullable=False)
    test_type = db.Column(db.String(100))
    results = db.Column(db.Text)
    file_path = db.Column(db.String(500))
    status = db.Column(db.String(30), default="pending")
    uploaded_by = db.Column(db.Integer, db.ForeignKey("users.id"))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relationships
    patient = db.relationship('Patient', backref='lab_results')
    uploaded_by_user = db.relationship('User', backref='lab_results')

    def __repr__(self):
        return f"<LabResult {self.id}>"

class Billing(db.Model):
    __tablename__ = "billing"
    id = db.Column(db.Integer, primary_key=True)
    patient_id = db.Column(db.Integer, db.ForeignKey("patients.id"), nullable=False)
    service_description = db.Column(db.String(200), nullable=False)
    amount = db.Column(db.Numeric(10, 2), nullable=False)
    tax = db.Column(db.Numeric(10, 2), default=0)
    total = db.Column(db.Numeric(10, 2), nullable=False)
    payment_method = db.Column(db.String(50))
    insurance_provider = db.Column(db.String(100))
    status = db.Column(db.String(30), default="pending")
    created_by = db.Column(db.Integer, db.ForeignKey("users.id"))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relationships
    patient = db.relationship('Patient', backref='billing_records')
    created_by_user = db.relationship('User', backref='billing_records')

    def __repr__(self):
        return f"<Billing {self.id}>"

class PatientVital(db.Model):
    __tablename__ = "patient_vitals"
    id = db.Column(db.Integer, primary_key=True)
    patient_id = db.Column(db.Integer, db.ForeignKey("patients.id"), nullable=False)
    recorded_by = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    blood_pressure = db.Column(db.String(20))
    heart_rate = db.Column(db.Integer)
    temperature = db.Column(db.Float)
    weight = db.Column(db.Float)
    height = db.Column(db.Float)
    notes = db.Column(db.Text)
    recorded_at = db.Column(db.DateTime, default=datetime.utcnow)

    # Relationships
    patient = db.relationship('Patient', backref='vitals')
    recorded_by_user = db.relationship('User', backref='vitals_recorded')

    def __repr__(self):
        return f"<PatientVital {self.id}>"

class MedicationAdministration(db.Model):
    __tablename__ = "medication_administrations"
    id = db.Column(db.Integer, primary_key=True)
    patient_id = db.Column(db.Integer, db.ForeignKey("patients.id"), nullable=False)
    prescription_id = db.Column(db.Integer, db.ForeignKey("prescriptions.id"), nullable=False)
    medication = db.Column(db.String(200), nullable=False)
    dosage = db.Column(db.String(100))
    administered_by = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    administered_at = db.Column(db.DateTime, default=datetime.utcnow)
    notes = db.Column(db.Text)
    status = db.Column(db.String(50), default="administered")  # administered, missed, refused

    # Relationships
    patient = db.relationship('Patient', backref='medication_administrations')
    prescription = db.relationship('Prescription', backref='administrations')
    administered_by_user = db.relationship('User', backref='medications_administered')

    def __repr__(self):
        return f"<MedicationAdministration {self.id}>"

class ShiftSchedule(db.Model):
    __tablename__ = "shift_schedules"
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    shift_date = db.Column(db.Date, nullable=False)
    shift_type = db.Column(db.String(50), nullable=False)  # morning, afternoon, night
    start_time = db.Column(db.Time, nullable=False)
    end_time = db.Column(db.Time, nullable=False)
    department = db.Column(db.String(100))
    responsibilities = db.Column(db.Text)
    status = db.Column(db.String(50), default="scheduled")  # scheduled, active, completed, cancelled
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relationships
    user = db.relationship('User', backref='shift_schedules')

    def __repr__(self):
        return f"<ShiftSchedule {self.id}>"

class MedicationInventory(db.Model):
    __tablename__ = "medication_inventory"
    id = db.Column(db.Integer, primary_key=True)
    medication_name = db.Column(db.String(200), nullable=False)
    quantity = db.Column(db.Integer, default=0)
    unit = db.Column(db.String(50))
    expiry_date = db.Column(db.Date)
    supplier = db.Column(db.String(200))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    def __repr__(self):
        return f"<MedicationInventory {self.medication_name}>"

class MedicationDispensing(db.Model):
    __tablename__ = "medication_dispensings"
    id = db.Column(db.Integer, primary_key=True)
    prescription_id = db.Column(db.Integer, db.ForeignKey("prescriptions.id"), nullable=False)
    patient_id = db.Column(db.Integer, db.ForeignKey("patients.id"), nullable=False)
    medication_name = db.Column(db.String(200), nullable=False)
    quantity_dispensed = db.Column(db.Integer, nullable=False)
    unit = db.Column(db.String(50))
    dispensed_by = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    dispensed_at = db.Column(db.DateTime, default=datetime.utcnow)
    notes = db.Column(db.Text)
    status = db.Column(db.String(50), default="dispensed")  # dispensed, verified, completed

    # Relationships
    prescription = db.relationship('Prescription', backref='dispensings')
    patient = db.relationship('Patient', backref='medication_dispensings')
    dispensed_by_user = db.relationship('User', backref='medications_dispensed')

    def __repr__(self):
        return f"<MedicationDispensing {self.id}>"

class PatientQuery(db.Model):
    __tablename__ = "patient_queries"
    id = db.Column(db.Integer, primary_key=True)
    patient_id = db.Column(db.Integer, db.ForeignKey("patients.id"), nullable=False)
    query_type = db.Column(db.String(100), nullable=False)  # medication_usage, side_effects, dosage, interactions
    query_text = db.Column(db.Text, nullable=False)
    response_text = db.Column(db.Text)
    responded_by = db.Column(db.Integer, db.ForeignKey("users.id"))
    status = db.Column(db.String(50), default="pending")  # pending, responded, closed
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    responded_at = db.Column(db.DateTime)

    # Relationships
    patient = db.relationship('Patient', backref='queries')
    responded_by_user = db.relationship('User', backref='query_responses')

    def __repr__(self):
        return f"<PatientQuery {self.id}>"

class LabRequest(db.Model):
    __tablename__ = "lab_requests"
    id = db.Column(db.Integer, primary_key=True)
    patient_id = db.Column(db.Integer, db.ForeignKey("patients.id"), nullable=False)
    doctor_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    test_name = db.Column(db.String(200), nullable=False)
    test_type = db.Column(db.String(100), nullable=False)  # blood_test, imaging, urinalysis, etc.
    priority = db.Column(db.String(50), default="normal")  # urgent, high, normal, low
    instructions = db.Column(db.Text)
    scheduled_date = db.Column(db.DateTime)
    status = db.Column(db.String(50), default="requested")  # requested, scheduled, in_progress, completed, cancelled
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relationships
    patient = db.relationship('Patient', backref='lab_requests')
    doctor = db.relationship('User', backref='lab_requests_ordered')

    def __repr__(self):
        return f"<LabRequest {self.id}>"

class LaboratoryInventory(db.Model):
    __tablename__ = "laboratory_inventory"
    id = db.Column(db.Integer, primary_key=True)
    item_name = db.Column(db.String(200), nullable=False)
    item_type = db.Column(db.String(100), nullable=False)  # equipment, supplies, reagents
    quantity = db.Column(db.Integer, default=0)
    unit = db.Column(db.String(50))
    expiry_date = db.Column(db.Date)
    supplier = db.Column(db.String(200))
    location = db.Column(db.String(100))
    status = db.Column(db.String(50), default="available")  # available, maintenance, out_of_order
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    def __repr__(self):
        return f"<LaboratoryInventory {self.id}>"

class PatientCheckIn(db.Model):
    __tablename__ = "patient_check_ins"
    id = db.Column(db.Integer, primary_key=True)
    patient_id = db.Column(db.Integer, db.ForeignKey("patients.id"), nullable=False)
    appointment_id = db.Column(db.Integer, db.ForeignKey("appointments.id"))
    check_in_time = db.Column(db.DateTime, default=datetime.utcnow)
    status = db.Column(db.String(50), default="checked_in")  # checked_in, waiting, in_consultation, completed
    department = db.Column(db.String(100))
    notes = db.Column(db.Text)
    checked_in_by = db.Column(db.Integer, db.ForeignKey("users.id"))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    # Relationships
    patient = db.relationship('Patient', backref='check_ins')
    appointment = db.relationship('Appointment', backref='check_ins')
    checked_in_by_user = db.relationship('User', backref='patient_check_ins')

    def __repr__(self):
        return f"<PatientCheckIn {self.id}>"

class PatientNotification(db.Model):
    __tablename__ = "patient_notifications"
    id = db.Column(db.Integer, primary_key=True)
    patient_id = db.Column(db.Integer, db.ForeignKey("patients.id"), nullable=False)
    notification_type = db.Column(db.String(100), nullable=False)  # appointment_reminder, appointment_update, billing, general
    title = db.Column(db.String(200), nullable=False)
    message = db.Column(db.Text, nullable=False)
    status = db.Column(db.String(50), default="pending")  # pending, sent, delivered, read
    sent_at = db.Column(db.DateTime)
    read_at = db.Column(db.DateTime)
    created_by = db.Column(db.Integer, db.ForeignKey("users.id"))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    # Relationships
    patient = db.relationship('Patient', backref='notifications')
    created_by_user = db.relationship('User', backref='notifications_created')

    def __repr__(self):
        return f"<PatientNotification {self.id}>"

class PatientFeedback(db.Model):
    __tablename__ = "patient_feedback"
    id = db.Column(db.Integer, primary_key=True)
    patient_id = db.Column(db.Integer, db.ForeignKey("patients.id"), nullable=False)
    feedback_type = db.Column(db.String(100), nullable=False)  # doctor, staff, service, overall
    rating = db.Column(db.Integer, nullable=False)  # 1-5 stars
    title = db.Column(db.String(200), nullable=False)
    feedback_text = db.Column(db.Text, nullable=False)
    doctor_id = db.Column(db.Integer, db.ForeignKey("users.id"))  # If feedback is about specific doctor
    status = db.Column(db.String(50), default="submitted")  # submitted, reviewed, responded
    response_text = db.Column(db.Text)
    responded_by = db.Column(db.Integer, db.ForeignKey("users.id"))
    responded_at = db.Column(db.DateTime)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    # Relationships
    patient = db.relationship('Patient', backref='feedback')
    doctor = db.relationship('User', foreign_keys=[doctor_id], backref='feedback_received')
    responded_by_user = db.relationship('User', foreign_keys=[responded_by], backref='feedback_responses')

    def __repr__(self):
        return f"<PatientFeedback {self.id}>"

class TelemedicineSession(db.Model):
    __tablename__ = "telemedicine_sessions"
    id = db.Column(db.Integer, primary_key=True)
    patient_id = db.Column(db.Integer, db.ForeignKey("patients.id"), nullable=False)
    doctor_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    appointment_id = db.Column(db.Integer, db.ForeignKey("appointments.id"))
    session_url = db.Column(db.String(500))
    session_id = db.Column(db.String(200), unique=True)
    status = db.Column(db.String(50), default="scheduled")  # scheduled, active, completed, cancelled
    scheduled_time = db.Column(db.DateTime, nullable=False)
    started_at = db.Column(db.DateTime)
    ended_at = db.Column(db.DateTime)
    duration_minutes = db.Column(db.Integer)
    notes = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    # Relationships
    patient = db.relationship('Patient', backref='telemedicine_sessions')
    doctor = db.relationship('User', backref='telemedicine_sessions')
    appointment = db.relationship('Appointment', backref='telemedicine_sessions')

    def __repr__(self):
        return f"<TelemedicineSession {self.id}>"

class HospitalSettings(db.Model):
    __tablename__ = "hospital_settings"
    id = db.Column(db.Integer, primary_key=True)
    setting_key = db.Column(db.String(100), unique=True, nullable=False)
    setting_value = db.Column(db.Text, nullable=False)
    setting_type = db.Column(db.String(50), default="string")  # string, number, boolean, json
    description = db.Column(db.Text)
    updated_by = db.Column(db.Integer, db.ForeignKey("users.id"))
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relationships
    updated_by_user = db.relationship('User', backref='settings_updated')

    def __repr__(self):
        return f"<HospitalSettings {self.setting_key}>"

class SystemLog(db.Model):
    __tablename__ = "system_logs"
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    action = db.Column(db.String(200), nullable=False)
    resource_type = db.Column(db.String(100))  # user, patient, appointment, prescription, etc.
    resource_id = db.Column(db.Integer)
    details = db.Column(db.Text)
    ip_address = db.Column(db.String(45))
    user_agent = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    # Relationships
    user = db.relationship('User', backref='system_logs')

    def __repr__(self):
        return f"<SystemLog {self.id}>"

class DataBackup(db.Model):
    __tablename__ = "data_backups"
    id = db.Column(db.Integer, primary_key=True)
    backup_name = db.Column(db.String(200), nullable=False)
    backup_type = db.Column(db.String(50), nullable=False)  # full, incremental, differential
    file_path = db.Column(db.String(500), nullable=False)
    file_size = db.Column(db.BigInteger)  # in bytes
    status = db.Column(db.String(50), default="in_progress")  # in_progress, completed, failed
    created_by = db.Column(db.Integer, db.ForeignKey("users.id"))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    completed_at = db.Column(db.DateTime)
    notes = db.Column(db.Text)

    # Relationships
    created_by_user = db.relationship('User', backref='backups_created')

    def __repr__(self):
        return f"<DataBackup {self.id}>"

class PredictiveAnalytics(db.Model):
    __tablename__ = "predictive_analytics"
    id = db.Column(db.Integer, primary_key=True)
    patient_id = db.Column(db.Integer, db.ForeignKey("patients.id"), nullable=False)
    prediction_type = db.Column(db.String(100), nullable=False)  # readmission_risk, disease_progression, treatment_outcome
    prediction_data = db.Column(db.Text, nullable=False)  # JSON data
    confidence_score = db.Column(db.Float, nullable=False)  # 0.0 to 1.0
    risk_level = db.Column(db.String(50), nullable=False)  # low, medium, high, critical
    recommendations = db.Column(db.Text)  # AI-generated recommendations
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relationships
    patient = db.relationship('Patient', backref='predictive_analytics')

    def __repr__(self):
        return f"<PredictiveAnalytics {self.id}>"

class SmartScheduling(db.Model):
    __tablename__ = "smart_scheduling"
    id = db.Column(db.Integer, primary_key=True)
    patient_id = db.Column(db.Integer, db.ForeignKey("patients.id"), nullable=False)
    doctor_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    suggested_times = db.Column(db.Text, nullable=False)  # JSON array of suggested times
    priority_score = db.Column(db.Float, nullable=False)  # 0.0 to 1.0
    urgency_level = db.Column(db.String(50), nullable=False)  # low, medium, high, urgent
    scheduling_reason = db.Column(db.String(200))  # reason for smart scheduling
    ai_confidence = db.Column(db.Float, nullable=False)  # AI confidence in suggestion
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    status = db.Column(db.String(50), default="pending")  # pending, accepted, rejected

    # Relationships
    patient = db.relationship('Patient', backref='smart_scheduling')
    doctor = db.relationship('User', backref='smart_scheduling')

    def __repr__(self):
        return f"<SmartScheduling {self.id}>"

class ChatbotSession(db.Model):
    __tablename__ = "chatbot_sessions"
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    patient_id = db.Column(db.Integer, db.ForeignKey("patients.id"))
    session_id = db.Column(db.String(200), unique=True, nullable=False)
    conversation_data = db.Column(db.Text)  # JSON conversation history
    intent_classification = db.Column(db.String(100))  # appointment, prescription, billing, general
    sentiment_analysis = db.Column(db.String(50))  # positive, negative, neutral
    resolution_status = db.Column(db.String(50), default="open")  # open, resolved, escalated
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_activity = db.Column(db.DateTime, default=datetime.utcnow)

    # Relationships
    user = db.relationship('User', backref='chatbot_sessions')
    patient = db.relationship('Patient', backref='chatbot_sessions')

    def __repr__(self):
        return f"<ChatbotSession {self.id}>"

class ChatbotMessage(db.Model):
    __tablename__ = "chatbot_messages"
    id = db.Column(db.Integer, primary_key=True)
    session_id = db.Column(db.Integer, db.ForeignKey("chatbot_sessions.id"), nullable=False)
    message_type = db.Column(db.String(50), nullable=False)  # user, bot, system
    message_content = db.Column(db.Text, nullable=False)
    nlp_analysis = db.Column(db.Text)  # JSON NLP analysis data
    response_time = db.Column(db.Float)  # response time in seconds
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    # Relationships
    session = db.relationship('ChatbotSession', backref='messages')

    def __repr__(self):
        return f"<ChatbotMessage {self.id}>"

# Authentication middleware
@app.before_request
def check_authentication():
    # Skip authentication for public pages and static files
    public_endpoints = ['index', 'login', 'register', 'static']
    if request.endpoint in public_endpoints or request.path.startswith('/static/'):
        return
    
    # Check if user is logged in
    if 'user_id' not in session:
        if request.endpoint and not request.endpoint.startswith('api_'):
            return redirect(url_for('login'))
        else:
            return jsonify({"msg": "Authentication required"}), 401

@app.after_request
def add_cache_control_headers(response):
    # Add cache control headers to prevent back button access after logout
    if request.endpoint not in ['index', 'login', 'register', 'static']:
        response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate, max-age=0'
        response.headers['Pragma'] = 'no-cache'
        response.headers['Expires'] = '0'
    return response

# Authentication decorators
def role_required(*allowed_roles):
    def decorator(fn):
        @wraps(fn)
        @jwt_required()
        def wrapper(*args, **kwargs):
            claims = get_jwt()
            role = claims.get("role")
            if role not in allowed_roles:
                return jsonify({"msg": "Forbidden"}), 403
            return fn(*args, **kwargs)
        return wrapper
    return decorator

def session_role_required(*allowed_roles):
    def decorator(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            user_role = session.get('user_role')
            if user_role not in allowed_roles:
                flash('Access denied', 'error')
                return redirect(url_for('dashboard'))
            return fn(*args, **kwargs)
        return wrapper
    return decorator

# Blockchain functions
def generate_hash(data):
    """Generate SHA-256 hash of data"""
    if isinstance(data, dict):
        data = str(data)
    return hashlib.sha256(data.encode()).hexdigest()

def store_hash(data):
    """Store hash in blockchain (stub implementation)"""
    hash_value = generate_hash(data)
    print(f"Blockchain hash stored: {hash_value}")
    return hash_value

# Routes
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        data = request.get_json() or request.form
        email = data.get("email", "").strip().lower()
        password = data.get("password", "")
        
        user = User.query.filter_by(email=email).first()
        if user and user.check_password(password):
            # Update last login
            user.last_login = datetime.utcnow()
            db.session.commit()
            
            additional_claims = {"role": user.role, "name": user.full_name}
            token = create_access_token(identity=str(user.id), additional_claims=additional_claims, expires_delta=timedelta(hours=8))
            session['user_id'] = user.id
            session['user_role'] = user.role
            session['user_name'] = user.full_name
            session['user_email'] = user.email
            
            return jsonify({
                "access_token": token, 
                "role": user.role, 
                "name": user.full_name,
                "redirect": "/dashboard"
            })
        else:
            return jsonify({"msg": "Invalid credentials"}), 401
    
    return render_template('login.html')

@app.route('/dashboard')
def dashboard():
    user_id = session.get('user_id')
    if not user_id:
        return redirect(url_for('login'))
    
    user = User.query.get(user_id)
    if not user:
        return redirect(url_for('login'))
    
    # Get dashboard data based on role
    dashboard_data = get_dashboard_data(user.role, user_id)
    
    return render_template('dashboard.html', 
                         current_user=user, 
                         dashboard_data=dashboard_data)

def get_dashboard_data(role, user_id):
    """Get dashboard data based on user role"""
    data = {
        'patients_count': 0,
        'appointments_count': 0,
        'prescriptions_count': 0,
        'lab_results_count': 0,
        'billing_count': 0,
        'recent_appointments': [],
        'recent_patients': [],
        'recent_prescriptions': [],
        'recent_lab_results': [],
        'recent_billing': [],
        'pending_tasks': []
    }
    
    if role in [UserRole.ADMIN, UserRole.DOCTOR, UserRole.NURSE, UserRole.RECEPTIONIST]:
        data['patients_count'] = Patient.query.count()
        data['recent_patients'] = Patient.query.order_by(Patient.created_at.desc()).limit(5).all()
    
    if role in [UserRole.ADMIN, UserRole.DOCTOR, UserRole.RECEPTIONIST]:
        if role == UserRole.DOCTOR:
            data['appointments_count'] = Appointment.query.filter_by(doctor_id=user_id).count()
            data['recent_appointments'] = Appointment.query.filter_by(doctor_id=user_id).order_by(Appointment.scheduled_for.desc()).limit(5).all()
        else:
            data['appointments_count'] = Appointment.query.count()
            data['recent_appointments'] = Appointment.query.order_by(Appointment.scheduled_for.desc()).limit(5).all()
    
    if role in [UserRole.ADMIN, UserRole.DOCTOR, UserRole.PHARMACY_NURSE]:
        if role == UserRole.DOCTOR:
            data['prescriptions_count'] = Prescription.query.filter_by(doctor_id=user_id).count()
            data['recent_prescriptions'] = Prescription.query.filter_by(doctor_id=user_id).order_by(Prescription.created_at.desc()).limit(5).all()
        else:
            data['prescriptions_count'] = Prescription.query.count()
            data['recent_prescriptions'] = Prescription.query.order_by(Prescription.created_at.desc()).limit(5).all()
    
    if role in [UserRole.ADMIN, UserRole.DOCTOR, UserRole.LAB_ASSISTANT]:
        data['lab_results_count'] = LabResult.query.count()
        data['recent_lab_results'] = LabResult.query.order_by(LabResult.created_at.desc()).limit(5).all()
    
    if role in [UserRole.ADMIN, UserRole.RECEPTIONIST]:
        data['billing_count'] = Billing.query.count()
        data['recent_billing'] = Billing.query.order_by(Billing.created_at.desc()).limit(5).all()
    
    # Add pending tasks based on role
    if role == UserRole.DOCTOR:
        data['pending_tasks'] = [
            f"You have {Appointment.query.filter_by(doctor_id=user_id, status='scheduled').count()} upcoming appointments",
            f"You have {Prescription.query.filter_by(doctor_id=user_id, status='active').count()} active prescriptions"
        ]
    elif role == UserRole.PHARMACY_NURSE:
        data['pending_tasks'] = [
            f"You have {Prescription.query.filter_by(status='active').count()} prescriptions to dispense",
            f"Check {MedicationInventory.query.filter(MedicationInventory.quantity <= 10).count()} low stock items",
            f"Respond to {PatientQuery.query.filter_by(status='pending').count()} patient queries"
        ]
    elif role == UserRole.LAB_ASSISTANT:
        data['pending_tasks'] = [
            f"You have {LabRequest.query.filter_by(status='requested').count()} pending lab requests",
            f"Upload {LabRequest.query.filter_by(status='in_progress').count()} test results",
            f"Check {LaboratoryInventory.query.filter(LaboratoryInventory.quantity <= 5).count()} low stock items"
        ]
    elif role == UserRole.NURSE:
        # Get today's shift for the nurse
        today = datetime.now().date()
        today_shift = ShiftSchedule.query.filter_by(user_id=user_id, shift_date=today).first()
        
        data['pending_tasks'] = [
            f"You have {Prescription.query.filter_by(status='active').count()} active prescriptions to monitor",
            f"Check vital signs for {Patient.query.count()} patients",
            f"Review {MedicationAdministration.query.filter_by(status='administered').count()} medication administrations"
        ]
        
        if today_shift:
            data['shift_info'] = {
                'shift_type': today_shift.shift_type,
                'start_time': today_shift.start_time.strftime('%H:%M'),
                'end_time': today_shift.end_time.strftime('%H:%M'),
                'department': today_shift.department,
                'status': today_shift.status
            }
        else:
            data['shift_info'] = None
    elif role == UserRole.RECEPTIONIST:
        data['pending_tasks'] = [
            f"You have {Appointment.query.filter_by(status='scheduled').count()} scheduled appointments",
            f"You have {Billing.query.filter_by(status='pending').count()} pending bills",
            f"Check-in {PatientCheckIn.query.filter_by(status='checked_in').count()} patients today"
        ]
    elif role == UserRole.PATIENT:
        data['pending_tasks'] = [
            f"You have {Appointment.query.filter_by(patient_id=user_id, status='scheduled').count()} upcoming appointments",
            f"You have {Prescription.query.filter_by(patient_id=user_id, status='active').count()} active prescriptions",
            f"Check your health records and lab results"
        ]
    elif role == UserRole.ADMIN:
        data['pending_tasks'] = [
            f"System has {User.query.count()} total users",
            f"Monitor system performance and security"
        ]
    
    return data

# Role-specific pages
@app.route('/patients')
@session_role_required(UserRole.ADMIN, UserRole.DOCTOR, UserRole.NURSE, UserRole.RECEPTIONIST)
def patients_page():
    user_role = session.get('user_role')
    patients = Patient.query.all()
    return render_template('patients.html', patients=patients, current_role=user_role)

@app.route('/appointments')
@session_role_required(UserRole.ADMIN, UserRole.DOCTOR, UserRole.RECEPTIONIST)
def appointments_page():
    user_role = session.get('user_role')
    user_id = session.get('user_id')
    
    if user_role == UserRole.DOCTOR:
        appointments = Appointment.query.filter_by(doctor_id=user_id).all()
    else:
        appointments = Appointment.query.all()
    
    return render_template('appointments.html', appointments=appointments, current_role=user_role)

@app.route('/prescriptions')
@session_role_required(UserRole.ADMIN, UserRole.DOCTOR, UserRole.PHARMACY_NURSE, UserRole.NURSE)
def prescriptions_page():
    user_role = session.get('user_role')
    user_id = session.get('user_id')
    
    if user_role == UserRole.DOCTOR:
        prescriptions = Prescription.query.filter_by(doctor_id=user_id).all()
    else:
        prescriptions = Prescription.query.all()
    
    return render_template('prescriptions.html', prescriptions=prescriptions, current_role=user_role)

@app.route('/create-prescription')
@session_role_required(UserRole.DOCTOR, UserRole.ADMIN)
def create_prescription_page():
    patients = Patient.query.all()
    return render_template('create_prescription.html', patients=patients)

@app.route('/vital-monitoring')
@session_role_required(UserRole.DOCTOR, UserRole.NURSE, UserRole.ADMIN)
def vital_monitoring_page():
    patients = Patient.query.all()
    return render_template('vital_monitoring.html', patients=patients)

@app.route('/medication-administration')
@session_role_required(UserRole.DOCTOR, UserRole.NURSE, UserRole.ADMIN)
def medication_administration_page():
    patients = Patient.query.all()
    return render_template('medication_administration.html', patients=patients)

@app.route('/shift-schedule')
@session_role_required(UserRole.DOCTOR, UserRole.NURSE, UserRole.ADMIN)
def shift_schedule_page():
    users = User.query.filter(User.role.in_(['doctor', 'nurse'])).all()
    current_user = User.query.get(session.get('user_id'))
    return render_template('shift_schedule.html', users=users, current_user=current_user)

@app.route('/pharmacy-dashboard')
@session_role_required(UserRole.PHARMACY_NURSE, UserRole.ADMIN)
def pharmacy_dashboard_page():
    return render_template('pharmacy_dashboard.html')

@app.route('/lab-dashboard')
@session_role_required(UserRole.LAB_ASSISTANT, UserRole.ADMIN)
def lab_dashboard_page():
    patients = Patient.query.all()
    return render_template('lab_dashboard.html', patients=patients)

@app.route('/receptionist-dashboard')
@session_role_required(UserRole.RECEPTIONIST, UserRole.ADMIN)
def receptionist_dashboard_page():
    patients = Patient.query.all()
    return render_template('receptionist_dashboard.html', patients=patients)

@app.route('/patient-dashboard')
@session_role_required(UserRole.PATIENT, UserRole.ADMIN)
def patient_dashboard_page():
    return render_template('patient_dashboard.html')

@app.route('/admin-dashboard')
@session_role_required(UserRole.ADMIN)
def admin_dashboard_page():
    return render_template('admin_dashboard.html')

@app.route('/ai-dashboard')
@session_role_required(UserRole.ADMIN, UserRole.DOCTOR)
def ai_dashboard_page():
    return render_template('ai_dashboard.html')

@app.route('/lab-results')
@session_role_required(UserRole.ADMIN, UserRole.DOCTOR, UserRole.LAB_ASSISTANT)
def lab_results_page():
    user_role = session.get('user_role')
    lab_results = LabResult.query.all()
    return render_template('lab_results.html', lab_results=lab_results, current_role=user_role)

@app.route('/billing')
@session_role_required(UserRole.ADMIN, UserRole.RECEPTIONIST)
def billing_page():
    user_role = session.get('user_role')
    billing_records = Billing.query.all()
    return render_template('billing.html', billing_records=billing_records, current_role=user_role)

@app.route('/admin')
@session_role_required(UserRole.ADMIN)
def admin_page():
    users = User.query.all()
    return render_template('admin.html', users=users)

@app.route('/logout')
def logout():
    session.clear()
    response = redirect(url_for('login'))
    
    # Clear any cookies
    response.set_cookie('session', '', expires=0)
    response.set_cookie('token', '', expires=0)
    
    # Add cache control headers to prevent back button access
    response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate, max-age=0'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'
    
    return response

# Real-time notifications API
@app.route('/api/notifications')
def get_notifications():
    # Check if user is authenticated
    if 'user_id' not in session:
        return jsonify({"msg": "User not authenticated"}), 401
    
    user_role = session.get('user_role')
    notifications = {
        'prescription_notifications': 0,
        'lab_notifications': 0
    }
    
    if user_role == 'pharmacy_nurse':
        notifications['prescription_notifications'] = Prescription.query.filter_by(status='active').count()
    elif user_role == 'lab_assistant':
        notifications['lab_notifications'] = LabResult.query.filter_by(status='pending').count()
    
    return jsonify(notifications)

# API Routes
@app.route('/api/auth/register', methods=['POST'])
def register():
    data = request.get_json() or {}
    email = data.get("email", "").strip().lower()
    full_name = data.get("full_name", "").strip()
    password = data.get("password", "")
    role = data.get("role", UserRole.PATIENT)
    phone = data.get("phone", "")
    department = data.get("department", "")
    
    if not email or not password or not full_name:
        return jsonify({"msg": "Missing required fields"}), 400
    
    if User.query.filter_by(email=email).first():
        return jsonify({"msg": "Email already registered"}), 409
    
    user = User(email=email, full_name=full_name, role=role, phone=phone, department=department)
    user.set_password(password)
    db.session.add(user)
    db.session.commit()
    
    return jsonify({"id": user.id, "email": user.email, "role": user.role}), 201

@app.route('/api/patients', methods=['GET', 'POST'])
@session_role_required(UserRole.DOCTOR, UserRole.NURSE, UserRole.RECEPTIONIST, UserRole.ADMIN)
def patients_api():
    if request.method == 'GET':
        patients = Patient.query.all()
        return jsonify([{
            "id": p.id,
            "patient_id": p.patient_id,
            "name": p.name,
            "age": p.age,
            "address": p.address,
            "phone": p.phone,
            "gender": p.gender,
            "emergency_contact": p.emergency_contact,
            "insurance_provider": p.insurance_provider,
            "medical_history": p.medical_history,
            "allergies": p.allergies,
            "blood_type": p.blood_type,
            "created_at": p.created_at.isoformat()
        } for p in patients]), 200
    
    elif request.method == 'POST':
        data = request.get_json()
        patient_id = data.get("patient_id")
        name = data.get("name")
        
        if not all([patient_id, name]):
            return jsonify({"msg": "Missing required fields"}), 400
        
        if Patient.query.filter_by(patient_id=patient_id).first():
            return jsonify({"msg": "Patient ID already exists"}), 409
        
        new_patient = Patient(
            patient_id=patient_id,
            name=name,
            age=data.get("age"),
            address=data.get("address"),
            phone=data.get("phone"),
            gender=data.get("gender"),
            emergency_contact=data.get("emergency_contact"),
            insurance_provider=data.get("insurance_provider"),
            medical_history=data.get("medical_history"),
            allergies=data.get("allergies"),
            blood_type=data.get("blood_type")
        )
        db.session.add(new_patient)
        db.session.commit()
        return jsonify({"msg": "Patient created successfully", "id": new_patient.id}), 201

@app.route('/api/patients/<int:patient_id>', methods=['GET', 'PUT', 'DELETE'])
@session_role_required(UserRole.DOCTOR, UserRole.NURSE, UserRole.RECEPTIONIST, UserRole.ADMIN)
def patient_detail_api(patient_id):
    patient = Patient.query.get(patient_id)
    if not patient:
        return jsonify({"msg": "Patient not found"}), 404
    
    if request.method == 'GET':
        return jsonify({
            "id": patient.id,
            "patient_id": patient.patient_id,
            "name": patient.name,
            "age": patient.age,
            "address": patient.address,
            "phone": patient.phone,
            "gender": patient.gender,
            "emergency_contact": patient.emergency_contact,
            "insurance_provider": patient.insurance_provider,
            "medical_history": patient.medical_history,
            "allergies": patient.allergies,
            "blood_type": patient.blood_type,
            "created_at": patient.created_at.isoformat()
        }), 200
    
    elif request.method == 'PUT':
        data = request.get_json()
        
        patient.name = data.get("name", patient.name)
        patient.age = data.get("age", patient.age)
        patient.address = data.get("address", patient.address)
        patient.phone = data.get("phone", patient.phone)
        patient.gender = data.get("gender", patient.gender)
        patient.emergency_contact = data.get("emergency_contact", patient.emergency_contact)
        patient.insurance_provider = data.get("insurance_provider", patient.insurance_provider)
        patient.medical_history = data.get("medical_history", patient.medical_history)
        patient.allergies = data.get("allergies", patient.allergies)
        patient.blood_type = data.get("blood_type", patient.blood_type)
        
        db.session.commit()
        return jsonify({"msg": "Patient updated successfully"}), 200
    
    elif request.method == 'DELETE':
        db.session.delete(patient)
        db.session.commit()
        return jsonify({"msg": "Patient deleted successfully"}), 200

@app.route('/api/appointments', methods=['GET', 'POST'])
@jwt_required()
@role_required(UserRole.DOCTOR, UserRole.RECEPTIONIST, UserRole.ADMIN)
def appointments_api():
    if request.method == 'GET':
        appointments = Appointment.query.all()
        return jsonify([{
            "id": a.id,
            "patient_id": a.patient_id,
            "doctor_id": a.doctor_id,
            "scheduled_for": a.scheduled_for.isoformat(),
            "appointment_type": a.appointment_type,
            "location": a.location,
            "notes": a.notes,
            "status": a.status,
            "created_at": a.created_at.isoformat()
        } for a in appointments]), 200
    
    elif request.method == 'POST':
        data = request.get_json()
        patient_id = data.get("patient_id")
        doctor_id = data.get("doctor_id")
        scheduled_for = data.get("scheduled_for")
        
        if not all([patient_id, doctor_id, scheduled_for]):
            return jsonify({"msg": "Missing required fields"}), 400
        
        try:
            scheduled_for = datetime.fromisoformat(scheduled_for)
        except ValueError:
            return jsonify({"msg": "Invalid date format"}), 400
        
        new_appointment = Appointment(
            patient_id=patient_id,
            doctor_id=doctor_id,
            scheduled_for=scheduled_for,
            appointment_type=data.get("appointment_type"),
            location=data.get("location"),
            notes=data.get("notes")
        )
        db.session.add(new_appointment)
        db.session.commit()
        return jsonify({"msg": "Appointment created successfully", "id": new_appointment.id}), 201

@app.route('/api/prescriptions', methods=['GET', 'POST'])
@jwt_required()
@role_required(UserRole.DOCTOR, UserRole.PHARMACY_NURSE, UserRole.ADMIN, UserRole.NURSE)
def prescriptions_api():
    if request.method == 'GET':
        prescriptions = Prescription.query.all()
        return jsonify([{
            "id": p.id,
            "patient_id": p.patient_id,
            "doctor_id": p.doctor_id,
            "medication": p.medication,
            "dosage": p.dosage,
            "instructions": p.instructions,
            "status": p.status,
            "blockchain_hash": p.blockchain_hash,
            "created_at": p.created_at.isoformat()
        } for p in prescriptions]), 200
    
    elif request.method == 'POST':
        data = request.get_json()
        patient_id = data.get("patient_id")
        doctor_id = data.get("doctor_id")
        medication = data.get("medication")
        
        if not all([patient_id, doctor_id, medication]):
            return jsonify({"msg": "Missing required fields"}), 400
        
        new_prescription = Prescription(
            patient_id=patient_id,
            doctor_id=doctor_id,
            medication=medication,
            dosage=data.get("dosage"),
            instructions=data.get("instructions")
        )
        db.session.add(new_prescription)
        db.session.commit()
        
        # Store prescription hash in blockchain
        prescription_data = f"{patient_id}_{doctor_id}_{medication}_{data.get('dosage')}_{data.get('instructions')}"
        hash_value = store_hash(prescription_data)
        new_prescription.blockchain_hash = hash_value
        db.session.commit()
        
        return jsonify({
            "msg": "Prescription created successfully", 
            "id": new_prescription.id,
            "blockchain_hash": hash_value
        }), 201

@app.route('/api/prescriptions/<int:patient_id>', methods=['GET'])
@session_role_required(UserRole.DOCTOR, UserRole.PHARMACY_NURSE, UserRole.ADMIN, UserRole.NURSE, UserRole.PATIENT)
def patient_prescriptions_api(patient_id):
    prescriptions = Prescription.query.filter_by(patient_id=patient_id).order_by(Prescription.created_at.desc()).all()
    
    return jsonify([{
        "id": p.id,
        "patient_id": p.patient_id,
        "doctor_id": p.doctor_id,
        "doctor_name": p.doctor.full_name if p.doctor else "Unknown",
        "medication": p.medication,
        "dosage": p.dosage,
        "instructions": p.instructions,
        "frequency": p.frequency,
        "duration": p.duration,
        "status": p.status,
        "blockchain_hash": p.blockchain_hash,
        "created_at": p.created_at.isoformat()
    } for p in prescriptions]), 200

# Vital Monitoring API
@app.route('/api/vitals', methods=['GET', 'POST'])
@jwt_required()
@role_required(UserRole.DOCTOR, UserRole.NURSE, UserRole.ADMIN)
def vitals_api():
    if request.method == 'GET':
        patient_id = request.args.get('patient_id')
        if patient_id:
            vitals = PatientVital.query.filter_by(patient_id=patient_id).order_by(PatientVital.recorded_at.desc()).all()
        else:
            vitals = PatientVital.query.order_by(PatientVital.recorded_at.desc()).limit(50).all()
        
        return jsonify([{
            "id": v.id,
            "patient_id": v.patient_id,
            "patient_name": v.patient.name if v.patient else "Unknown",
            "blood_pressure": v.blood_pressure,
            "heart_rate": v.heart_rate,
            "temperature": v.temperature,
            "weight": v.weight,
            "height": v.height,
            "notes": v.notes,
            "recorded_at": v.recorded_at.isoformat(),
            "recorded_by": v.recorded_by_user.full_name if v.recorded_by_user else "Unknown"
        } for v in vitals]), 200
    
    elif request.method == 'POST':
        data = request.get_json()
        patient_id = data.get("patient_id")
        recorded_by = session.get('user_id')
        
        if not patient_id:
            return jsonify({"msg": "Patient ID is required"}), 400
        
        new_vital = PatientVital(
            patient_id=patient_id,
            recorded_by=recorded_by,
            blood_pressure=data.get("blood_pressure"),
            heart_rate=data.get("heart_rate"),
            temperature=data.get("temperature"),
            weight=data.get("weight"),
            height=data.get("height"),
            notes=data.get("notes")
        )
        
        db.session.add(new_vital)
        db.session.commit()
        
        return jsonify({
            "msg": "Vital signs recorded successfully",
            "id": new_vital.id
        }), 201

@app.route('/api/vitals/<int:patient_id>', methods=['GET'])
@session_role_required(UserRole.DOCTOR, UserRole.NURSE, UserRole.ADMIN, UserRole.PATIENT)
def patient_vitals_api(patient_id):
    vitals = PatientVital.query.filter_by(patient_id=patient_id).order_by(PatientVital.recorded_at.desc()).all()
    
    return jsonify([{
        "id": v.id,
        "patient_id": v.patient_id,
        "blood_pressure": v.blood_pressure,
        "heart_rate": v.heart_rate,
        "temperature": v.temperature,
        "weight": v.weight,
        "height": v.height,
        "notes": v.notes,
        "recorded_at": v.recorded_at.isoformat(),
        "recorded_by": v.recorded_by_user.full_name if v.recorded_by_user else "Unknown"
    } for v in vitals]), 200

# Medication Administration API
@app.route('/api/medication-administration', methods=['GET', 'POST'])
@jwt_required()
@role_required(UserRole.DOCTOR, UserRole.NURSE, UserRole.ADMIN)
def medication_administration_api():
    if request.method == 'GET':
        patient_id = request.args.get('patient_id')
        if patient_id:
            administrations = MedicationAdministration.query.filter_by(patient_id=patient_id).order_by(MedicationAdministration.administered_at.desc()).all()
        else:
            administrations = MedicationAdministration.query.order_by(MedicationAdministration.administered_at.desc()).limit(50).all()
        
        return jsonify([{
            "id": a.id,
            "patient_id": a.patient_id,
            "patient_name": a.patient.name if a.patient else "Unknown",
            "prescription_id": a.prescription_id,
            "medication": a.medication,
            "dosage": a.dosage,
            "administered_at": a.administered_at.isoformat(),
            "administered_by": a.administered_by_user.full_name if a.administered_by_user else "Unknown",
            "notes": a.notes,
            "status": a.status
        } for a in administrations]), 200
    
    elif request.method == 'POST':
        data = request.get_json()
        patient_id = data.get("patient_id")
        prescription_id = data.get("prescription_id")
        administered_by = session.get('user_id')
        
        if not all([patient_id, prescription_id]):
            return jsonify({"msg": "Patient ID and Prescription ID are required"}), 400
        
        # Get prescription details
        prescription = Prescription.query.get(prescription_id)
        if not prescription:
            return jsonify({"msg": "Prescription not found"}), 404
        
        new_administration = MedicationAdministration(
            patient_id=patient_id,
            prescription_id=prescription_id,
            medication=prescription.medication,
            dosage=prescription.dosage,
            administered_by=administered_by,
            notes=data.get("notes"),
            status="administered"
        )
        
        db.session.add(new_administration)
        db.session.commit()
        
        return jsonify({
            "msg": "Medication administered successfully",
            "id": new_administration.id
        }), 201

# Shift Schedule API
@app.route('/api/shift-schedules', methods=['GET', 'POST'])
@session_role_required(UserRole.DOCTOR, UserRole.NURSE, UserRole.ADMIN)
def shift_schedules_api():
    if request.method == 'GET':
        user_id = request.args.get('user_id')
        shift_date = request.args.get('shift_date')
        shift_type = request.args.get('shift_type')
        
        query = ShiftSchedule.query
        
        if user_id:
            query = query.filter_by(user_id=user_id)
        if shift_date:
            query = query.filter_by(shift_date=datetime.strptime(shift_date, '%Y-%m-%d').date())
        if shift_type:
            query = query.filter_by(shift_type=shift_type)
            
        schedules = query.order_by(ShiftSchedule.shift_date.desc(), ShiftSchedule.start_time).all()
        
        result = []
        for s in schedules:
            try:
                result.append({
                    "id": s.id,
                    "user_id": s.user_id,
                    "user_name": s.user.full_name if s.user else "Unknown",
                    "shift_date": s.shift_date.isoformat() if s.shift_date else None,
                    "shift_type": s.shift_type,
                    "start_time": s.start_time.strftime('%H:%M') if s.start_time else None,
                    "end_time": s.end_time.strftime('%H:%M') if s.end_time else None,
                    "department": s.department,
                    "responsibilities": s.responsibilities,
                    "status": s.status,
                    "created_at": s.created_at.isoformat() if s.created_at else None
                })
            except Exception as e:
                print(f"Error serializing shift schedule {s.id}: {e}")
                continue
        
        return jsonify(result), 200
    
    elif request.method == 'POST':
        data = request.get_json()
        user_id = data.get("user_id")
        
        if not user_id:
            return jsonify({"msg": "User ID is required"}), 400
        
        new_schedule = ShiftSchedule(
            user_id=user_id,
            shift_date=datetime.strptime(data.get("shift_date"), '%Y-%m-%d').date(),
            shift_type=data.get("shift_type"),
            start_time=datetime.strptime(data.get("start_time"), '%H:%M').time(),
            end_time=datetime.strptime(data.get("end_time"), '%H:%M').time(),
            department=data.get("department"),
            responsibilities=data.get("responsibilities"),
            status=data.get("status", "scheduled")
        )
        
        db.session.add(new_schedule)
        db.session.commit()
        
        return jsonify({
            "msg": "Shift schedule created successfully",
            "id": new_schedule.id
        }), 201

# Medication Dispensing API
@app.route('/api/medication-dispensing', methods=['GET', 'POST'])
@jwt_required()
@role_required(UserRole.PHARMACY_NURSE, UserRole.ADMIN)
def medication_dispensing_api():
    if request.method == 'GET':
        patient_id = request.args.get('patient_id')
        prescription_id = request.args.get('prescription_id')
        
        query = MedicationDispensing.query
        
        if patient_id:
            query = query.filter_by(patient_id=patient_id)
        if prescription_id:
            query = query.filter_by(prescription_id=prescription_id)
            
        dispensings = query.order_by(MedicationDispensing.dispensed_at.desc()).all()
        
        return jsonify([{
            "id": d.id,
            "prescription_id": d.prescription_id,
            "patient_id": d.patient_id,
            "patient_name": d.patient.name if d.patient else "Unknown",
            "medication_name": d.medication_name,
            "quantity_dispensed": d.quantity_dispensed,
            "unit": d.unit,
            "dispensed_by": d.dispensed_by_user.full_name if d.dispensed_by_user else "Unknown",
            "dispensed_at": d.dispensed_at.isoformat(),
            "notes": d.notes,
            "status": d.status
        } for d in dispensings]), 200
    
    elif request.method == 'POST':
        data = request.get_json()
        prescription_id = data.get("prescription_id")
        patient_id = data.get("patient_id")
        dispensed_by = session.get('user_id')
        
        if not all([prescription_id, patient_id]):
            return jsonify({"msg": "Prescription ID and Patient ID are required"}), 400
        
        # Get prescription details
        prescription = Prescription.query.get(prescription_id)
        if not prescription:
            return jsonify({"msg": "Prescription not found"}), 404
        
        # Check inventory
        inventory_item = MedicationInventory.query.filter_by(medication_name=prescription.medication).first()
        if not inventory_item or inventory_item.quantity < data.get("quantity_dispensed", 1):
            return jsonify({"msg": "Insufficient medication in inventory"}), 400
        
        # Create dispensing record
        new_dispensing = MedicationDispensing(
            prescription_id=prescription_id,
            patient_id=patient_id,
            medication_name=prescription.medication,
            quantity_dispensed=data.get("quantity_dispensed", 1),
            unit=data.get("unit", "tablets"),
            dispensed_by=dispensed_by,
            notes=data.get("notes"),
            status="dispensed"
        )
        
        # Update inventory
        inventory_item.quantity -= data.get("quantity_dispensed", 1)
        
        db.session.add(new_dispensing)
        db.session.commit()
        
        return jsonify({
            "msg": "Medication dispensed successfully",
            "id": new_dispensing.id
        }), 201

# Inventory Management API
@app.route('/api/inventory', methods=['GET', 'POST', 'PUT'])
@jwt_required()
@role_required(UserRole.PHARMACY_NURSE, UserRole.ADMIN)
def inventory_api():
    if request.method == 'GET':
        medication_name = request.args.get('medication_name')
        low_stock = request.args.get('low_stock', 'false').lower() == 'true'
        
        query = MedicationInventory.query
        
        if medication_name:
            query = query.filter(MedicationInventory.medication_name.ilike(f'%{medication_name}%'))
        if low_stock:
            query = query.filter(MedicationInventory.quantity <= 10)  # Low stock threshold
            
        inventory = query.order_by(MedicationInventory.medication_name).all()
        
        return jsonify([{
            "id": i.id,
            "medication_name": i.medication_name,
            "quantity": i.quantity,
            "unit": i.unit,
            "expiry_date": i.expiry_date.isoformat() if i.expiry_date else None,
            "supplier": i.supplier,
            "created_at": i.created_at.isoformat(),
            "updated_at": i.updated_at.isoformat()
        } for i in inventory]), 200
    
    elif request.method == 'POST':
        data = request.get_json()
        
        new_inventory = MedicationInventory(
            medication_name=data.get("medication_name"),
            quantity=data.get("quantity", 0),
            unit=data.get("unit", "tablets"),
            expiry_date=datetime.strptime(data.get("expiry_date"), '%Y-%m-%d').date() if data.get("expiry_date") else None,
            supplier=data.get("supplier")
        )
        
        db.session.add(new_inventory)
        db.session.commit()
        
        return jsonify({
            "msg": "Inventory item added successfully",
            "id": new_inventory.id
        }), 201
    
    elif request.method == 'PUT':
        data = request.get_json()
        inventory_id = data.get("id")
        
        inventory_item = MedicationInventory.query.get(inventory_id)
        if not inventory_item:
            return jsonify({"msg": "Inventory item not found"}), 404
        
        inventory_item.medication_name = data.get("medication_name", inventory_item.medication_name)
        inventory_item.quantity = data.get("quantity", inventory_item.quantity)
        inventory_item.unit = data.get("unit", inventory_item.unit)
        inventory_item.expiry_date = datetime.strptime(data.get("expiry_date"), '%Y-%m-%d').date() if data.get("expiry_date") else inventory_item.expiry_date
        inventory_item.supplier = data.get("supplier", inventory_item.supplier)
        
        db.session.commit()
        
        return jsonify({
            "msg": "Inventory item updated successfully"
        }), 200

# Patient Queries API
@app.route('/api/patient-queries', methods=['GET', 'POST', 'PUT'])
@jwt_required()
@role_required(UserRole.PHARMACY_NURSE, UserRole.ADMIN)
def patient_queries_api():
    if request.method == 'GET':
        patient_id = request.args.get('patient_id')
        status = request.args.get('status')
        
        query = PatientQuery.query
        
        if patient_id:
            query = query.filter_by(patient_id=patient_id)
        if status:
            query = query.filter_by(status=status)
            
        queries = query.order_by(PatientQuery.created_at.desc()).all()
        
        return jsonify([{
            "id": q.id,
            "patient_id": q.patient_id,
            "patient_name": q.patient.name if q.patient else "Unknown",
            "query_type": q.query_type,
            "query_text": q.query_text,
            "response_text": q.response_text,
            "responded_by": q.responded_by_user.full_name if q.responded_by_user else None,
            "status": q.status,
            "created_at": q.created_at.isoformat(),
            "responded_at": q.responded_at.isoformat() if q.responded_at else None
        } for q in queries]), 200
    
    elif request.method == 'POST':
        data = request.get_json()
        
        new_query = PatientQuery(
            patient_id=data.get("patient_id"),
            query_type=data.get("query_type"),
            query_text=data.get("query_text"),
            status="pending"
        )
        
        db.session.add(new_query)
        db.session.commit()
        
        return jsonify({
            "msg": "Patient query submitted successfully",
            "id": new_query.id
        }), 201
    
    elif request.method == 'PUT':
        data = request.get_json()
        query_id = data.get("id")
        responded_by = get_jwt_identity()
        
        query = PatientQuery.query.get(query_id)
        if not query:
            return jsonify({"msg": "Query not found"}), 404
        
        query.response_text = data.get("response_text")
        query.responded_by = responded_by
        query.status = data.get("status", "responded")
        query.responded_at = datetime.utcnow()
        
        db.session.commit()
        
        return jsonify({
            "msg": "Query response updated successfully"
        }), 200

# Lab Request Management API
@app.route('/api/lab-requests', methods=['GET', 'POST', 'PUT'])
@session_role_required(UserRole.DOCTOR, UserRole.LAB_ASSISTANT, UserRole.ADMIN)
def lab_requests_api():
    if request.method == 'GET':
        patient_id = request.args.get('patient_id')
        doctor_id = request.args.get('doctor_id')
        status = request.args.get('status')
        priority = request.args.get('priority')
        
        query = LabRequest.query
        
        if patient_id:
            query = query.filter_by(patient_id=patient_id)
        if doctor_id:
            query = query.filter_by(doctor_id=doctor_id)
        if status:
            query = query.filter_by(status=status)
        if priority:
            query = query.filter_by(priority=priority)
            
        requests = query.order_by(LabRequest.created_at.desc()).all()
        
        return jsonify([{
            "id": r.id,
            "patient_id": r.patient_id,
            "patient_name": r.patient.name if r.patient else "Unknown",
            "doctor_id": r.doctor_id,
            "doctor_name": r.doctor.full_name if r.doctor else "Unknown",
            "test_name": r.test_name,
            "test_type": r.test_type,
            "priority": r.priority,
            "instructions": r.instructions,
            "scheduled_date": r.scheduled_date.isoformat() if r.scheduled_date else None,
            "status": r.status,
            "created_at": r.created_at.isoformat()
        } for r in requests]), 200
    
    elif request.method == 'POST':
        data = request.get_json()
        doctor_id = session.get('user_id')
        
        new_request = LabRequest(
            patient_id=data.get("patient_id"),
            doctor_id=doctor_id,
            test_name=data.get("test_name"),
            test_type=data.get("test_type"),
            priority=data.get("priority", "normal"),
            instructions=data.get("instructions"),
            scheduled_date=datetime.strptime(data.get("scheduled_date"), '%Y-%m-%dT%H:%M') if data.get("scheduled_date") else None,
            status="requested"
        )
        
        db.session.add(new_request)
        db.session.commit()
        
        return jsonify({
            "msg": "Lab request created successfully",
            "id": new_request.id
        }), 201
    
    elif request.method == 'PUT':
        data = request.get_json()
        request_id = data.get("id")
        
        lab_request = LabRequest.query.get(request_id)
        if not lab_request:
            return jsonify({"msg": "Lab request not found"}), 404
        
        lab_request.test_name = data.get("test_name", lab_request.test_name)
        lab_request.test_type = data.get("test_type", lab_request.test_type)
        lab_request.priority = data.get("priority", lab_request.priority)
        lab_request.instructions = data.get("instructions", lab_request.instructions)
        lab_request.scheduled_date = datetime.strptime(data.get("scheduled_date"), '%Y-%m-%dT%H:%M') if data.get("scheduled_date") else lab_request.scheduled_date
        lab_request.status = data.get("status", lab_request.status)
        
        db.session.commit()
        
        return jsonify({
            "msg": "Lab request updated successfully"
        }), 200

# Laboratory Inventory API
@app.route('/api/laboratory-inventory', methods=['GET', 'POST', 'PUT'])
@session_role_required(UserRole.LAB_ASSISTANT, UserRole.ADMIN)
def laboratory_inventory_api():
    if request.method == 'GET':
        item_type = request.args.get('item_type')
        low_stock = request.args.get('low_stock', 'false').lower() == 'true'
        
        query = LaboratoryInventory.query
        
        if item_type:
            query = query.filter_by(item_type=item_type)
        if low_stock:
            query = query.filter(LaboratoryInventory.quantity <= 5)  # Low stock threshold
            
        inventory = query.order_by(LaboratoryInventory.item_name).all()
        
        return jsonify([{
            "id": i.id,
            "item_name": i.item_name,
            "item_type": i.item_type,
            "quantity": i.quantity,
            "unit": i.unit,
            "expiry_date": i.expiry_date.isoformat() if i.expiry_date else None,
            "supplier": i.supplier,
            "location": i.location,
            "status": i.status,
            "created_at": i.created_at.isoformat()
        } for i in inventory]), 200
    
    elif request.method == 'POST':
        data = request.get_json()
        
        new_inventory = LaboratoryInventory(
            item_name=data.get("item_name"),
            item_type=data.get("item_type"),
            quantity=data.get("quantity", 0),
            unit=data.get("unit", "pieces"),
            expiry_date=datetime.strptime(data.get("expiry_date"), '%Y-%m-%d').date() if data.get("expiry_date") else None,
            supplier=data.get("supplier"),
            location=data.get("location"),
            status=data.get("status", "available")
        )
        
        db.session.add(new_inventory)
        db.session.commit()
        
        return jsonify({
            "msg": "Laboratory inventory item added successfully",
            "id": new_inventory.id
        }), 201
    
    elif request.method == 'PUT':
        data = request.get_json()
        inventory_id = data.get("id")
        
        inventory_item = LaboratoryInventory.query.get(inventory_id)
        if not inventory_item:
            return jsonify({"msg": "Inventory item not found"}), 404
        
        inventory_item.item_name = data.get("item_name", inventory_item.item_name)
        inventory_item.item_type = data.get("item_type", inventory_item.item_type)
        inventory_item.quantity = data.get("quantity", inventory_item.quantity)
        inventory_item.unit = data.get("unit", inventory_item.unit)
        inventory_item.expiry_date = datetime.strptime(data.get("expiry_date"), '%Y-%m-%d').date() if data.get("expiry_date") else inventory_item.expiry_date
        inventory_item.supplier = data.get("supplier", inventory_item.supplier)
        inventory_item.location = data.get("location", inventory_item.location)
        inventory_item.status = data.get("status", inventory_item.status)
        
        db.session.commit()
        
        return jsonify({
            "msg": "Inventory item updated successfully"
        }), 200

# Patient Check-In API
@app.route('/api/patient-checkin', methods=['GET', 'POST', 'PUT'])
@jwt_required()
@role_required(UserRole.RECEPTIONIST, UserRole.ADMIN)
def patient_checkin_api():
    if request.method == 'GET':
        patient_id = request.args.get('patient_id')
        status = request.args.get('status')
        date = request.args.get('date')
        
        query = PatientCheckIn.query
        
        if patient_id:
            query = query.filter_by(patient_id=patient_id)
        if status:
            query = query.filter_by(status=status)
        if date:
            query = query.filter(db.func.date(PatientCheckIn.check_in_time) == date)
            
        check_ins = query.order_by(PatientCheckIn.check_in_time.desc()).all()
        
        return jsonify([{
            "id": c.id,
            "patient_id": c.patient_id,
            "patient_name": c.patient.name if c.patient else "Unknown",
            "appointment_id": c.appointment_id,
            "check_in_time": c.check_in_time.isoformat(),
            "status": c.status,
            "department": c.department,
            "notes": c.notes,
            "checked_in_by": c.checked_in_by_user.full_name if c.checked_in_by_user else "Unknown"
        } for c in check_ins]), 200
    
    elif request.method == 'POST':
        data = request.get_json()
        checked_in_by = session.get('user_id')
        
        new_checkin = PatientCheckIn(
            patient_id=data.get("patient_id"),
            appointment_id=data.get("appointment_id"),
            status=data.get("status", "checked_in"),
            department=data.get("department"),
            notes=data.get("notes"),
            checked_in_by=checked_in_by
        )
        
        db.session.add(new_checkin)
        db.session.commit()
        
        return jsonify({
            "msg": "Patient checked in successfully",
            "id": new_checkin.id
        }), 201
    
    elif request.method == 'PUT':
        data = request.get_json()
        checkin_id = data.get("id")
        
        checkin = PatientCheckIn.query.get(checkin_id)
        if not checkin:
            return jsonify({"msg": "Check-in record not found"}), 404
        
        checkin.status = data.get("status", checkin.status)
        checkin.department = data.get("department", checkin.department)
        checkin.notes = data.get("notes", checkin.notes)
        
        db.session.commit()
        
        return jsonify({
            "msg": "Check-in status updated successfully"
        }), 200

# Patient Notification API
@app.route('/api/patient-notifications', methods=['GET', 'POST', 'PUT'])
@session_role_required(UserRole.RECEPTIONIST, UserRole.ADMIN, UserRole.PATIENT)
def patient_notifications_api():
    if request.method == 'GET':
        patient_id = request.args.get('patient_id')
        notification_type = request.args.get('notification_type')
        status = request.args.get('status')
        
        query = PatientNotification.query
        
        if patient_id:
            query = query.filter_by(patient_id=patient_id)
        if notification_type:
            query = query.filter_by(notification_type=notification_type)
        if status:
            query = query.filter_by(status=status)
            
        notifications = query.order_by(PatientNotification.created_at.desc()).all()
        
        return jsonify([{
            "id": n.id,
            "patient_id": n.patient_id,
            "patient_name": n.patient.name if n.patient else "Unknown",
            "notification_type": n.notification_type,
            "title": n.title,
            "message": n.message,
            "status": n.status,
            "sent_at": n.sent_at.isoformat() if n.sent_at else None,
            "read_at": n.read_at.isoformat() if n.read_at else None,
            "created_by": n.created_by_user.full_name if n.created_by_user else "Unknown",
            "created_at": n.created_at.isoformat()
        } for n in notifications]), 200
    
    elif request.method == 'POST':
        data = request.get_json()
        created_by = session.get('user_id')
        
        new_notification = PatientNotification(
            patient_id=data.get("patient_id"),
            notification_type=data.get("notification_type"),
            title=data.get("title"),
            message=data.get("message"),
            status="pending",
            created_by=created_by
        )
        
        db.session.add(new_notification)
        db.session.commit()
        
        return jsonify({
            "msg": "Notification created successfully",
            "id": new_notification.id
        }), 201
    
    elif request.method == 'PUT':
        data = request.get_json()
        notification_id = data.get("id")
        
        notification = PatientNotification.query.get(notification_id)
        if not notification:
            return jsonify({"msg": "Notification not found"}), 404
        
        notification.status = data.get("status", notification.status)
        if data.get("status") == "sent":
            notification.sent_at = datetime.utcnow()
        elif data.get("status") == "read":
            notification.read_at = datetime.utcnow()
        
        db.session.commit()
        
        return jsonify({
            "msg": "Notification status updated successfully"
        }), 200

# Hospital Settings API
@app.route('/api/hospital-settings', methods=['GET', 'POST', 'PUT'])
@jwt_required()
@role_required(UserRole.ADMIN)
def hospital_settings_api():
    if request.method == 'GET':
        settings = HospitalSettings.query.all()
        return jsonify([{
            "id": s.id,
            "setting_key": s.setting_key,
            "setting_value": s.setting_value,
            "setting_type": s.setting_type,
            "description": s.description,
            "updated_by": s.updated_by_user.full_name if s.updated_by_user else "System",
            "updated_at": s.updated_at.isoformat()
        } for s in settings]), 200
    
    elif request.method == 'POST':
        data = request.get_json()
        updated_by = get_jwt_identity()
        
        new_setting = HospitalSettings(
            setting_key=data.get("setting_key"),
            setting_value=data.get("setting_value"),
            setting_type=data.get("setting_type", "string"),
            description=data.get("description"),
            updated_by=updated_by
        )
        
        db.session.add(new_setting)
        db.session.commit()
        
        return jsonify({
            "msg": "Setting created successfully",
            "id": new_setting.id
        }), 201
    
    elif request.method == 'PUT':
        data = request.get_json()
        setting_id = data.get("id")
        updated_by = get_jwt_identity()
        
        setting = HospitalSettings.query.get(setting_id)
        if not setting:
            return jsonify({"msg": "Setting not found"}), 404
        
        setting.setting_value = data.get("setting_value", setting.setting_value)
        setting.setting_type = data.get("setting_type", setting.setting_type)
        setting.description = data.get("description", setting.description)
        setting.updated_by = updated_by
        setting.updated_at = datetime.utcnow()
        
        db.session.commit()
        
        return jsonify({
            "msg": "Setting updated successfully"
        }), 200

# System Logs API
@app.route('/api/system-logs', methods=['GET'])
@jwt_required()
@role_required(UserRole.ADMIN)
def system_logs_api():
    user_id = request.args.get('user_id')
    action = request.args.get('action')
    resource_type = request.args.get('resource_type')
    start_date = request.args.get('start_date')
    end_date = request.args.get('end_date')
    page = int(request.args.get('page', 1))
    per_page = int(request.args.get('per_page', 50))
    
    query = SystemLog.query
    
    if user_id:
        query = query.filter_by(user_id=user_id)
    if action:
        query = query.filter(SystemLog.action.contains(action))
    if resource_type:
        query = query.filter_by(resource_type=resource_type)
    if start_date:
        query = query.filter(SystemLog.created_at >= datetime.strptime(start_date, '%Y-%m-%d'))
    if end_date:
        query = query.filter(SystemLog.created_at <= datetime.strptime(end_date, '%Y-%m-%d'))
    
    logs = query.order_by(SystemLog.created_at.desc()).paginate(
        page=page, per_page=per_page, error_out=False
    )
    
    return jsonify({
        "logs": [{
            "id": log.id,
            "user_id": log.user_id,
            "user_name": log.user.full_name if log.user else "System",
            "action": log.action,
            "resource_type": log.resource_type,
            "resource_id": log.resource_id,
            "details": log.details,
            "ip_address": log.ip_address,
            "user_agent": log.user_agent,
            "created_at": log.created_at.isoformat()
        } for log in logs.items],
        "total": logs.total,
        "pages": logs.pages,
        "current_page": page
    }), 200

# Data Backup API
@app.route('/api/data-backups', methods=['GET', 'POST', 'PUT'])
@jwt_required()
@role_required(UserRole.ADMIN)
def data_backups_api():
    if request.method == 'GET':
        backups = DataBackup.query.order_by(DataBackup.created_at.desc()).all()
        return jsonify([{
            "id": b.id,
            "backup_name": b.backup_name,
            "backup_type": b.backup_type,
            "file_path": b.file_path,
            "file_size": b.file_size,
            "status": b.status,
            "created_by": b.created_by_user.full_name if b.created_by_user else "System",
            "created_at": b.created_at.isoformat(),
            "completed_at": b.completed_at.isoformat() if b.completed_at else None,
            "notes": b.notes
        } for b in backups]), 200
    
    elif request.method == 'POST':
        data = request.get_json()
        created_by = get_jwt_identity()
        
        new_backup = DataBackup(
            backup_name=data.get("backup_name"),
            backup_type=data.get("backup_type", "full"),
            file_path=data.get("file_path"),
            file_size=data.get("file_size"),
            status="in_progress",
            created_by=created_by,
            notes=data.get("notes")
        )
        
        db.session.add(new_backup)
        db.session.commit()
        
        return jsonify({
            "msg": "Backup initiated successfully",
            "id": new_backup.id
        }), 201
    
    elif request.method == 'PUT':
        data = request.get_json()
        backup_id = data.get("id")
        
        backup = DataBackup.query.get(backup_id)
        if not backup:
            return jsonify({"msg": "Backup not found"}), 404
        
        backup.status = data.get("status", backup.status)
        backup.file_size = data.get("file_size", backup.file_size)
        backup.notes = data.get("notes", backup.notes)
        
        if data.get("status") == "completed":
            backup.completed_at = datetime.utcnow()
        
        db.session.commit()
        
        return jsonify({
            "msg": "Backup status updated successfully"
        }), 200

# System Analytics API
@app.route('/api/system-analytics')
@jwt_required()
@role_required(UserRole.ADMIN)
def system_analytics_api():
    # Get comprehensive system analytics
    total_users = User.query.count()
    total_patients = Patient.query.count()
    total_appointments = Appointment.query.count()
    total_prescriptions = Prescription.query.count()
    total_lab_results = LabResult.query.count()
    total_billing = Billing.query.count()
    
    # Get user distribution by role
    user_roles = db.session.query(User.role, db.func.count(User.id)).group_by(User.role).all()
    role_distribution = {role: count for role, count in user_roles}
    
    # Get appointments by status
    appointment_status = db.session.query(Appointment.status, db.func.count(Appointment.id)).group_by(Appointment.status).all()
    appointment_distribution = {status: count for status, count in appointment_status}
    
    # Get prescriptions by status
    prescription_status = db.session.query(Prescription.status, db.func.count(Prescription.id)).group_by(Prescription.status).all()
    prescription_distribution = {status: count for status, count in prescription_status}
    
    # Get billing by status
    billing_status = db.session.query(Billing.status, db.func.count(Billing.id)).group_by(Billing.status).all()
    billing_distribution = {status: count for status, count in billing_status}
    
    # Get recent activity (last 30 days)
    thirty_days_ago = datetime.utcnow() - timedelta(days=30)
    recent_logs = SystemLog.query.filter(SystemLog.created_at >= thirty_days_ago).count()
    
    # Get daily statistics for the last 7 days
    daily_stats = []
    for i in range(7):
        date = datetime.utcnow() - timedelta(days=i)
        start_of_day = date.replace(hour=0, minute=0, second=0, microsecond=0)
        end_of_day = date.replace(hour=23, minute=59, second=59, microsecond=999999)
        
        daily_appointments = Appointment.query.filter(
            Appointment.scheduled_for >= start_of_day,
            Appointment.scheduled_for <= end_of_day
        ).count()
        
        daily_prescriptions = Prescription.query.filter(
            Prescription.created_at >= start_of_day,
            Prescription.created_at <= end_of_day
        ).count()
        
        daily_logs = SystemLog.query.filter(
            SystemLog.created_at >= start_of_day,
            SystemLog.created_at <= end_of_day
        ).count()
        
        daily_stats.append({
            "date": date.strftime('%Y-%m-%d'),
            "appointments": daily_appointments,
            "prescriptions": daily_prescriptions,
            "system_logs": daily_logs
        })
    
    return jsonify({
        "overview": {
            "total_users": total_users,
            "total_patients": total_patients,
            "total_appointments": total_appointments,
            "total_prescriptions": total_prescriptions,
            "total_lab_results": total_lab_results,
            "total_billing": total_billing,
            "recent_activity": recent_logs
        },
        "distributions": {
            "user_roles": role_distribution,
            "appointment_status": appointment_distribution,
            "prescription_status": prescription_distribution,
            "billing_status": billing_distribution
        },
        "daily_stats": daily_stats
    }), 200

# Predictive Analytics API
@app.route('/api/predictive-analytics', methods=['GET', 'POST'])
@session_role_required(UserRole.DOCTOR, UserRole.ADMIN)
def predictive_analytics_api():
    if request.method == 'GET':
        patient_id = request.args.get('patient_id')
        prediction_type = request.args.get('prediction_type')
        
        query = PredictiveAnalytics.query
        
        if patient_id:
            query = query.filter_by(patient_id=patient_id)
        if prediction_type:
            query = query.filter_by(prediction_type=prediction_type)
            
        predictions = query.order_by(PredictiveAnalytics.created_at.desc()).all()
        
        return jsonify([{
            "id": p.id,
            "patient_id": p.patient_id,
            "patient_name": p.patient.name if p.patient else "Unknown",
            "prediction_type": p.prediction_type,
            "prediction_data": json.loads(p.prediction_data) if p.prediction_data else {},
            "confidence_score": p.confidence_score,
            "risk_level": p.risk_level,
            "recommendations": p.recommendations,
            "created_at": p.created_at.isoformat()
        } for p in predictions]), 200
    
    elif request.method == 'POST':
        data = request.get_json()
        
        # Simulate AI prediction (in real implementation, this would call ML models)
        prediction_data = {
            "symptoms": data.get("symptoms", []),
            "vitals": data.get("vitals", {}),
            "history": data.get("history", {}),
            "risk_factors": data.get("risk_factors", [])
        }
        
        # Mock AI analysis
        confidence_score = 0.85
        risk_level = "medium"
        recommendations = "Monitor patient closely and consider additional tests"
        
        new_prediction = PredictiveAnalytics(
            patient_id=data.get("patient_id"),
            prediction_type=data.get("prediction_type"),
            prediction_data=json.dumps(prediction_data),
            confidence_score=confidence_score,
            risk_level=risk_level,
            recommendations=recommendations
        )
        
        db.session.add(new_prediction)
        db.session.commit()
        
        return jsonify({
            "msg": "Prediction generated successfully",
            "id": new_prediction.id,
            "confidence_score": confidence_score,
            "risk_level": risk_level,
            "recommendations": recommendations
        }), 201

# Smart Scheduling API
@app.route('/api/smart-scheduling', methods=['GET', 'POST', 'PUT'])
@session_role_required(UserRole.DOCTOR, UserRole.RECEPTIONIST, UserRole.ADMIN)
def smart_scheduling_api():
    if request.method == 'GET':
        patient_id = request.args.get('patient_id')
        doctor_id = request.args.get('doctor_id')
        status = request.args.get('status')
        
        query = SmartScheduling.query
        
        if patient_id:
            query = query.filter_by(patient_id=patient_id)
        if doctor_id:
            query = query.filter_by(doctor_id=doctor_id)
        if status:
            query = query.filter_by(status=status)
            
        schedules = query.order_by(SmartScheduling.created_at.desc()).all()
        
        return jsonify([{
            "id": s.id,
            "patient_id": s.patient_id,
            "patient_name": s.patient.name if s.patient else "Unknown",
            "doctor_id": s.doctor_id,
            "doctor_name": s.doctor.full_name if s.doctor else "Unknown",
            "suggested_times": json.loads(s.suggested_times) if s.suggested_times else [],
            "priority_score": s.priority_score,
            "urgency_level": s.urgency_level,
            "scheduling_reason": s.scheduling_reason,
            "ai_confidence": s.ai_confidence,
            "status": s.status,
            "created_at": s.created_at.isoformat()
        } for s in schedules]), 200
    
    elif request.method == 'POST':
        data = request.get_json()
        
        # Simulate AI smart scheduling
        suggested_times = data.get("suggested_times", [])
        priority_score = data.get("priority_score", 0.7)
        urgency_level = data.get("urgency_level", "medium")
        ai_confidence = 0.88
        
        new_schedule = SmartScheduling(
            patient_id=data.get("patient_id"),
            doctor_id=data.get("doctor_id"),
            suggested_times=json.dumps(suggested_times),
            priority_score=priority_score,
            urgency_level=urgency_level,
            scheduling_reason=data.get("scheduling_reason"),
            ai_confidence=ai_confidence,
            status="pending"
        )
        
        db.session.add(new_schedule)
        db.session.commit()
        
        return jsonify({
            "msg": "Smart scheduling suggestion created successfully",
            "id": new_schedule.id,
            "ai_confidence": ai_confidence
        }), 201
    
    elif request.method == 'PUT':
        data = request.get_json()
        schedule_id = data.get("id")
        
        schedule = SmartScheduling.query.get(schedule_id)
        if not schedule:
            return jsonify({"msg": "Schedule not found"}), 404
        
        schedule.status = data.get("status", schedule.status)
        db.session.commit()
        
        return jsonify({
            "msg": "Schedule status updated successfully"
        }), 200

# Chatbot API
@app.route('/api/chatbot', methods=['GET', 'POST'])
def chatbot_api():
    if request.method == 'GET':
        session_id = request.args.get('session_id')
        
        if session_id:
            session = ChatbotSession.query.filter_by(session_id=session_id).first()
            if not session:
                return jsonify({"msg": "Session not found"}), 404
            
            messages = ChatbotMessage.query.filter_by(session_id=session.id).order_by(ChatbotMessage.created_at.asc()).all()
            
            return jsonify({
                "session": {
                    "id": session.id,
                    "session_id": session.session_id,
                    "intent_classification": session.intent_classification,
                    "sentiment_analysis": session.sentiment_analysis,
                    "resolution_status": session.resolution_status,
                    "created_at": session.created_at.isoformat()
                },
                "messages": [{
                    "id": m.id,
                    "message_type": m.message_type,
                    "message_content": m.message_content,
                    "nlp_analysis": json.loads(m.nlp_analysis) if m.nlp_analysis else {},
                    "response_time": m.response_time,
                    "created_at": m.created_at.isoformat()
                } for m in messages]
            }), 200
        else:
            # Create new session
            user_id = session.get('user_id')
            if not user_id:
                return jsonify({"msg": "User not authenticated"}), 401
            new_session_id = f"chat_{user_id}_{int(datetime.utcnow().timestamp())}"
            
            new_session = ChatbotSession(
                user_id=user_id,
                session_id=new_session_id,
                intent_classification="general",
                sentiment_analysis="neutral",
                resolution_status="open"
            )
            
            db.session.add(new_session)
            db.session.commit()
            
            return jsonify({
                "session_id": new_session_id,
                "msg": "New chat session created"
            }), 201
    
    elif request.method == 'POST':
        data = request.get_json()
        session_id = data.get("session_id")
        message = data.get("message")
        
        if not session_id or not message:
            return jsonify({"msg": "Session ID and message are required"}), 400
        
        # Check if user is authenticated
        user_id = session.get('user_id')
        if not user_id:
            return jsonify({"msg": "User not authenticated"}), 401
        
        session = ChatbotSession.query.filter_by(session_id=session_id).first()
        if not session:
            return jsonify({"msg": "Session not found"}), 404
        
        # Simulate NLP processing
        nlp_analysis = {
            "intent": "appointment_booking",
            "entities": ["doctor", "time", "date"],
            "sentiment": "positive",
            "confidence": 0.92
        }
        
        # Create user message
        user_message = ChatbotMessage(
            session_id=session.id,
            message_type="user",
            message_content=message,
            nlp_analysis=json.dumps(nlp_analysis),
            response_time=0.5
        )
        
        db.session.add(user_message)
        
        # Generate AI response
        ai_response = generate_chatbot_response(message, nlp_analysis)
        
        # Create bot message
        bot_message = ChatbotMessage(
            session_id=session.id,
            message_type="bot",
            message_content=ai_response,
            nlp_analysis=json.dumps({"response_type": "helpful", "confidence": 0.89}),
            response_time=1.2
        )
        
        db.session.add(bot_message)
        
        # Update session
        session.last_activity = datetime.utcnow()
        session.intent_classification = nlp_analysis["intent"]
        session.sentiment_analysis = nlp_analysis["sentiment"]
        
        db.session.commit()
        
        return jsonify({
            "response": ai_response,
            "intent": nlp_analysis["intent"],
            "sentiment": nlp_analysis["sentiment"],
            "confidence": nlp_analysis["confidence"]
        }), 200

def generate_chatbot_response(message, nlp_analysis):
    """Generate AI chatbot response focused on HealthSync website functionality"""
    intent = nlp_analysis.get("intent", "general")
    sentiment = nlp_analysis.get("sentiment", "neutral")
    
    # Website functionality keywords
    website_keywords = [
        'appointment', 'book', 'schedule', 'prescription', 'medication', 'billing', 'payment',
        'patient', 'record', 'dashboard', 'login', 'logout', 'register', 'profile',
        'doctor', 'nurse', 'admin', 'receptionist', 'lab', 'pharmacy', 'vital', 'monitor',
        'report', 'test', 'result', 'lab', 'check', 'view', 'edit', 'add', 'delete',
        'help', 'how', 'what', 'where', 'when', 'why', 'feature', 'function', 'use'
    ]
    
    # Check if the message is about website functionality
    is_website_related = any(keyword in message.lower() for keyword in website_keywords)
    
    if is_website_related:
        # Provide website-specific help
        responses = {
            "appointment_booking": [
                "To book an appointment in HealthSync:\n1. Go to the Appointments page\n2. Click 'Schedule New Appointment'\n3. Select patient, doctor, and time\n4. Add notes and confirm\n\nNeed help with a specific step?",
                "For appointment scheduling:\n• **Doctors/Receptionists**: Can create and manage all appointments\n• **Patients**: Can view their appointments in the Patient Portal\n• **Admins**: Have full access to all appointment features\n\nWhat specific appointment help do you need?"
            ],
            "prescription": [
                "Prescription management in HealthSync:\n• **Doctors**: Can create and view prescriptions\n• **Pharmacy Nurses**: Can dispense medications\n• **Patients**: Can view their prescriptions in Patient Portal\n• **Nurses**: Can administer medications\n\nWhich role are you and what do you need help with?",
                "To manage prescriptions:\n1. Go to Prescriptions page\n2. Click 'Create New Prescription' (for doctors)\n3. Fill in medication details\n4. Save and track status\n\nNeed help with prescription features?"
            ],
            "billing": [
                "Billing management features:\n• **Receptionists**: Can create and manage bills\n• **Patients**: Can view bills and payments in Patient Portal\n• **Admins**: Have full billing access\n• **Doctors**: Can view billing related to their patients\n\nWhat billing help do you need?",
                "To handle billing:\n1. Go to Billing page\n2. Create new bill or view existing ones\n3. Add service details and amounts\n4. Process payments\n5. Generate receipts\n\nNeed specific billing assistance?"
            ],
            "patient_records": [
                "Patient record management:\n• **Doctors/Nurses**: Full access to patient records\n• **Receptionists**: Limited access for registration\n• **Admins**: Complete patient management\n• **Patients**: Can view their own records\n\nWhat patient record help do you need?",
                "To access patient records:\n1. Go to Patient Records page\n2. Search by patient ID or name\n3. View detailed medical history\n4. Edit information (if authorized)\n5. Add new records\n\nNeed help with patient management?"
            ],
            "dashboard": [
                "HealthSync Dashboard features:\n• **Role-based access**: Different dashboards for each user type\n• **Quick actions**: Easy access to common tasks\n• **Real-time data**: Live updates and notifications\n• **Analytics**: Performance metrics and insights\n\nWhat dashboard help do you need?",
                "Dashboard navigation:\n• Use the sidebar menu for main features\n• Quick action buttons for common tasks\n• Role-specific information and tools\n• Real-time updates and notifications\n\nNeed help navigating your dashboard?"
            ],
            "login": [
                "Login help for HealthSync:\n• Use your email and password\n• Different roles have different access levels\n• Contact admin if you can't access your account\n• Make sure you're using the correct credentials\n\nNeed help with login issues?",
                "To login to HealthSync:\n1. Go to the login page\n2. Enter your email and password\n3. Select your role\n4. Click 'Login'\n5. You'll be redirected to your dashboard\n\nHaving trouble logging in?"
            ],
            "ai_features": [
                "HealthSync AI Features:\n• **Predictive Analytics**: Risk assessment and predictions\n• **Smart Scheduling**: AI-powered appointment optimization\n• **AI Chatbot**: This assistant for website help\n• **AI Dashboard**: Advanced analytics and insights\n\nWhat AI feature interests you?",
                "AI capabilities in HealthSync:\n• Doctors and Admins can access AI Dashboard\n• Predictive analytics for patient care\n• Smart scheduling suggestions\n• AI-powered insights and recommendations\n\nNeed help with AI features?"
            ],
            "general": [
                "I'm here to help you with HealthSync features! I can assist with:\n• **Appointments**: Booking and management\n• **Prescriptions**: Creating and tracking\n• **Patient Records**: Viewing and editing\n• **Billing**: Payment and invoice management\n• **Dashboard**: Navigation and features\n• **AI Tools**: Advanced analytics\n\nWhat would you like to know about?",
                "Welcome to HealthSync! I can help you with:\n• Understanding different user roles and permissions\n• Navigating the website features\n• Using specific functionalities\n• Troubleshooting common issues\n• Learning about AI capabilities\n\nHow can I assist you today?"
            ]
        }
        
        # Determine the best response based on keywords
        if any(word in message.lower() for word in ['appointment', 'book', 'schedule']):
            intent = "appointment_booking"
        elif any(word in message.lower() for word in ['prescription', 'medication', 'medicine']):
            intent = "prescription"
        elif any(word in message.lower() for word in ['billing', 'payment', 'invoice', 'bill']):
            intent = "billing"
        elif any(word in message.lower() for word in ['patient', 'record', 'medical', 'history']):
            intent = "patient_records"
        elif any(word in message.lower() for word in ['dashboard', 'home', 'main']):
            intent = "dashboard"
        elif any(word in message.lower() for word in ['login', 'sign', 'access', 'password']):
            intent = "login"
        elif any(word in message.lower() for word in ['ai', 'artificial', 'intelligence', 'smart', 'analytics']):
            intent = "ai_features"
        else:
            intent = "general"
        
        import random
        return random.choice(responses.get(intent, responses["general"]))
    
    else:
        # For non-website related queries, redirect to website help
        return "I'm here to help you with HealthSync website features and functionality. I can assist you with:\n\n• **Appointments**: How to book and manage appointments\n• **Prescriptions**: Creating and tracking medications\n• **Patient Records**: Viewing and managing patient information\n• **Billing**: Payment and invoice management\n• **Dashboard**: Navigating your role-specific dashboard\n• **AI Features**: Using advanced analytics and predictions\n• **User Roles**: Understanding different access levels\n\nWhat HealthSync feature would you like to learn about?"

# Patient Feedback API
@app.route('/api/patient-feedback', methods=['GET', 'POST', 'PUT'])
@jwt_required()
@role_required(UserRole.PATIENT, UserRole.ADMIN)
def patient_feedback_api():
    if request.method == 'GET':
        patient_id = request.args.get('patient_id')
        feedback_type = request.args.get('feedback_type')
        status = request.args.get('status')
        
        query = PatientFeedback.query
        
        if patient_id:
            query = query.filter_by(patient_id=patient_id)
        if feedback_type:
            query = query.filter_by(feedback_type=feedback_type)
        if status:
            query = query.filter_by(status=status)
            
        feedbacks = query.order_by(PatientFeedback.created_at.desc()).all()
        
        return jsonify([{
            "id": f.id,
            "patient_id": f.patient_id,
            "patient_name": f.patient.name if f.patient else "Unknown",
            "feedback_type": f.feedback_type,
            "rating": f.rating,
            "title": f.title,
            "feedback_text": f.feedback_text,
            "doctor_id": f.doctor_id,
            "doctor_name": f.doctor.full_name if f.doctor else None,
            "status": f.status,
            "response_text": f.response_text,
            "responded_by": f.responded_by_user.full_name if f.responded_by_user else None,
            "responded_at": f.responded_at.isoformat() if f.responded_at else None,
            "created_at": f.created_at.isoformat()
        } for f in feedbacks]), 200
    
    elif request.method == 'POST':
        data = request.get_json()
        patient_id = session.get('user_id')
        
        new_feedback = PatientFeedback(
            patient_id=patient_id,
            feedback_type=data.get("feedback_type"),
            rating=data.get("rating"),
            title=data.get("title"),
            feedback_text=data.get("feedback_text"),
            doctor_id=data.get("doctor_id"),
            status="submitted"
        )
        
        db.session.add(new_feedback)
        db.session.commit()
        
        return jsonify({
            "msg": "Feedback submitted successfully",
            "id": new_feedback.id
        }), 201
    
    elif request.method == 'PUT':
        data = request.get_json()
        feedback_id = data.get("id")
        responded_by = get_jwt_identity()
        
        feedback = PatientFeedback.query.get(feedback_id)
        if not feedback:
            return jsonify({"msg": "Feedback not found"}), 404
        
        feedback.status = data.get("status", feedback.status)
        feedback.response_text = data.get("response_text", feedback.response_text)
        feedback.responded_by = responded_by
        feedback.responded_at = datetime.utcnow()
        
        db.session.commit()
        
        return jsonify({
            "msg": "Feedback response updated successfully"
        }), 200

# Telemedicine API
@app.route('/api/telemedicine-sessions', methods=['GET', 'POST', 'PUT'])
@jwt_required()
@role_required(UserRole.PATIENT, UserRole.DOCTOR, UserRole.ADMIN)
def telemedicine_sessions_api():
    if request.method == 'GET':
        patient_id = request.args.get('patient_id')
        doctor_id = request.args.get('doctor_id')
        status = request.args.get('status')
        
        query = TelemedicineSession.query
        
        if patient_id:
            query = query.filter_by(patient_id=patient_id)
        if doctor_id:
            query = query.filter_by(doctor_id=doctor_id)
        if status:
            query = query.filter_by(status=status)
            
        sessions = query.order_by(TelemedicineSession.scheduled_time.desc()).all()
        
        return jsonify([{
            "id": s.id,
            "patient_id": s.patient_id,
            "patient_name": s.patient.name if s.patient else "Unknown",
            "doctor_id": s.doctor_id,
            "doctor_name": s.doctor.full_name if s.doctor else "Unknown",
            "appointment_id": s.appointment_id,
            "session_url": s.session_url,
            "session_id": s.session_id,
            "status": s.status,
            "scheduled_time": s.scheduled_time.isoformat(),
            "started_at": s.started_at.isoformat() if s.started_at else None,
            "ended_at": s.ended_at.isoformat() if s.ended_at else None,
            "duration_minutes": s.duration_minutes,
            "notes": s.notes,
            "created_at": s.created_at.isoformat()
        } for s in sessions]), 200
    
    elif request.method == 'POST':
        data = request.get_json()
        patient_id = session.get('user_id')
        
        new_session = TelemedicineSession(
            patient_id=patient_id,
            doctor_id=data.get("doctor_id"),
            appointment_id=data.get("appointment_id"),
            session_url=data.get("session_url"),
            session_id=data.get("session_id"),
            status="scheduled",
            scheduled_time=datetime.strptime(data.get("scheduled_time"), '%Y-%m-%dT%H:%M') if data.get("scheduled_time") else None,
            notes=data.get("notes")
        )
        
        db.session.add(new_session)
        db.session.commit()
        
        return jsonify({
            "msg": "Telemedicine session scheduled successfully",
            "id": new_session.id
        }), 201
    
    elif request.method == 'PUT':
        data = request.get_json()
        session_id = data.get("id")
        
        session = TelemedicineSession.query.get(session_id)
        if not session:
            return jsonify({"msg": "Session not found"}), 404
        
        session.status = data.get("status", session.status)
        if data.get("status") == "active":
            session.started_at = datetime.utcnow()
        elif data.get("status") == "completed":
            session.ended_at = datetime.utcnow()
            if session.started_at:
                duration = session.ended_at - session.started_at
                session.duration_minutes = int(duration.total_seconds() / 60)
        
        session.notes = data.get("notes", session.notes)
        
        db.session.commit()
        
        return jsonify({
            "msg": "Session status updated successfully"
        }), 200

# Patient Health Records API
@app.route('/api/patient-health-records')
@session_role_required(UserRole.PATIENT, UserRole.ADMIN)
def patient_health_records_api():
    patient_id = session.get('user_id')
    
    # Get patient's complete health records
    patient = Patient.query.get(patient_id)
    if not patient:
        return jsonify({"msg": "Patient not found"}), 404
    
    # Get appointments
    appointments = Appointment.query.filter_by(patient_id=patient_id).order_by(Appointment.scheduled_for.desc()).all()
    
    # Get prescriptions
    prescriptions = Prescription.query.filter_by(patient_id=patient_id).order_by(Prescription.created_at.desc()).all()
    
    # Get lab results
    lab_results = LabResult.query.filter_by(patient_id=patient_id).order_by(LabResult.created_at.desc()).all()
    
    # Get vital signs
    vitals = PatientVital.query.filter_by(patient_id=patient_id).order_by(PatientVital.recorded_at.desc()).all()
    
    # Get billing records
    billing = Billing.query.filter_by(patient_id=patient_id).order_by(Billing.created_at.desc()).all()
    
    return jsonify({
        "patient": {
            "id": patient.id,
            "patient_id": patient.patient_id,
            "name": patient.name,
            "email": patient.email,
            "phone": patient.phone,
            "date_of_birth": patient.date_of_birth.isoformat() if patient.date_of_birth else None,
            "gender": patient.gender,
            "address": patient.address,
            "insurance_provider": patient.insurance_provider,
            "emergency_contact": patient.emergency_contact
        },
        "appointments": [{
            "id": a.id,
            "appointment_time": a.scheduled_for.isoformat(),
            "doctor_name": a.doctor.full_name if a.doctor else "Unknown",
            "department": a.department,
            "status": a.status,
            "notes": a.notes
        } for a in appointments],
        "prescriptions": [{
            "id": p.id,
            "medication": p.medication,
            "dosage": p.dosage,
            "instructions": p.instructions,
            "frequency": p.frequency,
            "duration": p.duration,
            "status": p.status,
            "created_at": p.created_at.isoformat(),
            "doctor_name": p.doctor.full_name if p.doctor else "Unknown"
        } for p in prescriptions],
        "lab_results": [{
            "id": l.id,
            "test_name": l.test_name,
            "test_type": l.test_type,
            "results": l.results,
            "status": l.status,
            "created_at": l.created_at.isoformat(),
            "file_path": l.file_path
        } for l in lab_results],
        "vitals": [{
            "id": v.id,
            "blood_pressure": v.blood_pressure,
            "heart_rate": v.heart_rate,
            "temperature": v.temperature,
            "weight": v.weight,
            "height": v.height,
            "notes": v.notes,
            "recorded_at": v.recorded_at.isoformat(),
            "recorded_by": v.recorded_by_user.full_name if v.recorded_by_user else "Unknown"
        } for v in vitals],
        "billing": [{
            "id": b.id,
            "service_type": b.service_type,
            "amount": b.amount,
            "status": b.status,
            "payment_method": b.payment_method,
            "created_at": b.created_at.isoformat()
        } for b in billing]
    }), 200

@app.route('/api/lab-results', methods=['GET', 'POST'])
@session_role_required(UserRole.DOCTOR, UserRole.LAB_ASSISTANT, UserRole.ADMIN)
def lab_results_api():
    if request.method == 'GET':
        lab_results = LabResult.query.all()
        return jsonify([{
            "id": l.id,
            "patient_id": l.patient_id,
            "test_name": l.test_name,
            "test_type": l.test_type,
            "results": l.results,
            "file_path": l.file_path,
            "status": l.status,
            "uploaded_by": l.uploaded_by,
            "created_at": l.created_at.isoformat()
        } for l in lab_results]), 200
    
    elif request.method == 'POST':
        data = request.get_json()
        patient_id = data.get("patient_id")
        test_name = data.get("test_name")
        
        if not all([patient_id, test_name]):
            return jsonify({"msg": "Missing required fields"}), 400
        
        new_lab_result = LabResult(
            patient_id=patient_id,
            test_name=test_name,
            test_type=data.get("test_type"),
            results=data.get("results"),
            file_path=data.get("file_path"),
            status=data.get("status", "pending"),
            uploaded_by=session.get('user_id')
        )
        db.session.add(new_lab_result)
        db.session.commit()
        return jsonify({"msg": "Lab result created successfully", "id": new_lab_result.id}), 201

@app.route('/api/billing', methods=['GET', 'POST'])
@jwt_required()
@role_required(UserRole.RECEPTIONIST, UserRole.ADMIN)
def billing_api():
    if request.method == 'GET':
        bills = Billing.query.all()
        return jsonify([{
            "id": bill.id,
            "patient_id": bill.patient_id,
            "service_description": bill.service_description,
            "amount": str(bill.amount),
            "tax": str(bill.tax),
            "total": str(bill.total),
            "payment_method": bill.payment_method,
            "insurance_provider": bill.insurance_provider,
            "status": bill.status,
            "created_at": bill.created_at.isoformat(),
            "created_by": bill.created_by
        } for bill in bills]), 200
    
    elif request.method == 'POST':
        data = request.get_json()
        patient_id = data.get("patient_id")
        service_description = data.get("service_description")
        amount = data.get("amount")
        
        if not all([patient_id, service_description, amount]):
            return jsonify({"msg": "Missing billing data"}), 400
        
        tax = data.get("tax", 0)
        total = float(amount) + float(tax)
        
        new_bill = Billing(
            patient_id=patient_id,
            service_description=service_description,
            amount=amount,
            tax=tax,
            total=total,
            payment_method=data.get("payment_method"),
            insurance_provider=data.get("insurance_provider"),
            status=data.get("status", "pending"),
            created_by=session.get('user_id')
        )
        db.session.add(new_bill)
        db.session.commit()
        return jsonify({"msg": "Billing record created", "id": new_bill.id}), 201

@app.route('/api/users', methods=['GET', 'POST', 'DELETE'])
@jwt_required()
@role_required(UserRole.ADMIN)
def users_api():
    if request.method == 'GET':
        users = User.query.all()
        return jsonify([{
            "id": u.id,
            "email": u.email,
            "full_name": u.full_name,
            "role": u.role,
            "phone": u.phone,
            "department": u.department,
            "is_active": u.is_active,
            "created_at": u.created_at.isoformat(),
            "last_login": u.last_login.isoformat() if u.last_login else None
        } for u in users]), 200
    
    elif request.method == 'POST':
        data = request.get_json()
        email = data.get("email")
        full_name = data.get("full_name")
        password = data.get("password")
        role = data.get("role")
        phone = data.get("phone", "")
        department = data.get("department", "")
        
        if not all([email, full_name, password, role]):
            return jsonify({"msg": "Missing required fields"}), 400
        
        if User.query.filter_by(email=email).first():
            return jsonify({"msg": "Email already exists"}), 409
        
        user = User(email=email, full_name=full_name, role=role, phone=phone, department=department)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()
        
        return jsonify({"msg": "User created successfully", "id": user.id}), 201
    
    elif request.method == 'DELETE':
        user_id = request.args.get('user_id')
        if not user_id:
            return jsonify({"msg": "User ID required"}), 400
        
        user = User.query.get(user_id)
        if not user:
            return jsonify({"msg": "User not found"}), 404
        
        db.session.delete(user)
        db.session.commit()
        return jsonify({"msg": "User deleted successfully"}), 200

# Database initialization
def init_db():
    """Initialize database and create sample data"""
    try:
        with app.app_context():
            # Create tables
            db.create_all()
            
            # Check if data already exists
            if User.query.first():
                print("✅ Sample data already exists!")
                return
            
            print("🌱 Creating sample data...")
            
            # Create sample users
            users_data = [
                {'email': 'admin@healthsync.com', 'full_name': 'Admin User', 'role': UserRole.ADMIN, 'password': 'admin123', 'phone': '+1-555-0001', 'department': 'Administration'},
                {'email': 'doctor@healthsync.com', 'full_name': 'Dr. Johnson', 'role': UserRole.DOCTOR, 'password': 'doctor123', 'phone': '+1-555-0002', 'department': 'Cardiology'},
                {'email': 'nurse@healthsync.com', 'full_name': 'Nurse Smith', 'role': UserRole.NURSE, 'password': 'nurse123', 'phone': '+1-555-0003', 'department': 'General Medicine'},
                {'email': 'receptionist@healthsync.com', 'full_name': 'Receptionist Brown', 'role': UserRole.RECEPTIONIST, 'password': 'receptionist123', 'phone': '+1-555-0004', 'department': 'Reception'},
                {'email': 'patient@healthsync.com', 'full_name': 'Patient Smith', 'role': UserRole.PATIENT, 'password': 'patient123', 'phone': '+1-555-0005', 'department': 'Patient'},
                {'email': 'lab@healthsync.com', 'full_name': 'Lab Assistant Wilson', 'role': UserRole.LAB_ASSISTANT, 'password': 'lab123', 'phone': '+1-555-0005', 'department': 'Laboratory'},
                {'email': 'pharmacy@healthsync.com', 'full_name': 'Pharmacy Nurse Davis', 'role': UserRole.PHARMACY_NURSE, 'password': 'pharmacy123', 'phone': '+1-555-0006', 'department': 'Pharmacy'}
            ]
            
            for user_data in users_data:
                user = User(
                    email=user_data['email'],
                    full_name=user_data['full_name'],
                    role=user_data['role'],
                    phone=user_data['phone'],
                    department=user_data['department']
                )
                user.set_password(user_data['password'])
                db.session.add(user)
            
            # Create sample patients
            patients_data = [
                {'patient_id': 'P001', 'name': 'John Smith', 'age': 45, 'address': '123 Main St', 'phone': '+1-555-0123', 'gender': 'Male', 'emergency_contact': 'Jane Smith +1-555-0124', 'insurance_provider': 'Blue Cross', 'medical_history': 'Diabetes, Hypertension', 'allergies': 'Penicillin', 'blood_type': 'A+'},
                {'patient_id': 'P002', 'name': 'Jane Doe', 'age': 32, 'address': '456 Oak Ave', 'phone': '+1-555-0456', 'gender': 'Female', 'emergency_contact': 'John Doe +1-555-0457', 'insurance_provider': 'Aetna', 'medical_history': 'Asthma', 'allergies': 'None', 'blood_type': 'B+'},
                {'patient_id': 'P003', 'name': 'Robert Johnson', 'age': 58, 'address': '789 Pine Rd', 'phone': '+1-555-0789', 'gender': 'Male', 'emergency_contact': 'Mary Johnson +1-555-0790', 'insurance_provider': 'Cigna', 'medical_history': 'Heart Disease', 'allergies': 'Shellfish', 'blood_type': 'O+'},
                {'patient_id': 'P004', 'name': 'Sarah Wilson', 'age': 28, 'address': '321 Elm St', 'phone': '+1-555-0321', 'gender': 'Female', 'emergency_contact': 'Mike Wilson +1-555-0322', 'insurance_provider': 'UnitedHealth', 'medical_history': 'None', 'allergies': 'Latex', 'blood_type': 'AB+'},
                {'patient_id': 'P005', 'name': 'Michael Brown', 'age': 67, 'address': '654 Maple Ave', 'phone': '+1-555-0654', 'gender': 'Male', 'emergency_contact': 'Linda Brown +1-555-0655', 'insurance_provider': 'Medicare', 'medical_history': 'Arthritis, High Blood Pressure', 'allergies': 'Aspirin', 'blood_type': 'A-'}
            ]
            
            for patient_data in patients_data:
                patient = Patient(**patient_data)
                db.session.add(patient)
            
            # Create sample appointments
            appointments_data = [
                {'patient_id': 1, 'doctor_id': 2, 'scheduled_for': datetime.now() + timedelta(hours=2), 'appointment_type': 'General Consultation', 'location': 'Room 101', 'notes': 'Routine checkup', 'status': 'scheduled'},
                {'patient_id': 2, 'doctor_id': 2, 'scheduled_for': datetime.now() + timedelta(days=1), 'appointment_type': 'Follow-up', 'location': 'Room 102', 'notes': 'Follow-up for previous treatment', 'status': 'scheduled'},
                {'patient_id': 3, 'doctor_id': 2, 'scheduled_for': datetime.now() + timedelta(days=2), 'appointment_type': 'Emergency', 'location': 'Emergency Room', 'notes': 'Urgent care needed', 'status': 'scheduled'},
                {'patient_id': 4, 'doctor_id': 2, 'scheduled_for': datetime.now() - timedelta(hours=1), 'appointment_type': 'General Consultation', 'location': 'Room 103', 'notes': 'Completed appointment', 'status': 'completed'},
                {'patient_id': 5, 'doctor_id': 2, 'scheduled_for': datetime.now() + timedelta(days=3), 'appointment_type': 'Specialist Consultation', 'location': 'Room 104', 'notes': 'Cardiology consultation', 'status': 'scheduled'}
            ]
            
            for appointment_data in appointments_data:
                appointment = Appointment(**appointment_data)
                db.session.add(appointment)
            
            # Create sample prescriptions
            prescriptions_data = [
                {'patient_id': 1, 'doctor_id': 2, 'medication': 'Amoxicillin', 'dosage': '500mg', 'instructions': 'Take twice daily with food', 'status': 'active'},
                {'patient_id': 2, 'doctor_id': 2, 'medication': 'Ibuprofen', 'dosage': '400mg', 'instructions': 'Take as needed for pain', 'status': 'active'},
                {'patient_id': 3, 'doctor_id': 2, 'medication': 'Lisinopril', 'dosage': '10mg', 'instructions': 'Take once daily in the morning', 'status': 'active'},
                {'patient_id': 4, 'doctor_id': 2, 'medication': 'Metformin', 'dosage': '500mg', 'instructions': 'Take twice daily with meals', 'status': 'active'},
                {'patient_id': 5, 'doctor_id': 2, 'medication': 'Atorvastatin', 'dosage': '20mg', 'instructions': 'Take once daily in the evening', 'status': 'active'}
            ]
            
            for prescription_data in prescriptions_data:
                prescription = Prescription(**prescription_data)
                db.session.add(prescription)
            
            # Create sample lab results
            lab_results_data = [
                {'patient_id': 1, 'test_name': 'Complete Blood Count', 'test_type': 'Blood Test', 'results': 'Normal range', 'status': 'completed', 'uploaded_by': 5},
                {'patient_id': 2, 'test_name': 'Lipid Panel', 'test_type': 'Blood Test', 'results': 'Cholesterol levels within normal range', 'status': 'completed', 'uploaded_by': 5},
                {'patient_id': 3, 'test_name': 'X-Ray Chest', 'test_type': 'Imaging', 'results': 'No abnormalities detected', 'status': 'completed', 'uploaded_by': 5},
                {'patient_id': 4, 'test_name': 'Blood Glucose', 'test_type': 'Blood Test', 'results': 'Elevated glucose levels', 'status': 'pending', 'uploaded_by': 5},
                {'patient_id': 5, 'test_name': 'ECG', 'test_type': 'Cardiac Test', 'results': 'Normal sinus rhythm', 'status': 'completed', 'uploaded_by': 5}
            ]
            
            for lab_result_data in lab_results_data:
                lab_result = LabResult(**lab_result_data)
                db.session.add(lab_result)
            
            # Create sample billing records
            billing_data = [
                {'patient_id': 1, 'service_description': 'General Consultation', 'amount': 150.00, 'tax': 12.00, 'total': 162.00, 'payment_method': 'cash', 'insurance_provider': 'Blue Cross', 'status': 'paid', 'created_by': 4},
                {'patient_id': 2, 'service_description': 'Follow-up Visit', 'amount': 100.00, 'tax': 8.00, 'total': 108.00, 'payment_method': 'credit', 'insurance_provider': 'Aetna', 'status': 'pending', 'created_by': 4},
                {'patient_id': 3, 'service_description': 'Emergency Visit', 'amount': 300.00, 'tax': 24.00, 'total': 324.00, 'payment_method': 'insurance', 'insurance_provider': 'Cigna', 'status': 'pending', 'created_by': 4},
                {'patient_id': 4, 'service_description': 'Lab Test', 'amount': 75.00, 'tax': 6.00, 'total': 81.00, 'payment_method': 'cash', 'insurance_provider': 'UnitedHealth', 'status': 'paid', 'created_by': 4},
                {'patient_id': 5, 'service_description': 'Specialist Consultation', 'amount': 200.00, 'tax': 16.00, 'total': 216.00, 'payment_method': 'check', 'insurance_provider': 'Medicare', 'status': 'pending', 'created_by': 4}
            ]
            
            for billing_data_item in billing_data:
                billing = Billing(**billing_data_item)
                db.session.add(billing)
            
            # Create sample medication inventory
            from datetime import date
            inventory_data = [
                {'medication_name': 'Amoxicillin', 'quantity': 100, 'unit': 'tablets', 'expiry_date': date(2025, 12, 31), 'supplier': 'MedSupply Inc'},
                {'medication_name': 'Ibuprofen', 'quantity': 200, 'unit': 'tablets', 'expiry_date': date(2025, 6, 30), 'supplier': 'PharmaCorp'},
                {'medication_name': 'Lisinopril', 'quantity': 50, 'unit': 'tablets', 'expiry_date': date(2025, 9, 15), 'supplier': 'HealthMed Ltd'},
                {'medication_name': 'Metformin', 'quantity': 150, 'unit': 'tablets', 'expiry_date': date(2025, 11, 20), 'supplier': 'MedSupply Inc'},
                {'medication_name': 'Atorvastatin', 'quantity': 75, 'unit': 'tablets', 'expiry_date': date(2025, 8, 10), 'supplier': 'PharmaCorp'}
            ]
            
            for inventory_item in inventory_data:
                inventory = MedicationInventory(**inventory_item)
                db.session.add(inventory)
            
            # Create sample shift schedules
            from datetime import time
            shift_schedules_data = [
                {'user_id': 2, 'shift_date': date.today(), 'shift_type': 'morning', 'start_time': time(6, 0), 'end_time': time(14, 0), 'department': 'Cardiology', 'responsibilities': 'Morning rounds, patient consultations, emergency cases', 'status': 'scheduled'},
                {'user_id': 2, 'shift_date': date.today() + timedelta(days=1), 'shift_type': 'afternoon', 'start_time': time(14, 0), 'end_time': time(22, 0), 'department': 'Cardiology', 'responsibilities': 'Afternoon consultations, follow-up visits, documentation', 'status': 'scheduled'},
                {'user_id': 3, 'shift_date': date.today(), 'shift_type': 'morning', 'start_time': time(6, 0), 'end_time': time(14, 0), 'department': 'General Medicine', 'responsibilities': 'Patient care, medication administration, vital monitoring', 'status': 'active'},
                {'user_id': 3, 'shift_date': date.today() + timedelta(days=1), 'shift_type': 'night', 'start_time': time(22, 0), 'end_time': time(6, 0), 'department': 'General Medicine', 'responsibilities': 'Night shift patient monitoring, emergency response', 'status': 'scheduled'},
                {'user_id': 2, 'shift_date': date.today() - timedelta(days=1), 'shift_type': 'afternoon', 'start_time': time(14, 0), 'end_time': time(22, 0), 'department': 'Cardiology', 'responsibilities': 'Completed afternoon shift', 'status': 'completed'},
            ]
            
            for shift_data in shift_schedules_data:
                shift = ShiftSchedule(**shift_data)
                db.session.add(shift)
            
            # Create Patient record for the patient user
            patient_user = User.query.filter_by(email='patient@healthsync.com').first()
            if patient_user:
                patient_record = Patient(
                    patient_id=f"P{patient_user.id:04d}",
                    name=patient_user.full_name,
                    age=35,
                    address="123 Patient Street, Health City",
                    phone=patient_user.phone,
                    gender="Male",
                    emergency_contact="Jane Smith (Spouse) - +1-555-0199",
                    insurance_provider="HealthCare Plus",
                    medical_history="No significant medical history",
                    allergies="None known",
                    blood_type="O+"
                )
                db.session.add(patient_record)
            
            # Commit all changes
            db.session.commit()
            print("✅ Sample data created successfully!")
            
    except Exception as e:
        print(f"❌ Database initialization failed: {e}")
        print("🔄 Please check your PostgreSQL connection and try again.")
        raise e

if __name__ == "__main__":
    print("🏥 Starting HealthSync - Smart Hospital Management System")
    print("=" * 60)
    
    # Initialize database
    print("📊 Initializing database...")
    init_db()
    
    print("🚀 Starting Flask development server...")
    print("📍 Application will be available at: http://localhost:5000")
    print("🔐 Login page: http://localhost:5000/login")
    print("📊 Dashboard: http://localhost:5000/dashboard")
    print("=" * 60)
    print("Press Ctrl+C to stop the server")
    print("=" * 60)
    
    # Run the application
    app.run(
        host="0.0.0.0",
        port=5000,
        debug=True,
        use_reloader=True
    )