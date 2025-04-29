from flask_sqlalchemy import SQLAlchemy
from datetime import datetime

db = SQLAlchemy()

class Admin(db.Model):
    __tablename__ = 'admin_table'  # Matches the PostgreSQL table
    admin_id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    admin_email = db.Column(db.String(255), unique=True, nullable=False)
    admin_password = db.Column(db.Text, nullable=False)

    # ✅ New Fields
    admin_status = db.Column(db.String(10), nullable=False, default='active')  # "active" or "deactive"
    admin_head = db.Column(db.String(10), nullable=False, default='no-head')  # "head" or "no-head"


    def __init__(self, admin_email, admin_password, admin_status="active", admin_head="no-head"):
        self.admin_email = admin_email
        self.admin_password = admin_password
        self.admin_status = admin_status
        self.admin_head = admin_head

    def __repr__(self):
        return f"<Admin {self.admin_email} - {self.admin_status} - {self.admin_head}>"




class RectaAdmin(db.Model):
    __tablename__ = 'Recta_admin_user'  # Matches the PostgreSQL table name

    recta_id = db.Column(db.BigInteger, primary_key=True, autoincrement=True)  # Ensures unique ID
    recta_firstname = db.Column(db.String(50), nullable=False)
    recta_lastname = db.Column(db.String(50), nullable=False)
    recta_email = db.Column(db.String(100), unique=True, nullable=False)  # Unique constraint for email
    recta_contact = db.Column(db.String(20), nullable=True)
    recta_password = db.Column(db.String(255), nullable=False)  # Stored securely (hashing recommended)

    # ✅ Admin Status Fields
    admin_status = db.Column(db.String(10), nullable=False, default='active')  # "active" or "deactive"
    admin_head = db.Column(db.String(10), nullable=False, default='non-head')  # "head" or "non-head"
    
    # ✅ New column for tracking deactivation time
    deactivated_at = db.Column(db.DateTime, nullable=True)

    def __init__(self, recta_firstname, recta_lastname, recta_email, recta_contact, recta_password, admin_status="active", admin_head="non-head"):
        self.recta_firstname = recta_firstname
        self.recta_lastname = recta_lastname
        self.recta_email = recta_email
        self.recta_contact = recta_contact
        self.recta_password = recta_password  # Store securely (use hashing)
        self.admin_status = admin_status  # Default: "active"
        self.admin_head = admin_head  # Default: "non-head"
        self.deactivated_at = None  # Default: Not deactivated

    def deactivate(self):
        """Set admin to 'deactive' and store deactivation time."""
        self.admin_status = "deactive"
        self.deactivated_at = datetime.utcnow()

    def activate(self):
        """Set admin to 'active' and remove deactivation time."""
        self.admin_status = "active"
        self.deactivated_at = None

    def __repr__(self):
        return f"<RectaAdmin {self.recta_email} - Status: {self.admin_status} - Role: {self.admin_head}>"




class ExternalAdminUser(db.Model):
    __tablename__ = 'external_admin_user'

    id = db.Column(db.BigInteger, primary_key=True, autoincrement=True)
    first_name = db.Column(db.String(50), nullable=False)
    last_name = db.Column(db.String(50), nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    employee_id = db.Column(db.String(20), unique=True, nullable=False)
    company = db.Column(db.String(100), nullable=False)
    account_process_name = db.Column(db.String(100), nullable=False)
    contact_no = db.Column(db.String(20), nullable=False)
    password = db.Column(db.String(255), nullable=True)  # Increased length

class User(db.Model):
    __tablename__ = 'user_table'  # Matches the PostgreSQL table

    user_id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    user_email = db.Column(db.String(255), unique=True, nullable=False)
    user_password = db.Column(db.Text, nullable=False)
    user_process = db.Column(db.Text, nullable=False)

    def __init__(self, user_email, user_password, user_process):
        self.user_email = user_email
        self.user_password = user_password
        self.user_process = user_process

    def __repr__(self):
        return f"<User {self.user_email}>"




class create_user_hr_employee(db.Model):
    __tablename__ = 'create_user_hr_employee'  # Table name in the database

    serial_number = db.Column(db.Integer, primary_key=True, autoincrement=True)
    employee_id = db.Column(db.String(20), unique=True, nullable=False)
    agent_name = db.Column(db.String(100), nullable=False)
    email_address = db.Column(db.String(255), unique=True, nullable=False)
    process_name = db.Column(db.String(100), nullable=False)
    company_name = db.Column(db.String(100), nullable=False)
    password = db.Column(db.String(255), nullable=False)  # ✅ Added password field

    def __init__(self, employee_id, agent_name, email_address, process_name, company_name, password):
        self.employee_id = employee_id
        self.agent_name = agent_name
        self.email_address = email_address
        self.process_name = process_name
        self.company_name = company_name
        self.password = password  # ✅ Store password

    def __repr__(self):
        return f"<Employee {self.employee_id} - {self.agent_name}>"



class create_hr_training_user(db.Model):
    __tablename__ = 'create_hr_training_user'  # Table name in the database

    serial_number = db.Column(db.Integer, primary_key=True, autoincrement=True)
    trainer_id = db.Column(db.String(20), unique=True, nullable=False)
    trainer_name = db.Column(db.String(100), nullable=False)
    email_address = db.Column(db.String(255), unique=True, nullable=False)
    process_name = db.Column(db.String(100), nullable=False)
    company_name = db.Column(db.String(100), nullable=False)
    password = db.Column(db.String(255), nullable=False)  # ✅ Added password field

    def __init__(self, trainer_id, trainer_name, email_address, process_name, company_name, password):
        self.trainer_id = trainer_id
        self.trainer_name = trainer_name
        self.email_address = email_address
        self.process_name = process_name
        self.company_name = company_name
        self.password = password  # ✅ Store password

    def __repr__(self):
        return f"<Employee {self.trainer_id} - {self.trainer_name}>"



class trainer_upload_employee_data(db.Model):
    __tablename__ = 'trainer_upload_employee_data'  # Table name in the database

    emp_id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    agent_name = db.Column(db.String(20), unique=True, nullable=False)
    employee_id = db.Column(db.String(100), nullable=False)
    email_address = db.Column(db.String(255), unique=True, nullable=False)
    position = db.Column(db.String(100), nullable=False)
    contact = db.Column(db.String(20), nullable=False)
    process_name = db.Column(db.String(100), nullable=False)
    batch_no = db.Column(db.String(100), nullable=False)
    department = db.Column(db.String(255), nullable=False)  # ✅ Added password field
    password = db.Column(db.String(255), nullable=False)  # ✅ Added password field
    supervisor_name_trainer = db.Column(db.String(100), nullable=False)


    def __init__(self, agent_name, employee_id, email_address, position, contact, process_name, batch_no,department,password,supervisor_name_trainer):
        self.agent_name = agent_name
        self.employee_id = employee_id
        self.email_address = email_address
        self.position = position
        self.contact = contact  # ✅ Store password
        self.process_name = process_name
        self.batch_no = batch_no
        self.department = department
        self.password=password
        self.supervisor_name_trainer=supervisor_name_trainer


    def __repr__(self):
        return f"<Employee {self.employee_id} - {self.agent_name}>"


class create_hr_operation_user(db.Model):
    __tablename__ = 'create_hr_operation_user'  # Table name in the database

    op_serial_number = db.Column(db.Integer, primary_key=True, autoincrement=True)
    op_id = db.Column(db.String(20), unique=True, nullable=False)
    op_first_name = db.Column(db.String(100), nullable=False)
    op_last_name = db.Column(db.String(100), nullable=False)
    op_email = db.Column(db.String(255), unique=True, nullable=False)
    op_contact_no = db.Column(db.String(20), nullable=False)
    op_process_name = db.Column(db.String(100), nullable=False)
    op_company_name = db.Column(db.String(100), nullable=False)
    op_password = db.Column(db.String(255), nullable=False)  # ✅ Added password field

    def __init__(self, op_id, op_first_name, op_last_name,op_email, op_contact_no, op_process_name, op_company_name,op_password):
        self.op_id = op_id
        self.op_first_name = op_first_name
        self.op_last_name=op_last_name
        self.op_email = op_email
        self.op_contact_no = op_contact_no
        self.op_process_name = op_process_name
        self.op_company_name = op_company_name  # ✅ Store password
        self.op_password = op_password

    def __repr__(self):
        return f"<Employee {self.op_id} - {self.op_first_name}>"




class create_hr_wfm_user(db.Model):
    __tablename__ = 'create_hr_wfm_user'  # Table name in the database

    wfm_serial_number = db.Column(db.Integer, primary_key=True, autoincrement=True)
    wfm_id = db.Column(db.String(20), unique=True, nullable=False)
    wfm_first_name = db.Column(db.String(100), nullable=False)
    wfm_last_name = db.Column(db.String(100), nullable=False)
    wfm_email = db.Column(db.String(255), unique=True, nullable=False)
    wfm_contact_no = db.Column(db.String(20), nullable=False)
    wfm_process_name = db.Column(db.String(100), nullable=False)
    wfm_company_name = db.Column(db.String(100), nullable=False)
    wfm_password = db.Column(db.String(255), nullable=False)  # ✅ Added password field

    def __init__(self, wfm_id, wfm_first_name, wfm_last_name, wfm_email, wfm_contact_no, wfm_process_name, wfm_company_name,wfm_password):
        self.wfm_id = wfm_id
        self.wfm_first_name = wfm_first_name
        self.wfm_last_name= wfm_last_name
        self.wfm_email = wfm_email
        self.wfm_contact_no = wfm_contact_no
        self.wfm_process_name = wfm_process_name
        self.wfm_company_name = wfm_company_name  # ✅ Store password
        self.wfm_password = wfm_password

    def __repr__(self):
        return f"<Employee {self.wfm_id} - {self.wfm_first_name}>"



class ShiftSchedule(db.Model):
    __tablename__ = 'shift_schedule'

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    emp_id = db.Column(db.String(10), nullable=False)
    name = db.Column(db.String(100), nullable=False)  # ⬆ Increased
    location = db.Column(db.String(20), nullable=False)  # ⬆ Increased
    supervisor = db.Column(db.String(100), nullable=False)  # ⬆ Increased
    shift = db.Column(db.String(50), nullable=False)  # ⬆ Increased to 50
    date = db.Column(db.String(30), nullable=False)  # ⬆ Increased to 30
    shift_time = db.Column(db.String(30), nullable=False)  # ⬆ Increased to 30
    wfm_user_uploaded_name = db.Column(db.String(50), nullable=False)  # ⬆ Increased to 50

    def __init__(self, emp_id, name, location, supervisor, shift, date, shift_time, wfm_user_uploaded_name):
        self.emp_id = emp_id
        self.name = name
        self.location = location
        self.supervisor = supervisor
        self.shift = shift
        self.date = date
        self.shift_time = shift_time
        self.wfm_user_uploaded_name = wfm_user_uploaded_name

