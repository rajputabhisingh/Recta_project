from flask import Blueprint, jsonify, render_template, request, redirect, url_for, flash, get_flashed_messages, session, current_app
from flask_mail import Message
from itsdangerous import URLSafeTimedSerializer
from models.models import db, Admin, RectaAdmin, ExternalAdminUser, User, create_user_hr_employee, ShiftSchedule, create_hr_training_user, create_hr_operation_user, create_hr_wfm_user, trainer_upload_employee_data  # ✅ Import `db` properly
from werkzeug.security import generate_password_hash, check_password_hash
from app import mail  # ✅ Import `mail` from `app.py`
import secrets  # ✅ FIXED: Missing import
from flask_mail import Mail, Message
from sqlalchemy.exc import IntegrityError
from werkzeug.utils import secure_filename
import pandas as pd
import os 
from apscheduler.schedulers.background import BackgroundScheduler
from datetime import datetime, timedelta
import re
#selenium import
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.common.keys import Keys
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
import time
import subprocess

auth = Blueprint('auth', __name__)

ui_feature = Blueprint('ui_feature', __name__)  # Blueprint Define
tables = Blueprint('tables', __name__)  # Blueprint Define
samples = Blueprint('samples', __name__)  # Blueprint Define


# Flask-Mail Config
from flask import current_app as app

mail = Mail()

# ✅ Scheduler to delete deactivated admins
scheduler = BackgroundScheduler()

# **UPLOAD FOLDER**
UPLOAD_FOLDER = "uploads"
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

def get_serializer():
    return URLSafeTimedSerializer(current_app.config['SECRET_KEY'])

@auth.after_request
def add_no_cache_headers(response):
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Pragma"] = "no-cache"
    response.headers["Expires"] = "0"
    return response



def auto_login_multiple_sites(credentials, headless=False):
    chrome_options = Options()

    if headless:
        chrome_options.add_argument("--headless=new")

    chrome_options.add_argument("--start-maximized")
    chrome_options.add_argument("--disable-blink-features=AutomationControlled")
    chrome_options.add_argument("--ignore-certificate-errors")
    chrome_options.add_argument("--allow-running-insecure-content")
    chrome_options.add_argument("--disable-dev-shm-usage")
    chrome_options.add_argument("--no-sandbox")
    chrome_options.add_experimental_option("excludeSwitches", ["enable-automation"])
    chrome_options.add_experimental_option("useAutomationExtension", False)
    chrome_options.add_argument(
        "--user-agent=Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36"
    )

    driver = webdriver.Chrome(options=chrome_options)

    for idx, cred in enumerate(credentials):
        site = cred['Website']
        email = cred['Email']
        password = cred['Password']

        if idx > 0:
            driver.execute_script("window.open('');")
            driver.switch_to.window(driver.window_handles[-1])

        try:
            driver.get(site)
            print(f"\n🌐 Opening {site} in tab {idx+1}...")

            wait = WebDriverWait(driver, 15)

            if "amazon" in site:
                wait.until(EC.element_to_be_clickable((By.ID, "nav-link-accountList"))).click()
                wait.until(EC.visibility_of_element_located((By.ID, "ap_email"))).send_keys(email)
                driver.find_element(By.ID, "continue").click()
                wait.until(EC.visibility_of_element_located((By.ID, "ap_password"))).send_keys(password)
                driver.find_element(By.ID, "signInSubmit").click()
                print(f"✅ Amazon login attempted for {email}")

            elif "accounts.google.com" in site or "mail.google.com" in site:
                wait.until(EC.visibility_of_element_located((By.ID, "identifierId"))).send_keys(email)
                driver.find_element(By.ID, "identifierNext").click()
                time.sleep(2)  # Let password field appear
                wait.until(EC.visibility_of_element_located((By.NAME, "password"))).send_keys(password)
                driver.find_element(By.ID, "passwordNext").click()
                print(f"✅ Gmail login attempted for {email}")

            elif "youtube.com" in site:
                try:
                    wait.until(EC.element_to_be_clickable(
                        (By.XPATH, "//yt-formatted-string[text()='Sign in']"))).click()
                except:
                    print("🔁 Already signed in or no sign-in button")

                wait.until(EC.visibility_of_element_located((By.ID, "identifierId"))).send_keys(email)
                driver.find_element(By.ID, "identifierNext").click()
                time.sleep(2)
                wait.until(EC.visibility_of_element_located((By.NAME, "password"))).send_keys(password)
                driver.find_element(By.ID, "passwordNext").click()
                print(f"✅ YouTube login attempted for {email}")

            else:
                print(f"⚠️ No automation logic for: {site}")

            time.sleep(5)

        except Exception as e:
            print(f"❌ Login failed for {site}: {e}")

    print("\n🚀 All tabs processed. Check manually.")
    input("👀 Press Enter to exit browser...")
    driver.quit()



def read_emp_credentials_file(file_path, agent_name):
    """
    Reads a CSV or Excel file containing credentials and filters by agent_name (EmpName).
    :param file_path: Path to CSV or Excel file
    :param agent_name: The agent name (EmpName) to filter
    :return: Filtered list of dictionaries with matched rows
    """
    try:
        if file_path.lower().endswith('.csv'):
            df = pd.read_csv(file_path)
        elif file_path.lower().endswith(('.xlsx', '.xls')):
            df = pd.read_excel(file_path, engine='openpyxl')
        else:
            raise ValueError("Unsupported file format. Please upload .csv or .xlsx")

        # Clean and compare by lower-case for reliability
        df['EmpName'] = df['EmpName'].astype(str).str.lower()
        agent_name = agent_name.lower()

        # Filter rows
        matched_rows = df[df['EmpName'] == agent_name]

        return matched_rows.to_dict(orient='records')

    except Exception as e:
        print(f"Error reading file: {e}")
        return []


@auth.route("/user_login", methods=['GET', 'POST'])
def user_login():
    get_flashed_messages()  # ✅ Clears previous flash messages

    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')

        # ✅ Check if email exists in User table (HR Employee)
        user_hr = User.query.filter_by(user_email=email, user_process="hr_process").first()
        # ✅ Check if email exists in User table and belongs to trainer
        trainer = User.query.filter_by(user_email=email, user_process="trainer_process").first()
        # ✅ Check if email exists in User table and belongs to operation user
        operation_user = User.query.filter_by(user_email=email, user_process="operation_process").first()

        wfm_user =User.query.filter_by(user_email=email, user_process="wfm_process").first()

        emp_user =User.query.filter_by(user_email=email, user_process="emp_user").first()

        # ✅ HR Process Login
        if user_hr and user_hr.user_password == password:
            session['user_logged_in'] = True  
            session['user_email'] = user_hr.user_email  
            flash("HR User Login successful!", "success")
            return redirect(url_for("auth.user_dashboard"))

        # ✅ Trainer Process Login
        elif trainer and trainer.user_password == password:
            session['user_logged_in'] = True  
            session['user_email'] = trainer.user_email  
            flash("Trainer Login successful!", "success")
            return redirect(url_for("auth.trainer_dashboard"))

        # ✅ Operation Process Login (Uses Hashed Password)
        elif operation_user and check_password_hash(operation_user.user_password, password):
            session['user_logged_in'] = True  
            session['user_email'] = operation_user.user_email  
            flash("Operation User Login successful!", "success")
            return redirect(url_for("auth.operation_dashboard"))

        elif wfm_user and check_password_hash(wfm_user.user_password,password):
            session['user_logged_in']=True
            session['user_email']=wfm_user.user_email
            flash("wfm User Login successful!", "success")
            return redirect(url_for("auth.wfm_dashboard"))

        elif emp_user and emp_user.user_password==password:
            session['user_logged_in']=True
            session['user_email']=emp_user.user_email
            flash("wfm User Login successful!", "success")
            breakpoint()
            # ✅ Step 1: Get agent_name from DB using email
            trainer_emp = trainer_upload_employee_data.query.filter_by(email_address=email).first()

            if not trainer_emp:
                flash("Trainer mapping not found for this email!", "danger")
                return redirect(url_for("auth.user_login"))

            agent_name = trainer_emp.agent_name
            # ✅ Step 2: Read from either Excel or CSV
            credentials_file_path = os.path.join("static", "Employee_Website_Credentials.xlsx")  # or .csv
            credentials = read_emp_credentials_file(credentials_file_path, agent_name)

            session['emp_credentials'] = credentials  # Store to use on dashboard
            # Call with headless = False if you want to see browser
            auto_login_multiple_sites(credentials, headless=False)
            return redirect(url_for("auth.emp_user_dashboard"))
        else:
            # ✅ If email doesn't exist in any table or password is incorrect
            flash("Invalid email or password. Please try again.", "danger")
            return redirect(url_for('auth.user_login'))  

    return render_template('user_login.html')


# ✅ Function to Automate Amazon Login or Sign Up
def amazon_auto_login_or_signup():
    """Automates Amazon login or account creation."""
    email = session.get('user_email')  # ✅ Get logged-in user's email
    password = session.get('user_password')  # ✅ Get logged-in user's password

    if not email or not password:
        flash("❌ No user email or password found. Please log in again.", "danger")
        return
    
    options = webdriver.ChromeOptions()
    options.add_argument("--start-maximized")
    
    driver = webdriver.Chrome(options=options)  # Open Chrome
    driver.get("https://www.amazon.com/ap/signin")
    time.sleep(3)

    try:
        # ✅ Enter Email
        email_input = driver.find_element(By.ID, "ap_email")
        email_input.send_keys(email)
        email_input.send_keys(Keys.RETURN)
        time.sleep(3)

        # ✅ If Amazon asks for a password, log in
        if "ap_password" in driver.page_source:
            password_input = driver.find_element(By.ID, "ap_password")
            password_input.send_keys(password)
            password_input.send_keys(Keys.RETURN)
            time.sleep(5)
            flash("✅ Amazon Login Successful!", "success")
            return driver

        # ✅ If email is not recognized, go to signup
        driver.get("https://www.amazon.com/ap/register")
        time.sleep(3)

        # ✅ Fill Signup Form
        driver.find_element(By.ID, "ap_customer_name").send_keys("New User")  # Name
        driver.find_element(By.ID, "ap_email").send_keys(email)
        driver.find_element(By.ID, "ap_password").send_keys(password)
        driver.find_element(By.ID, "ap_password_check").send_keys(password)
        driver.find_element(By.ID, "continue").click()
        time.sleep(5)

        flash("✅ Amazon Account Created Successfully! Please verify OTP manually.", "success")

    except Exception as e:
        flash(f"❌ Amazon Automation Failed: {e}", "danger")

    return driver


# ✅ Emp User Dashboard Route
@auth.route("/emp_user_dashboard", methods=['GET', 'POST'])
def emp_user_dashboard():
    if request.method == 'POST':
        # ✅ Call Amazon Login/Signup Automation
        amazon_auto_login_or_signup()

    return render_template("emp_user_dashboard.html")



@auth.route("/user_logout")
def user_logout():
    session.clear()
    session.pop('user_logged_in', None)  # ✅ Destroy session
    session.pop('_flashes', None)  # ✅ Flash messages ko clear karo
    flash("You have been logged out.", "info")  # ✅ Logout ka message set karo
    return redirect(url_for('auth.user_login'))  # ✅ Redirect to login page


@auth.route("/user_dashboard")
def user_dashboard():
    return render_template("user_dashboard.html")  # Your user dashboard page


@auth.route("/admin_login", methods=['GET', 'POST'])
def admin_login():
    get_flashed_messages()  # ✅ Clears previous flash messages

    # ✅ If already logged in, redirect to dashboard
    if session.get('admin_logged_in'):
        return redirect(url_for("auth.dashboard_admin"))

    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')

        user = Admin.query.filter_by(admin_email=email).first()

        if user:
            # ✅ Check if the account is deactivated
            if user.admin_status == "deactive":
                flash("Your account is deactivated. Contact the administrator.", "danger")
                return redirect(url_for('auth.admin_login'))

            # ✅ Check password
            if user.admin_password == password:
                session['admin_logged_in'] = True  
                session['admin_email'] = user.admin_email  # ✅ Store email in session
                flash("Login successful!", "success")
                return redirect(url_for("auth.dashboard_admin"))
        
        # ❌ Invalid email or password
        flash("Invalid email or password. Please try again.", "danger")
        return redirect(url_for('auth.admin_login'))  

    return render_template('admin_login.html')



@auth.route("/admin_logout")
def admin_logout():
    session.pop('admin_logged_in', None)  # ✅ Destroy session
    session.pop('_flashes', None)  # ✅ Flash messages ko clear karo
    session.pop('_flashes', None)  # ✅ Clear flash messages
    flash("You have been logged out.", "info")  # ✅ Logout ka message set karo
    return redirect(url_for('auth.admin_login'))  # ✅ Redirect to login page


@auth.route("/dashboard_admin")
def dashboard_admin():
    # ✅ Agar user logged in nahi hai, to login page pe redirect karo
    if not session.get('admin_logged_in'):
        return redirect(url_for("auth.admin_login"))

    return render_template("dashboard_admin.html")  # Your admin dashboard page

@auth.route("/admin_forgot_password", methods=['GET', 'POST'])
def admin_forgot_password():
    if request.method == 'POST':
        email = request.form.get('email')
        user = Admin.query.filter_by(admin_email=email).first()
        
        if user:
            s = get_serializer()
            token = s.dumps(email, salt="password-reset")  
            reset_link = url_for('auth.admin_reset_forget_password', token=token, _external=True)

            msg = Message("Password Reset Request",
                          sender="bcnews54@gmail.com",
                          recipients=[email])
            msg.body = f"Click the link to reset your password: {reset_link}"
            mail.send(msg)

            flash("Password reset link has been sent to your email.", "info")
            return redirect(url_for('auth.admin_forgot_password'))
        else:
            flash("No account found with this email.", "danger")

    return render_template("admin_forgot_password.html")


@auth.route("/admin_reset_forget_password/<token>", methods=['GET', 'POST'])
def admin_reset_forget_password(token):
    try:
        s = get_serializer()
        email = s.loads(token, salt="password-reset", max_age=3600)
    except:
        flash("Invalid or expired token", "danger")
        return redirect(url_for("auth.admin_forgot_password"))

    if request.method == 'POST':
        new_password = request.form.get("new_password")
        confirm_password = request.form.get("confirm_password")

        if new_password != confirm_password:
            flash("Passwords do not match.", "danger")
            return redirect(url_for('auth.admin_reset_forget_password', token=token))

        user = Admin.query.filter_by(admin_email=email).first()

        if user:
            # ✅ Directly store new password (No Hashing)
            user.admin_password = new_password
            db.session.commit()

            flash("Your password has been updated!", "success")
            return redirect(url_for("auth.admin_login"))

    return render_template("admin_reset_forget_password.html")


@auth.route("/create_recta_admin", methods=['GET', 'POST'])
def create_recta_admin():
    if request.method == 'POST':
        first_name = request.form['first_name']
        last_name = request.form['last_name']
        email = request.form['email']
        
        # ✅ FIXED: Get the serializer instance correctly
        s = get_serializer()  # Call the function to get the serializer
        # ✅ Generate Secure Token (Valid for 5 Minutes)
        token = s.dumps({'first_name': first_name, 'last_name': last_name, 'email': email})

        # ✅ Create Registration Link
        registration_link = url_for('auth.verify_recta_admin', token=token, _external=True)

        # ✅ Send Email
        msg = Message('Complete Your Recta Admin Form', sender=app.config['MAIL_USERNAME'], recipients=[email])
        msg.body = f"Hello {first_name},\n\nClick the link below to complete your registration (Valid for 5 minutes):\n{registration_link}\n\nBest Regards,\nYour Team"
        mail.send(msg)

         # ✅ Show Flash Message Instead of JSON
        flash("Verification link has been sent to email!", "success")
        return redirect(url_for('auth.create_recta_admin'))

    return render_template('create_recta_admin.html')




@auth.route("/verify_recta_admin", methods=['GET', 'POST'])
def verify_recta_admin():
    if request.method == 'GET':  
        token = request.args.get('token')  
        if not token:
            flash("Invalid or expired token!", "danger")
            return redirect(url_for('auth.create_recta_admin'))

        try:
            s = get_serializer()
            data = s.loads(token, max_age=300)  
        except Exception as e:
            print(f"Token error: {e}")  
            flash("Invalid or expired token!", "danger")
            return redirect(url_for('auth.create_recta_admin'))

        return render_template('verify_recta_admin.html', 
                               first_name=data['first_name'], 
                               last_name=data['last_name'], 
                               email=data['email'], 
                               token=token)  

    elif request.method == 'POST':  
        token = request.form.get('token')  
        breakpoint()
        print(f"Token Length: {len(token)}")  # Debugging ke liye token ki length print karo
        contact = request.form['contact']
        password = request.form['password']
        status = request.form.get('status', 'active')  # ✅ Default "active"
        is_head = request.form.get('is_head', 'non-head')  # ✅ Default "no-head"

        if not token:
            flash("Invalid or expired token!", "danger")
            return redirect(url_for('auth.create_recta_admin'))

        try:
            s = get_serializer()
            data = s.loads(token, max_age=300)  
        except Exception as e:
            print(f"Token error on submit: {e}")
            flash("Invalid or expired token!", "danger")
            return redirect(url_for('auth.create_recta_admin'))


        try:
            # # ✅ Pehle check karo ki email already exist toh nahi karta
            existing_admin = RectaAdmin.query.filter_by(recta_email=data['email']).first()
            
            if existing_admin:
                flash("Email already exists in RectaAdmin!", "danger")
                return redirect(url_for('auth.create_recta_admin'))

            # ✅ Store in `RectaAdmin` table
            recta_admin = RectaAdmin(
                recta_firstname=data['first_name'],
                recta_lastname=data['last_name'],
                recta_email=data['email'],
                recta_contact=contact,
                recta_password=password,
                admin_status=status,
                admin_head=is_head

            ) 
                
            db.session.add(recta_admin)

            existing_admin = Admin.query.filter_by(admin_email=data['email']).first()
            
            if existing_admin:
                flash("Email already exists in Admin panel!", "danger")
                # return redirect(url_for('auth.create_recta_admin'))

            # ✅ Store in `Admin` table
            new_admin_entry = Admin(
                admin_email=data['email'],
                admin_password=password ,
                admin_status=status,
                admin_head=is_head
            )
            db.session.add(new_admin_entry)

            # ✅ Ek hi baar me dono tables ko commit karo
            db.session.commit()

            flash("Registration successful! You can now log in.", "success")
            return redirect(url_for('auth.admin_login'))

        except IntegrityError as e:
            db.session.rollback()  # ⚠️ Agar unique constraint fail ho to rollback karo
            print(f"IntegrityError: {e}")  # ✅ Debug ke liye error print karo
            flash("Email already registered!", "danger")
            return redirect(url_for('auth.create_recta_admin'))

        except Exception as e:
            db.session.rollback()  # ✅ Unexpected error handle karo
            print(f"Unexpected Error: {e}")
            flash("Something went wrong!", "danger")
            return redirect(url_for('auth.create_recta_admin'))


#show the recta admin details 
@auth.route("/show_recta_admin_user", methods=['GET'])
def show_recta_admin_user():
    # ✅ Get logged-in admin's email from session
    admin_email = session.get('admin_email')

    if not admin_email:
        flash("You are not logged in!", "danger")
        return redirect(url_for('auth.admin_login'))

    # ✅ Check if the logged-in admin exists
    admin_logged_in = Admin.query.filter_by(admin_email=admin_email).first()

    if not admin_logged_in:
        flash("Your admin account was not found!", "danger")
        return redirect(url_for('auth.admin_login'))

    # ✅ If Admin is Head, show all RectaAdmins
    if admin_logged_in.admin_head == "head":
        recta_admins = RectaAdmin.query.all()
    else:
        # ❌ If Non-Head, show flash message and return empty list
        flash("You are not an Admin Head. You cannot view this list.", "warning")
        recta_admins = []

    return render_template("show_recta_admin_user.html", recta_admins=recta_admins)


@auth.route("/toggle_admin_status/<int:admin_id>")
def toggle_admin_status(admin_id):
    # ✅ Fetch admin from RectaAdmin table
    admin = RectaAdmin.query.get(admin_id)
    
    # ✅ Fetch the corresponding admin in Admin table
    linked_admin = Admin.query.filter_by(admin_email=admin.recta_email).first()

    if not admin:
        flash("Admin not found!", "danger")
        return redirect(url_for("auth.show_recta_admin_user"))

    # ✅ Toggle status and update `deactivated_at`
    if admin.admin_status == "active":
        admin.admin_status = "deactive"
        admin.deactivated_at = datetime.utcnow()  # Store deactivation time
        
        # ✅ Also deactivate in `Admin` table
        if linked_admin:
            linked_admin.admin_status = "deactive"
        
    else:
        admin.admin_status = "active"
        admin.deactivated_at = None  # Reset deactivation time
        
        # ✅ Also activate in `Admin` table
        if linked_admin:
            linked_admin.admin_status = "active"

    # ✅ Commit both table updates
    db.session.commit()
    flash("Admin status updated successfully!", "success")

    return redirect(url_for("auth.show_recta_admin_user"))

# ✅ Function to delete users after 1 day of deactivation
def delete_old_deactivated_users():
    one_day_ago = datetime.utcnow() - timedelta(days=1)
    
    # ✅ Fetch all deactivated users from RectaAdmin
    old_users = RectaAdmin.query.filter(RectaAdmin.admin_status == "deactive", 
                                        RectaAdmin.deactivated_at <= one_day_ago).all()
    
    for user in old_users:
        # ✅ Also remove from `Admin` table
        linked_admin = Admin.query.filter_by(admin_email=user.recta_email).first()
        if linked_admin:
            db.session.delete(linked_admin)  # Remove from Admin table
        
        db.session.delete(user)  # Remove from RectaAdmin table

    db.session.commit()
    print(f"Deleted {len(old_users)} deactivated users")

# ✅ Schedule the task to run every 24 hours
scheduler.add_job(delete_old_deactivated_users, 'interval', hours=24)
scheduler.start()


#Create the Flask Route to Toggle Admin Head Status
@auth.route("/toggle_admin_head/<int:admin_id>")
def toggle_admin_head(admin_id):
    admin = RectaAdmin.query.get(admin_id)
    
    if not admin:
        flash("Admin not found!", "danger")
        return redirect(url_for("auth.show_recta_admin_user"))

    # ✅ Find the matching admin in Admin table
    main_admin = Admin.query.filter_by(admin_email=admin.recta_email).first()

    # ✅ Toggle status in both tables
    if admin.admin_head == "head":
        admin.admin_head = "no-head"
        if main_admin:
            main_admin.admin_head = "no-head"
    else:
        admin.admin_head = "head"
        if main_admin:
            main_admin.admin_head = "head"

    db.session.commit()
    flash("Admin Head status updated successfully!", "success")

    return redirect(url_for("auth.show_recta_admin_user"))



# this is admin pandel side hr external admin user link send 
@auth.route("/create_external_admin_user", methods=['GET', 'POST'])
def create_external_admin_user():
    if request.method == 'POST':
        first_name = request.form['first_name']
        last_name = request.form['last_name']
        email = request.form['email']
        
        # ✅ FIXED: Get the serializer instance correctly
        s = get_serializer()  # Call the function to get the serializer
        # ✅ Generate Secure Token (Valid for 5 Minutes)
        token = s.dumps({'first_name': first_name, 'last_name': last_name, 'email': email})

        # ✅ Create Registration Link
        registration_link = url_for('auth.verify_create_external_admin_user', token=token, _external=True)

        # ✅ Send Email
        msg = Message('Complete Your External Admin Form', sender=app.config['MAIL_USERNAME'], recipients=[email])
        msg.body = f"Hello {first_name},\n\nClick the link below to complete your registration (Valid for 5 minutes):\n{registration_link}\n\nBest Regards,\nYour Team"
        mail.send(msg)

         # ✅ Show Flash Message Instead of JSON
        flash("Verification link has been sent to email!", "success")
        return redirect(url_for('auth.create_external_admin_user'))

    return render_template('create_external_admin_user.html')


# verify external hr and open form through and verify form 
@auth.route("/verify_create_external_admin_user", methods=['GET', 'POST'])
def verify_create_external_admin_user():
    if request.method == 'GET':  
        token = request.args.get('token')  
        if not token:
            flash("Invalid or expired token!", "danger")
            return redirect(url_for('auth.create_external_admin_user'))

        try:
            s = get_serializer()
            data = s.loads(token, max_age=300)  
        except Exception as e:
            print(f"Token error: {e}")  
            flash("Invalid or expired token!", "danger")
            return redirect(url_for('auth.create_external_admin_user'))

        return render_template('verify_create_external_admin_user.html', 
                               first_name=data['first_name'], 
                               last_name=data['last_name'], 
                               email=data['email'], 
                               token=token)  

    elif request.method == 'POST':  
        token = request.form.get('token') 
        # breakpoint() 
        print(f"Token Length: {len(token)}")  # Debugging ke liye token ki length print karo
        employee_id = request.form['employee_id']
        company = request.form['company']
        account_name = request.form['account_name']
        contact = request.form['contact']
        password = request.form['password']

        if not token:
            flash("Invalid or expired token!", "danger")
            return redirect(url_for('auth.create_external_admin_user'))

        try:
            s = get_serializer()
            data = s.loads(token, max_age=300)  
        except Exception as e:
            print(f"Token error on submit: {e}")
            flash("Invalid or expired token!", "danger")
            return redirect(url_for('auth.create_external_admin_user'))


        try:
            # # ✅ Pehle check karo ki email already exist toh nahi karta
            existing_admin = ExternalAdminUser.query.filter_by(email=data['email']).first()
            
            if existing_admin:
                flash("Email already exists in External Admin user!", "danger")
                return redirect(url_for('auth.create_external_admin_user'))

            # ✅ Store in `RectaAdmin` table
            external_admin = ExternalAdminUser(
                first_name=data['first_name'],
                last_name=data['last_name'],
                email=data['email'],
                employee_id=employee_id,
                company=company,
                account_process_name=account_name,
                contact_no=contact,
                password=password
            ) 
                
            db.session.add(external_admin)

            # ✅ Store in `user_table` table
            new_user_entry = User(
                user_email=data['email'],
                user_password=password ,
                user_process="hr_process"
            )
            db.session.add(new_user_entry)

            # ✅ Ek hi baar me dono tables ko commit karo
            db.session.commit()

            flash("Registration successful! You can now log in.", "success")
            return redirect(url_for('auth.user_login'))

        except IntegrityError as e:
            db.session.rollback()  # ⚠️ Agar unique constraint fail ho to rollback karo
            print(f"IntegrityError: {e}")  # ✅ Debug ke liye error print karo
            flash("Email already registered!", "danger")
            return redirect(url_for('auth.create_external_admin_user'))

        except Exception as e:
            db.session.rollback()  # ✅ Unexpected error handle karo
            print(f"Unexpected Error: {e}")
            flash("Something went wrong!", "danger")
            return redirect(url_for('auth.create_external_admin_user'))


#hr upload excel file from user and send the link each agent user
@auth.route("/create_user_hr_form", methods=['GET', 'POST'])
def create_user_hr_form():
    # breakpoint()
    if 'user_email' not in session:  # ✅ Check if HR is logged in
        flash("Please log in first!", "danger")
        return redirect(url_for('auth.user_login'))

    hr_email = session['user_email']  # ✅ Fetch logged-in HR user's email
    
    # ✅ Check if the logged-in user is an External Admin
    external_admin = ExternalAdminUser.query.filter_by(email=hr_email).first()
    if not external_admin:
        # ✅ Redirect non-admin users to Employee Dashboard
        flash("Access denied! You do not have permission to upload files.", "danger")
        return redirect(url_for('auth.user_agent_employee_dashboard'))  # Redirect non-admins
    
    if request.method == 'POST':
        # **1. Upload File**
        file = request.files['file']
        if not file:
            flash("Please upload a file!", "danger")
            return redirect(request.url)

        filename = secure_filename(file.filename)
        filepath = os.path.join(UPLOAD_FOLDER, filename)
        file.save(filepath)

        # **2. Read Excel File**
        try:
            df = pd.read_excel(filepath)
            # Normalize column names
            df.columns = df.columns.str.strip().str.lower().str.replace(' ', '_')  # Convert all to lowercase & replace spaces with '_'

            for index, row in df.iterrows():
                email = row.get('email_address', None)  # Use `.get()` to avoid KeyError
                employee_id = row.get('employee_id', None)
                agent_name = row.get('agent_name', None)
                company_name = row.get('company_name', None)
                process_name = row.get('process_name', None)
                # ✅ **Dump all details inside token (Encrypted)**
                user_data = {
                    "email": email,
                    "employee_id": employee_id,
                    "agent_name": agent_name,
                    "company_name": company_name,
                    "process_name": process_name
                }
                token = get_serializer().dumps(user_data, salt='email-confirm')

                # ✅ **Generate Dynamic Registration Link**
                form_link = url_for('auth.hr_complete_registration_agent', token=token, _external=True)

                # **4. Send Email**
                msg = Message(
                    "Complete Your Registration",
                    sender=hr_email,
                    recipients=[email]
                )
                msg.body = f"""
                Hello {agent_name},

                Click the link below to complete your Hr agent employee registration:

                {form_link}

                Regards,
                HR Team
                """
                
                mail.send(msg)

            flash("Emails sent successfully!", "success")
        except Exception as e:
            flash(f"Error processing file: {e}", "danger")

    return render_template("create_user_hr_form.html")
   



@auth.route("/user_agent_employee_dashboard")
def user_agent_employee_dashboard():
    if not session.get('user_logged_in'):
        flash("Please log in to access your dashboard.", "warning")
        return redirect(url_for('auth.user_login'))
    
    return render_template("user_agent_employee_dashboard.html")


@auth.route("/user_agent_employee_logout")
def user_agent_employee_logout():
    session.clear()  # ✅ Clear full session
    flash("You have been logged out.", "info")
    return redirect(url_for('auth.user_login'))



# **5. Form for hr agent User Registration** hr send data each user link click link open form each agent user
@auth.route("/hr_complete_registration_agent", methods=['GET', 'POST'])
def hr_complete_registration_agent():
    if request.method == 'GET':
        token = request.args.get('token') 
        # breakpoint() 
        if not token:
            flash("Invalid or expired token!", "danger")
            return redirect(url_for('auth.create_user_hr_form'))

        try:
            # ✅ Decode the token (returns a dictionary)
            user_data = get_serializer().loads(token, salt='email-confirm', max_age=86400)

            # ✅ Access dictionary values correctly
            employee_id = user_data.get('employee_id', '')
            agent_name = user_data.get('agent_name', '')
            user_email = user_data.get('email', '')  # `email` key instead of `user_email`
            process_name = user_data.get('process_name', '')
            company_name = user_data.get('company_name', '')

        except Exception as e:
            print(f"❌ Token Error: {e}")  # Debugging
            flash("Invalid or expired link!", "danger")
            return redirect(url_for('auth.create_user_hr_form'))

        return render_template("hr_complete_registration_agent.html", 
                                   employee_id=employee_id,
                                   agent_name=agent_name,
                                   user_email=user_email,
                                   process_name=process_name,
                                   company_name=company_name,
                                   token=token)


    elif request.method == 'POST':
        token = request.form.get('token')  
        password = request.form['password']
        breakpoint()
        if not token:
            flash("Invalid or expired token please request hr team send again your request!", "danger")
            return redirect(url_for('auth.hr_complete_registration_agent'))

        try:
            user_data = get_serializer().loads(token, salt='email-confirm', max_age=86400)    

        except Exception as e:
            print(f"Token error on submit: {e}")
            flash("Invalid or expired token please request hr team send again your request!", "danger")
            return redirect(url_for('auth.hr_complete_registration_agent'))

        try:
            # ✅ Pehle check karo ki email already exist toh nahi karta
            existing_user_under_hr = create_user_hr_employee.query.filter_by(email_address=user_data['email']).first()
            
            if existing_user_under_hr:
                flash("Email already exists in create_user_hr_employee user hr employee!", "danger")
                return redirect(url_for('auth.hr_complete_registration_agent'))

            # ✅ Register create_user_hr_employee
            user_form_under_hr= create_user_hr_employee(
                employee_id=user_data['employee_id'],
                agent_name=user_data['agent_name'],
                email_address=user_data['email'],
                process_name=user_data['process_name'],
                company_name=user_data['company_name'],
                password=password
            )
            db.session.add(user_form_under_hr)

            # ✅ Store in `user_table` table
            new_user_entry_form_under_hr = User(
                user_email=user_data['email'],
                user_password=password
            )
            db.session.add(new_user_entry_form_under_hr)

            # ✅ Ek hi baar me dono tables ko commit karo
            db.session.commit()
            flash("User registered successfully!", "success")
            return redirect(url_for('auth.user_login'))

        except SignatureExpired:
            flash("Token has expired! Please request HR for a new link.", "danger")
            return redirect(url_for('auth.hr_complete_registration_agent'))

        except BadSignature:
            flash("Invalid token! Please request HR for a valid link.", "danger")
            return redirect(url_for('auth.hr_complete_registration_agent'))

        except Exception as e:
            db.session.rollback()  
            flash("Something went wrong!", "danger")
            return redirect(url_for('auth.hr_complete_registration_agent'))


# hr through create create trainer user
@auth.route("/create_training_user",methods=['GET', 'POST'])
def create_training_user():
    # breakpoint()
    if 'user_email' not in session:  # ✅ Check if HR is logged in
        flash("Please log in first!", "danger")
        return redirect(url_for('auth.user_login'))

    hr_email = session['user_email']  # ✅ Fetch logged-in HR user's email
    
    # ✅ Check if the logged-in user is an External Admin
    external_admin = ExternalAdminUser.query.filter_by(email=hr_email).first()
    if not external_admin:
        # ✅ Redirect non-admin users to Employee Dashboard
        flash("Access denied! You do not have permission to upload files.", "danger")
        return redirect(url_for('auth.trainer_dashboard'))  # Redirect non-admins

    if request.method == 'POST':
        # **1. Upload File**
        file = request.files['file']
        if not file:
            flash("Please upload a file!", "danger")
            return redirect(request.url)

        filename = secure_filename(file.filename)
        filepath = os.path.join(UPLOAD_FOLDER, filename)
        file.save(filepath)

        # **2. Read Excel File**
        try:
            df = pd.read_excel(filepath)
            # breakpoint()
            # Normalize column names
            df.columns = df.columns.str.strip().str.lower().str.replace(' ', '_')  # Convert all to lowercase & replace spaces with '_'

            for index, row in df.iterrows():
                email = row.get('email_address', None)  # Use `.get()` to avoid KeyError
                trainer_id = row.get('trainer_id', None)
                trainer_name = row.get('trainer_name', None)
                company_name = row.get('company_name', None)
                process_name = row.get('process_name', None)
                # ✅ **Dump all details inside token (Encrypted)**
                user_data = {
                    "email": email,
                    "trainer_id": trainer_id,
                    "trainer_name": trainer_name,
                    "company_name": company_name,
                    "process_name": process_name
                }
                token = get_serializer().dumps(user_data, salt='email-confirm')

                # ✅ **Generate Dynamic Registration Link**
                form_link = url_for('auth.hr_complete_registration_link_for_trainer', token=token, _external=True)

                # **4. Send Email**
                msg = Message(
                    "Complete Your Registration",
                    sender=hr_email,
                    recipients=[email]
                )
                msg.body = f"""
                Hello {trainer_name},

                Click the link below to complete your Trainer employee registration:

                {form_link}

                Regards,
                HR Team
                """
                
                mail.send(msg)

            flash("Emails sent successfully!", "success")
        except Exception as e:
            flash(f"Error processing file: {e}", "danger")
   
    return render_template("create_training_user.html")


# this is traner dashabord upload employye list generate link
@auth.route("/trainer_dashboard",methods=['GET', 'POST'])
def trainer_dashboard():
    trainer_email = session['user_email']  # ✅ Fetch logged-in HR user's email

    if request.method == 'POST':
        # **1. Upload File**
        file = request.files['file']
        if not file:
            flash("Please upload a file!", "danger")
            return redirect(request.url)

        filename = secure_filename(file.filename)
        filepath = os.path.join(UPLOAD_FOLDER, filename)
        file.save(filepath)

        # **2. Read Excel File**
        try:
            df = pd.read_excel(filepath)
            # breakpoint()
            # Normalize column names
            df.columns = df.columns.str.strip().str.lower().str.replace(' ', '_')  # Convert all to lowercase & replace spaces with '_'

            for index, row in df.iterrows():
                agent_name = row.get('agent_name', None)  # Use `.get()` to avoid KeyError
                employee_id = row.get('employee_id', None)
                email_address = row.get('email_address', None)
                position = row.get('position', None)
                contact = row.get('contact', None)
                process_name = row.get('process_name', None)
                batch_no = row.get('batch_no', None)
                department = row.get('department', None)
                # ✅ **Dump all details inside token (Encrypted)**
                trainer_data = {
                    "agent_name": agent_name,
                    "employee_id": employee_id,
                    "email_address": email_address,
                    "position": position,
                    "contact": contact,
                    "process_name":process_name,
                    "batch_no":batch_no,
                    "department":department,
                    "trainer_email":trainer_email

                }
                token = get_serializer().dumps(trainer_data, salt='email-confirm')

                # ✅ **Generate Dynamic Registration Link**
                form_link = url_for('auth.trainer_send_url_from_emp_reg', token=token, _external=True)

                # **4. Send Email**
                msg = Message(
                    "Complete Your Registration",
                    sender=trainer_email,
                    recipients=[email_address]
                )
                msg.body = f"""
                Hello {agent_name},

                You have been invited to complete your employee registration.  

                Please click the link below to complete your registration form:  

                🔗 **Registration Link:** {form_link}  

                ⚠️ **Note:** This link is valid for **24 hours** only. If the link expires, please contact Trainer to request a new one.  

                Best regards,  
                **Trainer Team**
                """
               
                mail.send(msg)

            flash("Emails sent successfully!", "success")
        except Exception as e:
            flash(f"Error processing file: {e}", "danger")

    return render_template("trainer_dashboard.html")


# trainer send url all employee and employee click link and registraion form
@auth.route("/trainer_send_url_from_emp_reg", methods=['GET', 'POST'])
def trainer_send_url_from_emp_reg():
    if request.method == 'GET':
        token = request.args.get('token') 
        # breakpoint() 
        if not token:
            flash("Invalid or expired token!", "danger")
            return redirect(url_for('auth.trainer_dashboard'))

        try:
            # ✅ Decode the token (returns a dictionary)
            trainer_emp_data = get_serializer().loads(token, salt='email-confirm', max_age=86400)
            # breakpoint()
            # ✅ Access dictionary values correctly
            agent_name = trainer_emp_data.get('agent_name', '')
            employee_id = trainer_emp_data.get('employee_id', '')
            email_address = trainer_emp_data.get('email_address', '')  # `email` key instead of `user_email`
            position = trainer_emp_data.get('position', '')
            contact = trainer_emp_data.get('contact', '')
            process_name = trainer_emp_data.get('process_name', '')
            batch_no = trainer_emp_data.get('batch_no', '')
            department = trainer_emp_data.get('department', '')
            trainer_email = trainer_emp_data.get('trainer_email','')


        except Exception as e:
            print(f"❌ Token Error: {e}")  # Debugging
            flash("Invalid or expired link!", "danger")
            return redirect(url_for('auth.trainer_dashboard'))

        return render_template("trainer_send_url_from_emp_reg.html", 
                                   agent_name=agent_name,
                                   employee_id=employee_id,
                                   email_address=email_address,
                                   position=position,
                                   contact=contact,
                                   process_name=process_name,
                                   batch_no=batch_no,
                                   department=department,
                                   trainer_email=trainer_email,
                                   token=token)


    elif request.method == 'POST':
        token = request.form.get('token')  
        password = request.form['password']
        trainer_emp_data = get_serializer().loads(token, salt='email-confirm', max_age=86400)  
        trainer_email = trainer_emp_data.get('trainer_email') or session.get('user_email')
        
        if not trainer_email:
            flash("Session expired! Please log in again.", "danger")
            return redirect(url_for('auth.user_login'))  # Redirect to login if session is missing

        # ✅ Fetch trainer details using the stored email
        trainer = create_hr_training_user.query.filter_by(email_address=trainer_email).first()

        if not trainer:
            flash("Trainer not found!", "danger")
            return redirect(url_for('auth.trainer_send_url_from_emp_reg'))  # Redirect back

        trainer_name = trainer.trainer_name  # ✅ Trainer name is now correctly assigned

        if not token:
            flash("Invalid or expired token please request your trainer send again your request!", "danger")
            return redirect(url_for('auth.trainer_send_url_from_emp_reg'))

        try:
            trainer_emp_data = get_serializer().loads(token, salt='email-confirm', max_age=86400)    

        except Exception as e:
            print(f"Token error on submit: {e}")
            flash("Invalid or expired token please request your trainer send again your request!", "danger")
            return redirect(url_for('auth.trainer_send_url_from_emp_reg'))

        try:
            existing_emp = trainer_upload_employee_data.query.filter_by(email_address=trainer_emp_data['email_address']).first()
            
            if existing_emp:
                flash("Email already exists employee!", "danger")
                return redirect(url_for('auth.trainer_send_url_from_emp_reg'))

            # ✅ Register emp data
            create_hr_training_user_data= trainer_upload_employee_data(
                agent_name=trainer_emp_data['agent_name'],
                employee_id=trainer_emp_data['employee_id'],
                email_address=trainer_emp_data['email_address'],
                position=trainer_emp_data['position'],
                contact=trainer_emp_data['contact'],
                process_name=trainer_emp_data['process_name'],
                batch_no=trainer_emp_data['batch_no'],
                department=trainer_emp_data['department'],
                password=password,
                supervisor_name_trainer=trainer_name
            )
            db.session.add(create_hr_training_user_data)
            # ✅ Pehle check karo ki email already exist toh nahi karta
            existing_emp_data_user_table= User.query.filter_by(user_email=trainer_emp_data['email_address']).first()
            
            if existing_emp_data_user_table:
                flash("Email already exists in database!", "danger")
                return render_template('trainer_send_url_from_emp_reg.html', token=token)

            # ✅ Store in `user_table` table
            under_trainer_emp_data_store = User(
                user_email=trainer_emp_data['email_address'],
                user_password=password,
                user_process = "emp_user"
            )
            db.session.add(under_trainer_emp_data_store)

            # ✅ Ek hi baar me dono tables ko commit karo
            db.session.commit()
            flash("User registered successfully!", "success")
            return redirect(url_for('auth.user_login'))

        except SignatureExpired:
            flash("Token has expired! Please request HR for a new link.", "danger")
            return redirect(url_for('auth.trainer_send_url_from_emp_reg'))

        except BadSignature:
            flash("Invalid token! Please request HR for a valid link.", "danger")
            return redirect(url_for('auth.trainer_send_url_from_emp_reg'))

        except Exception as e:
            db.session.rollback()  
            flash("Something went wrong!", "danger")
            return redirect(url_for('auth.trainer_send_url_from_emp_reg'))



# hr through send all trainer link regstration
@auth.route("/hr_complete_registration_link_for_trainer", methods=['GET', 'POST'])
def hr_complete_registration_link_for_trainer():
    if request.method == 'GET':
        token = request.args.get('token') 
        # breakpoint() 
        if not token:
            flash("Invalid or expired token!", "danger")
            return redirect(url_for('auth.create_training_user'))

        try:
            # ✅ Decode the token (returns a dictionary)
            user_data = get_serializer().loads(token, salt='email-confirm', max_age=86400)

            # ✅ Access dictionary values correctly
            trainer_id = user_data.get('trainer_id', '')
            trainer_name = user_data.get('trainer_name', '')
            user_email = user_data.get('email', '')  # `email` key instead of `user_email`
            process_name = user_data.get('process_name', '')
            company_name = user_data.get('company_name', '')

        except Exception as e:
            print(f"❌ Token Error: {e}")  # Debugging
            flash("Invalid or expired link!", "danger")
            return redirect(url_for('auth.create_training_user'))

        return render_template("hr_complete_registration_link_for_trainer.html", 
                                   trainer_id=trainer_id,
                                   trainer_name=trainer_name,
                                   user_email=user_email,
                                   process_name=process_name,
                                   company_name=company_name,
                                   token=token)


    elif request.method == 'POST':
        token = request.form.get('token')  
        password = request.form['password']
        # breakpoint()
        if not token:
            flash("Invalid or expired token please request hr team send again your request!", "danger")
            return redirect(url_for('auth.hr_complete_registration_link_for_trainer'))

        try:
            user_data = get_serializer().loads(token, salt='email-confirm', max_age=86400)    

        except Exception as e:
            print(f"Token error on submit: {e}")
            flash("Invalid or expired token please request hr team send again your request!", "danger")
            return redirect(url_for('auth.hr_complete_registration_link_for_trainer'))

        try:
            existing_user_inside_create_hr_training_user = create_hr_training_user.query.filter_by(email_address=user_data['email']).first()
            
            if existing_user_inside_create_hr_training_user:
                flash("Email already exists in create_user_hr_employee user hr employee!", "danger")
                return redirect(url_for('auth.hr_complete_registration_link_for_trainer'))

            # ✅ Register create_user_hr_employee
            create_hr_training_user_data= create_hr_training_user(
                trainer_id=user_data['trainer_id'],
                trainer_name=user_data['trainer_name'],
                email_address=user_data['email'],
                process_name=user_data['process_name'],
                company_name=user_data['company_name'],
                password=password
            )
            db.session.add(create_hr_training_user_data)
            # ✅ Pehle check karo ki email already exist toh nahi karta
            existing_trainer_user_in_user_table= User.query.filter_by(user_email=user_data['email']).first()
            
            if existing_trainer_user_in_user_table:
                flash("Email already exists in database!", "danger")
                return render_template('hr_complete_registration_link_for_trainer.html', token=token)
            # ✅ Store in `user_table` table
            new_trainer_entry_form_under_hr = User(
                user_email=user_data['email'],
                user_password=password  ,
                user_process = "trainer_process"
            )
            db.session.add(new_trainer_entry_form_under_hr)

            # ✅ Ek hi baar me dono tables ko commit karo
            db.session.commit()
            flash("User registered successfully!", "success")
            return redirect(url_for('auth.user_login'))

        except SignatureExpired:
            flash("Token has expired! Please request HR for a new link.", "danger")
            return redirect(url_for('auth.hr_complete_registration_agent'))

        except BadSignature:
            flash("Invalid token! Please request HR for a valid link.", "danger")
            return redirect(url_for('auth.hr_complete_registration_agent'))

        except Exception as e:
            db.session.rollback()  
            flash("Something went wrong!", "danger")
            return redirect(url_for('auth.hr_complete_registration_link_for_trainer'))




# hr through create create_operation_user
@auth.route("/create_operation_user", methods=['GET', 'POST'])
def create_operation_user():
    if request.method == 'POST':
        op_id = request.form.get('operation_id')
        first_name = request.form.get('first_name')
        last_name = request.form.get('last_name')
        email = request.form.get('op_email')
        contact = request.form.get('op_contact')
        process_name = request.form.get('process_name')
        company_name = request.form.get('company_name')

        # ✅ Duplicate Check
        existing_op_user = create_hr_operation_user.query.filter_by(op_email=email).first()
        if existing_op_user:
            flash("This email is already registered!", "danger")
            return redirect(url_for('auth.create_operation_user'))

        # ✅ Store full user data in the token (not just email)
        user_data = {
            "email": email,
            "op_id": op_id,
            "first_name": first_name,
            "last_name": last_name,
            "contact": contact,
            "process_name": process_name,
            "company_name": company_name
        }
        token = get_serializer().dumps(user_data, salt='email-confirm')

        # ✅ Generate verification link
        verification_url = url_for('auth.verify_email_operation_user', token=token, _external=True)

        # ✅ Send verification email
        send_verification_email_operation_user(email, first_name, verification_url)

        flash(f"Verification link sent to {first_name} at {email}!", "success")
        return redirect(url_for('auth.create_operation_user'))

    return render_template("create_operation_user_reg.html")



# ✅ Email Sending Function operation user
def send_verification_email_operation_user(email, name, verification_url):
    hr_email = session.get('user_email')  # ✅ Get logged-in HR's email

    if not hr_email:
        flash("HR email not found! Please log in again.", "danger")
        return

    msg = Message(
        subject="Verify Your Email",
        sender=hr_email,  # ✅ Set HR's email as sender
        recipients=[email]
    )
    msg.body = f"""
    Hi {name},  

    Please click the link below to complete your registration:  
    {verification_url}  

    This link is valid for only 24 hours.  
    Set your password and submit to complete the process.  

    Regards,  
    {hr_email}  # ✅ Display HR's email in the message too
    """
    mail.send(msg)



@auth.route("/verify_email_operation_user", methods=['GET', 'POST'])
def verify_email_operation_user():
    if request.method == 'POST':
        token = request.form.get('token')
        password = request.form.get('password')

        if not token:
            flash("Invalid or expired token!", "danger")
            return redirect(url_for('auth.create_operation_user'))

        try:
            # ✅ Extract full user data from token
            user_data = get_serializer().loads(token, salt='email-confirm', max_age=86400)  # ⏳ 24-hour expiry
        except SignatureExpired:
            flash("The verification link has expired. Please request a new link.", "danger")
            return redirect(url_for('auth.create_operation_user'))
        except BadSignature:
            flash("Invalid verification link!", "danger")
            return redirect(url_for('auth.create_operation_user'))

        email = user_data["email"]

        # ✅ Check if the user already exists in the database
        user = create_hr_operation_user.query.filter_by(op_email=email).first()

        if not user:
            # ✅ Insert full user details into `create_hr_operation_user`
            user = create_hr_operation_user(
                op_id=user_data["op_id"],
                op_first_name=user_data["first_name"],
                op_last_name=user_data["last_name"],
                op_email=email,
                op_contact_no=user_data["contact"],
                op_process_name=user_data["process_name"],
                op_company_name=user_data["company_name"],
                op_password=generate_password_hash(password)  # ✅ Hash the password before storing
            )
            db.session.add(user)

            # ✅ Also insert into `user_table` with process_name as "operation_process"
            new_user_entry = User(
                user_email=email,
                user_password=generate_password_hash(password),
                user_process="operation_process"  # ✅ Static value for process_name
            )
            db.session.add(new_user_entry)

        else:
            # ✅ Update existing user's password in both tables
            user.op_password = generate_password_hash(password)
            
            existing_user_op = User.query.filter_by(user_email=email).first()
            if existing_user_op:
                existing_user.user_password = generate_password_hash(password)
            else:
                # ✅ If user doesn't exist in `user_table`, insert new entry
                new_user_entry = User(
                    user_email=email,
                    user_password=generate_password_hash(password),
                    user_process="operation_process"
                )
                db.session.add(new_user_entry)

        db.session.commit()  # ✅ Save changes to DB

        flash(f"Email verified for {user.op_first_name}! Password set successfully. You can now log in.", "success")
        return redirect(url_for('auth.user_login'))  # ✅ Redirect to login page

    # ✅ If GET request, fetch and display user details
    token = request.args.get('token')
    if not token:
        flash("Invalid verification link!", "danger")
        return redirect(url_for('auth.create_operation_user'))

    try:
        user_data = get_serializer().loads(token, salt='email-confirm', max_age=86400)  # ⏳ 24-hour expiry
    except (SignatureExpired, BadSignature):
        flash("Invalid or expired token!", "danger")
        return redirect(url_for('auth.create_operation_user'))

    return render_template("verify_email_operation_user.html", token=token, user_data=user_data)




# hr through create create_wfm_user
@auth.route("/create_wfm_user", methods=['GET', 'POST'])
def create_wfm_user():
    if request.method == 'POST':
        wfm_id = request.form.get('wfm_id')
        wfm_first_name = request.form.get('wfm_first_name')
        wfm_last_name = request.form.get('wfm_last_name')
        wfm_email = request.form.get('wfm_email')
        wfm_contact_no = request.form.get('wfm_contact')
        wfm_process_name = request.form.get('wfm_process_name')
        wfm_company_name = request.form.get('wfm_company_name')

        # ✅ Duplicate Check
        existing_wfm_user = create_hr_wfm_user.query.filter_by(wfm_email=wfm_email).first()
        if existing_wfm_user:
            flash("This email is already registered!", "danger")
            return redirect(url_for('auth.create_wfm_user'))

        # ✅ Store full user data in the token (not just email)
        wfm_user_data = {
            "wfm_email": wfm_email,
            "wfm_id": wfm_id,
            "wfm_first_name": wfm_first_name,
            "wfm_last_name": wfm_last_name,
            "wfm_contact_no": wfm_contact_no,
            "wfm_process_name": wfm_process_name,
            "wfm_company_name": wfm_company_name
        }
        token = get_serializer().dumps(wfm_user_data, salt='email-confirm')

        # ✅ Generate verification link
        verification_url = url_for('auth.verify_email_wfm_user', token=token, _external=True)

        # ✅ Send verification email
        send_verification_email_wfm_user(wfm_email, wfm_first_name, verification_url)

        flash(f"Verification link sent to {wfm_first_name} at {wfm_email}!", "success")
        return redirect(url_for('auth.create_wfm_user'))

    return render_template("create_wfm_user_reg.html")


# ✅ Email Sending Function wfm user
def send_verification_email_wfm_user(wfm_email, wfm_first_name, verification_url):
    hr_email = session.get('user_email')  # ✅ Get logged-in HR's email

    if not hr_email:
        flash("HR email not found! Please log in again.", "danger")
        return

    msg = Message(
        subject="Verify Your Email",
        sender=hr_email,  # ✅ Set HR's email as sender
        recipients=[wfm_email]
    )
    msg.body = f"""
    Hi {wfm_first_name},  

    Please click the link below to complete your registration:  
    {verification_url}  

    This link is valid for only 24 hours.  
    Set your password and submit to complete the process.  

    Regards,  
    {hr_email}  # ✅ Display HR's email in the message too
    """
    mail.send(msg)


@auth.route("/verify_email_wfm_user", methods=['GET', 'POST'])
def verify_email_wfm_user():
    # breakpoint()
    if request.method == 'POST':
        token = request.form.get('token')
        password = request.form.get('password')

        if not token:
            flash("Invalid or expired token!", "danger")
            return redirect(url_for('auth.create_wfm_user'))

        try:
            # ✅ Extract full user data from token
           wfm_user_data = get_serializer().loads(token, salt='email-confirm', max_age=86400)  # ⏳ 24-hour expiry
        except SignatureExpired:
            flash("The verification link has expired. Please request a new link.", "danger")
            return redirect(url_for('auth.create_wfm_user'))
        except BadSignature:
            flash("Invalid verification link!", "danger")
            return redirect(url_for('auth.create_wfm_user'))

        email = wfm_user_data["wfm_email"]

        # ✅ Check if the user already exists in the database
        wfm_user = create_hr_wfm_user.query.filter_by(wfm_email=email).first()

        if not wfm_user:
            # ✅ Insert full user details into `create_hr_operation_user`
            wfm_user = create_hr_wfm_user(
                wfm_id=wfm_user_data["wfm_id"],
                wfm_first_name=wfm_user_data["wfm_first_name"],
                wfm_last_name=wfm_user_data["wfm_last_name"],
                wfm_email=email,
                wfm_contact_no=wfm_user_data["wfm_contact_no"],
                wfm_process_name=wfm_user_data["wfm_process_name"],
                wfm_company_name=wfm_user_data["wfm_company_name"],
                wfm_password=generate_password_hash(password)  # ✅ Hash the password before storing
            )
            db.session.add(wfm_user)

            # ✅ Also insert into `user_table` with process_name as "operation_process"
            new_user_entry_wfm = User(
                user_email=email,
                user_password=generate_password_hash(password),
                user_process="wfm_process"  # ✅ Static value for process_name
            )
            db.session.add(new_user_entry_wfm)

        else:
            # ✅ Update existing user's password in both tables
            wfm_user.wfm_password = generate_password_hash(password)
            breakpoint()
            existing_user_wfm = User.query.filter_by(user_email=email).first()
            if existing_user_wfm:
                existing_user_wfm.user_password = generate_password_hash(password)
            else:
                # ✅ If user doesn't exist in `user_table`, insert new entry
                new_user_entry_wfm = User(
                    user_email=email,
                    user_password=generate_password_hash(password),
                    user_process="wfm_process"
                )
                db.session.add(new_user_entry_wfm)

        db.session.commit()  # ✅ Save changes to DB

        flash(f"Email verified for {wfm_user.wfm_first_name}! Password set successfully. You can now log in.", "success")
        return redirect(url_for('auth.user_login'))  # ✅ Redirect to login page

    # ✅ If GET request, fetch and display user details
    token = request.args.get('token')
    if not token:
        flash("Invalid verification link!", "danger")
        return redirect(url_for('auth.create_wfm_user'))

    try:
        wfm_user_data = get_serializer().loads(token, salt='email-confirm', max_age=86400)  # ⏳ 24-hour expiry
    except (SignatureExpired, BadSignature):
        flash("Invalid or expired token!", "danger")
        return redirect(url_for('auth.create_wfm_user'))

    return render_template("verify_email_wfm_user.html", token=token, wfm_user_data=wfm_user_data)



# wfm tdahboard
@auth.route("/wfm_dashboard", methods=['GET', 'POST'])
def wfm_dashboard():
    wfm_email = session.get('user_email')  # ✅ Fetch logged-in WFM user's email

    if request.method == 'POST':
        # **1. Upload CSV/Excel File**
        file = request.files.get('file')
        if not file:
            flash("Please upload a file!", "danger")
            return redirect(request.url)

        filename = secure_filename(file.filename)
        filepath = os.path.join(UPLOAD_FOLDER, filename)
        file.save(filepath)

        # **2. Read File (CSV or Excel)**
        try:
            df = pd.read_excel(filepath, engine='openpyxl') if filepath.endswith(('.xlsx', '.xls')) else pd.read_csv(filepath)
            df.columns = df.columns.str.strip().str.lower().str.replace(' ', '_')  # Normalize column names

            # ✅ Extract date columns dynamically (like "24-Mar Mon")
            date_columns = [col for col in df.columns if re.match(r'\d{1,2}-[A-Za-z]{3}', col)]
            breakpoint()
            # ✅ Extract Year from filename or system date
            year_match = re.search(r'(\d{4})', filename)
            year = year_match.group(1) if year_match else str(datetime.now().year)

            # ✅ Loop through each row and store data
            for index, row in df.iterrows():
                emp_id = row.get('emp', None)
                name = row.get('name', None)
                location = row.get('location', None)
                supervisor = row.get('supervisor', None)
                shift = row.get('shift', None)  # ✅ Store the general shift time

                # ✅ Loop through date columns to store shifts dynamically
                for col in date_columns:
                    day, month_abbr = col.split('-')[:2]  # Extract "24" and "Mar"
                    full_date = f"{day}-{month_abbr}-{year}"  # ✅ Correct format: "24-Mar-2025"
                    shift_time = row.get(col, None)  # ✅ Get shift time for that date

                    # ✅ **Store in Database**
                    new_shift = ShiftSchedule(
                        emp_id=emp_id,
                        name=name,
                        location=location,
                        supervisor=supervisor,
                        shift=shift,  # ✅ Store row-wise shift time
                        date=full_date,  # ✅ Dynamic date
                        shift_time=shift_time,  # ✅ Store actual shift timing
                        wfm_user_uploaded_name=wfm_email
                    )
                    db.session.add(new_shift)

            db.session.commit()  # ✅ Save all data
            flash("Shift schedule uploaded successfully!", "success")

        except Exception as e:
            flash(f"Error processing file: {e}", "danger")

    return render_template("wfm_dashboard.html")



# hr through create create_quality_team_user
@auth.route("/create_quality_team_user", methods=['GET', 'POST'])
def create_quality_team_user():
    return render_template("create_quality_team_user.html")


@auth.route("/hr_create_single_account", methods=['GET', 'POST'])
def hr_create_single_account():
    if request.method == 'POST':
        employee_id = request.form.get('employee_id')
        agent_name = request.form.get('agent_name')
        email_address = request.form.get('email')
        process_name = request.form.get('process_name')
        company_name = request.form.get('company_name')
        password = request.form.get('password')

        # ✅ Check if the user already exists in the DB
        existing_user = create_user_hr_employee.query.filter_by(email_address=email_address).first()

        if existing_user:
            flash("User already exists with this email!", "danger")
            return redirect(url_for('auth.hr_create_single_account'))  # Redirect back to form

        # ✅ If user does not exist, insert into DB
        hr_through_under_new_user_employee= create_user_hr_employee(
            employee_id=employee_id,
            agent_name=agent_name,
            email_address=email_address,
            process_name=process_name,
            company_name=company_name,
            password=password
        )

        db.session.add(hr_through_under_new_user_employee)
        db.session.commit()

        flash("User registered successfully!", "success")
        return redirect(url_for('auth.user_dashboard'))  # Redirect to user dashboard

    return render_template("hr_create_single_account.html")  # Render the form page


@ui_feature.route('/ui-features/buttons')
def buttons():
    return render_template('ui-features/buttons.html')  # Correct Path

@ui_feature.route('/ui-features/dropdowns')
def dropdowns():
    return render_template('ui-features/dropdowns.html')  # Correct Path

@tables.route("/tables/basic_table")
def basic_table():
    return render_template("tables/basic-table.html")

@samples.route("/samples/samples_login")
def samples_login():
    return render_template("samples/login.html")

@samples.route("/samples/samples_register")
def samples_register():
    return render_template("samples/register.html")
