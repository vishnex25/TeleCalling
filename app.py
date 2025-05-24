from flask import Flask, render_template, request, redirect, url_for, flash, Response
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
import pandas as pd
from sqlalchemy.types import JSON
from flask_migrate import Migrate
from flask import Flask, request, render_template, redirect, url_for
import os
from sqlalchemy import cast, Integer
from datetime import datetime,timedelta,timezone
from flask import send_file
import io
import pytz
from flask import jsonify
from sqlalchemy.exc import SQLAlchemyError
from flask_wtf.csrf import CSRFProtect, generate_csrf, validate_csrf
from flask_socketio import SocketIO, emit
import os.path

app = Flask(__name__)
csrf = CSRFProtect(app)
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['SECRET_KEY'] = 'your-secret-key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///datab0.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['WTF_CSRF_CHECK_DEFAULT'] = False
app.config['WTF_CSRF_ENABLED'] = False

socketio = SocketIO(app, cors_allowed_origins="*")

if not os.path.exists(app.config['UPLOAD_FOLDER']):
    os.makedirs(app.config['UPLOAD_FOLDER'])

db = SQLAlchemy(app)

# Initialize Flask-Migrate
migrate = Migrate(app, db)

login_manager = LoginManager(app)
login_manager.login_view = 'login'

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), nullable=False)
    password = db.Column(db.String(100), nullable=False)
    role = db.Column(db.String(20), nullable=False, default='user')
    college = db.Column(db.String(50), nullable=True)
    department = db.Column(db.String(50), nullable=True)
    active = db.Column(db.Boolean, default=True, nullable=False)
    thumb_id = db.Column(db.String(100), unique=True, nullable=True)
    password = db.Column(db.String(128), nullable=False)


class Activity(db.Model):
    __tablename__ = 'activity'
    id = db.Column(db.Integer, primary_key=True)
    sn = db.Column(db.Integer, nullable=False)  # Serial number
    data = db.Column(JSON, nullable=False)  # Store all other columns as JSON
    admin_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)  # Add admin_id
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    status = db.Column(db.String(20), default='pending')  # pending, reviewed
    review = db.Column(db.String(20))  # positive, negative
    submitted_at = db.Column(db.DateTime)  # Timestamp for user response
    assigned_date = db.Column(db.DateTime, default=datetime.utcnow)  # Add this line
    assigned_time = db.Column(db.DateTime, default=datetime.utcnow)  # Add this line
    remarks = db.Column(db.String(200))  # Add this line
    district = db.Column(db.String(100))  # Add district column
    uploaded_date = db.Column(db.Date, default=datetime.utcnow)  # Add this line
    second_reviews = db.relationship('SecondReview', backref='activity_review', lazy='dynamic')

    @property
    def second_reviews_count(self):
        return self.second_reviews.count()

class ReviewHistory(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    activity_id = db.Column(db.Integer, db.ForeignKey('activity.id'), nullable=False)
    review = db.Column(db.String(20))
    remarks = db.Column(db.String(200))
    submitted_at = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    activity = db.relationship('Activity', backref='review_history')


class SecondReview(db.Model):
    __tablename__ = 'second_reviews'

    id = db.Column(db.Integer, primary_key=True)
    activity_id = db.Column(db.Integer, db.ForeignKey('activity.id'))
    review = db.Column(db.String(100))
    remarks = db.Column(db.Text)
    submitted_at = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))

    # Relationships
    activity = db.relationship('Activity', back_populates='second_reviews')
    user = db.relationship('User')

# Flask-Login user loader
@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))  # Use Session.get() instead of Query.get()

# Routes
@app.route('/')
def home():
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        identifier = request.form['username']  # This can be either username or Thumb ID
        password = request.form['password']

        # Check if the identifier is a username or Thumb ID
        user = User.query.filter((User.username == identifier) | (User.thumb_id == identifier)).first()

        if user and check_password_hash(user.password, password):
            login_user(user)  # Log in the user
            if user.role == 'admin':
                return redirect(url_for('admin_dashboard'))
            elif user.role == 'subuser':
                return redirect(url_for('subuser_dashboard'))
            else:
                return redirect(url_for('user_dashboard'))
        flash('Invalid credentials', 'error')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        password = generate_password_hash(request.form['password'])
        thumb_id = request.form['thumb_id']  # Get the Thumb ID
        college = request.form['college']
        department = request.form['department']  # Get the selected department

        # Check if the Thumb ID already exists
        existing_user = User.query.filter_by(thumb_id=thumb_id).first()
        if existing_user:
            flash('Thumb ID already exists. Please use a different Thumb ID.', 'error')
            return redirect(url_for('signup'))

        new_user = User(
            username=username,
            password=password,
            thumb_id=thumb_id,  # Save the Thumb ID
            role='user',
            college=college,
            department=department
        )
        db.session.add(new_user)
        db.session.commit()
        flash('Account created!', 'success')
        return redirect(url_for('login'))
    return render_template('signup.html')

@app.route('/admin_signup', methods=['GET', 'POST'])
def admin_signup():
    if request.method == 'POST':
        username = request.form['username']
        password = generate_password_hash(request.form['password'])
        new_admin = User(username=username, password=password, role='admin')
        db.session.add(new_admin)
        db.session.commit()
        flash('Admin account created!', 'success')
        return redirect(url_for('login'))
    return render_template('admin_signup.html')

@app.route('/admin_dashboard')
@login_required
def admin_dashboard():
    # Fetch users with their responses
    user_responses = db.session.query(User).filter(
        User.active == True,
        User.role == 'user'
    ).all()

    # Prepare user data with thumb_id
    for user in user_responses:
        user.thumb_id = user.thumb_id if user.thumb_id else None
        user.assigned_activities = Activity.query.filter_by(user_id=user.id).count()
        user.pending_responses = Activity.query.filter_by(
            user_id=user.id,
            status='pending'
        ).count()

        # Calculate response counts for each type
        response_types = [
            'Interested_for_TART', 'Not_interested_for_TART', 'After_Result',
            'Call_Later', 'Joined_in_Excel', 'Joined_in_Other_College',
            'No_Response', 'Not_Willing', 'Switched_off', 'Willing_to_Join',
            'Wrong_Number', 'Waiting_for_NEET'
        ]

        for response_type in response_types:
            setattr(user, response_type, Activity.query.filter_by(
                user_id=user.id,
                status='reviewed',
                review=response_type.replace('_', ' ')
            ).count())

    # Calculate district counts
    districts = db.session.query(Activity.district).distinct().all()
    districts = [district[0] for district in districts if district[0]]

    district_counts = {}
    for district in districts:
        district_counts[district] = {
            'Interested for TART': Activity.query.filter_by(district=district, review='Interested for TART').count(),
            'Not interested for TART': Activity.query.filter_by(district=district, review='Not interested for TART').count(),
            'After Result': Activity.query.filter_by(district=district, review='After Result').count(),
            'Call Later': Activity.query.filter_by(district=district, review='Call Later').count(),
            'Joined in Excel': Activity.query.filter_by(district=district, review='Joined in Excel').count(),
            'Joined in Other College': Activity.query.filter_by(district=district, review='Joined in Other College').count(),
            'No Response': Activity.query.filter_by(district=district, review='No Response').count(),
            'Not Willing': Activity.query.filter_by(district=district, review='Not Willing').count(),
            'Switched off': Activity.query.filter_by(district=district, review='Switched off').count(),
            'Willing to Join': Activity.query.filter_by(district=district, review='Willing to Join').count(),
            'Wrong Number': Activity.query.filter_by(district=district, review='Wrong Number').count(),
            'Waiting for NEET': Activity.query.filter_by(district=district, review='Waiting for NEET').count()
        }

    # Calculate total response data
    total_response_data = {
        'Interested for TART': Activity.query.filter_by(review='Interested for TART').count(),
        'Not interested for TART': Activity.query.filter_by(review='Not interested for TART').count(),
        'After Result': Activity.query.filter_by(review='After Result').count(),
        'Call Later': Activity.query.filter_by(review='Call Later').count(),
        'Joined in Excel': Activity.query.filter_by(review='Joined in Excel').count(),
        'Joined in Other College': Activity.query.filter_by(review='Joined in Other College').count(),
        'No Response': Activity.query.filter_by(review='No Response').count(),
        'Not Willing': Activity.query.filter_by(review='Not Willing').count(),
        'Switched off': Activity.query.filter_by(review='Switched off').count(),
        'Willing to Join': Activity.query.filter_by(review='Willing to Join').count(),
        'Wrong Number': Activity.query.filter_by(review='Wrong Number').count(),
        'Waiting for NEET': Activity.query.filter_by(review='Waiting for NEET').count()
    }

    # Get all colleges
    colleges = db.session.query(User.college).distinct().all()
    colleges = [college[0] for college in colleges if college[0]]

    # Calculate college-wise counts
    college_counts = {}
    total_college_response_data = {
        'Interested for TART': 0,
        'Not interested for TART': 0,
        'After Result': 0,
        'Call Later': 0,
        'Joined in Excel': 0,
        'Joined in Other College': 0,
        'No Response': 0,
        'Not Willing': 0,
        'Switched off': 0,
        'Willing to Join': 0,
        'Wrong Number': 0,
        'Waiting for NEET': 0,
        'Total': 0
    }

    for college in colleges:
        college_counts[college] = {
            'Interested for TART': db.session.query(Activity).join(User, Activity.user_id == User.id).filter(
                User.college == college,
                Activity.review == 'Interested for TART'
            ).count(),
            'Not interested for TART': db.session.query(Activity).join(User, Activity.user_id == User.id).filter(
                User.college == college,
                Activity.review == 'Not interested for TART'
            ).count(),
            'After Result': db.session.query(Activity).join(User, Activity.user_id == User.id).filter(
                User.college == college,
                Activity.review == 'After Result'
            ).count(),
            'Call Later': db.session.query(Activity).join(User, Activity.user_id == User.id).filter(
                User.college == college,
                Activity.review == 'Call Later'
            ).count(),
            'Joined in Excel': db.session.query(Activity).join(User, Activity.user_id == User.id).filter(
                User.college == college,
                Activity.review == 'Joined in Excel'
            ).count(),
            'Joined in Other College': db.session.query(Activity).join(User, Activity.user_id == User.id).filter(
                User.college == college,
                Activity.review == 'Joined in Other College'
            ).count(),
            'No Response': db.session.query(Activity).join(User, Activity.user_id == User.id).filter(
                User.college == college,
                Activity.review == 'No Response'
            ).count(),
            'Not Willing': db.session.query(Activity).join(User, Activity.user_id == User.id).filter(
                User.college == college,
                Activity.review == 'Not Willing'
            ).count(),
            'Switched off': db.session.query(Activity).join(User, Activity.user_id == User.id).filter(
                User.college == college,
                Activity.review == 'Switched off'
            ).count(),
            'Willing to Join': db.session.query(Activity).join(User, Activity.user_id == User.id).filter(
                User.college == college,
                Activity.review == 'Willing to Join'
            ).count(),
            'Wrong Number': db.session.query(Activity).join(User, Activity.user_id == User.id).filter(
                User.college == college,
                Activity.review == 'Wrong Number'
            ).count(),
            'Waiting for NEET': db.session.query(Activity).join(User, Activity.user_id == User.id).filter(
                User.college == college,
                Activity.review == 'Waiting for NEET'
            ).count(),
            'Total': db.session.query(Activity).join(User, Activity.user_id == User.id).filter(
                User.college == college
            ).count()
        }

        # Update grand totals
        for key in total_college_response_data:
            if key in college_counts[college]:
                total_college_response_data[key] += college_counts[college][key]

    # Calculate response counts
    response_types = [
        'Interested for TART', 'Not interested for TART',
        'After Result', 'Call Later', 'Joined in Excel',
        'Joined in Other College', 'No Response', 'Not Willing',
        'Switched off', 'Willing to Join', 'Wrong Number',
        'Waiting for NEET'
    ]

    response_counts = {}
    for response_type in response_types:
        response_counts[response_type] = Activity.query.filter_by(
            review=response_type
        ).count()

    # Calculate upload statistics
    last_activity = Activity.query.order_by(Activity.uploaded_date.desc()).first()
    upload_stats = {
        'last_upload_date': last_activity.uploaded_date if last_activity else None,
        'total_uploaded': Activity.query.count(),
        'pending_assignments': Activity.query.filter_by(user_id=None).count(),
        'assigned_data': Activity.query.filter(Activity.user_id.isnot(None)).count(),
        'min_sn': db.session.query(db.func.min(Activity.sn)).scalar(),
        'max_sn': db.session.query(db.func.max(Activity.sn)).scalar(),
        'min_date': db.session.query(db.func.min(Activity.uploaded_date)).scalar(),
        'max_date': db.session.query(db.func.max(Activity.uploaded_date)).scalar()
    }

    # Calculate college assignment details
    college_assignment_details = {}
    for college in colleges:
        # Get all activities assigned to users from this college
        activities = db.session.query(Activity)\
            .join(User, Activity.user_id == User.id)\
            .filter(User.college == college)\
            .all()

        if activities:
            # Get date range
            min_date = min(a.uploaded_date for a in activities)
            max_date = max(a.uploaded_date for a in activities)
            date_range = f"{min_date.strftime('%Y-%m-%d')} to {max_date.strftime('%Y-%m-%d')}"

            # Get SN ranges (group consecutive numbers)
            sns = sorted([a.sn for a in activities])
            ranges = []
            start = sns[0]
            prev = sns[0]

            for sn in sns[1:]:
                if sn != prev + 1:
                    ranges.append(f"{start}-{prev}" if start != prev else f"{start}")
                    start = sn
                prev = sn
            ranges.append(f"{start}-{prev}" if start != prev else f"{start}")

            college_assignment_details[college] = {
                'assigned': len(activities),
                'pending': Activity.query.filter_by(user_id=None).count(),
                'date_range': date_range,
                'sn_ranges': ranges[:5],  # Show first 5 ranges
                'total_ranges': len(ranges)
            }

    return render_template(
        'admin_dashboard.html',
        user_responses=user_responses,
        users=User.query.all(),
        district_counts=district_counts,
        total_response_data=total_response_data,
        colleges=colleges,
        college_counts=college_counts,
        total_college_response_data=total_college_response_data,
        response_counts=response_counts,
        upload_stats=upload_stats,
        college_assignment_details=college_assignment_details
    )

@app.route('/admin/search_user')
@login_required
def admin_search_user():
    if current_user.role != 'admin':
        return jsonify({'error': 'Permission denied'}), 403

    search_term = request.args.get('q', '').strip()
    if not search_term:
        return jsonify({'error': 'Search term required'}), 400

    try:
        # Search by username, email, or thumb_id
        users = User.query.filter(
            (User.username.ilike(f'%{search_term}%')) |
            (User.thumb_id.ilike(f'%{search_term}%'))
        ).limit(10).all()

        return jsonify({
            'users': [{
                'id': user.id,
                'username': user.username,
                'college': user.college,
                'department': user.department,
                'role': user.role,
                'active': user.active,
                'thumb_id': user.thumb_id
            } for user in users]
        })
    except Exception as e:
        app.logger.error(f"Error searching users: {str(e)}")
        return jsonify({'error': 'Search failed'}), 500

@app.route('/admin/reset_password/<int:user_id>', methods=['POST'])
@login_required
def admin_reset_password(user_id):
    if current_user.role != 'admin':
        return jsonify({'error': 'Permission denied'}), 403

    try:
        # Get CSRF token from request headers or form data
        csrf_token = request.headers.get('X-CSRFToken') or request.form.get('csrf_token')

        if not csrf_token:
            return jsonify({'error': 'CSRF token missing', 'success': False}), 400

        # Validate CSRF token
        try:
            validate_csrf(csrf_token)
        except:
            return jsonify({'error': 'CSRF token invalid', 'success': False}), 400

        data = request.get_json()
        new_password = data.get('new_password')

        if not new_password or len(new_password) < 8:
            return jsonify({'error': 'Password must be at least 8 characters', 'success': False}), 400

        user = User.query.get(user_id)
        if not user:
            return jsonify({'error': 'User not found'}), 404

        user.password = generate_password_hash(new_password)
        db.session.commit()

        return jsonify({
            'success': True,
            'message': 'Password reset successfully'
        })
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e), 'success': False}), 500



@app.route('/upload', methods=['POST'])
@login_required
def upload():
    if 'file' not in request.files:
        flash('No file selected', 'error')
        return redirect(url_for('admin_dashboard'))

    file = request.files['file']
    if file.filename == '':
        flash('No file selected', 'error')
        return redirect(url_for('admin_dashboard'))

    if file and file.filename.endswith(('.xlsx', '.xls')):
        try:
            df = pd.read_excel(file)

            # Check if the "SN" and "District" columns exist
            if 'SN' not in df.columns or 'District' not in df.columns:
                flash('Excel file must contain "SN" and "District" columns', 'error')
                return redirect(url_for('admin_dashboard'))

            # Iterate through each row and store data
            for _, row in df.iterrows():
                sn = row['SN']
                district = row['District']  # Extract district from the row
                data = row.to_dict()

                # Create a new Activity record with the current date as uploaded_date
                activity = Activity(
                    sn=sn,
                    data=data,
                    admin_id=current_user.id,
                    district=district,
                    uploaded_date=datetime.utcnow().date()  # Store the current date
                )
                db.session.add(activity)

            db.session.commit()
            flash('File uploaded successfully', 'success')
        except Exception as e:
            flash(f'Error: {str(e)}', 'error')
    else:
        flash('Invalid file format. Please upload an Excel file (.xlsx or .xls)', 'error')

    return redirect(url_for('admin_dashboard'))

@app.route('/assign', methods=['POST'])
@login_required
def assign():
    sn_list = list(map(int, request.form.getlist('sn')))
    user_id = request.form['user_id']
    activities = Activity.query.filter(Activity.sn.in_(sn_list)).all()
    for activity in activities:
        activity.user_id = user_id
    db.session.commit()
    flash('Activities assigned successfully', 'success')
    return redirect(url_for('admin_dashboard'))

@app.route('/user_dashboard')
@login_required
def user_dashboard():
    # Fetch activities assigned to the current user, grouped by assigned_date and assigned_time
    activities = Activity.query.filter_by(user_id=current_user.id).order_by(Activity.assigned_date.desc(), Activity.assigned_time.desc()).all()

    # Group activities by assigned_date and assigned_time (in IST)
    activities_by_date_time = {}
    for activity in activities:
        # Convert UTC to IST
        ist_date = utc_to_ist(activity.assigned_date).strftime('%Y-%m-%d')  # Format date as string
        ist_time = utc_to_ist(activity.assigned_time).strftime('%H:%M:%S')  # Format time as string

        if ist_date not in activities_by_date_time:
            activities_by_date_time[ist_date] = {}
        if ist_time not in activities_by_date_time[ist_date]:
            activities_by_date_time[ist_date][ist_time] = []
        activities_by_date_time[ist_date][ist_time].append(activity)

    return render_template('user_dashboard.html', activities_by_date_time=activities_by_date_time, utc_to_ist=utc_to_ist)

@app.route('/submit_review', methods=['POST'])
@login_required
def submit_review():
    activity_id = request.form['activity_id']
    review = request.form['review']
    remarks = request.form.get('remarks', '')
    activity = Activity.query.get(activity_id)

    if activity and activity.user_id == current_user.id:
        # Always create history entry when submitting a review
        review_history = ReviewHistory(
            activity_id=activity.id,
            review=activity.review,  # Store the current review before updating
            remarks=activity.remarks,  # Store current remarks
            user_id=current_user.id
        )
        db.session.add(review_history)

        # Update activity with new review
        activity.review = review
        activity.remarks = remarks
        activity.status = 'reviewed'
        activity.submitted_at = datetime.utcnow()

        db.session.commit()

        # Check if this is an AJAX request
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            return jsonify({
                'success': True,
                'message': 'Review submitted successfully!',
                'activity_id': activity.id,
                'review': review,
                'remarks': remarks,
                'status': 'reviewed',
                'submitted_at': activity.submitted_at.isoformat()
            })
        else:
            flash('Review submitted successfully!', 'success')
            return redirect(url_for('user_dashboard'))

    # If activity not found or doesn't belong to user
    if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
        return jsonify({
            'success': False,
            'message': 'Activity not found or you do not have permission to review it.'
        }), 404
    else:
        flash('Activity not found or you do not have permission to review it.', 'error')
        return redirect(url_for('user_dashboard'))

@app.route('/', methods=['GET', 'POST'])
def upload_file():
    if request.method == 'POST':
        # Check if the file is present in the request
        if 'file' not in request.files:
            return "No file part in the request", 400

        file = request.files['file']

        # If the user does not select a file, the browser submits an empty file
        if file.filename == '':
            return "No selected file", 400

        # Save the file to the upload folder
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], file.filename)
        file.save(file_path)

        # Read the Excel file
        try:
            df = pd.read_excel(file_path)
        except Exception as e:
            return f"Error reading the file: {e}", 400

        # Check if the "SN" column exists
        if 'SN' not in df.columns:
            return "Excel file must contain an 'SN' column", 400

        # Redirect to the assign data page with the file path
        return redirect(url_for('assign_data', file_path=file_path))

    return render_template('upload.html')

@app.route('/assign_data', methods=['GET', 'POST'])
def assign_data():
    file_path = request.args.get('file_path')

    if not file_path:
        return "File path not provided", 400

    # Read the Excel file
    try:
        df = pd.read_excel(file_path)
    except Exception as e:
        return f"Error reading the file: {e}", 400

    if request.method == 'POST':
        # Get the selected user and SN from the form
        user_email = request.form.get('user_email')
        sn = request.form.get('sn')

        # Assign the data to the user (you can modify this logic as needed)
        # For example, you can save this assignment to a database or send an email
        # Here, we just print the assignment
        print(f"Assigning data with SN {sn} to user {user_email}")

        return f"Data with SN {sn} has been assigned to {user_email}"

    # Render the assign data page with the list of SNs
    sn_list = df['SN'].tolist()
    return render_template('assign_data.html', sn_list=sn_list)

@app.route('/assign_activities', methods=['POST'])
def assign_activities():
    selected_activities = request.form.getlist('selected_activities')  # Get selected activity IDs
    user_id = request.form.get('user_id')  # Get selected user ID

    if not selected_activities:
        flash("No activities selected.", "error")
    elif not user_id:
        flash("No user selected.", "error")
    else:
        # Assign selected activities to the chosen user
        for activity_id in selected_activities:
            activity = Activity.query.get(activity_id)
            if activity:
                activity.user_id = user_id
                db.session.commit()
        flash(f"Successfully assigned {len(selected_activities)} activities to user.", "success")

    return redirect(url_for('admin_dashboard'))

@app.route('/admin_actions', methods=['POST'])
def admin_actions():
    action = request.form.get('action')  # Get the action (assign, delete_selected, delete_all)

    if action == 'assign':
        user_ids = request.form.getlist('user_ids')  # Get selected user IDs
        sn_range = request.form.get('sn_range')  # Get the SN range (e.g., "1-20")

        if not user_ids:
            flash("No users selected.", "error")
        else:
            if sn_range:  # If SN range is provided
                try:
                    start_sn, end_sn = map(int, sn_range.split('-'))
                    activities = Activity.query.filter(
                        Activity.sn >= start_sn,
                        Activity.sn <= end_sn
                    ).all()
                    if not activities:
                        flash(f"No activities found in the SN range {sn_range}.", "error")
                    else:
                        for activity in activities:
                            activity.user_id = user_ids[0]  # Assign to the first user
                        db.session.commit()
                        flash(f"Successfully assigned {len(activities)} activities to user.", "success")
                except ValueError:
                    flash("Invalid SN range format. Please use the format 'start-end'.", "error")
            else:  # If no SN range, use selected activities
                selected_activities = request.form.getlist('selected_activities')  # Get selected activity IDs
                if not selected_activities:
                    flash("No activities selected.", "error")
                else:
                    for activity_id in selected_activities:
                        activity = Activity.query.get(activity_id)
                        if activity:
                            activity.user_id = user_ids[0]  # Assign to the first user
                    db.session.commit()
                    flash(f"Successfully assigned {len(selected_activities)} activities to user.", "success")

    elif action == 'delete_selected':
        selected_activities = request.form.getlist('selected_activities')  # Get selected activity IDs
        if not selected_activities:
            flash("No activities selected.", "error")
        else:
            # Delete selected activities
            for activity_id in selected_activities:
                activity = Activity.query.get(activity_id)
                if activity:
                    db.session.delete(activity)
            db.session.commit()
            flash(f"Successfully deleted {len(selected_activities)} activities.", "success")



    elif action == 'delete_all':
        # Delete all activities
        Activity.query.delete()
        db.session.commit()
        flash("All activities deleted successfully.", "success")

    return redirect(url_for('admin_dashboard'))

# Define the custom filter
@app.template_filter('get_username')
def get_username(user_id):
    if user_id:
        user = User.query.get(user_id)
        return user.username if user else "Not Assigned"
    return "Not Assigned"

@app.route('/download_responses/<response_type>')
@login_required
def download_responses(response_type):
    if current_user.role != 'admin':
        flash('You do not have permission to access this page.', 'error')
        return redirect(url_for('admin_dashboard'))

    # Fetch responses based on the type
    if response_type == 'Interested for TART':
        activities = Activity.query.filter_by(review='Interested for TART').all()
    elif response_type == 'Not interested for TART':
        activities = Activity.query.filter_by(review='Not interested for TART').all()
    elif response_type == 'After Result':
        activities = Activity.query.filter_by(review='After Result').all()
    elif response_type == 'Call Later':
        activities = Activity.query.filter_by(review='Call Later').all()
    elif response_type == 'Joined in Excel':
        activities = Activity.query.filter_by(review='Joined in Excel').all()
    elif response_type == 'Joined in Other College':
        activities = Activity.query.filter_by(review='Joined in Other College').all()
    elif response_type == 'No Response':
        activities = Activity.query.filter_by(review='No Response').all()
    elif response_type == 'Not Willing':
        activities = Activity.query.filter_by(review='Not Willing').all()
    elif response_type == 'Switched off':
        activities = Activity.query.filter_by(review='Switched off').all()
    elif response_type == 'Willing to Join':
        activities = Activity.query.filter_by(review='Willing to Join').all()
    elif response_type == 'Wrong Number':
        activities = Activity.query.filter_by(review='Wrong Number').all()
    elif response_type == 'Waiting for NEET':
        activities = Activity.query.filter_by(review='Waiting for NEET').all()
    elif response_type == 'Pending':  # Add this condition for pending activities
        activities = Activity.query.filter_by(status='pending').all()
    else:
        flash('Invalid response type.', 'error')
        return redirect(url_for('admin_dashboard'))

    # Convert the data to a pandas DataFrame
    data = []
    for activity in activities:
        row = activity.data  # Assuming 'data' is a JSON column
        row['SN'] = activity.sn
        row['Admin'] = get_username(activity.admin_id)
        row['User'] = get_username(activity.user_id)
        row['Submitted At'] = activity.submitted_at.strftime('%Y-%m-%d %H:%M:%S') if activity.submitted_at else ''
        data.append(row)

    df = pd.DataFrame(data)

    # Create an in-memory Excel file
    output = io.BytesIO()

    # Truncate the worksheet name to 31 characters
    sheet_name = f'{response_type.capitalize()} Responses'
    sheet_name = sheet_name[:31]  # Truncate to 31 characters

    with pd.ExcelWriter(output, engine='xlsxwriter') as writer:
        df.to_excel(writer, index=False, sheet_name=sheet_name)
    output.seek(0)

    # Send the file as a response
    return send_file(
        output,
        mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
        as_attachment=True,
        download_name=f'{response_type}_responses.xlsx'
    )

@app.route('/auto_assign_by_college', methods=['POST'])
@login_required
def auto_assign_by_college():
    if current_user.role != 'admin':
        flash('You do not have permission to perform this action.', 'error')
        return redirect(url_for('admin_dashboard'))

    college = request.form.get('college')  # Get the selected college
    if not college:
        flash('No college selected.', 'error')
        return redirect(url_for('admin_dashboard'))

    # Fetch all unassigned activities
    unassigned_activities = Activity.query.filter_by(user_id=None).all()

    # Fetch all active users of the selected college
    users = User.query.filter_by(college=college, role='user', active=True).all()

    if not users:
        flash(f'No active users found for {college}.', 'error')
        return redirect(url_for('admin_dashboard'))

    # Split and assign activities to active users
    for i, activity in enumerate(unassigned_activities):
        user = users[i % len(users)]  # Distribute activities evenly among active users
        activity.user_id = user.id
        db.session.commit()

    flash(f'Successfully auto-assigned activities to active users of {college}.', 'success')
    return redirect(url_for('admin_dashboard'))

@app.route('/download_user_responses/<response_type>')
@login_required
def download_user_responses(response_type):
    # Get date range from query parameters
    start_date = request.args.get('start_date')
    end_date = request.args.get('end_date')
    status = request.args.get('status', 'reviewed')  # Default to reviewed

    # Base query - only activities for current user with status 'reviewed'
    query = Activity.query.filter_by(
        user_id=current_user.id,
        status='reviewed'
    )

    # Apply response type filter if not 'all'
    if response_type != 'all':
        query = query.filter_by(review=response_type)

    # Apply date filter if provided
    if start_date and end_date:
        try:
            start_date = datetime.strptime(start_date, '%Y-%m-%d')
            end_date = datetime.strptime(end_date, '%Y-%m-%d') + timedelta(days=1)  # Include end date
            query = query.filter(Activity.submitted_at.between(start_date, end_date))
        except ValueError:
            flash('Invalid date format', 'error')
            return redirect(url_for('user_dashboard'))

    activities = query.all()

    if not activities:
        flash("No data available for the selected criteria", "error")
        return redirect(url_for('user_dashboard'))

    # Convert to DataFrame with separate rows for each review
    data = []
    for act in activities:
        # Include the current review first
        row_data = {
            "SN": act.sn,
            "Review Type": act.review,
            "Remarks": act.remarks,
            "Submitted At": utc_to_ist(act.submitted_at).strftime('%Y-%m-%d %H:%M:%S') if act.submitted_at else '',
            **act.data
        }
        data.append(row_data)

    df = pd.DataFrame(data)

    # Reorder columns to put review info first
    columns_order = ['SN', 'Review Type', 'Remarks', 'Submitted At'] + \
                   [col for col in df.columns if col not in ['SN', 'Review Type', 'Remarks', 'Submitted At']]

    df = df[columns_order]

    output = io.BytesIO()
    with pd.ExcelWriter(output, engine='xlsxwriter') as writer:
        df.to_excel(writer, index=False, sheet_name='Responses')

        # Add formatting
        workbook = writer.book
        worksheet = writer.sheets['Responses']

        # Header format
        header_format = workbook.add_format({
            'bold': True,
            'text_wrap': True,
            'valign': 'top',
            'fg_color': '#D7E4BC',
            'border': 1
        })

        # Apply header format
        for col_num, value in enumerate(df.columns.values):
            worksheet.write(0, col_num, value, header_format)

        # Auto-adjust column widths
        for i, col in enumerate(df.columns):
            max_len = max(df[col].astype(str).map(len).max(), len(col)) + 2
            worksheet.set_column(i, i, max_len)

    output.seek(0)

    # Generate filename
    filename = f'user_responses'
    if response_type != 'all':
        filename += f'_{response_type}'
    if start_date and end_date:
        filename += f'_{start_date.date()}_to_{end_date.date()}'
    filename += '.xlsx'

    return send_file(
        output,
        mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
        as_attachment=True,
        download_name=filename
    )

def utc_to_ist(utc_dt):
    if utc_dt is None:
        return None
    return utc_dt + timedelta(hours=5, minutes=30)
@app.route('/get_filtered_users_responses')
@login_required
def get_filtered_users_responses():
    if current_user.role != 'subuser':
        return jsonify({'error': 'Unauthorized'}), 403

    start_date = request.args.get('start_date')
    end_date = request.args.get('end_date')

    try:
        # Convert dates if provided
        if start_date and end_date:
            start_date = datetime.strptime(start_date, '%Y-%m-%d')
            end_date = datetime.strptime(end_date, '%Y-%m-%d') + timedelta(days=1)

        # Fetch active users
        users = User.query.filter_by(role='user', active=True).all()

        user_data = []
        for user in users:
            user_row = {
                'id': user.id,
                'username': user.username,
                'college': user.college,
                'department': user.department,
                'thumb_id': user.thumb_id,
                'active': user.active,
                'assigned_activities': 0,
                'pending_responses': 0,
                'Interested_for_TART': 0,
                'Not_interested_for_TART': 0,
                'After_Result': 0,
                'Call_Later': 0,
                'Joined_in_Excel': 0,
                'Joined_in_Other_College': 0,
                'No_Response': 0,
                'Not_Willing': 0,
                'Switched_off': 0,
                'Willing_to_Join': 0,
                'Wrong_Number': 0,
                'Waiting_for_NEET': 0
            }

            # Query for assigned activities
            assigned_query = Activity.query.filter_by(user_id=user.id)
            if start_date and end_date:
                assigned_query = assigned_query.filter(Activity.assigned_date.between(start_date, end_date))
            user_row['assigned_activities'] = assigned_query.count()

            # Query for pending responses
            pending_query = Activity.query.filter_by(user_id=user.id, status='pending')
            if start_date and end_date:
                pending_query = pending_query.filter(Activity.assigned_date.between(start_date, end_date))
            user_row['pending_responses'] = pending_query.count()

            REVIEW_TYPES = [
    'Interested for TART', 'Not interested for TART', 'After Result',
    'Call Later', 'Joined in Excel', 'Joined in Other College',
    'No Response', 'Not Willing', 'Switched off', 'Willing to Join',
    'Wrong Number', 'Waiting for NEET', 'Pending'
]

            # Query for each response type
            for review_type in REVIEW_TYPES:
                if review_type != 'Pending':
                    key = review_type.replace(' ', '_')
                    review_query = Activity.query.filter_by(user_id=user.id, review=review_type)
                    if start_date and end_date:
                        review_query = review_query.filter(Activity.submitted_at.between(start_date, end_date))
                    user_row[key] = review_query.count()

            user_data.append(user_row)

        return jsonify(user_data)

    except Exception as e:
        app.logger.error(f"Error in get_filtered_users_responses: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/assign_by_range_and_college', methods=['POST'])
@login_required
def assign_by_range_and_college():
    if current_user.role != 'admin':
        flash('You do not have permission to perform this action.', 'error')
        return redirect(url_for('admin_dashboard'))

    sn_range = request.form.get('sn_range')
    college = request.form.get('college')
    selected_date = request.form.get('selected_date')  # Get the selected date
    selected_users = request.form.getlist('selected_users')  # Get selected user IDs

    if not sn_range or not college or not selected_date or not selected_users:
        flash('Please provide SN range, college, date, and select at least one user.', 'error')
        return redirect(url_for('admin_dashboard'))

    try:
        start_sn, end_sn = map(int, sn_range.split('-'))
        selected_date = datetime.strptime(selected_date, '%Y-%m-%d').date()  # Convert to date object
    except ValueError:
        flash('Invalid SN range or date format. Please use the format "start-end" and "YYYY-MM-DD".', 'error')
        return redirect(url_for('admin_dashboard'))

    # Fetch activities within the SN range and uploaded_date
    activities = Activity.query.filter(
        Activity.sn >= start_sn,
        Activity.sn <= end_sn,
        Activity.uploaded_date == selected_date  # Filter by uploaded_date
    ).all()

    if not activities:
        flash(f'No activities found in the SN range {sn_range} for the selected date.', 'error')
        return redirect(url_for('admin_dashboard'))

    # Fetch active users from the selected college
    users = User.query.filter(
        User.college == college,
        User.active == True,  # Only active users
        User.id.in_(selected_users)  # Only selected users
    ).all()

    if not users:
        flash(f'No active users found for {college}.', 'error')
        return redirect(url_for('admin_dashboard'))

    # Assign activities evenly to selected users
    num_users = len(users)
    num_activities = len(activities)
    activities_per_user = num_activities // num_users  # Number of activities per user
    remainder = num_activities % num_users  # Remaining activities to distribute

    for i, user in enumerate(users):
        # Calculate the range of activities to assign to this user
        start_index = i * activities_per_user
        end_index = start_index + activities_per_user

        # Distribute remaining activities
        if i < remainder:
            end_index += 1

        # Assign activities to the user
        for activity in activities[start_index:end_index]:
            activity.user_id = user.id
            activity.assigned_date = datetime.utcnow()  # Set the assigned date
            db.session.commit()

    flash(f'Successfully assigned {num_activities} activities evenly to {num_users} active users of {college} for {selected_date}.', 'success')
    return redirect(url_for('admin_dashboard'))


@app.route('/filter_and_download', methods=['POST'])
@login_required
def filter_and_download():
    if current_user.role != 'admin':
        flash('You do not have permission to perform this action.', 'error')
        return redirect(url_for('admin_dashboard'))

    # Get filter parameters from the form
    filter_college = request.form.get('filter_college')
    filter_department = request.form.get('filter_department')
    filter_operator = request.form.get('filter_operator')
    filter_review = request.form.get('filter_review')  # New: Filter by review type

    # Validate filter parameters
    if not filter_college or not filter_department or not filter_operator:
        flash('Please provide all filter parameters.', 'error')
        return redirect(url_for('admin_dashboard'))

    # Build the base query
    query = Activity.query.join(
        User, Activity.user_id == User.id  # Explicitly specify the join condition
    ).filter(
        User.college == filter_college
    )

    # Apply department filter based on the operator
    if filter_operator == '=':
        query = query.filter(User.department == filter_department)
    elif filter_operator == '!=':
        query = query.filter(User.department != filter_department)

    # Apply review filter if specified
    if filter_review:
        query = query.filter(Activity.review == filter_review)

    # Execute the query
    activities = query.all()

    # Convert the data to a pandas DataFrame
    data = []
    for activity in activities:
        row = activity.data  # Assuming 'data' is a JSON column
        row['SN'] = activity.sn
        row['Admin'] = get_username(activity.admin_id)
        row['User'] = get_username(activity.user_id)
        row['College'] = User.query.get(activity.user_id).college
        row['Department'] = User.query.get(activity.user_id).department
        row['Review'] = activity.review  # Include review type in the data
        row['Submitted At'] = activity.submitted_at.strftime('%Y-%m-%d %H:%M:%S') if activity.submitted_at else ''
        data.append(row)

    df = pd.DataFrame(data)

    # Create CSV file
    output = io.StringIO()
    df.to_csv(output, index=False)
    output.seek(0)

    # Generate filename
    filename = f'{filter_college}_{filter_department}_{filter_operator}'
    if filter_review:
        filename += f'_{filter_review}'
    filename += '_data.csv'

    # Send the file as a response
    return Response(
        output.getvalue(),
        mimetype='text/csv',
        headers={'Content-Disposition': f'attachment; filename={filename}'}
    )

@app.route('/download_uploaded_responses/<response_type>')
@login_required
def download_uploaded_responses(response_type):
    if current_user.role != 'admin':
        flash('You do not have permission to access this page.', 'error')
        return redirect(url_for('admin_dashboard'))

    # Fetch uploaded activities
    uploaded_activities = Activity.query.filter_by(admin_id=current_user.id).all()

    # Filter activities based on the selected response type
    if response_type == 'all':
        filtered_activities = uploaded_activities
    else:
        filtered_activities = [act for act in uploaded_activities if act.review == response_type]

    # Convert the data to a pandas DataFrame
    data = []
    for activity in filtered_activities:
        row = activity.data  # Assuming 'data' is a JSON column
        row['SN'] = activity.sn
        row['Admin'] = get_username(activity.admin_id)
        row['User'] = get_username(activity.user_id)
        row['Submitted At'] = activity.submitted_at.strftime('%Y-%m-%d %H:%M:%S') if activity.submitted_at else ''
        data.append(row)

    df = pd.DataFrame(data)

    # Create CSV file
    output = io.StringIO()
    df.to_csv(output, index=False)
    output.seek(0)

    # Send the file as a response
    return Response(
        output.getvalue(),
        mimetype='text/csv',
        headers={'Content-Disposition': f'attachment; filename={response_type}_uploaded_responses.csv'}
    )

@app.route('/admin/delete_user/<int:user_id>', methods=['POST'])
@login_required
def delete_user(user_id):
    if current_user.role != 'admin':
        flash('Permission denied', 'error')
        return redirect(url_for('admin_dashboard'))

    user = User.query.get(user_id)
    if user:
        # Delete or unassign activities
        Activity.query.filter_by(user_id=user.id).delete()
        db.session.delete(user)
        db.session.commit()
        flash('User deleted successfully', 'success')
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/update_user_status', methods=['POST'])
@login_required
def update_user_status():
    if current_user.role != 'admin':
        flash('Permission denied', 'error')
        return redirect(url_for('admin_dashboard'))

    user_id = request.form.get('user_id')
    status = request.form.get('status') == 'true'

    user = User.query.get(user_id)
    if user:
        user.active = status
        db.session.commit()
        flash('User status updated', 'success')
    return redirect(url_for('admin_dashboard'))

@app.route('/download_district_report/<district>')
@login_required
def download_district_report(district):
    if current_user.role != 'admin':
        flash('You do not have permission to access this page.', 'error')
        return redirect(url_for('admin_dashboard'))

    # Fetch activities for the selected district
    activities = Activity.query.filter_by(district=district).all()

    # Convert the data to a pandas DataFrame
    data = []
    for activity in activities:
        row = activity.data
        row['SN'] = activity.sn
        row['District'] = activity.district
        row['Review'] = activity.review
        row['Submitted At'] = activity.submitted_at.strftime('%Y-%m-%d %H:%M:%S') if activity.submitted_at else ''
        data.append(row)

    df = pd.DataFrame(data)

    # Create CSV file
    output = io.StringIO()
    df.to_csv(output, index=False)
    output.seek(0)

    # Send the file as a response
    return Response(
        output.getvalue(),
        mimetype='text/csv',
        headers={'Content-Disposition': f'attachment; filename={district}_report.csv'}
    )

@app.route('/download_all_data')
@login_required
def download_all_data():
    if current_user.role != 'admin':
        flash('You do not have permission to access this page.', 'error')
        return redirect(url_for('admin_dashboard'))

    # Get filter parameters from query parameters
    district_filter = request.args.get('district')
    start_date = request.args.get('start_date')
    end_date = request.args.get('end_date')

    # Convert to datetime objects if provided
    if start_date and end_date:
        start_date = datetime.strptime(start_date, '%Y-%m-%d')
        end_date = datetime.strptime(end_date, '%Y-%m-%d')
    else:
        start_date = None
        end_date = None

    # Fetch districts - either all or the filtered one
    if district_filter:
        districts = [district_filter]
    else:
        districts_result = db.session.query(Activity.district).distinct().all()
        districts = [district[0] for district in districts_result if district and district[0]]

    # Define review types
    review_types = [
        'Interested for TART', 'Not interested for TART', 'After Result',
        'Call Later', 'Joined in Excel', 'Joined in Other College',
        'No Response', 'Not Willing', 'Switched off', 'Willing to Join',
        'Wrong Number', 'Waiting for NEET'
    ]

    # Create summary data
    summary_data = []
    grand_total = 0

    for district in districts:
        district_counts = {}
        total = 0

        # Calculate response counts with date filters if provided
        for review_type in review_types:
            query = Activity.query.filter_by(
                district=district,
                review=review_type
            )

            if start_date and end_date:
                query = query.filter(
                    Activity.submitted_at >= start_date,
                    Activity.submitted_at <= end_date
                )

            count = query.count()
            district_counts[review_type] = count
            total += count

        district_counts['District'] = district
        district_counts['Total'] = total
        grand_total += total
        summary_data.append(district_counts)

    # Add grand total row if showing all districts
    if not district_filter:
        summary_data.append({
            'District': 'GRAND TOTAL',
            'Total': grand_total,
            **{rt: sum(d[rt] for d in summary_data) for rt in review_types}
        })

    # Create DataFrame
    columns = ['District'] + review_types + ['Total']
    df = pd.DataFrame(summary_data, columns=columns)

    # Create CSV file
    output = io.StringIO()
    df.to_csv(output, index=False)
    output.seek(0)

    # Generate filename
    filename = 'district_wise_reports'
    if district_filter:
        filename += f'_{district_filter}'
    if start_date and end_date:
        filename += f'_{start_date.date()}_to_{end_date.date()}'
    filename += '.csv'

    return Response(
        output.getvalue(),
        mimetype='text/csv',
        headers={'Content-Disposition': f'attachment; filename={filename}'}
    )

@app.route('/download_college_wise_data')
@login_required
def download_college_wise_data():
    if current_user.role != 'admin':
        flash('You do not have permission to access this page.', 'error')
        return redirect(url_for('admin_dashboard'))

    # Get date range from query parameters
    start_date = request.args.get('start_date')
    end_date = request.args.get('end_date')

    # Convert to datetime objects if provided
    if start_date and end_date:
        try:
            start_date = datetime.strptime(start_date, '%Y-%m-%d')
            end_date = datetime.strptime(end_date, '%Y-%m-%d') + timedelta(days=1)  # Include end date
        except ValueError:
            flash('Invalid date format. Please use YYYY-MM-DD.', 'error')
            return redirect(url_for('admin_dashboard'))
    else:
        # If no dates provided, return an error
        flash('Please select both start and end dates', 'error')
        return redirect(url_for('admin_dashboard'))

    # Define all response types
    review_types = [
        'Interested for TART', 'Not interested for TART', 'After Result',
        'Call Later', 'Joined in Excel', 'Joined in Other College',
        'No Response', 'Not Willing', 'Switched off', 'Willing to Join',
        'Wrong Number', 'Waiting for NEET'
    ]

    # Fetch all colleges
    colleges = db.session.query(User.college).distinct().all()
    colleges = [college[0] for college in colleges if college[0]]

    # Create summary data
    summary_data = []
    grand_totals = {rt: 0 for rt in review_types}
    grand_total_all = 0

    for college in colleges:
        college_counts = {'College': college}
        total = 0

        # Calculate response counts for each review type
        for review_type in review_types:
            query = Activity.query.join(
                User, Activity.user_id == User.id
            ).filter(
                User.college == college,
                Activity.review == review_type
            )

            # Always apply date filter
            query = query.filter(
                Activity.submitted_at >= start_date,
                Activity.submitted_at <= end_date
            )

            count = query.count()
            college_counts[review_type] = count
            total += count
            grand_totals[review_type] += count

        # Add college total
        college_counts['Total'] = total
        grand_total_all += total

        summary_data.append(college_counts)

    # Add Grand Total row
    grand_total_row = {
        'College': 'GRAND TOTAL',
        **grand_totals,
        'Total': grand_total_all
    }
    summary_data.append(grand_total_row)

    # Create DataFrame
    columns = ['College'] + review_types + ['Total']
    df = pd.DataFrame(summary_data, columns=columns)

    # Create CSV file
    output = io.StringIO()
    df.to_csv(output, index=False)
    output.seek(0)

    # Generate filename with dates if filtered
    filename = 'college_wise_reports'
    if start_date and end_date:
        filename += f'_{start_date.date()}_to_{end_date.date()}'
    filename += '.csv'

    return Response(
        output.getvalue(),
        mimetype='text/csv',
        headers={'Content-Disposition': f'attachment; filename={filename}'}
    )

@app.route('/delete_uploaded_data', methods=['POST'])
@login_required
def delete_uploaded_data():
    if current_user.role != 'admin':
        flash('You do not have permission to perform this action.', 'error')
        return redirect(url_for('admin_dashboard'))

    selected_date = request.form.get('selected_date')  # Get the selected date

    if not selected_date:
        flash('Please select a date.', 'error')
        return redirect(url_for('admin_dashboard'))

    try:
        selected_date = datetime.strptime(selected_date, '%Y-%m-%d').date()  # Convert to date object
    except ValueError:
        flash('Invalid date format. Please use the format YYYY-MM-DD.', 'error')
        return redirect(url_for('admin_dashboard'))

    # Delete activities with the selected uploaded_date
    deleted_count = Activity.query.filter_by(uploaded_date=selected_date).delete()
    db.session.commit()

    flash(f'Successfully deleted {deleted_count} activities for {selected_date}.', 'success')
    return redirect(url_for('admin_dashboard'))

@app.route('/download_pending_responses')
@login_required
def download_pending_responses():
    if current_user.role != 'admin':
        flash('You do not have permission to access this page.', 'error')
        return redirect(url_for('admin_dashboard'))

    # Fetch pending activities with a join to the User table
    activities = Activity.query.filter_by(status='pending').all()

    # Convert the data to a pandas DataFrame
    data = []
    for activity in activities:
        row = activity.data  # Assuming 'data' is a JSON column
        row['SN'] = activity.sn
        row['Admin'] = get_username(activity.admin_id)

        # Get the user information
        user = User.query.get(activity.user_id)
        row['User'] = user.username if user else ''
        row['Thumb ID'] = user.thumb_id if user else ''  # Add the thumb ID column
        row['College'] = user.college if user else ''
        row['Department'] = user.department if user else ''

        row['Submitted At'] = activity.submitted_at.strftime('%Y-%m-%d %H:%M:%S') if activity.submitted_at else ''
        data.append(row)

    df = pd.DataFrame(data)

    # Create CSV file
    output = io.StringIO()
    df.to_csv(output, index=False)
    output.seek(0)

    # Send the file as a response
    return Response(
        output.getvalue(),
        mimetype='text/csv',
        headers={'Content-Disposition': f'attachment; filename=pending_responses.csv'}
    )
@app.route('/search_user/<username>', methods=['GET'])
@login_required
def search_user(username):
    try:
        if current_user.role != 'admin':
            return jsonify({'error': 'Permission denied'}), 403

        # Case-insensitive search for username
        user = User.query.filter(db.func.lower(User.username) == username.strip().lower()).first()

        if not user:
            return jsonify({'error': 'User not found'}), 404

        # Get all activities for the user with pagination
        activities = Activity.query.filter_by(user_id=user.id).all()

        # Build comprehensive response
        response_data = {
            'user': {
                'id': user.id,
                'username': user.username,
                'college': user.college,
                'department': user.department,
                'active': user.active,
                'thumb_id': user.thumb_id
            },
            'stats': {
                'total_activities': len(activities),
                'pending': sum(1 for a in activities if a.status == 'pending'),
                'reviewed': sum(1 for a in activities if a.status == 'reviewed')
            },
            'activities': [
                {
                    'id': a.id,
                    'sn': a.sn,
                    'district': a.district,
                    'status': a.status,
                    'review': a.review,
                    'assigned_date': a.assigned_date.isoformat() if a.assigned_date else None,
                    'submitted_at': a.submitted_at.isoformat() if a.submitted_at else None,
                    'remarks': a.remarks
                } for a in activities
            ]
        }

        return jsonify(response_data)

    except Exception as e:
        app.logger.error(f"Error in user search: {str(e)}")
        return jsonify({'error': 'Server error'}), 500

@app.route('/search_user_by_thumb_id/<thumb_id>', methods=['GET'])
@login_required
def search_user_by_thumb_id(thumb_id):
    try:
        if current_user.role != 'admin':
            return jsonify({'error': 'Permission denied'}), 403

        # Case-insensitive search for Thumb ID
        user = User.query.filter(db.func.lower(User.thumb_id) == thumb_id.strip().lower()).first()

        if not user:
            return jsonify({'error': 'User not found'}), 404

        # Fetch all activities for the user
        activities = Activity.query.filter_by(user_id=user.id).all()

        # Build JSON response
        response_data = {
            'user': {
                'id': user.id,
                'username': user.username,
                'college': user.college,
                'department': user.department,
                'active': user.active,
                'thumb_id': user.thumb_id
            },
            'activities': [
                {
                    'id': a.id,
                    'sn': a.sn,
                    'district': a.district,
                    'status': a.status,
                    'review': a.review,
                    'assigned_date': a.assigned_date.isoformat() if a.assigned_date else None,
                    'submitted_at': a.submitted_at.isoformat() if a.submitted_at else None,
                    'remarks': a.remarks
                } for a in activities
            ]
        }

        return jsonify(response_data)

    except SQLAlchemyError as e:
        app.logger.error(f"Database error: {str(e)}")
        return jsonify({'error': 'Database error'}), 500
    except Exception as e:
        app.logger.error(f"Unexpected error: {str(e)}")
        return jsonify({'error': 'Server error'}), 500

@app.route('/download_filtered_data')
@login_required
def download_filtered_data():
    if current_user.role != 'admin':
        flash('You do not have permission to access this page.', 'error')
        return redirect(url_for('admin_dashboard'))

    # Get filter parameters from the query string
    filter_date = request.args.get('date')
    filter_college = request.args.get('college')
    filter_department = request.args.get('department')

    # Build the base query
    query = Activity.query.join(User, Activity.user_id == User.id)

    # Apply filters
    if filter_date:
        filter_date = datetime.strptime(filter_date, '%Y-%m-%d').date()
        query = query.filter(Activity.assigned_date == filter_date)
    if filter_college:
        query = query.filter(User.college == filter_college)
    if filter_department:
        query = query.filter(User.department == filter_department)

    # Fetch filtered activities
    activities = query.all()

    # Convert the data to a pandas DataFrame
    data = []
    for activity in activities:
        row = activity.data  # Assuming 'data' is a JSON column
        row['SN'] = activity.sn
        row['Admin'] = get_username(activity.admin_id)

        # Get the user information
        user = User.query.get(activity.user_id)
        row['User'] = user.username if user else ''
        row['Thumb ID'] = user.thumb_id if user else ''  # Add the thumb ID column
        row['College'] = user.college if user else ''
        row['Department'] = user.department if user else ''

        row['Review'] = activity.review
        row['Submitted At'] = activity.submitted_at.strftime('%Y-%m-%d %H:%M:%S') if activity.submitted_at else ''
        data.append(row)

    df = pd.DataFrame(data)

    # Create CSV file
    output = io.StringIO()
    df.to_csv(output, index=False)
    output.seek(0)

    # Send the file as a response
    return Response(
        output.getvalue(),
        mimetype='text/csv',
        headers={'Content-Disposition': f'attachment; filename=filtered_data.csv'}
    )

@app.route('/get_response_counts')
@login_required
def get_response_counts():
    if current_user.role != 'admin':
        return jsonify({'error': 'Permission denied'}), 403

    # Get filter parameters
    college = request.args.get('college', '')
    department = request.args.get('department', '')
    date = request.args.get('date', '')

    # Build base query with explicit join condition
    query = db.session.query(Activity.review, db.func.count(Activity.id)).join(
        User, Activity.user_id == User.id  # Explicitly specify the join condition
    )

    # Apply filters
    if college:
        query = query.filter(User.college == college)
    if department:
        query = query.filter(User.department == department)
    if date:
        query = query.filter(db.func.date(Activity.submitted_at) == date)

    # Group and get counts
    counts = query.group_by(Activity.review).all()

    # Define all response types
    response_types = [
        'Interested for TART', 'Not interested for TART',
        'After Result', 'Call Later', 'Joined in Excel',
        'Joined in Other College', 'No Response', 'Not Willing',
        'Switched off', 'Willing to Join', 'Wrong Number',
        'Waiting for NEET'
    ]

    # Prepare data
    data = []
    for rt in response_types:
        count = next((c for r, c in counts if r == rt), 0)
        data.append({'response': rt, 'count': count})

    return jsonify({'counts': data})

@app.route('/download_response_counts')
@login_required
def download_response_counts():
    if current_user.role != 'admin':
        flash('You do not have permission to access this page.', 'error')
        return redirect(url_for('admin_dashboard'))

    # Get filter parameters from the query string
    college = request.args.get('college', '')
    department = request.args.get('department', '')
    date = request.args.get('date', '')

    # Build the base query with explicit join condition
    query = db.session.query(Activity.review, db.func.count(Activity.id)).join(
        User, Activity.user_id == User.id  # Explicitly specify the join condition
    )

    # Apply filters
    if college:
        query = query.filter(User.college == college)
    if department:
        query = query.filter(User.department == department)
    if date:
        query = query.filter(db.func.date(Activity.submitted_at) == date)

    # Group by review type and get counts
    counts = query.group_by(Activity.review).all()

    # Define all response types
    response_types = [
        'Interested for TART', 'Not interested for TART',
        'After Result', 'Call Later', 'Joined in Excel',
        'Joined in Other College', 'No Response', 'Not Willing',
        'Switched off', 'Willing to Join', 'Wrong Number',
        'Waiting for NEET'
    ]

    # Prepare data
    data = []
    total_count = 0  # Initialize total count

    for rt in response_types:
        count = next((c for r, c in counts if r == rt), 0)
        data.append({'Response Type': rt, 'Count': count})
        total_count += count  # Add to total count

    # Add the "Total" row to the data
    data.append({'Response Type': 'Total', 'Count': total_count})

    # Convert to DataFrame
    df = pd.DataFrame(data)

    # Create an in-memory Excel file
    output = io.BytesIO()
    with pd.ExcelWriter(output, engine='xlsxwriter') as writer:
        df.to_excel(writer, index=False, sheet_name='Response Counts')
    output.seek(0)

    # Send the file as a response
    return send_file(
        output,
        mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
        as_attachment=True,
        download_name='response_counts.xlsx'
    )

@app.route('/get_review_history/<int:activity_id>')
@login_required
def get_review_history(activity_id):
    history = ReviewHistory.query.filter_by(activity_id=activity_id)\
        .order_by(ReviewHistory.submitted_at.desc())\
        .all()

    history_data = [{
        'review': item.review,
        'remarks': item.remarks,
        'submitted_at': item.submitted_at.isoformat() if item.submitted_at else None
    } for item in history]

    return jsonify({'history': history_data})

@app.route('/download_details/<document_type>')
@login_required
def download_details(document_type):
    """
    Route to download various PDF documents
    document_type can be: placement, scholarship, sret, booklet, fees_structure
    """
    # Map document types to file paths
    document_map = {
        'placement': 'static/pdfs/placement.pdf',
        'scholarship': 'static/pdfs/scholarship.pdf',
        'sret': 'static/pdfs/sret.pdf',
        'booklet': 'static/pdfs/booklet.pdf',
        'fees_structure': 'static/pdfs/fees_structure.pdf'
    }

    # Check if the requested document type is valid
    if document_type not in document_map:
        flash('Invalid document type requested', 'error')
        return redirect(url_for('user_dashboard'))

    # Get the file path
    file_path = document_map[document_type]

    # Check if the file exists
    if not os.path.isfile(file_path):
        flash(f'The requested document ({document_type}) is not available', 'error')
        return redirect(url_for('user_dashboard'))

    # Generate a friendly filename for the download
    download_name = f"{document_type.replace('_', ' ').title()}.pdf"

    # Send the file
    return send_file(
        file_path,
        mimetype='application/pdf',
        as_attachment=True,
        download_name=download_name
    )

@app.route('/get_second_review/<int:activity_id>')
@login_required
def get_second_review(activity_id):
    # Get the second most recent review (first is the current activity review)
    second_review = ReviewHistory.query.filter_by(activity_id=activity_id)\
        .order_by(ReviewHistory.submitted_at.desc())\
        .offset(1).first()

    if second_review:
        return jsonify({
            'review': second_review.review,
            'remarks': second_review.remarks,
            'submitted_at': second_review.submitted_at.isoformat() if second_review.submitted_at else None
        })
    return jsonify({})

@app.route('/subuser_dashboard')
@login_required
def subuser_dashboard():
    if current_user.role != 'subuser':
        return redirect(url_for('login'))

    # Define response types
    response_types = [
        'Interested for TART', 'Not interested for TART', 'After Result',
        'Call Later', 'Joined in Excel', 'Joined in Other College',
        'No Response', 'Not Willing', 'Switched off', 'Willing to Join',
        'Wrong Number', 'Waiting for NEET'
    ]

    # Get active users with their responses
    user_responses = db.session.query(User).filter(
        User.active == True,
        User.role == 'user'
    ).all()

    # Prepare user data with thumb_id and response counts
    for user in user_responses:
        user.thumb_id = user.thumb_id if user.thumb_id else None
        user.assigned_activities = Activity.query.filter_by(user_id=user.id).count()
        user.pending_responses = Activity.query.filter_by(
            user_id=user.id,
            status='pending'
        ).count()

        # Calculate response counts for each type
        for response_type in [rt.replace(' ', '_') for rt in response_types]:
            setattr(user, response_type, Activity.query.filter_by(
                user_id=user.id,
                status='reviewed',
                review=response_type.replace('_', ' ')
            ).count())

    # Prepare response counts
    response_counts = {}
    for response_type in response_types:
        count = Activity.query.filter_by(review=response_type).count()
        response_counts[response_type] = count

    # Prepare district counts
    district_counts = {}
    districts = db.session.query(Activity.district).distinct().all()
    districts = [d[0] for d in districts if d[0]]

    for district in districts:
        district_counts[district] = {}
        district_total = 0

        for rt in response_types:
            count = Activity.query.filter_by(district=district, review=rt).count()
            district_counts[district][rt] = count
            district_total += count

        district_counts[district]['Total'] = district_total

    # Prepare college counts
    college_counts = {}
    colleges = db.session.query(User.college).distinct().all()
    colleges = [c[0] for c in colleges if c[0]]

    for college in colleges:
        college_counts[college] = {}
        college_total = 0

        for rt in response_types:
            count = Activity.query.join(
                User, Activity.user_id == User.id  # Explicitly specify the join condition
            ).filter(
                User.college == college,
                Activity.review == rt
            ).count()

            college_counts[college][rt] = count
            college_total += count

        college_counts[college]['Total'] = college_total

    # Render the template with all the data
    return render_template(
        'subuser_dashboard.html',
        user_responses=user_responses,
        response_counts=response_counts,
        district_counts=district_counts,
        college_counts=college_counts
    )

@app.route('/subuser_signup', methods=['GET', 'POST'])
def subuser_signup():
    if request.method == 'POST':
        username = request.form['username']
        password = generate_password_hash(request.form['password'])
        thumb_id = request.form['thumb_id']
        college = request.form['college']
        department = request.form['department']

        # Check if the Thumb ID already exists
        existing_user = User.query.filter_by(thumb_id=thumb_id).first()
        if existing_user:
            flash('Thumb ID already exists. Please use a different Thumb ID.', 'error')
            return redirect(url_for('subuser_signup'))

        new_user = User(
            username=username,
            password=password,
            thumb_id=thumb_id,
            role='subuser',
            college=college,
            department=department
        )
        db.session.add(new_user)
        db.session.commit()
        flash('Sub-user account created!', 'success')
        return redirect(url_for('login'))
    return render_template('subuser_signup.html')

@app.route('/get_filtered_response_counts')
@login_required
def get_filtered_response_counts():
    if current_user.role != 'subuser':
        return jsonify({'error': 'Permission denied'}), 403

    # Get filter parameters
    start_date = request.args.get('start_date')
    end_date = request.args.get('end_date')

    # Build base query
    query = db.session.query(Activity.review, db.func.count(Activity.id))

    # Apply date filters if provided
    if start_date and end_date:
        try:
            start_date = datetime.strptime(start_date, '%Y-%m-%d')
            end_date = datetime.strptime(end_date, '%Y-%m-%d') + timedelta(days=1)
            query = query.filter(Activity.submitted_at.between(start_date, end_date))
        except ValueError:
            return jsonify({'error': 'Invalid date format'}), 400

    # Group and get counts
    counts = query.group_by(Activity.review).all()

    # Define all response types
    response_types = [
        'Interested for TART', 'Not interested for TART',
        'After Result', 'Call Later', 'Joined in Excel',
        'Joined in Other College', 'No Response', 'Not Willing',
        'Switched off', 'Willing to Join', 'Wrong Number',
        'Waiting for NEET'
    ]

    # Prepare data
    data = []
    for rt in response_types:
        count = next((c for r, c in counts if r == rt), 0)
        data.append({'response': rt, 'count': count})

    return jsonify({'counts': data})

@app.route('/get_filtered_district_counts')
@login_required
def get_filtered_district_counts():
    if current_user.role != 'subuser':
        return jsonify({'error': 'Permission denied'}), 403

    # Get filter parameters
    start_date = request.args.get('start_date')
    end_date = request.args.get('end_date')

    # Fetch all districts
    districts = db.session.query(Activity.district).distinct().all()
    districts = [district[0] for district in districts if district[0]]

    # Define all response types
    response_types = [
        'Interested for TART', 'Not interested for TART',
        'After Result', 'Call Later', 'Joined in Excel',
        'Joined in Other College', 'No Response', 'Not Willing',
        'Switched off', 'Willing to Join', 'Wrong Number',
        'Waiting for NEET'
    ]

    # Prepare data
    data = []
    for district in districts:
        counts = {}
        for rt in response_types:
            query = Activity.query.filter_by(district=district, review=rt)
            if start_date and end_date:
                try:
                    start = datetime.strptime(start_date, '%Y-%m-%d')
                    end = datetime.strptime(end_date, '%Y-%m-%d') + timedelta(days=1)
                    query = query.filter(Activity.submitted_at.between(start, end))
                except ValueError:
                    return jsonify({'error': 'Invalid date format'}), 400
            counts[rt] = query.count()

        data.append({
            'name': district,
            'counts': counts
        })

    return jsonify(data)

@app.route('/get_filtered_subuser_college_counts')
@login_required
def get_filtered_subuser_college_counts():
    if current_user.role != 'subuser':
        return jsonify({'error': 'Permission denied'}), 403

    # Get filter parameters
    start_date = request.args.get('start_date')
    end_date = request.args.get('end_date')

    # Fetch all colleges
    colleges = db.session.query(User.college).distinct().all()
    colleges = [college[0] for college in colleges if college[0]]

    # Define all response types
    response_types = [
        'Interested for TART', 'Not interested for TART',
        'After Result', 'Call Later', 'Joined in Excel',
        'Joined in Other College', 'No Response', 'Not Willing',
        'Switched off', 'Willing to Join', 'Wrong Number',
        'Waiting for NEET'
    ]

    # Prepare data
    data = []
    for college in colleges:
        counts = {}
        for rt in response_types:
            query = Activity.query.join(
                    User, Activity.user_id == User.id  # Explicitly specify the join condition
                ).filter(
                    User.college == college,
                    Activity.review == rt
                )

            if start_date and end_date:
                try:
                    start = datetime.strptime(start_date, '%Y-%m-%d')
                    end = datetime.strptime(end_date, '%Y-%m-%d') + timedelta(days=1)
                    query = query.filter(Activity.submitted_at.between(start, end))
                except ValueError:
                    return jsonify({'error': 'Invalid date format'}), 400

            counts[rt] = query.count()

        data.append({
            'name': college,
            'counts': counts
        })

    return jsonify(data)

@app.route('/download_filtered_reports')
@login_required
def download_filtered_reports():
    if current_user.role != 'subuser':
        flash('You do not have permission to access this page.', 'error')
        return redirect(url_for('subuser_dashboard'))

    # Get filter parameters
    start_date = request.args.get('start_date')
    end_date = request.args.get('end_date')

    if not start_date or not end_date:
        flash('Please provide both start and end dates', 'error')
        return redirect(url_for('subuser_dashboard'))

    try:
        start_date = datetime.strptime(start_date, '%Y-%m-%d')
        end_date = datetime.strptime(end_date, '%Y-%m-%d') + timedelta(days=1)
    except ValueError:
        flash('Invalid date format. Please use YYYY-MM-DD.', 'error')
        return redirect(url_for('subuser_dashboard'))

    # Fetch all colleges
    colleges = db.session.query(User.college).distinct().all()
    colleges = [college[0] for college in colleges if college[0]]

    # Define all response types
    response_types = [
        'Interested for TART', 'Not interested for TART',
        'After Result', 'Call Later', 'Joined in Excel',
        'Joined in Other College', 'No Response', 'Not Willing',
        'Switched off', 'Willing to Join', 'Wrong Number',
        'Waiting for NEET'
    ]

    # Create summary data
    summary_data = []
    grand_totals = {rt: 0 for rt in response_types}
    grand_total_all = 0

    for college in colleges:
        college_counts = {'College': college}
        total = 0

        # Calculate response counts for each review type
        for review_type in response_types:
            count = Activity.query.join(
                User, Activity.user_id == User.id
            ).filter(
                User.college == college,
                Activity.review == review_type,
                Activity.submitted_at.between(start_date, end_date)
            ).count()

            college_counts[review_type] = count
            total += count
            grand_totals[review_type] += count

        # Add college total
        college_counts['Total'] = total
        grand_total_all += total

        summary_data.append(college_counts)

    # Add Grand Total row
    grand_total_row = {
        'College': 'GRAND TOTAL',
        **grand_totals,
        'Total': grand_total_all
    }
    summary_data.append(grand_total_row)

    # Create DataFrame
    columns = ['College'] + response_types + ['Total']
    df = pd.DataFrame(summary_data, columns=columns)

    # Create CSV file
    output = io.StringIO()
    df.to_csv(output, index=False)
    output.seek(0)

    # Generate filename with dates
    filename = f'college_reports_{start_date.date()}_to_{end_date.date()}.csv'

    return Response(
        output.getvalue(),
        mimetype='text/csv',
        headers={'Content-Disposition': f'attachment; filename={filename}'}
    )

@app.route('/download_subuser_full_report')
@login_required
def download_subuser_full_report():
    if current_user.role != 'subuser':
        flash('You do not have permission to access this page.', 'error')
        return redirect(url_for('subuser_dashboard'))

    # Define review types list first for consistency
    review_types = [
        'Interested for TART', 'Not interested for TART',
        'After Result', 'Call Later', 'Joined in Excel',
        'Joined in Other College', 'No Response', 'Not Willing',
        'Switched off', 'Willing to Join', 'Wrong Number',
        'Waiting for NEET'
    ]

    # Date filtering setup
    start_date = request.args.get('start_date')
    end_date = request.args.get('end_date')
    date_filter = []

    try:
        if start_date:
            start_datetime = datetime.strptime(start_date, '%Y-%m-%d')
            date_filter.append(Activity.submitted_at >= start_datetime)
        if end_date:
            end_datetime = datetime.strptime(end_date, '%Y-%m-%d') + timedelta(days=1)
            date_filter.append(Activity.submitted_at <= end_datetime)
    except ValueError:
        flash('Invalid date format. Please use YYYY-MM-DD format.', 'error')
        return redirect(url_for('subuser_dashboard'))

    # Prepare data for CSV files

    # Response Counts data
    response_counts = {rt: 0 for rt in review_types}
    for review in review_types:
        query = Activity.query.filter_by(review=review)
        if date_filter:
            query = query.filter(*date_filter)
        response_counts[review] = query.count()

    # Create response counts DataFrame
    df_response = pd.DataFrame({
        'Response Type': review_types,
        'Count': [response_counts[rt] for rt in review_types]
    })

    # Add total row
    total_count = sum(response_counts.values())
    df_response = pd.concat([df_response, pd.DataFrame([{'Response Type': 'Total', 'Count': total_count}])], ignore_index=True)

    # District-wise Reports data
    districts = db.session.query(Activity.district).distinct().all()
    districts = [d[0] for d in districts if d[0]]

    district_data = []
    for district in districts:
        counts = {'District': district}
        counts.update({rt: 0 for rt in review_types})

        for review in review_types:
            query = Activity.query.filter_by(
                district=district,
                review=review
            )
            if date_filter:
                query = query.filter(*date_filter)
            counts[review] = query.count()

        # Calculate total and maintain column order
        counts['Total'] = sum(counts[rt] for rt in review_types)
        district_data.append(counts)

    # Create district DataFrame with ordered columns
    district_columns = ['District'] + review_types + ['Total']
    df_district = pd.DataFrame(district_data, columns=district_columns)

    # Add grand total row
    grand_total_row = {'District': 'GRAND TOTAL'}
    for rt in review_types:
        grand_total_row[rt] = sum(d[rt] for d in district_data)
    grand_total_row['Total'] = sum(d['Total'] for d in district_data)
    df_district = pd.concat([df_district, pd.DataFrame([grand_total_row])], ignore_index=True)

    # College-wise Reports data
    colleges = db.session.query(User.college).distinct().all()
    colleges = [c[0] for c in colleges if c[0]]

    college_data = []
    for college in colleges:
        counts = {'College': college}
        counts.update({rt: 0 for rt in review_types})

        for review in review_types:
            query = db.session.query(Activity).join(
                User, Activity.user_id == User.id  # Explicit join condition
            ).filter(
                User.college == college,
                Activity.review == review
            )
            if date_filter:
                query = query.filter(*date_filter)
            counts[review] = query.count()

        # Calculate total and maintain column order
        counts['Total'] = sum(counts[rt] for rt in review_types)
        college_data.append(counts)

    # Create college DataFrame with ordered columns
    college_columns = ['College'] + review_types + ['Total']
    df_college = pd.DataFrame(college_data, columns=college_columns)

    # Add grand total row
    grand_total_row = {'College': 'GRAND TOTAL'}
    for rt in review_types:
        grand_total_row[rt] = sum(d[rt] for d in college_data)
    grand_total_row['Total'] = sum(d['Total'] for d in college_data)
    df_college = pd.concat([df_college, pd.DataFrame([grand_total_row])], ignore_index=True)

    # Create a single CSV file with all reports
    output = io.StringIO()

    # Write Response Counts section
    output.write("RESPONSE COUNTS\n")
    df_response.to_csv(output, index=False)
    output.write("\n\n")

    # Write District Reports section
    output.write("DISTRICT REPORTS\n")
    df_district.to_csv(output, index=False)
    output.write("\n\n")

    # Write College Reports section
    output.write("COLLEGE REPORTS\n")
    df_college.to_csv(output, index=False)

    # Reset the pointer to the beginning of the file
    output.seek(0)

    # Generate filename with date range
    filename = 'full_report.csv'
    if start_date and end_date:
        filename = f'full_report_from_{start_date}_to_{end_date}.csv'

    return Response(
        output.getvalue(),
        mimetype='text/csv',
        headers={'Content-Disposition': f'attachment; filename={filename}'}
    )


@app.route('/get_filtered_district_data')
@login_required
def get_filtered_district_data():
    if current_user.role != 'admin':
        return jsonify({'error': 'Permission denied'}), 403

    # Get date parameters
    start_date = request.args.get('start_date')
    end_date = request.args.get('end_date')

    # Validate dates
    if not start_date or not end_date:
        return jsonify({'error': 'Start and end dates are required'}), 400

    try:
        start_date = datetime.strptime(start_date, '%Y-%m-%d')
        end_date = datetime.strptime(end_date, '%Y-%m-%d') + timedelta(days=1)  # Include end date
    except ValueError:
        return jsonify({'error': 'Invalid date format'}), 400

    # Define review types
    review_types = [
        'Interested for TART', 'Not interested for TART', 'After Result',
        'Call Later', 'Joined in Excel', 'Joined in Other College',
        'No Response', 'Not Willing', 'Switched off', 'Willing to Join',
        'Wrong Number', 'Waiting for NEET'
    ]

    # Get all districts
    districts_result = db.session.query(Activity.district).distinct().all()
    districts = [d[0] for d in districts_result if d and d[0]]

    # Create district data
    district_data = []
    grand_totals = {rt: 0 for rt in review_types}

    for district in districts:
        district_info = {
            'name': district,
            'counts': {}
        }

        for review in review_types:
            query = Activity.query.filter_by(
                district=district,
                review=review
            )

            # Apply date filter
            query = query.filter(
                Activity.submitted_at >= start_date,
                Activity.submitted_at <= end_date
            )

            count = query.count()
            district_info['counts'][review] = count
            grand_totals[review] += count

        district_data.append(district_info)

    return jsonify({
        'districts': district_data,
        'grand_totals': grand_totals
    })

@app.route('/get_filtered_college_counts')
@login_required
def get_filtered_college_counts():
    if current_user.role != 'admin':
        return jsonify({'error': 'Permission denied'}), 403

    # Get date parameters
    start_date = request.args.get('start_date')
    end_date = request.args.get('end_date')

    # Define date filter
    date_filter = None
    if start_date and end_date:
        try:
            start_date = datetime.strptime(start_date, '%Y-%m-%d')
            end_date = datetime.strptime(end_date, '%Y-%m-%d') + timedelta(days=1)  # Include end date
            date_filter = (Activity.submitted_at >= start_date, Activity.submitted_at <= end_date)
        except ValueError:
            return jsonify({'error': 'Invalid date format'}), 400

    # Define review types
    review_types = [
        'Interested for TART', 'Not interested for TART', 'After Result',
        'Call Later', 'Joined in Excel', 'Joined in Other College',
        'No Response', 'Not Willing', 'Switched off', 'Willing to Join',
        'Wrong Number', 'Waiting for NEET'
    ]

    # Fetch all colleges
    colleges = db.session.query(User.college).distinct().all()
    colleges = [college[0] for college in colleges if college[0]]

    # Create college data
    college_data = []
    grand_totals = {review: 0 for review in review_types}

    for college in colleges:
        college_info = {
            'name': college,
            'counts': {}
        }

        college_total = 0
        for review in review_types:
            query = db.session.query(Activity).join(
                User, Activity.user_id == User.id
            ).filter(
                User.college == college,
                Activity.review == review
            )

            if date_filter:
                query = query.filter(*date_filter)

            count = query.count()
            college_info['counts'][review] = count
            grand_totals[review] += count
            college_total += count

        # Add total to college counts
        college_info['counts']['Total'] = college_total
        college_data.append(college_info)

    # Add grand total row
    grand_total_all = sum(grand_totals.values())
    grand_total_info = {
        'name': 'GRAND TOTAL',
        'counts': {**grand_totals, 'Total': grand_total_all}
    }
    college_data.append(grand_total_info)

    return jsonify(college_data)

@app.route('/download_district_data')
@login_required
def download_district_data():
    if current_user.role != 'admin':
        flash('You do not have permission to access this page.', 'error')
        return redirect(url_for('admin_dashboard'))

    # Get date parameters
    start_date = request.args.get('start_date')
    end_date = request.args.get('end_date')

    if not start_date or not end_date:
        flash('Please select both start and end dates', 'error')
        return redirect(url_for('admin_dashboard'))

    try:
        start_date = datetime.strptime(start_date, '%Y-%m-%d')
        end_date = datetime.strptime(end_date, '%Y-%m-%d') + timedelta(days=1)
    except ValueError:
        flash('Invalid date format', 'error')
        return redirect(url_for('admin_dashboard'))

    # Get all districts
    districts_result = db.session.query(Activity.district).distinct().all()
    districts = [d[0] for d in districts_result if d and d[0]]

    # Define all response types
    response_types = [
        'Interested for TART', 'Not interested for TART',
        'After Result', 'Call Later', 'Joined in Excel',
        'Joined in Other College', 'No Response', 'Not Willing',
        'Switched off', 'Willing to Join', 'Wrong Number',
        'Waiting for NEET'
    ]

    # Prepare data for Excel
    data = []
    grand_totals = {rt: 0 for rt in response_types}

    for district in districts:
        row = {'District': district}
        district_total = 0

        for rt in response_types:
            count = Activity.query.filter_by(
                district=district,
                review=rt
            ).filter(
                Activity.submitted_at.between(start_date, end_date)
            ).count()

            row[rt] = count
            grand_totals[rt] += count
            district_total += count

        row['Total'] = district_total  # Use the calculated total instead of summing
        data.append(row)

    # Add grand total row
    total_row = {'District': 'GRAND TOTAL'}
    for rt in response_types:
        total_row[rt] = grand_totals[rt]
    total_row['Total'] = sum(grand_totals.values())
    data.append(total_row)

    # Create DataFrame
    columns = ['District'] + response_types + ['Total']
    df = pd.DataFrame(data, columns=columns)

    # Create CSV file
    output = io.StringIO()
    df.to_csv(output, index=False)
    output.seek(0)

    # Generate filename
    filename = f'district_report_{start_date.date()}_to_{end_date.date()}.csv'

    return Response(
        output.getvalue(),
        mimetype='text/csv',
        headers={
            'Content-Disposition': f'attachment; filename={filename}'
        }
    )

@app.route('/submit_second_review', methods=['POST'])
@login_required
def submit_second_review():
    if request.method == 'POST':
        activity_id = request.form.get('activity_id')
        review = request.form.get('review')
        remarks = request.form.get('remarks')

        activity = Activity.query.get(activity_id)
        if not activity:
            return jsonify({'success': False, 'message': 'Activity not found'})

        # Create the second review
        second_review = SecondReview(
            activity_id=activity.id,
            review=review,
            remarks=remarks,
            user_id=current_user.id
        )

        db.session.add(second_review)
        db.session.commit()

        # Get the count of second reviews for this activity
        second_reviews_count = SecondReview.query.filter_by(activity_id=activity.id).count()

        # Emit socket event for real-time updates if using SocketIO
        try:
            socketio.emit('second_review_added', {
                'activity_id': activity.id,
                'second_reviews_count': second_reviews_count
            }, namespace='/admin')
        except Exception as e:
            # Log the error but continue
            app.logger.error(f"Error emitting socket event: {str(e)}")

        # Return JSON response for AJAX
        return jsonify({
            'success': True,
            'message': 'Second review submitted successfully',
            'activity_id': activity.id,
            'review': review,
            'remarks': remarks,
            'submitted_at': second_review.submitted_at.isoformat(),
            'second_reviews_count': second_reviews_count
        })

# Add this endpoint to your Flask app
@app.route('/get_activity_counts')
@login_required
def get_activity_counts():
    activities = Activity.query.all()
    return jsonify({
        'counts': {a.id: a.second_reviews_count for a in activities}
    })


if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    # Run the app with SocketIO
    app.run(host='0.0.0.0', port=5000, debug=True)