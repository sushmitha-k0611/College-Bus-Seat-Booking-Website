from flask import Flask, render_template, request, redirect, url_for, session, flash
from werkzeug.security import generate_password_hash, check_password_hash
import mysql.connector
import base64
from datetime import datetime
from werkzeug.utils import secure_filename
from flask import jsonify
from flask import Flask, render_template, request, redirect, url_for
import cv2
import numpy as np
from datetime import datetime
import os
import qrcode
import io
from apscheduler.schedulers.background import BackgroundScheduler
import atexit
from datetime import datetime, time

app = Flask(__name__)
app.secret_key = 'your_secret_key'

# MySQL connection setup
db = mysql.connector.connect(
    host="localhost",
    user="root",
    password="Sushmi@2103",
    database="college_bus_booking"
)
cursor = db.cursor(dictionary=True)
def reset_attendance():
    with app.app_context():
        try:
            cursor.execute("DELETE FROM attendance")
            db.commit()
            print(f"[{datetime.now()}] Attendance table reset successfully.")
        except Exception as e:
            print(f"Error resetting attendance: {e}")

scheduler = BackgroundScheduler()

# Schedule reset at 9:00 AM and 7:00 PM daily (change times as needed)
scheduler.add_job(reset_attendance, 'cron', hour=9, minute=0)
scheduler.add_job(reset_attendance, 'cron', hour=19, minute=0)

scheduler.start()

# Shut down scheduler when exiting
atexit.register(lambda: scheduler.shutdown())


UPLOAD_FOLDER = 'uploads/'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['ALLOWED_EXTENSIONS'] = {'png', 'jpg', 'jpeg', 'gif'}

# -------------------- AUTH ROUTES --------------------
@app.route('/favicon.ico')
def favicon():
    return '', 204  # No Content


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        role = request.form.get('role')  # get role from form

        if not email or not password or not confirm_password or not role:
            return render_template('register.html', error="All fields are required")

        if password != confirm_password:
            return render_template('register.html', error="Passwords do not match")

        password_hash = generate_password_hash(password)

        try:
            cursor.execute("SELECT * FROM users WHERE email = %s", (email,))
            existing_user = cursor.fetchone()

            if existing_user:
                return render_template('register.html', error="Email already registered")

            cursor.execute("INSERT INTO users (email, password_hash, role) VALUES (%s, %s, %s)", 
                           (email, password_hash, role))
            db.commit()

            return redirect(url_for('login'))

        except mysql.connector.Error as err:
            print("Database error:", err)
            return render_template('register.html', error="Internal server error")

    return render_template('register.html', is_admin=False)


@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        role = request.form.get('role')  # get role from form

        cursor.execute("SELECT * FROM users WHERE email = %s", (email,))
        user = cursor.fetchone()

        if user and check_password_hash(user['password_hash'], password):
            # Check if the role matches
            if user.get('role') == role:
                session['user'] = email
                session['role'] = role

                if role == 'admin':
                    return redirect(url_for('admin_dashboard'))
                elif role == 'student':
                    return redirect(url_for('student_dashboard'))
                else:
                    error = "Invalid role selected"
            else:
                error = "Role does not match user"
        else:
            error = 'Invalid credentials'

    return render_template('login.html', is_admin=False, error=error)


@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

@app.before_request
def require_login():
    allowed_routes = ['login', 'register', 'static']
    if request.endpoint not in allowed_routes and 'user' not in session:
        return redirect(url_for('login'))

        # -------------------- DASHBOARD ROUTES --------------------
@app.route('/admin/dashboard')
def admin_dashboard():
    # Check admin session
    if 'role' not in session or session['role'] != 'admin':
        return redirect(url_for('login'))

    # Get stats for dashboard cards
    cursor.execute("SELECT COUNT(*) as total_buses FROM buses")
    total_buses = cursor.fetchone()['total_buses']

    cursor.execute("SELECT COUNT(*) as total_queries FROM queries")
    total_queries = cursor.fetchone()['total_queries']

    cursor.execute("SELECT COUNT(*) as total_checkins FROM checkins")
    total_checkins = cursor.fetchone()['total_checkins']

    # Render dashboard page (with 3 boxes)
    return render_template('admin_dashboard.html', 
                           total_buses=total_buses,
                           total_queries=total_queries,
                           total_checkins=total_checkins)



@app.route('/student/dashboard')
def student_dashboard():
    if 'role' not in session or session['role'] != 'student':
        return redirect(url_for('login'))

    email = session['user']
    cursor.execute("SELECT COUNT(*) as total_bookings FROM bookings WHERE passenger_name = %s", (email,))
    total_bookings = cursor.fetchone()['total_bookings']

    cursor.execute("SELECT COUNT(*) as total_queries FROM queries WHERE email = %s", (email,))
    total_queries = cursor.fetchone()['total_queries']

    cursor.execute("SELECT COUNT(*) as total_attendance FROM attendance WHERE name = %s", (email,))
    total_attendance = cursor.fetchone()['total_attendance']

    return render_template('student_dashboard.html', total_bookings=total_bookings,
                           total_queries=total_queries, total_attendance=total_attendance)



# -------------------- MAIN ROUTES --------------------

@app.route('/')
def student_index():
    # Redirect if not logged in
    if 'user' not in session:
        return redirect(url_for('login'))

    # Optional: Redirect based on role, e.g., admins get admin dashboard
    if session.get('role') == 'admin':
        return redirect(url_for('admin_dashboard'))

    # Otherwise show student index page
    cursor.execute("SELECT bus_no FROM buses")
    buses = cursor.fetchall()

    cursor.execute("SELECT DISTINCT stop_name FROM stops")
    stops = cursor.fetchall()

    return render_template('student_index.html', buses=buses, stops=stops)

@app.route('/get_stops')
def get_stops():
    bus_no = request.args.get('bus_no')
    
    if not bus_no:
        return jsonify([])  # Return empty array if bus_no is not provided

    try:
        cursor.execute("SELECT id FROM buses WHERE bus_no = %s", (bus_no,))
        bus = cursor.fetchone()
        if not bus:
            return jsonify([])  # Return empty array if bus not found
        
        bus_id = bus['id']
        
        cursor.execute("SELECT stop_name FROM stops WHERE bus_id = %s", (bus_id,))
        stops = cursor.fetchall()

        # Return stops in JSON format
        return jsonify([stop['stop_name'] for stop in stops])
    
    except mysql.connector.Error as err:
        print("Database error:", err)
        return jsonify([])  # Return empty array in case of error


@app.route('/check', methods=['POST'])
def check():
    name = request.form.get('name')
    bus_no = request.form.get('bus_no')
    stop_name = request.form.get('stop_name')
    seats_str = request.form.get('seats')

    if not seats_str:
        return "Seats data missing", 400

    seats = seats_str.split(',')
    seats = [int(seat) for seat in seats if seat.isdigit()]

    if not name or not bus_no or not stop_name or not seats:
        return "Missing required data", 400

    try:
        cursor.execute("SELECT id FROM buses WHERE bus_no = %s", (bus_no,))
        bus = cursor.fetchone()
        if not bus:
            return "Bus not found", 404
        bus_id = bus['id']

        cursor.execute("""
            SELECT available_seats FROM stops
            WHERE bus_id = %s AND stop_name = %s
        """, (bus_id, stop_name))
        stop = cursor.fetchone()
        if not stop:
            return "Stop not found", 404
        if stop['available_seats'] is None or stop['available_seats'] < len(seats):
            return f"Only {stop['available_seats']} seats available", 400

        seat_str = ','.join(map(str, seats))

        checkin_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        cursor.execute("""
            INSERT INTO checkins (name, bus_no, seats, stop_name, checkin_time)
            VALUES (%s, %s, %s, %s, %s)
        """, (name, bus_no, seat_str, stop_name, checkin_time))

        cursor.execute("""
            INSERT INTO bookings (bus_id, stop_name, passenger_name, seats, seat_count)
            VALUES (%s, %s, %s, %s, %s)
        """, (bus_id, stop_name, name, seat_str, len(seats)))

        cursor.execute("""
            UPDATE stops SET available_seats = available_seats - %s
            WHERE bus_id = %s AND stop_name = %s
        """, (len(seats), bus_id, stop_name))

        db.commit()

        # Generate QR code
        qr_data = f"Name: {name}\nBus No: {bus_no}\nStop: {stop_name}\nCheck-in Time: {checkin_time}"
        qr = qrcode.make(qr_data)
        buffered = io.BytesIO()
        qr.save(buffered, format="PNG")
        qr_img_base64 = base64.b64encode(buffered.getvalue()).decode()

        # Show QR on success page
        return render_template('student_success.html', qr_img=qr_img_base64, name=name, bus_no=bus_no, stop=stop_name, time=checkin_time)

    except mysql.connector.Error as err:
        print("Database error:", err)
        db.rollback()
        return "Internal server error", 500
@app.route('/student/booking')
def student_booking():
    if 'role' not in session or session['role'] != 'student':
        return redirect(url_for('login'))

    # Load bus & stop data as needed
    cursor.execute("SELECT * FROM buses")
    buses = cursor.fetchall()

    cursor.execute("SELECT DISTINCT stop_name FROM stops")
    stops = cursor.fetchall()

    return render_template('student_booking.html', buses=buses, stops=stops)



@app.route('/admin/admin', methods=['GET', 'POST'])
def admin_admin():
    if 'role' not in session or session['role'] != 'admin':
        return redirect(url_for('login'))

    if request.method == 'POST':
        action = request.form.get('action')

        if action == 'add_bus':
            bus_no = request.form['bus_no']
            route = request.form['route']
            seats = request.form['seats']
            departure_time = request.form['departure_time']
            cursor.execute(
                "INSERT INTO buses (bus_no, route, total_seats, departure_time) VALUES (%s, %s, %s, %s)",
                (bus_no, route, seats, departure_time)
            )
            db.commit()
            return redirect(url_for('admin_admin') + '#buses')

        elif action == 'reply_query':
            query_id = request.form['query_id']
            reply = request.form['reply']
            cursor.execute(
                "UPDATE queries SET reply = %s WHERE id = %s",
                (reply, query_id)
            )
            db.commit()
            return redirect(url_for('admin_admin') + '#queries')

    cursor.execute("SELECT * FROM buses")
    buses = cursor.fetchall()

    cursor.execute("SELECT * FROM queries ORDER BY submitted_at DESC")
    queries = cursor.fetchall()

    return render_template('admin_admin.html', buses=buses, queries=queries)






@app.route('/student/liveupdates')
def student_liveupdates():
    cursor.execute("SELECT * FROM buses")
    buses = cursor.fetchall()
    updates = []
    for bus in buses:
        cursor.execute("SELECT stop_name, COUNT(*) as booked FROM attendance WHERE bus_no=%s GROUP BY stop_name", (bus['bus_no'],))
        stop_data = cursor.fetchall()
        stops = []
        for stop in stop_data:
            available = bus['total_seats'] - stop['booked']
            stops.append({"stop_name": stop['stop_name'], "booked": stop['booked'], "available": available})

        updates.append({"bus_no": bus['bus_no'], "route": bus['route'], "departure_time": bus['departure_time'], "stops": stops})

    return render_template('student_liveupdate.html', updates=updates)




# ------------------ Upload & Decode QR -------------------
@app.route('/upload_qr_attendance', methods=['POST'])
def upload_qr_attendance():
    if 'qr_image' not in request.files:
        flash("No file uploaded", "danger")
        return redirect(url_for('student_attendance'))

    file = request.files['qr_image']
    if file.filename == '':
        flash("No selected file", "warning")
        return redirect(url_for('student_attendance'))

    filepath = os.path.join('static', 'temp_qr.png')
    file.save(filepath)

    data = decode_qr_opencv(filepath)
    if not data:
        flash("Invalid QR code or unreadable image.", "danger")
        return redirect(url_for('student_attendance'))

    try:
        lines = data.strip().split("\n")
        qr_data = {}
        for line in lines:
            if ":" in line:
                key, value = line.split(":", 1)
                qr_data[key.strip().lower()] = value.strip()

        name = qr_data.get("name")
        bus_no = qr_data.get("bus no")
        stop_name = qr_data.get("stop")
        checkin_time_str = qr_data.get("check-in time")

        if not all([name, bus_no, stop_name, checkin_time_str]):
            flash("Missing required data in QR code.", "danger")
            return redirect(url_for('student_attendance'))

        checkin_time = datetime.strptime(checkin_time_str, "%Y-%m-%d %H:%M:%S")

        cur = db.cursor(dictionary=True)

        # Check if attendance already marked today
        check_query = """
            SELECT * FROM attendance 
            WHERE name = %s AND bus_no = %s AND stop_name = %s 
            AND DATE(checkin_time) = CURDATE()
        """
        cur.execute(check_query, (name, bus_no, stop_name))
        existing = cur.fetchone()

        if existing:
            flash("✅ Attendance already marked for today.", "info")
            cur.close()
            return redirect(url_for('student_attendance'))

        insert_query = """
            INSERT INTO attendance (name, bus_no, stop_name, checkin_time)
            VALUES (%s, %s, %s, %s)
        """
        cur.execute(insert_query, (name, bus_no, stop_name, checkin_time))
        db.commit()
        cur.close()

        flash("🎉 Attendance marked successfully!", "success")
    except Exception as e:
        print("Error:", e)
        flash("Something went wrong. Please try again.", "danger")

    return redirect(url_for('student_attendance'))




def decode_qr_opencv(image_path):
    image = cv2.imread(image_path)
    qr_detector = cv2.QRCodeDetector()
    data, points, _ = qr_detector.detectAndDecode(image)
    return data




@app.route('/delete_selected_attendance', methods=['POST'])
def delete_selected_attendance():
    try:
        # Get selected attendance IDs from the form
        selected_ids = request.form.getlist('attendance_ids')

        if not selected_ids:
            return "No records selected for deletion.", 400

        # Convert all IDs to integers (optional but safer)
        selected_ids = [int(id) for id in selected_ids]

        # Prepare SQL DELETE query
        format_strings = ','.join(['%s'] * len(selected_ids))
        query = f"DELETE FROM attendance WHERE id IN ({format_strings})"
        cursor.execute(query, tuple(selected_ids))
        db.commit()

        return redirect('/student/attendance')

    except Exception as e:
        print("Error deleting attendance:", e)
        return f"Error deleting records: {str(e)}", 500



 
# Route to display attendance records
@app.route('/student/attendance')
def student_attendance():
    # Create a new cursor (dictionary=True to get dict rows)
    cur = db.cursor(dictionary=True)
    cur.execute("SELECT id, name, bus_no, stop_name, checkin_time FROM attendance ORDER BY checkin_time DESC")
    rows = cur.fetchall()
    cur.close()  # Closing this cursor is fine since it's local

    attendance_data = []
    for row in rows:
        attendance_data.append({
            'id': row['id'],
            'name': row['name'],
            'bus_no': row['bus_no'],
            'stop_name': row['stop_name'],
            'checkin_time': row['checkin_time'].strftime('%Y-%m-%d %H:%M:%S')
        })

    return render_template('student_attendance.html', attendance=attendance_data)




@app.route('/student/query', methods=['GET', 'POST'])
def student_query():
    if request.method == 'POST':
        action = request.form.get('action')

        if action == 'reset':
            cursor.execute("DELETE FROM queries")
            db.commit()
            return redirect('student/query')
        else:
            name = request.form['name']
            email = request.form['email']
            message = request.form['message']
            cursor.execute(
                "INSERT INTO queries (name, email, message, submitted_at) VALUES (%s, %s, %s, %s)",
                (name, email, message, datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
            )
            db.commit()
            return redirect('/student/query')

    cursor.execute("SELECT * FROM queries ORDER BY submitted_at DESC")
    queries = cursor.fetchall()
    return render_template('student_query.html', queries=queries)

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

if __name__ == '__main__':
    app.run(debug=True)





