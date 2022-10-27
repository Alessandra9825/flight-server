from flask import Flask
from flaskext.mysql import MySQL
from flask import Flask, request, render_template, jsonify, redirect, url_for, session, flash, g
from werkzeug.security import check_password_hash, generate_password_hash
from waitress import serve
import functools
import boto3
import base64
from botocore.exceptions import ClientError


def get_secret():
    secret = ""
    secret_name = "Masterdb0012"
    region_name = "us-east-1"

    # Create a Secrets Manager client
    session = boto3.session.Session()
    client = session.client(
        service_name='secretsmanager',
        region_name=region_name
    )

    try:
        get_secret_value_response = client.get_secret_value(
            SecretId=secret_name
        )
    except ClientError as e:
        if e.response['Error']['Code'] == 'DecryptionFailureException':
            # Secrets Manager can't decrypt the protected secret text using the provided KMS key.
            # Deal with the exception here, and/or rethrow at your discretion.
            raise e
        elif e.response['Error']['Code'] == 'InternalServiceErrorException':
            # An error occurred on the server side.
            # Deal with the exception here, and/or rethrow at your discretion.
            raise e
        elif e.response['Error']['Code'] == 'InvalidParameterException':
            # You provided an invalid value for a parameter.
            # Deal with the exception here, and/or rethrow at your discretion.
            raise e
        elif e.response['Error']['Code'] == 'InvalidRequestException':
            # You provided a parameter value that is not valid for the current state of the resource.
            # Deal with the exception here, and/or rethrow at your discretion.
            raise e
        elif e.response['Error']['Code'] == 'ResourceNotFoundException':
            # We can't find the resource that you asked for.
            # Deal with the exception here, and/or rethrow at your discretion.
            raise e
    else:
        if 'SecretString' in get_secret_value_response:
            secret = get_secret_value_response['SecretString']
        else:
            decoded_binary_secret = base64.b64decode(
                get_secret_value_response['SecretBinary'])
        return secret


secretText = ((get_secret().replace("\r\n", "")).replace("  ", "")).strip()
password = (secretText.split(',')[1]).split(':')[1].strip().replace('"', "")
host = (secretText.split(',')[2]).split(':')[1].replace("}", "").strip()

mysql = MySQL()
app = Flask(__name__)
app.config['MYSQL_DATABASE_USER'] = 'root'
app.config['MYSQL_DATABASE_PASSWORD'] = password
app.config['MYSQL_DATABASE_DB'] = 'flight'
app.config['MYSQL_DATABASE_HOST'] = host
app.config.update(SECRET_KEY='dev')
mysql.init_app(app)
conn = mysql.connect()
if conn:
    cursor = conn.cursor()


@app.route("/", methods=['GET', 'POST'])
def home():
    if request.method == 'GET':
        return render_template('home.html')


@app.before_request
def load_logged_in_user():
    uname = session.get('uname')

    if uname is None:
        g.uname = None
    else:
        g.uname = uname


def login_required(view):
    @functools.wraps(view)
    def wrapped_view(**kwargs):
        if g.uname is None:
            return redirect(url_for('login'))

        return view(**kwargs)

    return wrapped_view


@app.route("/login",  methods=['GET', 'POST'])
def login():
    error = None
    if request.args.get('user_reg'):
        flash('User successfully created!')
    if request.method == 'POST':
        # if (request.form['input_uname'] != 'admin') or (request.form['input_passwd'] != 'admin'):
        #     error = 'Invalid Credentials. Please try again.'
        #     return render_template('login.html', error = error)
        username = str(request.form['input_uname'])
        password = str(request.form['input_passwd'])

        cursor.execute(
            "SELECT * FROM users WHERE uname = '{}'".format(username)
        )
        user = cursor.fetchone()

        if user is None:
            error = "Incorrect Username!"
        elif not check_password_hash(user[1], password):
            error = "Incorrect Password!"

        if error is None:
            session.clear()
            session['pno'] = user[2]
            session['uname'] = user[0]
            return redirect(url_for('bookticket'))

        flash(error)

    return render_template('login.html', error=error)


@app.route("/signup", methods=['GET', 'POST'])
def signup():
    error = None
    if request.method == 'POST':
        _pno = request.form['input_pno']
        _fname = request.form['input_fname']
        _lname = request.form['input_lname']
        _dob = request.form['input_dob']
        _address = request.form['input_address']
        _phone = request.form['input_phone']
        _uname = request.form['input_uname']
        _passwd = request.form['input_password']
        _conf_pass = request.form['conf_password']

        cursor.execute(
            "SELECT * FROM users WHERE users.uname = '{}' or users.pno = '{}' or users.phone_no = '{}'".format(
                _uname, _pno, _phone)
        )
        if cursor.fetchone() is not None:
            error = 'User is already registered'

        if _passwd != _conf_pass:
            error = 'Password and Confirm password fields do not match'

        if error is None:
            cursor.execute(
                "INSERT INTO users VALUES ('{}', '{}', '{}', '{}', '{}', '{}', '{}', '{}')".format(
                    _uname,
                    generate_password_hash(_passwd),
                    _pno,
                    _fname,
                    _lname,
                    _dob,
                    _phone,
                    _address
                )
            )
            res = cursor.fetchall()
            conn.commit()
            return redirect(url_for('login', user_reg=True))

        flash(error)
    return render_template('signup.html', error=error)


@app.route("/logout", methods=['GET'])
def logout():
    session.clear()
    return redirect(url_for('login'))


@app.route("/bookticket", methods=['GET', 'POST'])
@login_required
def bookticket():
    if request.method == 'GET':
        return render_template('app.html')
    else:
        if request.form['submit_button'] == 'select_srcdest':
            _src = request.form['inputsrc']
            _dst = request.form['inputdest']
            cursor.execute(
                "SELECT DISTINCT a1.location_code, a2.location_code FROM airport a1, airport a2 WHERE a1.city = '{}' and a2.city = '{}'".format(
                    _src, _dst)
            )
            airports = cursor.fetchone()
            cursor.execute(
                """SELECT flight.*, airline_name FROM flight, airline
                   WHERE source = '{}' and destination = '{}' AND
                   airline_id = (
                       SELECT DISTINCT flightScheduledForAirline.airline_id from flightScheduledForAirline
                       WHERE flightScheduledForAirline.airline_id = airline.airline_id AND
                       flight.flight_id = flightScheduledForAirline.flight_id
                   ) AND flight_id NOT IN (
                       SELECT ticket.flight_id from ticket
                       WHERE ticket.uname = '{}'
                    )""".format(_src, _dst, session['uname'])
            )
            flights = cursor.fetchall()

            if flights:
                return render_template('app.html', flights=flights, airports=airports)
            else:
                error = 'No flights available'
                flash(error)
                return render_template('app.html', src_dest=(_src, _dst), error=error)
        else:
            fno = request.form['submit_button']
            return redirect(url_for('payment', flight=fno))


@app.route("/profile", methods=['GET', 'POST'])
@login_required
def profile():
    if request.method == 'GET':
        cursor.execute(
            "SELECT * FROM users WHERE uname = '{}'".format(session['uname']))
        res = cursor.fetchall()
        cursor.execute(
            """SELECT * FROM ticket 
               JOIN flight ON ticket.flight_id = flight.flight_id
                WHERE uname = '{}'""".format(session['uname'])
        )
        tkts = cursor.fetchall()
        return render_template('users_view.html', result=res, tickets=tkts)
    else:
        if request.form['submit_button'] == 'update':
            return redirect(url_for('update'))
        else:
            tno = request.form['submit_button']
            cursor.execute(
                "SELECT * FROM users WHERE uname = '{}'".format(session['uname']))
            res = cursor.fetchall()
            cursor.execute(
                """DELETE FROM ticket
                   WHERE ticket_id = '{}'""".format(tno)
            )
            conn.commit()
            cursor.execute(
                """SELECT * FROM ticket 
               JOIN flight ON ticket.flight_id = flight.flight_id
                WHERE uname = '{}'""".format(session['uname'])
            )
            tkts = cursor.fetchall()
            return render_template('users_view.html', result=res, tickets=tkts)


@app.route("/update", methods=['GET', 'POST'])
@login_required
def update():
    # error = None
    if request.method == 'POST':
        _pno = request.form['input_pno']
        _fname = request.form['input_fname']
        _lname = request.form['input_lname']
        _dob = request.form['input_dob']
        _address = request.form['input_address']
        _phone = request.form['input_phone']
        # _uname = request.form['input_uname'] if not None
        _passwd = request.form['input_password']

        # if error is None:
        if request.form.get('input_pno', None):
            cursor.execute(
                "UPDATE users SET pno='{}' where users.uname = '{}'".format(
                    _pno,
                    session['uname'],
                )
            )
        if request.form.get('input_fname', None):
            cursor.execute(
                "UPDATE users SET first_name='{}' where users.uname = '{}'".format(
                    _fname,
                    session['uname'],
                )
            )
        if request.form.get('input_lname', None):
            cursor.execute(
                "UPDATE users SET last_name='{}' where users.uname = '{}'".format(
                    _lname,
                    session['uname'],
                )
            )
        if request.form.get('input_dob', None):
            cursor.execute(
                "UPDATE users SET DOB='{}' where users.uname = '{}'".format(
                    _dob,
                    session['uname'],
                )
            )
        if request.form.get('input_address', None):
            cursor.execute(
                "UPDATE users SET address='{}' where users.uname = '{}'".format(
                    _address,
                    session['uname'],
                )
            )
        if request.form.get('input_phone', None):
            cursor.execute(
                "UPDATE users SET phone_no='{}' where users.uname = '{}'".format(
                    _phone,
                    session['uname'],
                )
            )
        if request.form.get('input_password', None):
            cursor.execute(
                "UPDATE users SET passwd='{}' where users.uname = '{}'".format(
                    generate_password_hash(_passwd),
                    session['uname'],
                )
            )
        res = cursor.fetchall()
        conn.commit()
        return redirect(url_for('profile'))

        # flash(error)
    return render_template('update.html')


@app.route("/payment", methods=['GET', 'POST'])
@login_required
def payment():
    if request.method == 'GET' and not request.args.get('flight'):
        return redirect(url_for('bookticket'))
    elif request.args['flight']:
        flight_no = request.args['flight']
        username = session['uname']
        cursor.execute(
            "SELECT COUNT(*) FROM ticket WHERE flight_id = '{}'".format(flight_no)
        )
        count = int(cursor.fetchone()[0])
        ticket_id = str(flight_no) + str(count + 2)
        price = 100
        status = 'Booked'

        cursor.execute(
            "INSERT INTO ticket VALUES ('{}', '{}', '{}', '{}', '{}')".format(
                ticket_id,
                username,
                flight_no,
                status,
                price
            )
        )
        ins = cursor.fetchall()
        conn.commit()

        cursor.execute(
            "INSERT INTO booking VALUES ('{}', '{}')".format(
                ticket_id, flight_no)
        )
        ins = cursor.fetchall()
        conn.commit()

        # cursor.execute(
        #     """UPDATE TABLE flight SET count_ticket = count_ticket - 1 WHERE
        #      flight_id = '{}'""".format(flight_no)
        # )
        # update = cursor.fetchall()
        # conn.commit()

        cursor.execute(
            "INSERT INTO userMakesPayment VALUES ('{}', '{}')".format(
                username, ticket_id)
        )
        ins = cursor.fetchall()
        conn.commit()

        cursor.execute(
            """SELECT ticket_id, booking.flight_id, source, destination, first_name, last_name
                FROM booking, flight, users WHERE 
                ticket_id = '{}' AND
                booking.flight_id = flight.flight_id AND 
                users.uname = '{}'""".format(ticket_id, session['uname'])
        )
        payment = cursor.fetchone()
        return render_template('payment.html', payment=payment)


@app.route("/print", methods=['GET', 'POST'])
@login_required
def print():
    if request.method == 'GET':
        # payment = request.args['payment']
        return render_template('print.html', payment=payment)


if __name__ == "__main__":
    serve(app, host="0.0.0.0", port=8080)


def create_app():
    return app
