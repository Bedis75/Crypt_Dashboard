from flask import Flask, render_template, redirect, request, url_for, jsonify, session, flash
import mysql.connector

app = Flask(__name__)
app.secret_key = 'your_secret_key'

def get_db_connection():
    conn = mysql.connector.connect(
        host='localhost',
        user='root',
        password='',
        database='secsoa'
    )
    return conn

def prepare(PhraseEnClair):
    li1 = ["âà", "éèêë", "îï", "ô", "ûü", "ç"]
    li2 = ["A", "E", "I", "O", "U", "C"]
    for i in range(len(li1)):
        for char in li1[i]:
            PhraseEnClair = PhraseEnClair.replace(char, li2[i])
    return PhraseEnClair.upper()

def affine(text, a, b):
    encrypted_text = []
    for char in text:
        if char.isalpha():
            shift = 65 if char.isupper() else 97
            encrypted_text.append(chr((a * (ord(char) - shift) + b) % 26 + shift))
        else:
            encrypted_text.append(char)
    return ''.join(encrypted_text)

def affine_decrypt(text, a, b):
    a_inv = pow(a, -1, 26) 
    decrypted_text = []
    for char in text:
        if char.isalpha():
            shift = 65 if char.isupper() else 97
            decrypted_text.append(chr(a_inv * (ord(char) - shift - b) % 26 + shift))
        else:
            decrypted_text.append(char) 
    return ''.join(decrypted_text)


def caesar_encrypt(text, shift):
    encrypted_text = []
    for char in text:
        if char.isalpha(): 
            shift_base = 65 if char.isupper() else 97
            encrypted_char = chr((ord(char) - shift_base + shift) % 26 + shift_base)
            encrypted_text.append(encrypted_char)
        else:
            encrypted_text.append(char) 
    return ''.join(encrypted_text)


def caesar_decrypt(text, shift):
    return caesar_encrypt(text, -shift)


def vigenere_encrypt(text, keyword):
    encrypted_text = []
    keyword = keyword.lower()
    keyword_index = 0

    for char in text:
        if char.isalpha():
            shift = ord(keyword[keyword_index % len(keyword)]) - 97
            shift_base = 65 if char.isupper() else 97
            encrypted_text.append(chr((ord(char) - shift_base + shift) % 26 + shift_base))
            keyword_index += 1
        else:
            encrypted_text.append(char)

    return ''.join(encrypted_text)

def vigenere_decrypt(text, keyword):
    decrypted_text = []
    keyword = keyword.lower()
    keyword_index = 0

    for char in text:
        if char.isalpha():
            shift = ord(keyword[keyword_index % len(keyword)]) - 97
            shift_base = 65 if char.isupper() else 97
            decrypted_text.append(chr((ord(char) - shift_base - shift) % 26 + shift_base))
            keyword_index += 1
        else:
            decrypted_text.append(char)

    return ''.join(decrypted_text)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login', methods=['POST'])
def login():
    email_attempt = request.form.get('email')
    password_attempt = request.form.get('password')

    a = 5
    b = 8

    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT * FROM users WHERE email = %s", (affine(prepare(email_attempt), a, b),))
        user = cursor.fetchone()
        conn.close()

        if user:
            decrypted_password = affine_decrypt(user['password'], a, b)
            if decrypted_password == prepare(password_attempt):
                flash("Login successful!")
                session['user_id'] = user['id']
                return redirect(url_for('crypto_dashboard'))
            else:
                flash("Invalid credentials. Try again!")
        else:
            flash("User not found.")
    except Exception as e:
        flash(f"An error occurred: {e}")

    return redirect(url_for('index'))

@app.route('/crypto_dashboard')
def crypto_dashboard():
    if 'user_id' not in session:
        return jsonify(success=False, error="Please log in first.")
    
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT id, name FROM users WHERE id = %s", (session['user_id'],))
    user = cursor.fetchone()
    cursor.execute("SELECT id, content, method FROM notes WHERE user_id = %s", (session['user_id'],))
    notes = cursor.fetchall()
    conn.close()

    encrypted_notes = []
    for note in notes:
        encrypted_notes.append({
            'id': note[0],
            'content': note[1],
            'method': note[2]
        })

    return render_template('crypto_dashboard.html', notes=encrypted_notes, user_name=user[1])



@app.route('/add_note', methods=['POST'])
def add_note():
    if 'user_id' not in session:
        return jsonify(success=False, error="Please log in first.")
    
    note_content = request.json.get('note')
    encryption_method = request.json.get('method')
    #les valeurs qu'on peut modifier:
    a = 5
    b = 8
    shift = 3 
    keyword = "KEYWORD"
    encrypted_note = ''

    if encryption_method == 'affine':
        encrypted_note = affine(note_content, a, b)
    elif encryption_method == 'caesar':
        encrypted_note = caesar_encrypt(note_content, shift)
    elif encryption_method == 'vigenere':
        encrypted_note = vigenere_encrypt(note_content, keyword)

    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("INSERT INTO notes (content, method, user_id) VALUES (%s, %s, %s)", 
                       (encrypted_note, encryption_method, session['user_id']))
        conn.commit()
        conn.close()
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT id, content, method FROM notes WHERE user_id = %s", (session['user_id'],))
        notes = cursor.fetchall()
        conn.close()

        encrypted_notes = []
        for note in notes:
            encrypted_notes.append({
                'id': note[0],
                'content': note[1],
                'method': note[2]
            })

        return jsonify(success=True, notes=encrypted_notes)

    except Exception as e:
        return jsonify(success=False, error=str(e))


@app.route('/edit_note/<int:note_id>', methods=['PUT'])
def edit_note(note_id):
    if 'user_id' not in session:
        return jsonify(success=False, error="Please log in first.")
    
    new_note_content = request.json.get('note')
    encryption_method = request.json.get('method')
    #les valeurs q'on peut modifier
    a = 5
    b = 8
    shift = 3
    keyword = "KEYWORD" 
    encrypted_note = ''

    if encryption_method == 'affine':
        encrypted_note = affine(new_note_content, a, b)
    elif encryption_method == 'caesar':
        encrypted_note = caesar_encrypt(new_note_content, shift)
    elif encryption_method == 'vigenere':
        encrypted_note = vigenere_encrypt(new_note_content, keyword)

    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("UPDATE notes SET content = %s, method = %s WHERE id = %s AND user_id = %s", 
                       (encrypted_note, encryption_method, note_id, session['user_id']))
        conn.commit()
        conn.close()

        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT id, content, method FROM notes WHERE user_id = %s", (session['user_id'],))
        notes = cursor.fetchall()
        conn.close()

        encrypted_notes = []
        for note in notes:
            encrypted_notes.append({
                'id': note[0],
                'content': note[1], 
                'method': note[2]
            })

        return jsonify(success=True, notes=encrypted_notes)

    except Exception as e:
        return jsonify(success=False, error=str(e))

@app.route('/delete_note/<int:note_id>', methods=['DELETE'])
def delete_note(note_id):
    if 'user_id' not in session:
        return jsonify(success=False, error="Please log in first.")

    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("DELETE FROM notes WHERE id = %s AND user_id = %s", (note_id, session['user_id']))
        conn.commit()
        conn.close()

        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT id, content, method FROM notes WHERE user_id = %s", (session['user_id'],))
        notes = cursor.fetchall()
        conn.close()

        encrypted_notes = []
        for note in notes:
            encrypted_notes.append({
                'id': note[0],
                'content': note[1],
                'method': note[2]
            })

        return jsonify(success=True, notes=encrypted_notes)

    except Exception as e:
        return jsonify(success=False, error=str(e))

@app.route('/decrypt_note/<int:note_id>', methods=['GET'])
def decrypt_note(note_id):
    if 'user_id' not in session:
        return jsonify(success=False, error="Please log in first.")

    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT content, method FROM notes WHERE id = %s AND user_id = %s", (note_id, session['user_id']))
        note = cursor.fetchone()
        conn.close()
        #les valeurs qu'on peut modifier
        if note:
            method = note[1]
            encrypted_content = note[0]
            a = 5
            b = 8
            shift = 3  
            keyword = "KEYWORD"

            if method == 'affine':
                decrypted_content = affine_decrypt(encrypted_content, a, b)
            elif method == 'caesar':
                decrypted_content = caesar_decrypt(encrypted_content, shift)
            elif method == 'vigenere':
                decrypted_content = vigenere_decrypt(encrypted_content, keyword)

            return jsonify(success=True, decrypted_note=decrypted_content)
        else:
            return jsonify(success=False, error="Note not found.")

    except Exception as e:
        return jsonify(success=False, error=str(e))

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        name = request.form.get('name')
        email = request.form.get('email')
        password = request.form.get('password')

        a = 5
        b = 8

        prepared_password = prepare(password)
        encrypted_password = affine(prepared_password, a, b)
        encrypted_email = affine(prepare(email), a, b)

        try:
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute("INSERT INTO users (name, email, password) VALUES (%s, %s, %s)",
                           (name, encrypted_email, encrypted_password))
            conn.commit()
            conn.close()
            flash("Account created successfully!")
            return redirect(url_for('index'))
        except Exception as e:
            flash(f"Error: {e}")
            return redirect(url_for('signup'))

    return render_template('signup.html')

if __name__ == '__main__':
    app.run(debug=True)
