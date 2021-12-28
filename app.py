from pymongo import MongoClient
import jwt
import datetime
import hashlib
from flask import Flask, render_template, jsonify, request, redirect, url_for
from werkzeug.utils import secure_filename
from datetime import datetime, timedelta
import re


app = Flask(__name__)
app.config["TEMPLATES_AUTO_RELOAD"] = True
app.config['UPLOAD_FOLDER'] = "./static/profile"

SECRET_KEY = '15ya'

client = MongoClient('localhost', 27017)
# client = MongoClient('127.0.0.1', 27017, username="아이디", password="비밀번호")
db = client.db15ya


@app.route('/')
def home():
    token_receive = request.cookies.get('15ya_token')

    try:
        payload = jwt.decode(token_receive, SECRET_KEY, algorithms=['HS256'])
        print(payload)

        return render_template('index.html')
    except jwt.ExpiredSignatureError:
        return redirect(url_for("login", msg="로그인 시간이 만료되었습니다."))
    except jwt.exceptions.DecodeError:
        return redirect(url_for("login", msg="로그인 정보가 존재하지 않습니다."))


def valid_token():
    token_receive = request.cookies.get('15ya_token')
    # try:
    payload = jwt.decode(token_receive, SECRET_KEY, algorithms=['HS256'])
    print(payload)
    # user_info = db.users.find_one({'id'})


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'GET':
        # 로그인화면 이동
        msg = request.args.get("msg")
        return render_template('login.html', msg=msg)
    else:
        # 로그인 기능
        email_receive = request.form['email_give']
        password_receive = request.form['password_give']

        password_hash = hashlib.sha256(
            password_receive.encode('utf-8')).hexdigest()
        target = db.users.find_one(
            {'email': email_receive, 'password': password_hash})

    if target is not None:
        payload = {
            'id': email_receive,
            'exp': datetime.utcnow() + timedelta(seconds=60 * 60 * 24)  # 로그인 24시간 유지
        }
        token = jwt.encode(payload, SECRET_KEY, algorithm='HS256')
        return jsonify({'result': 'success', 'token': token})
    else:
        return jsonify({'result': 'failed', 'msg': '아이디 또는 비밀번호가 일치하지 않습니다.'})


def email_check(email):
    return bool(db.users.find_one({'email': email}))


@app.route('/register', methods=['GET', 'POST'])
def sign_up():
    if request.method == 'GET':
        # 회원가입 화면 이동
        return render_template('register.html')
    else:
        # 회원가입 기능
        email_receive = request.form['email_give']
        name_receive = request.form['name_give']
        nickname_receive = request.form['nickname_give']
        password_receive = request.form['password_give']
        # 비밀번호 암호화
        password_hash = hashlib.sha256(
            password_receive.encode('utf-8')).hexdigest()
        # 이메일 유효성 검사
        if (re.search('[^a-zA-Z0-9-_.@]+', email_receive) is not None
                or not (9 < len(email_receive) < 26)):
            return jsonify({'result': 'failed', 'msg': '휴대폰번호 또는 이메일의 형식을 확인해주세요. 영문과, 숫자, 일부 특수문자(.-_) 사용 가능. 10~25자 길이'})
        # 비밀번호 유효성 검사
        elif (re.search('[^a-zA-Z0-9!@#$%^&*]+', password_receive) is not None or
                not(7 < len(password_receive) < 21) or
                re.search('[0-9]+', password_receive) is None or
                re.search('[a-zA-Z]+', password_receive) is None):
            return jsonify({'result': 'failed', 'msg': '비밀번호의 형식을 확인해주세요. 영문과 숫자 필수 포함, 일부 특수문자(!@#$%^&*) 사용 가능. 8~20자 길이'})
        # 빈칸 검사
        elif not(email_receive and name_receive and nickname_receive and password_hash):
            return jsonify({'result': 'failed', 'msg': '빈칸을 입력해주세요.'})
        # 중복 이메일 검사
        elif email_check(email_receive):
            return jsonify({'result': 'failed', 'msg': '가입된 내역이 있습니다.'})

        doc = {
            'email': email_receive,
            'name': name_receive,
            'nickname': nickname_receive,
            'password': password_hash
        }
        db.users.insert_one(doc)
        return jsonify({'result': 'success'})


if __name__ == '__main__':
    app.run('0.0.0.0', port=5000, debug=True)
