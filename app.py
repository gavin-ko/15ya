from os import terminal_size
from flask.wrappers import Response
from pymongo import MongoClient
import jwt
import datetime
import hashlib
from flask import Flask, render_template, jsonify, request, redirect, url_for
from werkzeug.utils import secure_filename
from datetime import datetime, timedelta
import re
from uuid import uuid4


app = Flask(__name__)

SECRET_KEY = '15ya'

client = MongoClient('localhost', 27017)
# client = MongoClient('127.0.0.1', 27017, username="아이디", password="비밀번호")
db = client.db15ya


# 토큰 유효성 검사
def valid_token():
    token_receive = request.cookies.get('15ya_token')

    try:
        payload = jwt.decode(token_receive, SECRET_KEY, algorithms=['HS256'])
    except jwt.ExpiredSignatureError:
        return "로그인 시간이 만료되었습니다."
    except jwt.exceptions.DecodeError:
        return "로그인 정보가 존재하지 않습니다."
    else:
        return [True, payload['id']]


# 메인화면


@app.route('/')
def home():
    valid = valid_token()
    if valid[0] == True:
        return render_template('index.html')
    else:
        return redirect(url_for("login", msg=valid))

# 로그인


@ app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'GET':
        # 로그인상태로 접근 시
        valid = valid_token()
        if valid[0] == True:
            return redirect(url_for('home'))
        # 로그인화면 이동
        else:
            return render_template('login.html', msg=valid)
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

# 이메일 중복체크


def email_check(email):
    return bool(db.users.find_one({'email': email}))

# 회원가입


@ app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'GET':
        # 로그인 상태로 접근시
        valid = valid_token()
        if valid[0] == True:
            return redirect(url_for('home'))
        # 회원가입 화면 이동
        else:
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
            'password': password_hash,
            'profile_image': '../static/profile/default.jpeg',
            'posting': 0,
            'follower': 0,
            'follow': 0,
            'status_message': '',
            'bookmark': [],
        }
        db.users.insert_one(doc)
        return jsonify({'result': 'success'})

# 피드업로드


@ app.route('/api/feed_upload', methods=['GET', 'POST'])
def feed_upload():
    valid = valid_token()
    if request.method == 'GET':
        # 로그인 상태로 접근시
        if valid[0] == True:
            feeds = list(db.feeds.find())
            return render_template('feed.html', feeds=feeds)
        else:
            return redirect(url_for('home'))
    else:
        email = valid[1]
        file = request.files['file']
        file_name = str(uuid4().hex)
        id = db.users.find_one({'email': email})
        author = id['nickname']
        profile_image = id['profile_image']

        file.save('./static/media/' + secure_filename(file_name))
        image = f'../static/media/'+file_name
        content = request.form.get('content')
        latest_index = (db.feeds.find_one(
            {"$query": {}, "$orderby": {"index": -1}}))
        try:
            index = latest_index['index']
        except TypeError:
            index = 0
        doc = {
            'index': 1+index,
            'image': image,
            'content': content,
            'author': author,
            'profile_image': profile_image,
            'like': 0,
            'email': email
        }

        db.feeds.insert_one(doc)

        return jsonify({'result': 'success', 'msg': '업로드완료'})

# 피드 삭제


@app.route('/api/feed_delete', methods=['POST'])
def feed_delete():
    valid = valid_token()
    if valid[0] == True:
        email = valid[1]
        index_receive = int(request.form['index_give'])
        result = db.feeds.find_one({'email': email, 'index': index_receive})
        if result is not None:
            db.feeds.delete_one({'email': email, 'index': index_receive})
            return jsonify({'result': 'success', 'msg': '삭제완료!'})
        else:
            return jsonify({'result': 'failed', 'msg': '작성자만 삭제가 가능합니다.'})
    else:
        return redirect(url_for('home'))


if __name__ == '__main__':
    app.run('0.0.0.0', port=5000, debug=True)
