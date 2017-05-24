# coding=utf-8
# python built-in libs
import os
import time
import base64
import hashlib
import json
import functools

# Helper lib from pip
import timeago

# SQL stuff
import sqlalchemy
from sqlalchemy import Column, String, Integer, Text, Boolean, Float
import sqlalchemy.orm as sqlorm
from  sqlalchemy.ext.declarative import declarative_base
import psycopg2

# Flask
import flask
from flask import Flask, request, render_template
from flask_login import LoginManager
from flask_cors import CORS

# Initialization
app = Flask(__name__)
CORS(app)
loginManager = LoginManager()
loginManager.init_app(app)
Base = declarative_base()
#engine = sqlalchemy.create_engine("postgresql+psycopg2://gaotian:password@localhost:5432/tradeweb", echo=True)
engine = sqlalchemy.create_engine(os.environ.get('DATABASE_URL'), echo=True)
Session = sqlorm.scoped_session(sqlorm.sessionmaker(bind=engine))
# ============================================================================
#                                Classes 
# ============================================================================
# --------------------------------
#     Database Classes
# --------------------------------
class UserDb(Base):
    __tablename__ = 'Users'
    username    = Column(String(50), primary_key=True)
    password    = Column(String(32))
    token       = Column(String(32))
    email       = Column(String(50))
    cell        = Column(String(15))
    expire_time = Column(Integer)
    
class PostDb(Base):
    __tablename__ = "Posts"
    id            = Column(Integer, primary_key=True)
    category      = Column(String(20))
    title         = Column(String(50))
    author        = Column(String(50))
    content       = Column(Text)
    items         = Column(Text)
    availability  = Column(Text)
    add_time      = Column(Integer)
    expire_time   = Column(Integer)
    is_deleted    = Column(Boolean, default=False)

class RequestDb(Base):
    __tablename__ = "Requests"
    id           = Column(Integer, primary_key=True)
    reference    = Column(Integer)
    to_user      = Column(String(50))
    from_user    = Column(String(50))
    from_user_email = Column(String(50))
    from_user_cell = Column(String(15))
    from_user_address = Column(String(100))
    note         = Column(Text)
    order        = Column(Text)
    total_price  = Column(Float)
    status       = Column(String(10))
    add_time     = Column(Integer)
    expire_time  = Column(Integer)


# create_all() needs to be after all database classes
Base.metadata.create_all(bind=engine)

# ============================================================================
#                                 Decoreator
# ============================================================================
def needSession(write = False):
    def decorator(func):
        @functools.wraps(func)
        def wrapper(self, *args, **kwargs):
            if self.session == None:
                self.session = Session()
                createSession = True
            else:
                createSession = False
            res = func(self, *args, **kwargs)
            if write == True:
                self.session.commit()
            if createSession:
                self.session.close()
                self.session = None
            return res
        return wrapper
    return decorator

def require(*required_args, **kw_req_args):
    def decorator(func):
        @functools.wraps(func)
        def wrapper(*args, **kw):
            data = request.get_json()
            if data == None:
                resp = flask.jsonify( msg="No json!")
                resp.status_code = 400
                return resp
            for arg in required_args:
                if arg not in data:
                    resp = flask.jsonify(code=400, msg="wrong args! need "+arg)
                    resp.status_code = 400
                    return resp
            if kw_req_args != None:
                if "login" in kw_req_args:
                    assert('token' in required_args)
                    username = data[kw_req_args["login"]]
                    token = data['token']
                    u = User()
                    if not u.Exist(username, token):
                        resp = flask.jsonify(msg="This action requires login!")
                        resp.status_code = 401
                        return resp
                if "postValid" in kw_req_args:
                    p = Post()
                    if not p.Exist(data[kw_req_args["postValid"]]):
                        resp = flask.jsonify(msg="The reference post is not valid")
                        resp.status.code = 400
                        return resp
                if "reqFrom" in kw_req_args:
                    assert('id' in required_args)
                    r = Request()
                    if not r.ReqFrom(data['id'], data[kw_req_args["reqFrom"]]):
                        resp = flask.jsonify(msg="Request not from "+kw_req_args["reqFrom"])
                        resp.status_code = 400
                        return resp
                if "reqTo" in kw_req_args:
                    assert('id' in required_args)
                    r = Request()
                    if not r.ReqTo(data['id'], data[kw_req_args["reqTo"]]):
                        resp = flask.jsonify(msg="Request not to "+kw_req_args["reqTo"])
                        resp.status_code = 400
                        return resp
            return func(*args, **kw)
        return wrapper
    return decorator

# --------------------------------
#     Flask Classes
# --------------------------------
class User:
    def __init__(self, username = ""):
        self.authenticated = False
        self.username = username
        self.password = ""
        self.token = ""
        self.session = None

    def is_authenticated(self):
        return self.authenticated
    def is_active(self):
        return True
    def isanonymous(self):
        return True
    def get_id(self):
        return self.username

    @needSession(write = True)
    def Register(self, data):
        username = data['username']
        password = data['password']
        email    = data['email']
        #cell     = data['cell']
        if len(username) < 2 or len(username) > 50 or \
                len(password) < 8 or len(password) > 50 or \
                len(email) > 50:
            return 400, {"msg": "Invalid parameter"}
        for c in password:
            try:
                num = ord(c)
                if num < 33 or num > 126:
                    return 400, {"msg":"Invalid password charactor"}
            except:
                return 400, {"msg":"Invalid password charactor"}
        if self.session.query(UserDb).filter(UserDb.username == username).first() == None:
            self.token = base64.urlsafe_b64encode(os.urandom(24))
            self.session.add(UserDb(username=username, 
                    password=hashlib.md5(password).hexdigest(), 
                    email=email,
                    token=self.token))
            return 200, {"msg":"Success", "token":self.token}
        return 400, {"msg":"Username is used"}

    @needSession(write = True)
    def Login(self, username, password):
        ret = False
        q = self.session.query(UserDb).filter(UserDb.username == username, UserDb.password == hashlib.md5(password).hexdigest())
        if q.first() != None:
            self.token = base64.urlsafe_b64encode(os.urandom(24))
            q.update({UserDb.token:self.token, UserDb.expire_time:time.time()+600})
            self.username = username
            self.authenticated = True
            ret = True
        return ret
    
    @needSession(write = True)
    def Logoff(self, username, token):
        ret = False
        q = self.session.query(UserDb).filter(UserDb.username == username, UserDb.token == token)
        if q.first() != None:
            q.update({UserDb.token:"", UserDb.expire_time:0})
            self.username = username
            self.authenticated = False
            ret = True
        return ret
    
    @needSession(write = False)
    def Exist(self, username, token = None):
        ret = False
        if token != None:
            q = self.session.query(UserDb).filter(UserDb.username == username, UserDb.token == token)
        else:
            q = self.session.query(UserDb).filter(UserDb.username == username)
        if q.first() != None:
            ret = True
        return ret

    @needSession(write = False)
    def GetInfo(self, username, mine):
        if mine == True:
            q = self.session.query(UserDb).filter(UserDb.username == username)
            result = q.first()
            if result != None:
                d = result.__dict__
                return 200, {'email': d['email'], 'cell': d['cell']}
            else:
                return 400, {'msg': 'No such user!'}
        else:
            return 501, {'msg':'Not implemented yet!'}


class Post:
    def __init__(self):
        self.session = None

    @needSession(write = True)
    def Submit(self, data):
        u = User()
        if u.Exist(data['author'], data['token']):
            self.session.add(PostDb(category = data['category'], title=data['title'], author=data['author'], 
                    content=data['content'], items=json.dumps(data['items']), availability=json.dumps(data['availability']), add_time=time.time(), expire_time=data['expire_time']))
            return True
        return False
    
    @needSession(write = False)
    def Get(self, data, mine = False):
        ret = []
        if mine:
            result = self.session.query(PostDb).filter(PostDb.author == data['username']).order_by(PostDb.add_time.desc()).slice(int(data['start']), int(data['end']))
        else:
            result = self.session.query(PostDb).filter(PostDb.category == data['category'], PostDb.is_deleted != True).order_by(PostDb.add_time.desc()).slice(int(data['start']), int(data['end']))
        for row in result:
            d = row.__dict__
            temp = {}
            temp['id'] = d['id']
            temp['title'] = d['title']
            temp['author'] = d['author']
            temp['content'] = d['content']
            temp['items'] = json.loads(d['items'])
            temp['availability'] = json.loads(d['availability'])
            temp['is_deleted'] = d['is_deleted']
            temp['timeago'] = timeago.format(int(d['add_time']), locale='zh_CN')
            ret.append(temp)
        return ret

    @needSession(write = False)
    def GetByRef(self, postid):
        result = self.session.query(PostDb).filter(PostDb.id == postid).first()
        if result != None:
            return result.__dict__
        return {}

    @needSession(write = True)
    def UpdateItem(self, postid, order):
        q = self.session.query(PostDb).filter(PostDb.id == postid)
        result = q.first()
        if result != None:
            avai = json.loads(result.__dict__['availability'])
            for key in order:
                if key in avai:
                    avai[key] = int(avai[key]) - int(order[key][1])
                    if avai[key] < 0: 
                        return False
            print json.dumps(avai)
            q.update({PostDb.availability: json.dumps(avai)})
            return True
        return False

    @needSession(write = True)
    def Delete(self, data):
        u = User()
        author = data["username"]
        token  = data["token"]
        postid = data["postid"]
        q = self.session.query(PostDb).filter(PostDb.id == postid, 
                PostDb.author == author, 
                PostDb.is_deleted != True)
        if q.first() != None:
            q.update({PostDb.is_deleted : True})
            return True
        return False
    
    @needSession(write = False)
    def Exist(self, id):
        q = self.session.query(PostDb).filter(PostDb.id == id)
        if q.first() != None:
            return True
        return False

class Request:
    def __init__(self):
        self.session = None

    @needSession(write = True)
    def Submit(self, data):
        self.session.add(RequestDb(
                reference = data['reference'],
                to_user = data['to_user'], 
                from_user = data['from_user'], 
                from_user_email = data['from_user_email'],
                from_user_cell = data['from_user_cell'],
                from_user_address = data['from_user_address'],
                note = data['note'],
                order = json.dumps(data['order']), 
                total_price = data['total_price'], 
                status = 'ready',
                add_time = time.time(),
                expire_time = time.time() + 600))
        return True

    @needSession(write = False)
    def Get(self, data):
        ret = []
        if data['direction'] == 'toMe':
            result = self.session.query(RequestDb).filter(RequestDb.to_user == data['username']).order_by(RequestDb.add_time.desc()).slice(int(data['start']), int(data['end']))
        elif data['direction'] == 'fromMe':
            result = self.session.query(RequestDb).filter(RequestDb.from_user == data['username']).order_by(RequestDb.add_time.desc()).slice(int(data['start']), int(data['end']))
        else:
            return []
        for row in result:
            d = row.__dict__
            p = Post()
            pData = p.GetByRef(d['reference'])
            temp = {}
            temp['title'] = pData['title']
            for k in ['id', 'to_user', 'from_user', 'from_user_email', 'from_user_cell', 'from_user_address', 'order', 'total_price', 'status']:
                temp[k] = d[k]
            temp['timeago'] = timeago.format(int(d['add_time']), locale='zh_CN')
            ret.append(temp)
        return ret
            
    @needSession(write = True)
    def ChangeStatus(self, data):
        q = self.session.query(RequestDb).filter(RequestDb.id == data['id'])
        if q.first() == None:
            return 400, {'msg':'Wrong request ID'}
        result = q.first().__dict__
        status = result['status']
        toUser = result['to_user']
        fromUser = result['from_user']
        order  = json.loads(result['order'])
        reference = result['reference']

        if toUser == data['username']:
            if status == 'ready' and data['status'] == 'confirm':
                p = Post()
                if p.UpdateItem(reference, order):
                    q.update({RequestDb.status: 'confirm'})
                else:
                    return 400, {"msg": "Can not take this order"}
            elif status == 'ready' and data['status'] == 'decline':
                q.update({RequestDb.status: 'decline'})
            else:
                return 400, {"msg": "Invalid operation!"}
        elif fromUser == data['username']:
            if status == 'ready' and data['status'] == 'cancel':
                q.update({RequestDb.status: 'cancel'})
            elif status == 'confirm' and data['status'] == 'finish':
                q.update({RequestDb.status: 'finish'})
            elif status == 'confirm' and data['status'] == 'unfinish':
                q.update({RequestDb.status: 'unfinish'})
            else:
                return 400, {"msg": "Invalid operation"}
        else:
            return 400, {"msg": "Invalid user!"}

        return 200, {"msg": "Success"}


# ============================================================================
#                                 Server
# ============================================================================
@app.route("/")
def index():
    return render_template("index.html")

@app.route('/login', methods=['POST'])
@require("username", "password")
def Login():
    u = User()
    data = request.get_json()
    if u.Login(data["username"], data["password"]):
        resp = flask.jsonify(msg="Success", token=u.token, username=data["username"])
        resp.status_code = 200
    else:
        resp = flask.jsonify(msg="用户名或密码错误！")
        resp.status_code = 401
    return resp

@app.route('/logoff', methods=['POST'])
@require("username", "token")
def Logoff():
    u = User()
    data = request.get_json()
    if u.Logoff(data["username"], data["token"]):
        resp = flask.jsonify(msg="Sucess")
        resp.status_code = 200
    else:
        resp = flask.jsonify(msg="Fail")
        resp.status_code = 400
    return resp

@app.route('/register', methods=['POST'])
@require("username", "password", "email")
def Register():
    u = User()
    data = request.get_json()
    code, respJson = u.Register(data)
    resp = flask.jsonify(respJson)
    resp.status_code = code
    return resp

@app.route('/uservalid', methods=['POST'])
@require("username")
def ValidUser():
    u = User()
    data = request.get_json()
    if "token" in data:
        token = data["token"]
    else:
        token = None
    if u.Exist(data["username"], token):
        resp = flask.jsonify({"valid":True})
        resp.status_code = 200
    else:
        resp = flask.jsonify({"valid":False})
        resp.status_code = 200
    return resp

@app.route('/myinfo', methods=['POST'])
@require("username", "token", login="username")
def MyInfo():
    u = User()
    data = request.get_json()
    code, respJson = u.GetInfo(data['username'], mine = True)
    resp = flask.jsonify(respJson)
    resp.status_code = code
    return resp

@app.route('/post', methods=['POST'])
@require("category", "title", "author", "content", "items", "expire_time", "token", login="author")
def PutPost():
    p = Post()
    data = request.get_json()
    if p.Submit(data):
        resp = flask.jsonify(msg="Success")
        resp.status_code = 200
    else:
        resp = flask.jsonify(msg="Fail")
        resp.status_code = 400
    return resp

@app.route('/getpost', methods=['POST'])
@require("category", "start", "end")
def GetPost():
    p = Post()
    data = request.get_json()
    resp = flask.jsonify(p.Get(data))
    resp.status_code = 200
    return resp

@app.route('/getmypost', methods=['POST'])
@require("username", "token", "start", "end", login="username")
def GetMyPost():
    p = Post()
    data = request.get_json()
    resp = flask.jsonify(p.Get(data, mine=True))
    resp.status_code = 200
    return resp

@app.route('/deletepost', methods=['POST'])
@require("postid", "username", "token", login="username")
def DeletePost():
    p = Post()
    data = request.get_json()
    if p.Delete(data) == True:
        resp = flask.jsonify({"msg":"Success"})
        resp.status_code = 200
    else:
        resp = flask.jsonify({"msg":"Fail"})
        resp.status_code = 400
    return resp

@app.route('/request', methods=['POST'])
@require('reference', 'to_user', 'from_user', 'from_user_email', 'from_user_cell', 'from_user_address', 'note', 'order', 'total_price', 'token', login="from_user", postValid = "reference")
def PutRequest():
    r = Request()
    data = request.get_json()
    if data['to_user'] == data['from_user']:
        resp = flask.jsonify({"msg":"不能给自己下订单！"})
        resp.status_code = 400
    elif r.Submit(data) == True:
        resp = flask.jsonify({"msg":"Sucess"})
        resp.status_code = 200
    else:
        resp = flask.jsonify({"msg":"Fail"})
        resp.status_code = 400
    return resp

@app.route('/getrequest', methods=['POST'])
@require('username', 'token', 'direction', 'start', 'end', login="username")
def GetRequest():
    r = Request()
    data = request.get_json()
    resp = flask.jsonify(r.Get(data))
    resp.status_code = 200
    return resp
    
@app.route('/requeststatus', methods=['POST'])
@require('id', 'username', 'token', 'status', login="username")
def ChangeRequestStatus():
    r = Request()
    data = request.get_json()
    status_code, msg = r.ChangeStatus(data)
    resp = flask.jsonify(msg)
    resp.status_code = status_code 
    return resp

if __name__ == "__main__":
    app.run()
