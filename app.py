# python built-in libs
import os
import time
import base64
import hashlib
import json
import functools

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
engine = sqlalchemy.create_engine("postgresql+psycopg2://gaotian:password@localhost:5432/tradeweb", echo=True)
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
    add_time      = Column(Integer)
    expire_time   = Column(Integer)
    is_deleted    = Column(Boolean)

class RequestDb(Base):
    __tablename__ = "Requests"
    id           = Column(Integer, primary_key=True)
    reference    = Column(Integer)
    to_user      = Column(String(50))
    from_user    = Column(String(50))
    from_user_email = Column(String(50))
    from_user_cell = Column(String(15))
    order        = Column(Text)
    total_price  = Column(Float)
    is_canceled  = Column(Boolean)
    is_confirmed = Column(Boolean)
    is_finished  = Column(Boolean)
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
                        resp.status_code = 400
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
    def Register(self, username, password):
        ret = False
        if self.session.query(UserDb).filter(UserDb.username == username).first() == None:
            self.session.add(UserDb(username=username, password=hashlib.md5(password).hexdigest()))
            ret = True
        return ret

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


class Post:
    def __init__(self):
        self.session = None

    @needSession(write = True)
    def Submit(self, data):
        u = User()
        if u.Exist(data['author'], data['token']):
            self.session.add(PostDb(category = data['category'], title=data['title'], author=data['author'], 
                    content=data['content'], items=json.dumps(data['items']), add_time=time.time(), expire_time=data['expire_time']))
            return True
        return False
    
    @needSession(write = False)
    def Get(self, data):
        ret = []
        result = self.session.query(PostDb).filter(PostDb.category == data['category']).order_by(PostDb.add_time.desc()).slice(int(data['start']), int(data['end']))
        for row in result:
            d = row.__dict__
            temp = {}
            temp['title'] = d['title']
            temp['author'] = d['author']
            temp['content'] = d['content']
            temp['items'] = json.loads(d['items'])
            ret.append(temp)
        return ret

    @needSession(write = True)
    def Delete(self, data):
        u = User()
        author = data["username"]
        token  = data["token"]
        postid = data["postid"]
        q = self.session.query(PostDb).filter(PostDb.id == postid, 
                PostDb.author == author, 
                PostDb.is_deleted == False)
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
                order = json.dumps(data['order']), 
                total_price = data['total_price'], 
                is_canceled = False,
                is_finished = False,
                is_confirmed = False, 
                add_time = time.time(),
                expire_time = time.time() + 600))
        return True

    @needSession(write = True)
    def Cancel(self, data):
        q = self.session.query(RequestDb).filter(
                RequestDb.is_canceled == False,
                RequestDb.is_confirmed == False,
                RequestDb.is_finished == False,
                RequestDb.id == data['id'])
        if q.first() != None:
            q.update({RequestDb.is_canceled:True})
            return True
        return False

    @needSession(write = True)
    def Confirm(self, data):
        q = self.session.query(RequestDb).filter(
                RequestDb.is_canceled == False,
                RequestDb.is_confirmed == False,
                RequestDb.is_finished == False,
                RequestDb.id == data['id'])
        if q.first() != None:
            q.update({RequestDb.is_confirmed:True})
            return True
        return False

    @needSession(write = True)
    def Finish(self, data):
        q = self.session.query(RequestDb).filter(
                RequestDb.is_canceled == False,
                RequestDb.is_confirmed == True,
                RequestDb.is_finished == False,
                RequestDb.id == data['id'])
        if q.first() != None:
            q.update({RequestDb.is_finished:True})
            return True
        return False
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
        resp = flask.jsonify(msg="Success", token=u.token)
        resp.status_code = 200
    else:
        resp = flask.jsonify(msg="Fail")
        resp.status_code = 400
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
#@require("username", "password")
def Register():
    u = User()
    data = request.get_json()
    if u.Register(data["username"], data["password"]):
        resp = flask.jsonify(msg="Success")
        resp.status_code = 200
    else:
        resp = flask.jsonify(msg="Fail")
        resp.status_code = 400
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
@require('reference', 'to_user', 'from_user', 'from_user_email', 'from_user_cell', 'order', 'total_price', 'token', login="from_user", postValid = "reference")
def PutRequest():
    r = Request()
    data = request.get_json()
    if r.Submit(data) == True:
        resp = flask.jsonify({"msg":"Sucess"})
        resp.status_code = 200
    else:
        resp = flask.jsonify({"msg":"Fail"})
        resp.status_code = 400
    return resp
    
@app.route('/cancelrequest', methods=['POST'])
@require('id', 'username', 'token', login="username", reqFrom="username")
def CancelRequest():
    r = Request()
    data = request.get_json()
    if r.Cancel(data) == True:
        resp = flask.jsonify({"msg":"Sucess"})
        resp.status_code = 200
    else:
        resp = flask.jsonify({"msg":"Fail"})
        resp.status_code = 400
    return resp

@app.route('/confirmrequest', methods=['POST'])
@require('id', 'username', 'token', login="username", reqTo="username")
def ConfirmRequest():
    r = Request()
    data = request.get_json()
    if r.Confirm(data) == True:
        resp = flask.jsonify({"msg":"Sucess"})
        resp.status_code = 200
    else:
        resp = flask.jsonify({"msg":"Fail"})
        resp.status_code = 400
    return resp

@app.route('/finishrequest', methods=['POST'])
@require('id', 'username', 'token', login="username", reqFrom="username")
def FinishRequest():
    r = Request()
    data = request.get_json()
    if r.Finish(data) == True:
        resp = flask.jsonify({"msg":"Sucess"})
        resp.status_code = 200
    else:
        resp = flask.jsonify({"msg":"Fail"})
        resp.status_code = 400
    return resp
if __name__ == "__main__":
    app.run()
