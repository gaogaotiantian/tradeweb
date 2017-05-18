# python built-in libs
import os
import time
import base64
import hashlib
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

# Initialization
app = Flask(__name__)
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

class RequestDb(Base):
    __tablename__ = "Requests"
    id          = Column(Integer, primary_key=True)
    reference   = Column(Integer)
    touser      = Column(String(50))
    fromuser    = Column(String(50))
    order       = Column(Text)
    totalPrice  = Column(Float)
    isCanceled  = Column(Boolean)
    isConfirmed = Column(Boolean)


# create_all() needs to be after all database classes
Base.metadata.create_all(bind=engine)

# --------------------------------
#     Flask Classes
# --------------------------------
class User:
    def __init__(self, username = ""):
        self.authenticated = False
        self.username = username
        self.password = ""
        self.token = ""

    def is_authenticated(self):
        return self.authenticated
    def is_active(self):
        return True
    def isanonymous(self):
        return True
    def get_id(self):
        return self.username

    def Register(self, username, password):
        ret = False
        session = Session()
        if session.query(UserDb).filter(UserDb.username == username).first() == None:
            session.add(UserDb(username=username, password=hashlib.md5(password).hexdigest()))
            session.commit()
            ret = True
        session.close()
        return ret

    def Login(self, username, password):
        ret = False
        session = Session()
        q = session.query(UserDb).filter(UserDb.username == username, UserDb.password == hashlib.md5(password).hexdigest())
        if q.first() != None:
            self.token = base64.urlsafe_b64encode(os.urandom(24))
            q.update({UserDb.token:self.token, UserDb.expire_time:time.time()+600})
            session.commit()
            self.username = username
            self.authenticated = True
            ret = True
        session.close()
        return ret
    
    def Logoff(self, username, token):
        ret = False
        session = Session()
        q = session.query(UserDb).filter(UserDb.username == username, UserDb.token == token)
        if q.first() != None:
            q.update({UserDb.token:"", UserDb.expire_time:0})
            session.commit()
            self.username = username
            self.authenticated = False
            ret = True
        session.close()
        return ret
    
    def Exist(self, username, token):
        ret = False
        session = Session()
        q = session.query(UserDb).filter(UserDb.username == username, UserDb.token == token)
        if q.first() != None:
            ret = True
        session.close()
        return ret


class Post:
    def __init__(self):
        pass

    def Submit(self, data):
        ret = False
        u = User()
        if u.Exist(data['author'], data['token']):
            try:
                session = Session()
                session.add(PostDb(category = data['category'], title=data['title'], author=data['author'], 
                        content=data['content'], items=data['items'], add_time=time.time(), expire_time=data['expire_time']))
                session.commit()
                session.close()
                ret = True
            except Exception as e:
                print e
                ret = False
        return ret
    
    def Get(self, data):
        ret = []
        session = Session()
        result = session.query(PostDb).filter(PostDb.category == data['category']).order_by(PostDb.add_time.desc()).slice(int(data['start']), int(data['end']))
        for row in result:
            d = row.__dict__
            temp = {}
            temp['title'] = d['title']
            temp['author'] = d['author']
            temp['content'] = d['content']
            temp['items'] = d['items']
            ret.append(temp)
        return ret

# ============================================================================
#                                 Decoreator
# ============================================================================
def require(*required_args):
    def decorator(func):
        @functools.wraps(func)
        def wrapper(*args, **kw):
            if request.get_json() == None:
                resp = flask.jsonify( msg="No json!")
                resp.status_code = 400
                return resp
            for arg in required_args:
                if arg not in request.get_json():
                    resp = flask.jsonify(code=400, msg="wrong args! need "+arg)
                    resp.status_code = 400
                    return resp
            return func(*args, **kw)
        return wrapper
    return decorator

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
@require("username", "password")
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
@require("category", "title", "author", "content", "items", "expire_time", "token")
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

if __name__ == "__main__":
    app.run()
