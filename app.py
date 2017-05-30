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
if os.environ.get('DATABASE_URL') != None:
    engine = sqlalchemy.create_engine(os.environ.get('DATABASE_URL'), echo=False)
else:
    engine = sqlalchemy.create_engine("postgresql+psycopg2://gaotian:password@localhost:5432/tradeweb", echo=False)
Session = sqlorm.scoped_session(sqlorm.sessionmaker(bind=engine))
# ============================================================================
#                         Table-like Data
# ============================================================================
cardList = [
    [u"小队长卡", 1, "变成小队长，有效期30天。"],
    [u"中队长卡", 1, "变成中队长，有效期30天。"],
    [u"大队长卡", 1, "变成大队长，有效期30天。"]
]

cardData = {card[0]:{"price":card[1], "description":card[2]} for card in cardList}

# ============================================================================
#                                Classes 
# ============================================================================
# --------------------------------
#     Database Classes
# --------------------------------
class UserDb(Base):
    __tablename__   = 'Users'
    username        = Column(String(50), primary_key=True)
    password        = Column(String(32))
    token           = Column(String(32))
    email           = Column(String(50))
    cell            = Column(String(15), default="")
    address         = Column(String(100), default="")
    good_sell       = Column(Integer, default=0)
    good_purchase   = Column(Integer, default=0)
    bad_sell        = Column(Integer, default=0)
    bad_purchase    = Column(Integer, default=0)
    grades          = Column(Integer, default=0)
    level           = Column(Integer, default=0)
    level_exp_time  = Column(Integer, default=0)
    cards           = Column(Text, default="{}")
    expire_time     = Column(Integer, default=0)
    update_time     = Column(Integer, default=0)
    
class PostDb(Base):
    __tablename__ = "Posts"
    id            = Column(Integer, primary_key=True)
    category      = Column(String(20))
    title         = Column(String(50))
    author        = Column(String(50))
    content       = Column(Text)
    items         = Column(Text, default="{}")
    availability  = Column(Text, default="{}")
    buff          = Column(Text, default="{}")
    add_time      = Column(Integer)
    expire_time   = Column(Integer)
    update_time   = Column(Integer, default=0)
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
    note         = Column(Text, default="")
    order        = Column(Text, default="{}")
    total_price  = Column(Float)
    status       = Column(String(10))
    add_time     = Column(Integer)
    update_time   = Column(Integer)
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
                    u = User(username = username, token = token)
                    if not u.valid:
                        resp = flask.jsonify(msg="This action requires login!")
                        resp.status_code = 401
                        return resp
                if "postValid" in kw_req_args:
                    p = Post()
                    if not p.Exist(data[kw_req_args["postValid"]]):
                        resp = flask.jsonify(msg="The reference post is not valid")
                        resp.status.code = 400
                        return resp
            return func(*args, **kw)
        return wrapper
    return decorator
# --------------------------------
#     Flask Classes
# --------------------------------
class User:
    def __init__(self, username = "", password = None, token = None):
        self.session = None
        self.username = username
        if username != "":
            self.LoadData(username)
        else:
            self.data = None
        self.valid = self.IsValid(password, token)
        self.authenticated = False
        self.password = ""
        self.token = ""

    def __getitem__(self, key):
        if self.data == None:
            return None
        return self.data[key]

    @needSession(write = True)
    def Set(self, **kw_args):
        d = {}
        if 'cards' in kw_args:
            kw_args['cards'] = json.dumps(kw_args['cards'], sort_keys = True)
        q = self.session.query(UserDb).filter(UserDb.username == self.username) 
        if q.first() != None:
            q.update(kw_args)
    
    def IsValid(self, password, token):
        if self.data == None:
            return False
        else:
            if password == None and token == None:
                return True
            elif token != None:
                return token == self.data['token']
            elif password != None:
                return hashlib.md5(password).hexdigest() == self.data['password']
            assert(False)


    @needSession(write = False)
    def LoadData(self, username):
        q = self.session.query(UserDb).filter(UserDb.username == username)
        if q.first() == None:
            self.data = None
        else:
            self.data = q.first().__dict__
            self.data['cards'] = json.loads(self.data['cards'])
            if int(self.data['level']) == 0:
                self.data['post_gap'] = 600
            else:
                self.data['post_gap'] = 3000

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
                    password = hashlib.md5(password).hexdigest(), 
                    email    = email,
                    token=self.token))
            return 200, {"msg":"Success", "token":self.token}
        return 400, {"msg":"Username is used"}

    @needSession(write = True)
    def Login(self, remember):
        if self.valid:
            self.token = base64.urlsafe_b64encode(os.urandom(24))
            if remember:
                self.Set(token=self.token, expire_time=time.time()+3600*24*30)
            else:
                self.Set(token=self.token, expire_time=time.time()+3600)
            return 200, {"msg" : "Success!", "username": self.username, "token": self.token}
        return 400, {"msg": "用户名或密码错误！"}
    
    @needSession(write = True)
    def Logoff(self):
        if self.valid:
            self.Set(token = "", expire_time = 0)
            return 200, {"msg": "Success"}
        return 400, {"msg": "登出失败！"}
    
    @needSession(write = False)
    def Exist(self, username, token = None, password = None):
        if self.data == None or self.data['username'] != username:
            if token != None:
                q = self.session.query(UserDb).filter(UserDb.username == username, UserDb.token == token, UserDb.expire_time > time.time())
            else:
                q = self.session.query(UserDb).filter(UserDb.username == username)
            if q.first() != None:
                return True
            return False
        else:
            return self.data['token'] == token and self.data['expire_time'] > time.time()

    @needSession(write = False)
    def GetInfo(self, mine):
        if self.valid:
            d = {}
            if mine == True:
                for key in ['email', 'cell', 'address', 'good_sell', 'bad_sell', \
                        'good_purchase', 'bad_purchase', 'grades', 'cards', 'level']:
                    d[key] = self.data[key]
                return 200, d
            else:
                for key in ['good_sell', 'bad_sell', 'good_purchase', 'bad_purchase', 'grades', 'level']:
                    d[key] = self.data[key]
                return 200, d
        else:
            return 400, {'msg': 'No such user!'}

    @needSession(write = True)
    def ChangePassword(self, data):
        if self.valid:
            if hashlib.md5(data['old_password']).hexdigest() == self.data['password']:
                self.Set(password = hashlib.md5(data['new_password']).hexdigest())
                return 200, {"msg":"Success!"}
            else:
                return 400, {"msg":"Wrong user/password combination!"}

    @needSession(write = True)
    def UpdateInfo(self, data):
        if self.valid:
            self.Set(email = data['email'], cell = data['cell'], address = data['address'])
            return 200, {"msg": "Success!"}
        return 400, {"msg": "No such user!"}

    @needSession(write = True)
    def DoTransaction(self, trans, success):
        if self.valid:
            if trans == "sell":
                if success:
                    self.Set(good_sell = UserDb.good_sell + 1)
                    self.Set(grades = UserDb.grades + 1)
                else:
                    self.Set(bad_sell = UserDb.bad_sell + 1)
            elif trans == "purchase":
                if success:
                    self.Set(good_purchase = UserDb.good_purchase + 1)
                    self.Set(grades = UserDb.grades + 1)
                else:
                    self.Set(bad_purchase = UserDb.bad_purchase + 1)
            else:
                return False
            return True
        return False

    @needSession(write = True)
    def PurchaseCard(self, cardname):
        if self.valid:
            if cardname not in cardData:
                return 400, "没有这种卡！"
            else:
                g = self.data['grades'] - cardData[cardname]["price"] 
                if g < 0:
                    return 400, "学分不够！"
                else:
                    if cardname in self['cards']:
                        self['cards'][cardname] += 1
                    else:
                        self['cards'][cardname] = 1
                    self.Set(cards = self['cards'], grades = g)
                    return 200, "Success!"
        else:
            return 401, "需要先登录再操作！"

    @needSession(write = True)
    def UseCard(self, cardname):
        if self.valid:
            if cardname not in cardData:
                return 400, "没有这种卡！"
            else:
                if cardname in self['cards'] and self['cards'][cardname] > 0:
                    if cardname == '小队长卡':
                        if self['level'] < 1:
                            self.Set(level = 1, level_exp_time = time.time() + 30*24*3600)
                        else:
                            return 400, "您现在的等级无需使用这张卡。"
                    elif cardname == '中队长卡':
                        if self['level'] < 2:
                            self.Set(level = 2, level_exp_time = time.time() + 30*24*3600)
                        else:
                            return 400, "您现在的等级无需使用这张卡。"
                    elif cardname == '大队长卡':
                        if self['level'] < 3:
                            self.Set(level = 3, level_exp_time = time.time() + 30*24*3600)
                        else:
                            return 400, "您现在的等级无需使用这张卡。"
                    self['cards'][cardname] -= 1
                    self.Set(cards = self['cards'])
                else:
                    return 400, "卡的数量不够"
        else:
            return 401, "需要先登录再操作！"



class Post:
    def __init__(self):
        self.session = None

    @needSession(write = True)
    def Submit(self, data):
        u = User(username = data['author'], token = data['token'])
        if u.valid:
            q = self.session.query(PostDb).filter(PostDb.author == data['author']).order_by(PostDb.add_time.desc())
            if q.first() == None or q.first().__dict__['add_time'] < time.time() - u['post_gap']:
                self.session.add(PostDb(category = data['category'], 
                        title=data['title'], 
                        author=data['author'], 
                        content=data['content'], 
                        items=json.dumps(data['items']), 
                        availability=json.dumps(data['availability']), 
                        add_time=time.time(), 
                        expire_time=data['expire_time']))
                return 200, {"msg": "Success!"}
            else:
                return 400, {"msg": "您的用户级别发帖间隔为{}秒, 您还需要等待{}秒".format(u['post_gap'], int(u['post_gap'] - (time.time() - q.first().__dict__['add_time'])))}
        return 400, {"msg": "用户失效！"}
    
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
            q.update({PostDb.availability: json.dumps(avai)})
            return True
        return False

    @needSession(write = True)
    def Delete(self, data):
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
            for k in ['id', 'to_user', 'from_user', 'from_user_email', 'from_user_cell', 'from_user_address', 'order', 'total_price', 'status', 'note']:
                if k == 'order':
                    temp[k] = json.loads(d[k])
                else:
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
                u = User(fromUser)
                u.DoTransaction(trans="purchase", success=False)
            elif status == 'confirm' and data['status'] == 'finish':
                q.update({RequestDb.status: 'finish'})
                u = User(fromUser)
                u.DoTransaction(trans="purchase", success=True)
                u = User(toUser)
                u.DoTransaction(trans="sell", success=True)
            elif status == 'confirm' and data['status'] == 'unfinish':
                q.update({RequestDb.status: 'unfinish'})
                u = User(toUser)
                u.DoTransaction(trans="sell", success=False)
            else:
                return 400, {"msg": "Invalid operation"}
        else:
            return 400, {"msg": "Invalid user!"}

        return 200, {"msg": "Success"}


# ============================================================================
#                                 Server
# ============================================================================

# ----------------------------------
# ------ Utility Function ----------
# ----------------------------------
def GetResp(t):
    resp = flask.jsonify(t[1])
    resp.status_code = t[0]
    return resp
# ----------------------------------
#              API 
# ----------------------------------
@app.route("/")
def index():
    return render_template("index.html")

@app.route('/login', methods=['POST'])
@require("username", "password", "remember")
def Login():
    data = request.get_json()
    u = User(username = data['username'], password = data['password'])
    return GetResp(u.Login(data["remember"]))

@app.route('/logoff', methods=['POST'])
@require("username", "token")
def Logoff():
    data = request.get_json()
    u = User(username = data['username'], token = data['token'])
    return GetResp(u.Logoff())

@app.route('/register', methods=['POST'])
@require("username", "password", "email")
def Register():
    data = request.get_json()
    u = User(data['username'])
    return GetResp(u.Register(data))

@app.route('/uservalid', methods=['POST'])
@require("username")
def ValidUser():
    data = request.get_json()
    if "token" in data:
        token = data["token"]
    else:
        token = None
    u = User(username = data['username'], token = token)
    if u.valid:
        resp = flask.jsonify({"valid":True})
        resp.status_code = 200
    else:
        resp = flask.jsonify({"valid":False})
        resp.status_code = 200
    return resp

@app.route('/myinfo', methods=['POST'])
@require("username", "token", login="username")
def MyInfo():
    data = request.get_json()
    u = User(username = data['username'], token = data["token"])
    return GetResp(u.GetInfo(mine = True))

@app.route('/userinfo', methods=['POST'])
@require("username")
def UserInfo():
    data = request.get_json()
    u = User(username = data['username'])
    code, respJson = u.GetInfo(mine = False)
    resp = flask.jsonify(respJson)
    resp.status_code = code
    return resp

@app.route('/changepassword', methods=['POST'])
@require("username", "old_password", "new_password")
def ChangePassword():
    data = request.get_json()
    u = User(data["username"])
    return GetResp(u.ChangePassword(data))

@app.route('/updateinfo', methods=['POST'])
@require("username", "token", "email", "cell", "address")
def UpdateInfo():
    data = request.get_json()
    u = User(data["username"], token = data["token"])
    return GetResp(u.UpdateInfo(data))

@app.route('/getcardlist', methods=['POST'])
def GetCardList():
    resp = flask.jsonify(cardList)
    resp.status_code = 200
    return resp

@app.route('/purchasecard', methods=['POST'])
@require("username", "token", "cardname")
def PurchaseCard():
    data = request.get_json()
    u = User(data["username"], token = data["token"])
    return GetResp(u.PurchaseCard(data["cardname"]))

@app.route('/post', methods=['POST'])
@require("category", "title", "author", "content", "items", "expire_time", "token", login="author")
def PutPost():
    p = Post()
    data = request.get_json()
    return GetResp(p.Submit(data))

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
