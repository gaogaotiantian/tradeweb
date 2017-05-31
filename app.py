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
import psycopg2

# Flask
import flask
from flask import Flask, request, render_template
from flask_login import LoginManager
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy

# Initialization
if os.environ.get('DATABASE_URL') != None:
    DATABASE_URL = os.environ.get('DATABASE_URL')
else:
    DATABASE_URL = "postgresql+psycopg2://gaotian:password@localhost:5432/tradeweb"
app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = DATABASE_URL
CORS(app)
db = SQLAlchemy(app)
# ============================================================================
#                         Table-like Data
# ============================================================================
cardList = [
    [u"小队长卡", 1, "变成小队长，发帖间隔6小时，学分收益加倍，每帖最多5项，有效期30天。"],
    [u"中队长卡", 1, "变成中队长，发帖间隔3小时，学分收益三倍，每帖最多8项，有效期30天。"],
    [u"大队长卡", 1, "变成大队长，发帖间隔1小时，学分收益四倍，每帖最多12项，有效期30天。"],
    [u"加粗卡",   1, "把帖子标题加粗！"],
    [u"变红卡",   1, "把帖子标题变红！"],
    [u"变绿卡",   1, "把帖子标题变绿！"],
    [u"变蓝卡",   1, "把帖子标题变蓝！"]
]

cardData = {card[0]:{"price":card[1], "description":card[2]} for card in cardList}

# ============================================================================
#                                Classes 
# ============================================================================
# --------------------------------
#     Database Classes
# --------------------------------
class UserDb(db.Model):
    __tablename__   = 'Users'
    username        = db.Column(db.String(50), primary_key=True)
    password        = db.Column(db.String(32))
    token           = db.Column(db.String(32))
    email           = db.Column(db.String(50))
    cell            = db.Column(db.String(15), default="")
    address         = db.Column(db.String(100), default="")
    good_sell       = db.Column(db.Integer, default=0)
    good_purchase   = db.Column(db.Integer, default=0)
    bad_sell        = db.Column(db.Integer, default=0)
    bad_purchase    = db.Column(db.Integer, default=0)
    grades          = db.Column(db.Integer, default=0)
    level           = db.Column(db.Integer, default=1)
    level_exp_time  = db.Column(db.Integer, default=0)
    cards           = db.Column(db.Text, default="{}")
    expire_time     = db.Column(db.Integer, default=0)
    update_time     = db.Column(db.Integer, default=0)
    
class PostDb(db.Model):
    __tablename__ = "Posts"
    id            = db.Column(db.Integer, primary_key=True)
    category      = db.Column(db.String(20))
    title         = db.Column(db.String(50))
    author        = db.Column(db.String(50))
    content       = db.Column(db.Text)
    items         = db.Column(db.Text, default="{}")
    availability  = db.Column(db.Text, default="{}")
    buff          = db.Column(db.Text, default="{}")
    add_time      = db.Column(db.Integer)
    expire_time   = db.Column(db.Integer)
    update_time   = db.Column(db.Integer, default=0)
    is_deleted    = db.Column(db.Boolean, default=False)

class RequestDb(db.Model):
    __tablename__ = "Requests"
    id                = db.Column(db.Integer, primary_key=True)
    reference         = db.Column(db.Integer)
    to_user           = db.Column(db.String(50))
    from_user         = db.Column(db.String(50))
    from_user_email   = db.Column(db.String(50))
    from_user_cell    = db.Column(db.String(15))
    from_user_address = db.Column(db.String(100))
    note              = db.Column(db.Text, default="")
    order             = db.Column(db.Text, default="{}")
    total_price       = db.Column(db.Float)
    status            = db.Column(db.String(10))
    add_time          = db.Column(db.Integer)
    update_time       = db.Column(db.Integer)
    expire_time       = db.Column(db.Integer)


# create_all() needs to be after all database classes
db.create_all()

# ============================================================================
#                                 Decoreator
# ============================================================================

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
        self.username = username
        if username != "":
            self.data = UserDb.query.filter_by(username = username).first()
        else:
            self.data = None
        self.valid = self.IsValid(password, token)
        self.authenticated = False
        self.password = ""
        self.token = ""

    def __getitem__(self, key):
        if self.data == None:
            return None
        if key == "cards":
            return json.loads(self.data.__getattribute__(key))
        elif key == 'post_gap':
            if self.data.level == 0:
                return 24*3600
            elif self.data.level == 1:
                return 6*3600
            elif self.data.level == 2:
                return 3*3600
            elif self.data.level == 3:
                return 1*3600
        elif key == 'pending_requests':
            num  = RequestDb.query.filter_by(from_user = self['username'], status = 'confirm').count()
            num += RequestDb.query.filter_by(to_user = self['username'], status = 'ready').count()
            return num
        return self.data.__getattribute__(key)

    def __setitem__(self, key, val):
        if key == "cards":
            self.data.cards = json.dumps(val, sort_keys = True)
        else:
            self.data.__setattr__(key, val)
    
    def IsValid(self, password, token):
        if self.data == None:
            return False
        else:
            if password == None and token == None:
                return True
            elif token != None:
                return token == self.data.token and self.data.expire_time > time.time()
            elif password != None:
                return hashlib.md5(password).hexdigest() == self.data.password
            assert(False)

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
        if UserDb.query.filter_by(username = username).first() == None:
            token = base64.urlsafe_b64encode(os.urandom(24))
            newUser = UserDb(username = username, 
                    password = hashlib.md5(password).hexdigest(),
                    token = token,
                    email = email)
            db.session.add(newUser)
            db.session.commit()
            return 200, {"msg":"Success", "token":token}
        return 400, {"msg":"用户名已被占用"}

    def Login(self, remember):
        if self.valid:
            token = base64.urlsafe_b64encode(os.urandom(24))
            if remember:
                self.data.token = token
                self.data.expire_time = time.time() + 3600*24*30
            else:
                self.data.token = token
                self.data.expire_time = time.time() + 3600
            db.session.commit()
            return 200, {"msg" : "Success!", "username": self.data.username, "token": token}
        return 400, {"msg": "用户名或密码错误！"}
    
    def Logoff(self):
        if self.valid:
            self.data.token = ""
            self.data.expire_time = 0
            db.session.commit()
            return 200, {"msg": "Success"}
        return 400, {"msg": "登出失败！"}
    
    def GetInfo(self, mine):
        if self.valid:
            d = {}
            if mine == True:
                for key in ['email', 'cell', 'address', 'good_sell', 'bad_sell', \
                        'good_purchase', 'bad_purchase', 'grades', 'cards', 'level', \
                        'level_exp_time', 'pending_requests']:
                    if key == 'level_exp_time':
                        d[key] = int(self[key] - time.time())
                    else:
                        d[key] = self[key]
                return 200, d
            else:
                for key in ['good_sell', 'bad_sell', 'good_purchase', 'bad_purchase', \
                        'grades', 'level', 'level_exp_time']:
                    if key == 'level_exp_time':
                        d[key] = int(self[key] - time.time())
                    else:
                        d[key] = self[key]
                return 200, d
        else:
            return 400, {'msg': 'No such user!'}

    def ChangePassword(self, data):
        if self.valid:
            if hashlib.md5(data['old_password']).hexdigest() == self.data.password:
                self.data.password = hashlib.md5(data['new_password']).hexdigest()
                db.session.commit()
                return 200, {"msg":"Success!"}
            else:
                return 400, {"msg":"Wrong user/password combination!"}

    def UpdateInfo(self, data):
        if self.valid:
            self.data.email = data['email']
            self.data.cell = data['cell']
            self.data.address = data['address']
            db.session.commit()
            return 200, {"msg": "Success!"}
        return 400, {"msg": "No such user!"}

    def DoTransaction(self, trans, success):
        if self.valid:
            if trans == "sell":
                if success:
                    self.data.good_sell = self.data.good_sell + 1
                    self.data.grades = self.data.grades + self.data.level
                else:
                    self.data.bad_sell = self.data.bad_sell + 1
            elif trans == "purchase":
                if success:
                    self.data.good_purchase = self.data.good_purchase + 1
                    self.data.grades = self.data.grades + self.data.level
                else:
                    self.data.bad_purchase = self.data.bad_purchase + 1
            else:
                return False
            return True
        return False

    def PurchaseCard(self, cardname):
        if self.valid:
            if cardname not in cardData:
                return 400, "没有这种卡！"
            else:
                g = self.data.grades - cardData[cardname]["price"] 
                if self.data.grades < cardData[cardname]['price']:
                    return 400, "学分不够！"
                else:
                    cards = self['cards']
                    if cardname in cards:
                        cards[cardname] += 1
                    else:
                        cards[cardname] = 1
                    self['cards'] = cards
                    self.data.grades = self.data.grades - cardData[cardname]["price"]
                    db.session.commit()
                    return 200, "Success!"
        else:
            return 401, "需要先登录再操作！"

    def UseCard(self, cardname, target):
        if self.valid:
            if cardname not in cardData:
                return 400, {"msg":"没有这种卡！"}
            else:
                cards = self['cards']
                if cardname in cards and cards[cardname] > 0:
                    if cardname == u'小队长卡':
                        if self['level'] < 2:
                            self['level'] = 2
                            self['level_exp_time'] = time.time() + 30*24*3600
                        else:
                            return 400, {"msg":"您现在的等级无需使用这张卡。"}
                    elif cardname == u'中队长卡':
                        if self['level'] < 3:
                            self['level'] = 3
                            self['level_exp_time'] = time.time() + 30*24*3600
                        else:
                            return 400, {"msg":"您现在的等级无需使用这张卡。"}
                    elif cardname == u'大队长卡':
                        if self['level'] < 4:
                            self['level'] = 4
                            self['level_exp_time'] = time.time() + 30*24*3600
                        else:
                            return 400, {"msg":"您现在的等级无需使用这张卡。"}
                    elif cardname == u'加粗卡':
                        p = Post(target['postid'])
                        if p.AddBuff("bold", True) == False:
                            return 400, {"msg":"Fail"}
                    elif cardname == u'变红卡':
                        p = Post(target['postid'])
                        if p.AddBuff("color", "red") == False:
                            return 400, {"msg":"Fail"}
                    elif cardname == u'变绿卡':
                        p = Post(target['postid'])
                        if p.AddBuff("color", "green") == False:
                            return 400, {"msg":"Fail"}
                    elif cardname == u'变蓝卡':
                        p = Post(target['postid'])
                        if p.AddBuff("color", "blue") == False:
                            return 400, {"msg":"Fail"}
                    else:
                        return 400, {"msg":"Not implemented yet!"}
                    cards[cardname] -= 1
                    if cards[cardname] == 0:
                        cards.pop(cardname, None)
                    self['cards'] = cards
                    db.session.commit()
                    return 200, {"msg":"Success"}
                else:
                    return 400, {"msg":"卡的数量不够"}
        else:
            return 401, {"msg":"需要先登录再操作！"}



class Post:
    def __init__(self, postid = None):
        if postid != None:
            self.data = PostDb.query.get(postid)
        else:
            self.data = None

    def Submit(self, data):
        u = User(username = data['author'], token = data['token'])
        if u.valid:
            q = PostDb.query.filter_by(author = data['author']).order_by(PostDb.add_time.desc())
            if q.first() == None or q.first().__dict__['add_time'] < time.time() - u['post_gap']:
                p = PostDb(category = data['category'], 
                        title=data['title'], 
                        author=data['author'], 
                        content=data['content'], 
                        items=json.dumps(data['items']), 
                        availability=json.dumps(data['availability']), 
                        add_time=time.time(), 
                        expire_time=data['expire_time'])
                db.session.add(p)
                db.session.commit()
                return 200, {"msg": "Success!"}
            else:
                return 400, {"msg": "您的用户级别发帖间隔为{}秒, 您还需要等待{}秒".format(u['post_gap'], int(u['post_gap'] - (time.time() - q.first().__dict__['add_time'])))}
        return 400, {"msg": "用户失效！"}
    
    def Get(self, data, mine = False):
        ret = []
        if mine:
            result = PostDb.query.filter_by(author = data['username']).order_by(PostDb.add_time.desc()).slice(int(data['start']), int(data['end']))
        else:
            result = PostDb.query.filter_by(category = data['category'], is_deleted = False).order_by(PostDb.add_time.desc()).slice(int(data['start']), int(data['end']))
        for row in result:
            d = row.__dict__
            temp = {}
            for key in ['id', 'title', 'author', 'content', 'is_deleted']:
                temp[key] = d[key]
            temp['items'] = json.loads(d['items'])
            temp['availability'] = json.loads(d['availability'])
            temp['buff'] = json.loads(d['buff'])
            temp['timeago'] = timeago.format(int(d['add_time']), locale='zh_CN')
            ret.append(temp)
        return ret

    def GetByRef(self, postid):
        result = PostDb.query.get(postid)
        if result != None:
            return result.__dict__
        return {}

    def UpdateItem(self, postid, order):
        q = PostDb.query.get(postid)
        if q != None:
            avai = json.loads(q.__dict__['availability'])
            for key in order:
                if key in avai:
                    print avai
                    print avai[key], order[key][1]
                    avai[key] = int(avai[key]) - int(order[key][1])
                    if avai[key] < 0: 
                        return False
            q.availability = json.dumps(avai)
            db.session.commit()
            return True
        return False

    def Delete(self, data):
        author = data["username"]
        token  = data["token"]
        postid = data["postid"]
        q = PostDb.query.filter_by(id = postid, 
                author = author, 
                is_deleted = False)
        if q.first() != None:
            q.first().is_deleted = True
            db.session.commit()
            return True
        return False
    
    def Exist(self, id):
        q = PostDb.query.filter_by(id = id)
        if q.first() != None:
            return True
        return False

    def AddBuff(self, buff, val):
        if self.data == None:
            return False
        totalBuff = json.loads(self.data.buff)
        totalBuff[buff] = val
        self.data.buff = json.dumps(totalBuff)
        db.session.commit()
        return True

class Request:
    def Submit(self, data):
        newReq = RequestDb(
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
                expire_time = time.time() + 600)
        db.session.add(newReq)
        db.session.commit()
        return True

    def Get(self, data):
        ret = []
        if data['direction'] == 'toMe':
            result = RequestDb.query.filter_by(to_user = data['username']).order_by(RequestDb.add_time.desc()).slice(int(data['start']), int(data['end']))
        elif data['direction'] == 'fromMe':
            result = RequestDb.query.filter_by(from_user = data['username']).order_by(RequestDb.add_time.desc()).slice(int(data['start']), int(data['end']))
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
            
    def ChangeStatus(self, data):
        q = RequestDb.query.get(data['id'])
        if q == None:
            return 400, {'msg':'Wrong request ID'}
        result = q.__dict__
        status = result['status']
        toUser = result['to_user']
        fromUser = result['from_user']
        order  = json.loads(result['order'])
        reference = result['reference']

        if toUser == data['username']:
            if status == 'ready' and data['status'] == 'confirm':
                p = Post()
                if p.UpdateItem(reference, order):
                    q.status = 'confirm'
                else:
                    return 400, {"msg": "Can not take this order"}
            elif status == 'ready' and data['status'] == 'decline':
                q.status = 'decline'
            else:
                return 400, {"msg": "Invalid operation!"}
        elif fromUser == data['username']:
            if status == 'ready' and data['status'] == 'cancel':
                q.status = 'cancel'
                u = User(fromUser)
                u.DoTransaction(trans="purchase", success=False)
            elif status == 'confirm' and data['status'] == 'finish':
                q.status = 'finish'
                u = User(fromUser)
                u.DoTransaction(trans="purchase", success=True)
                u = User(toUser)
                u.DoTransaction(trans="sell", success=True)
            elif status == 'confirm' and data['status'] == 'unfinish':
                q.status = 'unfinish'
                u = User(toUser)
                u.DoTransaction(trans="sell", success=False)
            else:
                return 400, {"msg": "Invalid operation"}
        else:
            return 400, {"msg": "Invalid user!"}

        db.session.commit()
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
    return GetResp(u.GetInfo(mine = False))

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

@app.route('/usecard', methods=['POST'])
@require("username", "token", "cardname", "target")
def UseCard():
    data = request.get_json()
    u = User(data["username"], token = data["token"])
    return GetResp(u.UseCard(data["cardname"], data["target"]))

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
