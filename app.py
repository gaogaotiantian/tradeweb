# coding=utf-8
# python built-in libs
import os
import time
import base64
import hashlib
import json
import functools
import urllib

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
from flask_mail import Mail, Message

# Initialization
if os.environ.get('DATABASE_URL') != None:
    DATABASE_URL = os.environ.get('DATABASE_URL')
else:
    DATABASE_URL = "postgresql+psycopg2://gaotian:password@localhost:5432/tradeweb"
CLOUDINARY_API_SECRET = os.environ.get('CLOUDINARY_API_SECRET')
app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = DATABASE_URL
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 465
app.config['MAIL_USERNAME'] = os.environ.get('EMAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.environ.get('EMAIL_PASSWORD')
app.config['MAIL_USE_TLS'] = False
app.config['MAIL_USE_SSL'] = True
CORS(app)
db = SQLAlchemy(app)
mail = Mail(app)
# ============================================================================
#                         Table-like Data
# ============================================================================
cardList = [
    [u"小队长卡", 25, "变成小队长，发帖间隔6小时，学分收益加倍，每帖最多5项，有效期30天。"],
    [u"中队长卡", 100, "变成中队长，发帖间隔3小时，学分收益三倍，每帖最多8项，有效期30天。"],
    [u"大队长卡", 300, "变成大队长，发帖间隔1小时，学分收益四倍，每帖最多12项，有效期30天。"],
    [u"三好学生卡", 500, "变成三好学生，发帖间隔30分钟，学分收益五倍，每帖最多17项，有效期30天。"],
    [u"加粗卡",   15, "把帖子标题加粗！"],
    [u"变红卡",   25, "把帖子标题变红！"],
    [u"变绿卡",   25, "把帖子标题变绿！"],
    [u"变蓝卡",   25, "把帖子标题变蓝！"]
]

cardData = {card[0]:{"price":card[1], "description":card[2]} for card in cardList}

levelStatsRaw = [
#   
    [0,   0,  0],
    [24,  1,  3],
    [6,   2,  5],
    [3,   3,  8],
    [1,   4, 12],
    [0.5, 5, 17]
]

levelStat = [{"post_gap":l[0], "benefit":l[1], "post_limit":l[2]} for l in levelStatsRaw]

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
    level           = db.Column(db.Integer, default=3)
    level_exp_time  = db.Column(db.Integer, default=1498867200)
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
    images        = db.Column(db.Text, default="[]")
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
            if 1 <= self.data.level <= 5:
                return levelStat[self.data.level]['post_gap']*3600
            else:
                return 0
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
                    email = email,
                    expire_time = time.time() + 3600)
            db.session.add(newUser)
            db.session.commit()
            msg = Message('欢迎来到学子集！', sender = app.config['MAIL_USERNAME'], recipients = [email])
            msg.body = '在学子集，我们希望您可以诚信交易，尊重他人，利用好这个工具。祝愿您在学子集玩的愉快：）'
            mail.send(msg)
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
                        if d[key] < 0 and self['level'] > 1:
                            self['level'] = 1;
                            db.session.commit()
                    else:
                        d[key] = self[key]
                return 200, d
            else:
                for key in ['good_sell', 'bad_sell', 'good_purchase', 'bad_purchase', \
                        'grades', 'level', 'level_exp_time']:
                    if key == 'level_exp_time':
                        d[key] = int(self[key] - time.time())
                        if d[key] < 0 and self['level'] > 1:
                            self['level'] = 1;
                            db.session.commit()
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
                    self.AddGrade(5)
                else:
                    self.data.bad_sell = self.data.bad_sell + 1
            elif trans == "purchase":
                if success:
                    self.data.good_purchase = self.data.good_purchase + 1
                    self.AddGrade(5)
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

    def AddGrade(self, grade):
        self['grades'] = self['grades'] + self['level'] * grade
        db.session.commit()


class Post:
    def __init__(self, postid = None):
        if postid != None:
            self.data = PostDb.query.get(postid)
        else:
            self.data = None

    def Submit(self, data):
        u = User(username = data['author'], token = data['token'])
        if u.valid:
            q = PostDb.query.filter_by(author = data['author'], is_deleted = False).order_by(PostDb.add_time.desc())
            if q.first() == None or q.first().__dict__['add_time'] < time.time() - u['post_gap']:
                p = PostDb(category = data['category'], 
                        title=data['title'], 
                        author=data['author'], 
                        content=data['content'], 
                        items=json.dumps(data['items']), 
                        availability=json.dumps(data['availability']),
                        images=json.dumps(data['images']),
                        add_time=time.time(), 
                        expire_time=data['expire_time'])
                db.session.add(p)
                db.session.commit()
                u.AddGrade(1)
                return 200, {"msg": "Success!"}
            else:
                return 400, {"msg": "您的用户级别发帖间隔为{}秒, 您还需要等待{}秒".format(u['post_gap'], int(u['post_gap'] - (time.time() - q.first().__dict__['add_time'])))}
        return 400, {"msg": "用户失效！"}
    
    def Get(self, data, mine = False):
        ret = {}
        ret['posts'] = []
        if mine:
            result = PostDb.query.filter_by(author = data['username']).order_by(PostDb.add_time.desc()).slice(int(data['start']), int(data['end']))
        else:
            if data['category'] == u'全部':
                result = PostDb.query.filter_by(is_deleted = False).order_by(PostDb.add_time.desc()).slice(int(data['start']), int(data['end']))
                ret['count'] = PostDb.query.filter_by(is_deleted = False).count()
            else:
                result = PostDb.query.filter_by(category = data['category'], is_deleted = False).order_by(PostDb.add_time.desc()).slice(int(data['start']), int(data['end']))
                ret['count'] = PostDb.query.filter_by(category = data['category'], is_deleted = False).count()
        for row in result:
            d = row.__dict__
            temp = {}
            for key in ['id', 'title', 'author', 'content', 'is_deleted']:
                temp[key] = d[key]
            temp['items'] = json.loads(d['items'])
            temp['availability'] = json.loads(d['availability'])
            temp['buff'] = json.loads(d['buff'])
            temp['images'] = json.loads(d['images'])
            temp['timeago'] = timeago.format(int(d['add_time']), locale='zh_CN')
            ret['posts'].append(temp)
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
            u = User(author)
            u.AddGrade(-1)
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
        u = User(data['to_user'])
        p = Post(data['reference'])
        msg = Message(u'《{}》有新的订单了！'.format(p.data.title), sender = app.config['MAIL_USERNAME'], recipients = [u['email']])
        msg.html  = u'<p>赶紧去<a href="https://www.xueziji.com">学子集</a>看看吧！请在联系买家后尽快确认订单哟！</p>'
        msg.html += u'<p>订单详情：</p>'
        for name, od in data['order'].items():
            msg.html += u'<p>{}: ${}x{}</p>'.format(name, od[0], od[1])
        msg.html += u'<p>总价：${}</p>'.format(data['total_price'])

        mail.send(msg)
        return True

    def Get(self, data):
        ret = {}
        ret['orders'] = []
        if data['direction'] == 'toMe':
            result = RequestDb.query.filter_by(to_user = data['username']).order_by(RequestDb.add_time.desc()).slice(int(data['start']), int(data['end']))
            ret['count'] = RequestDb.query.filter_by(to_user = data['username']).count()
        elif data['direction'] == 'fromMe':
            result = RequestDb.query.filter_by(from_user = data['username']).order_by(RequestDb.add_time.desc()).slice(int(data['start']), int(data['end']))
            ret['count'] = RequestDb.query.filter_by(from_user = data['username']).count()
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
            ret['orders'].append(temp)
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

        p = Post()
        title = p.GetByRef(reference)['title']
        if toUser == data['username']:
            u = User(fromUser)
            msg = Message('订单更新情况！', sender = app.config['MAIL_USERNAME'], recipients = [u['email']])
            if status == 'ready' and data['status'] == 'confirm':
                if p.UpdateItem(reference, order):
                    q.status = 'confirm'
                    msg.html = u'您对《{}》的订单已经被确认！请等待卖家联系您，不要忘了在交易完成之后点完成按钮哟！去<a href="https://www.xueziji.com">学子集</a>看看吧！'.format(title)
                else:
                    return 400, {"msg": "Can not take this order"}
            elif status == 'ready' and data['status'] == 'decline':
                q.status = 'decline'
                msg.html = u'您对《{}》的订单已经被拒绝。请查看自己的联系方式是否没有填写或填写错误导致卖家无法联系您。去<a href="https://www.xueziji.com">学子集</a>看看吧！'.format(title)
            else:
                return 400, {"msg": "Invalid operation!"}
            mail.send(msg)
        elif fromUser == data['username']:
            u = User(toUser)
            msg = Message('订单更新情况！', sender = app.config['MAIL_USERNAME'], recipients = [u['email']])
            if status == 'ready' and data['status'] == 'cancel':
                q.status = 'cancel'
                u = User(fromUser)
                u.DoTransaction(trans="purchase", success=False)
                msg.body = u'您的《{}》来自 {} 的订单已经被取消。'.format(title, fromUser)
                mail.send(msg)
            elif status == 'confirm' and data['status'] == 'finish':
                q.status = 'finish'
                u = User(fromUser)
                u.DoTransaction(trans="purchase", success=True)
                msg = Message('订单更新情况！', sender = app.config['MAIL_USERNAME'], recipients = [u['email']])
                msg.html = u'恭喜！您的《{}》订单已经完成。学分又涨了哟！有机会可以试试各种卡片了！去<a href="https://www.xueziji.com">学子集</a>看看吧！'.format(title)
                mail.send(msg)
                u = User(toUser)
                u.DoTransaction(trans="sell", success=True)
                msg = Message('订单更新情况！', sender = app.config['MAIL_USERNAME'], recipients = [u['email']])
                msg.html = u'恭喜！您的《{}》订单已经完成。学分又涨了哟！有机会可以试试各种卡片了！去<a href="https://www.xueziji.com">学子集</a>看看吧！'.format(title)
                mail.send(msg)
            elif status == 'confirm' and data['status'] == 'unfinish':
                q.status = 'unfinish'
                u = User(toUser)
                u.DoTransaction(trans="sell", success=False)
                msg.body = u'您的《{}》与{}的交易失败。如果交易成功进行了，请联系网站管理员。'.format(title, fromUser)
                mail.send(msg)
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

@app.route('/signature', methods=['POST'])
def Signature():
    if CLOUDINARY_API_SECRET != None:
        data = request.get_json()
        for pickOutKey in ['file', 'type', 'resource_type', 'api_key']:
            if pickOutKey in data:
                data.pop(pickOutKey)
        s = '&'.join([str(t[0])+'='+str(t[1]) for t in sorted([(k, v) for k,v in data.items()])])
        s += CLOUDINARY_API_SECRET
        resp = flask.jsonify({"signature": hashlib.sha1(s).hexdigest()})
        resp.status_code = 200
    else:
        resp = flask.jsonify({"msg": "No valid cloudinary api secret exist"})
        resp.status_code = 403

    return resp
    
@app.route('/levelStat', methods=['POST'])
def LevelStat():
    resp = flask.jsonify(levelStat)
    resp.status_code = 200
    return resp

if __name__ == "__main__":
    app.run()
