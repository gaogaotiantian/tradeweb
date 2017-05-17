# coding:utf-8
import requests
import json
import argparse

def Post(url, category, title, author, content, items, token):
    headers = {'Content-Type' : 'application/json'}
    data = {
        'category': category,
        'title': title,
        'author': author,
        'content': content,
        'items': items,
        'token': token,
        'expire_time': 1
    }
    r = requests.post(url = url+'/post', headers = headers, data=json.dumps(data))
    print r.status_code
    print r.json()

def LoginEasy(url, un, pw):
    headers = {'Content-Type' : 'application/json'}
    data = {'username':un, 'password':pw}
    r = requests.post(url = url + "/login", headers = headers, data=json.dumps(data))
    if r.status_code != 200:
        print "Login Error"
    return r.json()['token']

if __name__ == '__main__':
    url = "http://localhost:8000/"
    parser = argparse.ArgumentParser()
    parser.add_argument('-u', dest="username", default="gaotian")
    parser.add_argument('-p', dest="password", default="password")
    parser.add_argument('-t', dest="title", default="title")
    parser.add_argument('-content', dest="content", default="content")
    parser.add_argument('-i', dest="items", default="{item1:1, item2:2}")
    parser.add_argument('-c', dest="category", default="外卖")
    options = parser.parse_args()
    token = LoginEasy(url, options.username, options.password)
    Post(url, options.category, options.title, options.username, options.content, options.items, token)

