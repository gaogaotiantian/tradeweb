import requests
import json
import argparse

def LoginEasy(url, un, pw):
    headers = {'Content-Type' : 'application/json'}
    data = {'username':un, 'password':pw}
    r = requests.post(url = url + "/login", headers = headers, data=json.dumps(data))
    return r.json()

def LogoffEasy(url, un, token):
    headers = {'Content-Type' : 'application/json'}
    data = {'username':un, 'token':token}
    r = requests.post(url = url + "/logoff", headers = headers, data=json.dumps(data))
    print r

if __name__ == '__main__':
    url = "http://localhost:8000/"
    parser = argparse.ArgumentParser()
    parser.add_argument('-u', dest="username", default="gaotian")
    parser.add_argument('-p', dest="password", default="password")
    options = parser.parse_args()
    resp = LoginEasy(url, options.username, options.password)
    LogoffEasy(url, options.username, resp["token"])
