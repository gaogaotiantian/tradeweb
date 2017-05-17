import requests
import json
import argparse

def RegisterEasy(url, un, pw):
    headers = {'Content-Type' : 'application/json'}
    data = {'username':un, 'password':pw}
    r = requests.post(url = url + "/register", headers = headers, data=json.dumps(data))
    print r

if __name__ == '__main__':
    url = "http://localhost:8000/"
    parser = argparse.ArgumentParser()
    parser.add_argument('-u', dest="username", default="gaotian")
    parser.add_argument('-p', dest="password", default="password")
    options = parser.parse_args()
    RegisterEasy(url, options.username, options.password)
