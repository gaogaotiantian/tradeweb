# coding:utf-8
import requests
import json
import argparse

def Get(url, category, start, end):
    headers = {'Content-Type' : 'application/json'}
    data = {
        'category': category,
        'start': start,
        'end': end
    };
    r = requests.post(url = url+'/getpost', headers = headers, data=json.dumps(data))
    print r.status_code
    print r.json()

if __name__ == '__main__':
    url = "http://localhost:8000/"
    parser = argparse.ArgumentParser()
    parser.add_argument('-u', dest="username", default="gaotian")
    parser.add_argument('-p', dest="password", default="password")
    parser.add_argument('-c', dest="category", default="外卖")
    parser.add_argument('-s', dest="start", default="1")
    parser.add_argument('-e', dest="end", default="3")
    options = parser.parse_args()
    Get(url, options.category, options.start, options.end)
    
