import requests,json
from tabulate import tabulate
url = "https://ap-southeast-1.aws.data.mongodb-api.com/app/data-zbetm/endpoint/data/v1/action/"
apikey = "hSl7T5DEqopdOtu6JYzUI4taQ6BwUmTSNRtBl2VXwIwpnMfjv13fsnpMxdgQltSX"
headers = {
  'Content-Type': 'application/json',
  'Access-Control-Request-Headers': '*',
  'api-key': apikey,
} 
def Search(message):
    option = ['-d','-n','-o']
    message = message.split(' ')
    op = [0]*3
    for msg in message:
        if msg in option:
            if(msg == '-d'):
                op[0] = message[message.index(msg) + 1]
            if(msg == '-n'):
                op[1] = message[message.index(msg) + 1]
            if(msg == '-o'):
                op[2] = message[message.index(msg) + 1]
    filter = {}
    if(op[0]):
        filter['upload_date'] = op[0]
    if(op[1]):
        filter['filename'] = op[1]
    if(op[2]):
        filter['owner'] = op[2]
    action = url + "find"
    payload = json.dumps({
        "collection": "Documents",
        "database": "CompanyStorage",
        "dataSource": "Cluster0",
        "filter" : filter,
        "projection":{
            "filename":1,
            "owner":1,
            "upload_date":1,
            "sha256":1
        }
    })    
    
    response = requests.request("POST", action, headers=headers, data=payload)
    result = json.loads(response.text)['documents']
    to_print = len(result)*[0]
    for i in range(0,len(result)):
        to_print[i] = result[i]['_id'], result[i]['filename'],result[i]['owner'],result[i]['upload_date'],result[i]['sha256']
    print(tabulate(to_print,headers=['ID','File Name','Owner','Upload Date','SHA256'],tablefmt='grid'))

msg = '/search -o hello'
Search(msg)