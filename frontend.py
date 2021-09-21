
import requests
import json
from requests.structures import CaseInsensitiveDict

token = ""



#to signUp
def signUp():
    URL = "http://127.0.0.1:5000/signUp" 
    headers = CaseInsensitiveDict()
    data = {"fName":"akhlaq","lName":"mahar","email":"abc12@gmail.com","userName":"akhlaq1","password":"akhlaq12345"}
    r = requests.post(url = URL, json = data)
    print(r.status_code)
    data = r.json()
    print(data)
signUp()

# to signIn
def login():
    URL = "http://127.0.0.1:5000/signIn"
    headers = CaseInsensitiveDict()
    headers["Authorization"] = "Basic YWtobGFxOmFraGxhcTEyMzQ1"
    r = requests.post(url = URL, headers = headers)
    #second way to pass basic auth
    #r = requests.post(url = URL, auth = ('akhlaq', 'akhlaq12345'))
    print(r.status_code)
    data = r.json()
    print(data)
    return data["x-access-tokens"]
token = login()


#to get all Jobs
def all_jobs():
    URL = "http://127.0.0.1:5000/jobs"
    headers = CaseInsensitiveDict()
    headers["x-access-tokens"] = token
    r = requests.get(url = URL, headers = headers)
    print(r.status_code)
    data = r.json()
    print(data)
all_jobs()

#to get job by id
def job_by_id(id):
    URL = "http://127.0.0.1:5000/jobs?id="+str(id)
    headers = CaseInsensitiveDict()
    headers["x-access-tokens"] = token
    r = requests.get(url = URL, headers = headers)
    print(r.status_code)
    data = r.json()
    print(data)
job_by_id(2)


#to get job by radius(lat,long,kilometer)
def job_by_radius(kilometer,lat,longi):
    URL = "http://127.0.0.1:5000/jobs?lat="+str(lat)+"&long="+str(longi)+"&kilometer="+str(kilometer)
    headers = CaseInsensitiveDict()
    headers["x-access-tokens"] = token
    r = requests.get(url = URL, headers = headers)
    print(r.status_code)
    data = r.json()
    print(data)
job_by_radius(30,77,300)

#to add new job
def add_job():
    URL = "http://127.0.0.1:5000/jobs" 
    headers = CaseInsensitiveDict()
    headers["x-access-tokens"] = token
    data = {"jobTitle":"Software Engineer","jobDesc":"Pakistan","latitiude":"31.5204","longitude":"74.3587","jobRate":"30k"}
    r = requests.post(url = URL, headers = headers, json = data)
    print(r.status_code)
    data = r.json()
    print(data)
add_job()

#to update job by id
def update_job(id):
    URL = "http://127.0.0.1:5000/jobs/"+str(id) 
    headers = CaseInsensitiveDict()
    headers["x-access-tokens"] = token
    data = {"jobTitle":"IT Support","jobDesc":"Pakistan","latitiude":"30","longitude":"77","jobRate":"30k"}
    r = requests.put(url = URL, headers = headers, json = data)
    print(r.status_code)
    data = r.json()
    print(data)
update_job(7)

#to soft delete job by id
def soft_delete_job(id):
    URL = "http://127.0.0.1:5000/jobs/"+str(id) 
    headers = CaseInsensitiveDict()
    headers["x-access-tokens"] = token
    r = requests.delete(url = URL, headers = headers)
    print(r.status_code)
    data = r.json()
    print(data)
soft_delete_job(10)

#to hard delete job by id
def hard_delete_job(id):
    URL = "http://127.0.0.1:5000/jobs/"+str(id) 
    headers = CaseInsensitiveDict()
    headers["x-access-tokens"] = token
    r = requests.delete(url = URL, headers = headers)
    print(r.status_code)
    data = r.json()
    print(data)
hard_delete_job(10)