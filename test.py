import requests
import json
import unittest
from requests.structures import CaseInsensitiveDict

class testUserApi(unittest.TestCase):
	def __init__(self, *args, **kwargs):
		super(testUserApi, self).__init__(*args, **kwargs)
		self.__api_base_url = "http://localhost:5000"
		self.__signUp = "/signUp"
		self.__signIn = "/signIn"


	def test_signIn_wrong(self):
		headers = CaseInsensitiveDict()
		headers["Authorization"] = "Basic YWtobGFxOmF1"
		r = requests.post(self.__api_base_url + self.__signIn, headers = headers)
		self.assertEqual(r.status_code, 401)
		self.assertEqual(r.headers["Content-Type"], "application/json")

	def test_signIn_correct(self):
		headers = CaseInsensitiveDict()
		headers["Authorization"] = "Basic YWtobGFxOmFraGxhcTEyMzQ1"
		r = requests.post(self.__api_base_url + self.__signIn, headers = headers)
		self.assertEqual(r.status_code, 200)
		self.assertEqual(r.headers["Content-Type"], "application/json")

	def test_singUp_wrong(self):
		payload = {"fName":"akhlaq","lName":"mahar","email":"abc@gmail.com","userName":"akhlaq","password":"akhlaq12345"}
		r = requests.post(self.__api_base_url + self.__signUp, json=payload)
		self.assertEqual(r.status_code, 401)
		self.assertEqual(r.headers["Content-Type"], "application/json")

	def test_singUp_correct(self):
		payload = {"fName":"akhlaq","lName":"mahar","email":"abc1234@gmail.com","userName":"akhlaq3","password":"akhlaq12345"}
		r = requests.post(self.__api_base_url + self.__signUp, json=payload)
		self.assertEqual(r.status_code, 200)
		self.assertEqual(r.headers["Content-Type"], "application/json")



class testJobApi(unittest.TestCase):
	def __init__(self, *args, **kwargs):
		super(testJobApi, self).__init__(*args, **kwargs)
		self.__api_base_url = "http://localhost:5000/jobs"
		headers = CaseInsensitiveDict()
		#to get jwt token
		headers["Authorization"] = "Basic YWtobGFxOmFraGxhcTEyMzQ1"
		r = requests.post("http://localhost:5000/signIn", headers = headers)
		headers["x-access-tokens"] = r.json()["x-access-tokens"]
		self.__token = headers

	def test_get_all_jobs(self):
		r = requests.get(self.__api_base_url , headers = self.__token)
		self.assertEqual(r.status_code, 200)
		self.assertEqual(r.headers["Content-Type"], "application/json")
	
	def test_get_job_by_id_not_found(self):
		r = requests.get(self.__api_base_url + "?id=999", headers = self.__token)
		self.assertEqual(r.status_code, 404)
		self.assertEqual(r.headers["Content-Type"], "application/json")

	def test_get_job_by_id_found(self):
		r = requests.get(self.__api_base_url + "?id=2", headers = self.__token)
		self.assertEqual(r.status_code, 200)
		self.assertEqual(r.headers["Content-Type"], "application/json")

	def test_get_job_by_radius_found(self):
		r = requests.get(self.__api_base_url + "?lat=32.3915&longi=74.4342&kilometer=15", headers = self.__token)
		self.assertEqual(r.status_code, 200)
		self.assertEqual(r.headers["Content-Type"], "application/json")

	def test_add_job(self):
		payload = {"jobTitle":"Software Engineer","jobDesc":"multan","latitiude":"31.5204","longitude":"74.3587","jobRate":"30k"}
		r = requests.post(self.__api_base_url , headers = self.__token, json=payload)
		self.assertEqual(r.status_code, 200)
		self.assertEqual(r.headers["Content-Type"], "application/json")

	def test_edit_job(self):
		payload = {"jobTitle":"Senior Software Engineer","jobDesc":"Saudi Arabia"}
		r = requests.put(self.__api_base_url  + "/2", headers = self.__token, json=payload)
		self.assertEqual(r.status_code, 200)
		self.assertEqual(r.headers["Content-Type"], "application/json")