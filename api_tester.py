import unittest
from test import testUserApi, testJobApi

if __name__ == '__main__':
	suite = unittest.TestLoader().loadTestsFromTestCase(testUserApi)
	unittest.TextTestRunner().run(suite)
	suite1 = unittest.TestLoader().loadTestsFromTestCase(testJobApi)
	unittest.TextTestRunner().run(suite1)