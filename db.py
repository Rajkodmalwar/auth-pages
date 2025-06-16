from pymongo import MongoClient

client = MongoClient("mongodb://localhost:27017/")
db = client['chatdb']
users = db['users']
tokens = db['tokens']
chathistory = db['chathistory']
