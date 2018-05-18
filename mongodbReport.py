#!_*_coding:utf-8_*_

from pymongo import MongoClient

conn = MongoClient('10.200.250.195', 27017)     #  connecte to the servicer's mongodb

db=conn.firmwareAnalytics     # connecte the special database

firmware = db.firmware      # the special collection



def dataInsert(md5, reportpath):
    reportclass = {'keywords': [], 'vulnerabilities': [], 'password_file': [], 'SSH/SSL': [], 'IP/URL/Email': [],
                   'configure_file': [], 'database_file': [], 'Blacklist': [], '/opt': [], 'shell_script': [],
                   'web_component': [], 'web_relevant': [], 'APK_relevant': []}
    # test2.insert({'name': 1, 'report': reportclass})
    firmware.update({'md5': md5}, {'$set': {'report': reportclass, 'reportpath':reportpath}})


def dataUpdate(md5, index, listtext):
    reportclass = ['title', 'keywords', 'vulnerabilities', 'password_file', 'SSH/SSL', 'IP/URL/Email',
                   'configure_file', 'database_file', 'Blacklist', '/opt', 'shell_script', 'web_component',
                   'web_relevant', 'APK_relevant']
    key = 'report.' + reportclass[index]
    firmware.update({'md5': md5}, {'$set': {key: listtext}})
