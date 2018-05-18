#!_*_coding:utf-8_*_
'''
每个文件中的存储格式有些不同，需要进行单独处理。
'''


def strsplit1(linestr):
    strtmp = linestr.strip().split('&')
    # dictstr = {'keyword':'','filepath':'','filetype':'','count':0}
    dictstr = {}
    dictstr['keyword'] = strtmp[0].strip()[1:len(strtmp[0])-2]
    dictstr['filepath'] = strtmp[1].strip()
    dictstr['filetype'] = strtmp[2].strip()
    dictstr['count'] = strtmp[3].strip()
    return dictstr


def strsplit2(linestr):   
    strtmp = linestr.strip().split('&')
    # dictstr = {'componentname': '', 'CVEnumber': '', 'describe': ''}
    dictstr = {}
    if len(strtmp) == 3:
        dictstr['componentname'] = strtmp[0].strip()[4:len(strtmp[0])]
        dictstr['CVEnumber'] = strtmp[1].strip()
        dictstr['describe'] = strtmp[2].strip()
    else:
        if strtmp[0].strip()[0:4] == 'AAAA':
            dictstr['componentname'] = strtmp[0].strip()[4:len(strtmp[0])]
            dictstr['CVEnumber'] = strtmp[1].strip()
        else:
            dictstr['CVEnumber'] = strtmp[0].strip()
            dictstr['describe'] = strtmp[1].strip()
    return dictstr


def strsplit3(linestr):     
    strtmp = linestr.strip().split('&')
    # dictstr = {'componentname': '', 'CVEnumber': ''}
    dictstr = {}
    dictstr['componentname'] = strtmp[0].strip()[4:len(strtmp[0])]
    dictstr['CVEnumber'] = strtmp[1].strip()
    return dictstr


def strsplit4(linestr):     
    strtmp = linestr.strip().split('&')
    # dictstr = {'filename': '', 'filetype': '', 'filepath': ''}
    dictstr = {}
    dictstr['filename'] = strtmp[0].strip()[4:len(strtmp[0])]
    dictstr['filetype'] = strtmp[1].strip()
    dictstr['filepath'] = strtmp[2].strip()
    return dictstr


def strsplit5(linestr):
    strtmp = linestr.strip().split('&')
    # dictstr = {'string_tpye': '', 'property_value': '', 'filetype': '', 'filepath': ''}
    dictstr = {}
    dictstr['string_tpye'] = strtmp[0].strip()
    findindex = strtmp[1].strip().find('.com')   
    if findindex != -1:
        dictstr['property_value'] = strtmp[1].strip()[0:findindex+4]
    elif strtmp[1].strip().find('.org') != -1:
        dictstr['property_value'] = strtmp[1].strip()[0:findindex+4]
    else:
        dictstr['property_value'] = strtmp[1].strip()
    dictstr['filetype'] = strtmp[2].strip()
    dictstr['filepath'] = strtmp[3].strip()
    return dictstr


def strsplit6(linestr):     
    strtmp = linestr.strip().split('&')
    # dictstr = {'name': '', 'type': '', 'path': ''}
    dictstr = {}
    dictstr['name'] = strtmp[0].strip()
    dictstr['type'] = strtmp[1].strip()
    dictstr['path'] = strtmp[2].strip()
    return dictstr


def strsplit7(linestr):     # case3 : 5,6,7,8,9,11
    strtmp = linestr.strip().split('&')
    # dictstr = {'name': '', 'type': '', 'path': ''}
    dictstr = {}
    dictstr['name'] = strtmp[0].strip()
    dictstr['type'] = strtmp[1].strip()
    dictstr['path'] = strtmp[2].strip()
    return dictstr


def strsplit8(linestr):     
    strtmp = linestr.strip().split('&')
    # dictstr = {'name': '', 'type': '', 'path': ''}
    dictstr = {}
    dictstr['name'] = strtmp[0].strip()
    dictstr['type'] = strtmp[1].strip()
    dictstr['path'] = strtmp[2].strip()
    return dictstr


def strsplit9(linestr):     # case3 : 5,6,7,8,9,11
    strtmp = linestr.strip().split('&')
    # dictstr = {'type': '', 'path': ''}
    dictstr = {}
    dictstr['type'] = strtmp[0].strip()
    dictstr['path'] = strtmp[1].strip()
    return dictstr


def strsplit10(linestr):     # case3 : 5,6,7,8,9,11
    strtmp = linestr.strip().split('&')
    # dictstr = {'scriptname': '', 'path': ''}
    dictstr = {}
    dictstr['scriptname'] = strtmp[0].strip()
    dictstr['path'] = strtmp[1].strip()
    return dictstr


def strsplit11(linestr):     # case3 : 5,6,7,8,9,11
    strtmp = linestr.strip().split('&')
    # dictstr = {'name': '', 'type': '', 'path': ''}
    dictstr = {}
    dictstr['name'] = strtmp[0].strip()
    dictstr['type'] = strtmp[1].strip()
    dictstr['path'] = strtmp[2].strip()
    return dictstr


def strsplit12(linestr):      # case1 : 1,12
    strtmp = linestr.strip().split('&')
    # dictstr = {'keyword':'','filepath':'','filetype':'','count':0}
    dictstr = {}
    dictstr['keyword'] = strtmp[0].strip()[1:len(strtmp[0])-2]
    dictstr['filepath'] = strtmp[1].strip()
    dictstr['filetype'] = strtmp[2].strip()
    dictstr['count'] = strtmp[3].strip()
    return dictstr


def strsplit13(linestr):     # case3 : 5,6,7,8,9,11
    strtmp = linestr.strip().split('&')
    # dictstr = {'type': '', 'path': '', 'related_content': ''}
    dictstr = {}
    dictstr['type'] = strtmp[0].strip()
    dictstr['path'] = strtmp[1].strip()
    dictstr['related_content'] = strtmp[2].strip()
    return dictstr

# 每个文件中的存储格式有些不同，需要进行单独处理。
def strsplit(number, linestr):
    if number == 1:
        dictlist = strsplit1(linestr)
    elif number == 2:
        dictlist = strsplit2(linestr)
    elif number == 3:
        dictlist = strsplit3(linestr)
    elif number == 4:
        dictlist = strsplit4(linestr)
    elif number == 5:
        dictlist = strsplit5(linestr)
    elif number == 6:
        dictlist = strsplit6(linestr)
    elif number == 7:
        dictlist = strsplit7(linestr)
    elif number == 8:
        dictlist = strsplit8(linestr)
    elif number == 9:
        dictlist = strsplit9(linestr)
    elif number == 10:
        dictlist = strsplit10(linestr)
    elif number == 11:
        dictlist = strsplit11(linestr)
    elif number == 12:
        dictlist = strsplit12(linestr)
    elif number == 13:
        dictlist = strsplit13(linestr)
    return dictlist