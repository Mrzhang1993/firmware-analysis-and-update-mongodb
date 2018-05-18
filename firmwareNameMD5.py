#!_*_coding:utf-8_*_

def file_firmname_md5(file_name):
    filename = open(file_name, 'rt')
    firmwarename = ''
    md5 = ''
    count = 1
    for line in filename.readlines():
        if count == 1:
            firmwarename = line.strip().split(':')[1]    # the first line
        elif count == 2:
            md5 =  line.strip().split(':')[1]    # the second line
            break
        count += 1
    return firmwarename, md5


def firmwarename_md5(path, filenames):   # path:每个厂家下的目录，filenames:每个厂家文件夹下包含的所有文件
    firmwarenames = []
    md5s = []
    for filename in filenames:
        abstract = filename.strip()[-8:]
        if abstract == 'abstract':      # 从以abstrct结尾的文件提取固件名和MD5
            firmwarename, md5 = file_firmname_md5(path+'/'+filename)    # 进行单独处理
            firmwarenames.append(firmwarename)
            md5s.append(md5)
    return firmwarenames, md5s   # 返回一个厂商包括的固件名和每个固件对应的MD5,firmwarenames and md5s are list



# number = file_md5("/home/zhangle/test/trommel_test/test_directory/_0fb46d6247c79a9533835c84617f7caf36d715d6.img_abstract")
# print(number)