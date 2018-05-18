#!_*_coding:utf-8_*_
import argparse
import mongodbReport
import splitstring2


parser = argparse.ArgumentParser(description="dataupdate: save the data in the report into the Mongodb")
parser.add_argument("-p", "--path", required=True, help="tmpfile directory path")     
parser.add_argument("-m", "--md5", required=True, help="md5 of a firmware")
parser.add_argument("-r", "--reportpath", required=True, help="report's path")

args = vars(parser.parse_args())

path = args['path'].strip('"')
md5 = args['md5']
reportpath = args['reportpath'].strip('"')

# 每执行一次main()则更新一个固件对应的report,reportpath信息
def main():

    mongodbReport.dataInsert(md5,reportpath)      # 先将report,reprotpath的结构增加进每个MD5对应的固件信息中
    for i in range(1, 14):
        filename = open(path + '/tmpfile' + str(i), 'rt')
        text = []
        if i == 5:    # tmpfile5 need some special deal  需要删除tmpfile5中重复的信息
            strlist = []
            for line in filename.readlines():
                if line == '\n':
                    continue
                else:
                    tmpstr = line.strip()
                    if tmpstr == '\n':
                        continue
                    else:
                        if tmpstr in strlist:   # remove the same string
                            continue
                        else:
                            strlist.append(tmpstr)
                            text.append(splitstring2.strsplit(i, line))
        else:
            for line in filename.readlines():      # 其余文件将每行记录进行分割处理
                if line == '\n':
                    continue
                else:
                    text.append(splitstring2.strsplit(i, line))
        mongodbReport.dataUpdate(md5, i, text)     # 只更新一个文件对应的值


if __name__ == '__main__':
    main()
