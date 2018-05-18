#!_*_coding:utf-8_*_
'''
单独对固件提取文件进行分析，获取无.sh后缀名但文件首行是*sh的文件，将文件名和路径存储到tmpfile10中
'''

import os
import argparse

parser = argparse.ArgumentParser(description="extmpfile10: save the information into the tmpfile10")
parser.add_argument("-p", "--path", required=True, help="trommel search for the firmware extracted's directory")
parser.add_argument("-t", "--tmpfilepath", required=True, help="the tmpfile path")

args = vars(parser.parse_args())

analysepath = args['path'].strip('"')
tmpfilepath = args['tmpfilepath'].strip('"')

# analysepath = '/home/zhangle/test/trommel_test/test_directory/IP-COM/_b_20160127055416_W175AP Highpower version.zip.extracted'
# tmpfilepath = '/home/zhangle/test/trommel_test/dir/tplink/0fb46d6247c79a9533835c84617f7caf36d715d6.img/tmpfile10'
tmpfilepath10 = tmpfilepath + '/tmpfile10'

# 对单独文件进行单独处理
def extractedsh(ff, tmpfilepath10, names):
	file = open(ff,'rb')     # 读取文件的二进制方式，读取文件的第一行
	line = file.readline()
	if line.find('sh') != -1 and line.find('#!') != -1:    # 文件的第一行中包含#！和sh则判断此文件是shell文件
		savepath = '.'+ff[ff.find('extracted')+9:]
		tmp = open(tmpfilepath10, 'a')
		if names in [".bashrc","rcS"]:
			tmp.write(names+'(启动脚本)'+' & '+savepath+'\n')
		else:
			tmp.write(names+' & '+savepath+'\n')

def main():
	for root, dirs, files in os.walk(analysepath):
		for names in files:
			ff = os.path.join(root,names)
			#Ignore any symlinks
			if not os.path.islink(ff):
				#Ignore the /dev directory. Script has problems with files in this directory
				dev_kw = "/dev/"
				if not dev_kw in ff:
					if analysepath and tmpfilepath10: 
						extractedsh(ff, tmpfilepath10, names)
						



if __name__ == '__main__':
	main()