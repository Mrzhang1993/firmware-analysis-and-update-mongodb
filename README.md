# firmware-analysis-and-update-mongodb
firmware analysis and update  mongodb on the servicer
## trommel
利用trommel工具对解压好的固件进行安全性分析
## 脚本文件的使用
在运行mainfunction.py脚本之前，注意更改mainfunction.py,dataupdate.sh,mongodbReport.py中涉及到路径和数据库链接参数。
### mainfunction.py
使用指令 python mainfunction.py 来进行主程序的运行
### dataupdate.sh
对一个解压缩好的固件目录进行具体trommel分析，tmpfile处理，mongdb信息存储，具体的shell指令进行文件的调用。
### firmwareNameMD5.py
以厂商为单位，通过分析厂商文件夹下的所有abstract文件获得整个厂商包含固件名和每个固件对应的MD5，即：firmwarename and MD5 are list，下标一一对应。
### splitstring.py
通过修改trommel工具，生成报告对应的不同类型的中间文件tmpfile，tmpfile文件的内容有所差别，splitstring.py需要对每个tmpfile文件单独处理，得到想要的存储信息。
### mongodbReport.py
进行数据库的链接，更新数据库信息。
