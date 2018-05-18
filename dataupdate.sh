#!/bin/bash

# DATAUPDATE_PATH="/home/zhangle/test/dataupdate2.0"    # local test
# TROMMEL_PATH="/home/zhangle/test/dataupdate2.0/trommel"    # local test
DATAUPDATE_PATH="/home/ubuntu/test/dataupdate2.0"           # servicer
TROMMEL_PATH="/home/ubuntu/test/dataupdate2.0/trommel"     # servicer
# tmpPath="/home/zhangle/test/trommel_test/test_directory/_0fb46d6247c79a9533835c84617f7caf36d715d6.img.extractedDirs"


# analyseDir="/home/zhangle/test/trommel_test/test_directory/_0fb46d6247c79a9533835c84617f7caf36d715d6.img.extracted"
analyseDir="$1"
# outputfile="/home/zhangle/test/trommel_test/test_report/"   # local test
outputfile="/home/ubuntu/test/trommel_reportfile/"   # servicer
tmp="$2"

#调用trommel分析工具

cd $TROMMEL_PATH
python trommel.py -p "${analyseDir}" -o $outputfile -t "${tmp}" >/dev/null 2>&1

#获取无.sh后缀名但文件首行是*sh的文件
cd $DATAUPDATE_PATH
python extmpfile10.py -p "${analyseDir}" -t "${tmp}"


# 分析tmpfile,将信息存储到Mongodb中
cd $DATAUPDATE_PATH
python dataupdate.py -p "${tmp}" -m "$3" -r "$4"


# rm -R $tmpPath
