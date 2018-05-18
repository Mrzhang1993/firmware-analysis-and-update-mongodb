#!_*_coding:utf-8_*_
import os
import firmwareNameMD5
import subprocess
# path = '/home/zhangle/test/trommel_test/test_directory/'   # firmware extracted zong path   # local test
# tmppath = '/home/zhangle/test/trommel_test/dir'            # local test
path = '/usr/local/mydata/firmwareExtracted/'  # servicer
tmppath = '/home/ubuntu/test/dir'              # servicer

manufacturers = os.listdir(path)
count = 0
   # record the process
for onecompany in manufacturers:
	onecompanypath = path + onecompany
	filenames = os.listdir(onecompanypath)
	firmwarename, md5 = firmwareNameMD5.firmwarename_md5(onecompanypath, filenames)     # extracte the firmware name and md5 of each manufacturer,firmwarename and md5 are list
	for i in range(len(firmwarename)):
		count += 1            # record the number of execute the program
		print "%d doing-->%s/-->%s-->%s" % (count, onecompany, firmwarename[i], md5[i])      # output the information to the termainal
		record = open('/home/ubuntu/test/dataupdate2.0/record','a')
		record.write("%d doing-->%s/-->%s-->%s\n" % (count, onecompany, firmwarename[i], md5[i]))     # record the information in the record file
		record.close()

		extractedfile = '_'+firmwarename[i]+'.extracted'           # extracted firmware file's directory
		analysepath = '"'+onecompanypath+'/'+extractedfile+'"'           # trommel analyse path
		tmpfilepath = '"'+tmppath+'/'+onecompany+'/'+ firmwarename[i] +'"'       # tmpfile's path
		reportpath = '"'+onecompanypath+'/'+'_'+firmwarename[i][0:firmwarename[i].rfind('.')]+'.pdf'+'"'    # the analysis report path
		
		executeshellfile = 'bash dataupdate.sh ' + analysepath + ' ' + tmpfilepath + ' ' + md5[i] + ' ' + reportpath    # the each paraeter must be an independent whole
		child = subprocess.Popen(executeshellfile, shell=True)        # suprocess.Popen() execute the .sh file
		child.wait()
		print

print 'This mission was completed'