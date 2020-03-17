#!/bin/bash
function get_tomcat_status {
	#a. 判断是否有正在运行的进程
	while read row; do
		return 1;
	done < <(ps -ef|grep -v "grep"|grep "tomcat")
	return 0;
}
function get_conf_file {
	local fileList=()
	fileList=("/usr/local/tomcat/conf/server.xml")
	echo ${fileList[@]}
}
function tomcatScan {
	userList=()
	while read -r tmp; do
		userList+=($tmp)	
	done < <(ps -ef|grep -v grep|grep tomcat|sed -e 's/\s\{1,\}/ /g'|cut -d" " -f1)
	for user in ${userList[@]}; do #"root" in ${user[@]} ]]; then
		if [[ $user == "root" ]]; then
			RootUserIfDisable=false
		fi
	done
	confFile="/usr/local/tomcat/conf/web.xml"
	shbinDir="/usr/local/tomcat/bin/"
	get_tomcat_status
	if [[ $? -eq 1 ]]; then
		tomcatScanResult="["
		fileList=()
		for file in $(get_conf_file); do
			fileList+=($file)
		done
		for i in ${!fileList[@]}; do
			if [[ $i == 0 ]]; then
				tomcatScanResult+="{\"filename\":\"${fileList[$i]}\",\"detail\":{"
			else
				tomcatScanResult+=",{\"filename\":\"${fileList[$i]}\",\"detail\":{"
			fi
			perm=$(stat -c %a ${fileList[$i]})
			#serverToken=$(awk -f awkxmlfilter /usr/local/tomcat/conf/server.xml |grep -E "server[[:blank:]]*="|awk 'BEGIN{FS="="}{print $2}'|cut -d"\"" -f2)
			serverToken=$(awk -f awkxmlfilter ${fileList[$i]}|grep -E "server[[:blank:]]*="|awk 'BEGIN{FS="="}{print $2}'|cut -d"\"" -f2)
			ajpPort=$(awk -f awkajpfilter ${fileList[$i]} |grep -E "[[:blank:]]*port[[:blank:]]*=[[:blank:]]*\""|awk 'BEGIN{FS="="}{print $2}'|cut -d"\"" -f2)
			shutdownPort=$(awk -f awkshutdownfilter ${fileList[$i]}|awk -F"port" '{split($2,test,"\"");print test[2]}')
			shutdownStr=$(awk -f awkshutdownfilter ${fileList[$i]}|awk -F"shutdown" '{split($2,test,"\"");print test[2]}')
			listingsParam=$(awk -f awkxmlfilter $confFile|awk '{if($0 ~ "listings"){getline out;print out}}'|awk '{FS=">";split($0,arr);FS="<";split(arr[2],arr2);print arr2[1]}')
			while read row; do
				if [ ${row} -gt 744 -o ${row:0-2} -gt 44 ]; then
				shPermLE744=false
				break
				fi
			done < <(ls $shbinDir|grep .sh|xargs -I {} stat -c %a ${shbinDir}{} 2>/dev/null)
			if [[ -n serverToken ]]; then
				if [[ -n $(echo $serverToken|grep -i "tomcat") ]]; then
					serverTokenIfChange=false
				else
					serverTokenIfChange=true
				fi
			else
				serverTokenIfChange=false
			fi
			if [[ -z $ajpPort ]]; then
				ajpIfDisableOrChange=true
			elif [[ $ajpPort == "8009" ]]; then
				ajpIfDisableOrChange=false
			else
				ajpIfDisableOrChange=true
			fi
			if [[ $shutdownPort == "-1" ]]; then
				shutdownPortIfDisableOrChange=true
				shutdownStrIfChange=true
			elif [[ $shutdownPort == "8005" ]]; then
				shutdownPortIfDisableOrChange=false
				if [[ $shutdownStr == "SHUTDOWN" ]]; then
					shutdownStrIfChange=false
				else
					shutdownStrIfChange=true
				fi
			else
				if [[ $shutdownStr == "SHUTDOWN" ]]; then
					shutdownStrIfChange=false
				else
					shutdownStrIfChange=true
				fi
				shutdownPortIfDisableOrChange=true
			fi
			if [[ $listingsParam == "true" ]]; then
				dirListIfDisable=false
			else
				dirListIfDisable=true
			fi
			tomcatScanResult+="\"serverTokenIfChange\":\"${serverTokenIfChange}\","
			tomcatScanResult+="\"ajpIfDisableOrChange\":\"${ajpIfDisableOrChange}\","
			tomcatScanResult+="\"shutdownPortIfDisableOrChange\":\"${shutdownPortIfDisableOrChange}\","
			tomcatScanResult+="\"shutdownStrIfChange\":\"${shutdownStrIfChange}\","
			tomcatScanResult+="\"dirListIfDisable\":\"${dirListIfDisable}\","
			if $serverTokenIfChange ; then
				echo -e "\033[32m [+] serverTokenIfChange : $serverTokenIfChange \033[0m"
			else
				echo -e "\033[31m [-] serverTokenIfChange : $serverTokenIfChange \033[0m"
			fi
			if $ajpIfDisableOrChange ; then
				echo -e "\033[32m [+] ajpIfDisableOrChange: $ajpIfDisableOrChange \033[0m"
			else
				echo -e "\033[31m [-] ajpIfDisableOrChange: $ajpIfDisableOrChange \033[0m"
			fi
			if $shutdownPortIfDisableOrChange ; then
				echo -e "\033[32m [+] shutdownPortIfDisableOrChange : $shutdownPortIfDisableOrChange \033[0m"
			else
				echo -e "\033[31m [-] shutdownPortIfDisableOrChange : $shutdownPortIfDisableOrChange \033[0m"
			fi
			if $shutdownStrIfChange ; then
				echo -e "\033[32m [+] shutdownStrIfChange : $shutdownStrIfChange \033[0m"
			else
				echo -e "\033[31m [-] shutdownStrIfChange : $shutdownStrIfChange \033[0m"
			fi
			if $dirListIfDisable ; then
				echo -e "\033[32m [+] dirListIfDisable : $dirListIfDisable \033[0m"
			else
				echo -e "\033[31m [-] dirListIfDisable : $dirListIfDisable \033[0m"
			fi
			if $RootUserIfDisable ; then
				echo -e "\033[32m [+] RootUserIfDisable : $RootUserIfDisable \033[0m"
			else
				echo -e "\033[31m [-] RootUserIfDisable : $RootUserIfDisable \033[0m"
			fi
			if [ ${perm} -le 600 -a ${perm:0-2} -le 0 ]; then
				permLE600=true
			else
				permLE600=false
			fi
			if $shPermLE744 ; then
				echo -e "\033[32m [+] perm less than or equal 744 : $shPermLE744 \033[0m"
			else
				echo -e "\033[31m [-] perm less than or equal 744 : $shPermLE744 \033[0m"
			fi
			tomcatScanResult+="\"shPermLE744\":\"${shPermLE744}\""
			tomcatScanResult+='}'
			tomcatScanResult+='}'
		done
		tomcatScanResult+=']'
		tomcatScanResult="{\"tomcatScanResultList\":${tomcatScanResult},\"RootUserIfDisable\":\"${RootUserIfDisable}\"}"
		#echo $tomcatScanResult 
		#echo $tomcatScanResult |jq
	
	else
		tomcatScanResult={}
	fi
	export tomcatScanResult=$tomcatScanResult
}
