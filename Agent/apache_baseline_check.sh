#!/bin/bash
function get_apache_status {
	#a. 判断是否有正在运行的进程
	while read row; do
		return 1;
	done < <(ps -ef|grep -v "grep"|grep "httpd")
	return 0;
}
function get_conf_file {
	local fileList=()
	fileList=("/etc/httpd/conf/httpd.conf")
	echo ${fileList[@]}
}
function clean_conf_file {
	cat "$1" |sed '/^\s*#/d' > /tmp/apachefile
	echo "/tmp/apachefile"
	#local fileList=()
	#count=1
	#for file in $(get_meta_conf_file); do
	#	local confile="/tmp/apacheconf${count}"
	#	cat "${file}"|sed '/^\s*#/d' > $confile
	#	fileList+=($confile)
	#	count=$(( $count + 1))
	#done
	#echo ${fileList[@]}
}
function apacheScan {
	userList=()
	while read -r tmp; do
		userList+=($tmp)	
	done < <(ps -ef|grep -v grep|grep httpd|sed -e 's/\s\{1,\}/ /g'|cut -d" " -f1)
	for user in ${userList[@]}; do #"root" in ${user[@]} ]]; then
		if [[ $user == "root" ]]; then
			RootUserIfDisable=false
		fi
	done
	get_apache_status
	if [[ $? -eq 1 ]]; then
		apacheScanResult="["
		fileList=()
		for file in $(get_conf_file); do
			fileList+=($file)
		done
		for i in ${!fileList[@]}; do
			if [[ $i == 0 ]]; then
				apacheScanResult+="{\"filename\":\"${fileList[$i]}\",\"detail\":{"
			else
				apacheScanResult+=",{\"filename\":\"${fileList[$i]}\",\"detail\":{"
			fi
			tmpFilename=$(clean_conf_file ${fileList[$i]})
			perm=$(stat -c %a ${tmpFilename})
			user=$(grep -i -e '^\s*User' ${tmpFilename}|awk '{print $2}')
			group=$(grep -i -e '^\s*Group' ${tmpFilename}|awk '{print $2}')
			serverRoot=$(grep -i -e "serverRoot" ${tmpFilename}|awk '{print $2}'|cut -d"\"" -f2)
			serverRootPerm=$(grep -i -e "serverRoot" ${tmpFilename}|awk '{print $2}'|cut -d"\"" -f2|xargs -I {} stat -c %a {})
			errorlogPerm=$(grep -i -e "ErrorLog" ${tmpFilename}|awk '{print $2}'|cut -d"\"" -f2|xargs -I {} stat -c %a "${serverRoot}/"{})
			logLevel=$(grep -i -e "LogLevel" ${tmpFilename}|cut -d" " -f2)
			dirList=$(grep -i -E -e 'Options.+indexes' ${tmpFilename})
			requestMethodLimit=$(grep -i -E -e 'LimitExcept' ${tmpFilename})
			defaultIndexFile="${serverRoot}/conf.d/welcome.conf"
			serverSignature=$(grep -i -e "ServerSignature" ${tmpFilename}|awk -F "ServerSignatur" '{split($2,arr," ");print arr[2]}')
			serverToken=$(grep -i -e "ServerToken" ${tmpFilename}|awk -F "ServerToken" '{split($2,arr," ");print arr[2]}')			
			if [[ "$user" == "root" ]]; then
				userIfNotRoot=false
			else
				userIfNotRoot=true
			fi

			if [[ "$group" == "root" ]]; then
				groupIfNotRoot=false
			else
				groupIfNotRoot=true
			fi
			if [ ${serverRootPerm} -gt 744 -o ${serverRootPerm:0-2} -gt 44 ]; then
				serverRootPermLE744=false
			else
				serverRootPermLE744=true
			fi
			if [ ${errorlogPerm} -gt 644 -o ${errorlogPerm} -gt 44 ]; then
				errorlogPermLE644=false
			else
				errorlogPermLE644=true
			fi
			#for tmp in ( "debug" "info" "notice" ); then
			tmp=("debug" "info" "notice")
			for tmp in ${tmp[@]}; do
				if [[ "$logLevel" =~ "$tmp" ]]; then
					logLevelGENotice=true
					break
				fi
				logLevelGENotice=false
			done
			if [[ -n $dirList ]]; then
				dirListIfDisable=true
			else
				dirListIfDisable=false
			fi
			if [[ -n $requestMethodLimit ]]; then
				requestMethodIfLimit=true
			else
				requestMethodIfLimit=false
			fi
			if [[ -f $defaultIndexFile ]]; then
				defaultIndexFileIfDel=false
			else
				defaultIndexFileIfDel=true
			fi
			if [[ "$serverSignature" =~ "Off" ]]; then
				serverSignatureIfDisable=true
			else
				serverSignatureIfDisable=false
			fi
			if [[ "$serverToken" =~ "Prod" ]]; then
				serverTokenIfChange=true
			else
				serverTokenIfChange=false
			fi
			
			apacheScanResult+="\"userIfNotRoot\":\"${userIfNotRoot}\","
			apacheScanResult+="\"groupIfNotRoot\":\"${groupIfNotRoot}\","
			apacheScanResult+="\"serverRootPermLE744\":\"${serverRootPermLE744}\","
			apacheScanResult+="\"errorlogPermLE644\":\"${errorlogPermLE644}\","
			apacheScanResult+="\"logLevelGENotice\":\"${logLevelGENotice}\","
			apacheScanResult+="\"dirListIfDisable\":\"${dirListIfDisable}\","
			apacheScanResult+="\"requestMethodIfLimit\":\"${requestMethodIfLimit}\","
			apacheScanResult+="\"defaultIndexFileIfDel\":\"${defaultIndexFileIfDel}\","
			apacheScanResult+="\"serverTokenIfChange\":\"${serverTokenIfChange}\","
			apacheScanResult+="\"serverSignatureIfDisable\":\"${serverSignatureIfDisable}\","
			if $userIfNotRoot ; then
				echo -e "\033[32m [+] userIfNotRoot: $userIfNotRoot \033[0m"
			else
				echo -e "\033[31m [-] userIfNotRoot: $userIfNotRoot \033[0m"
			fi
			if $groupIfNotRoot ; then
				echo -e "\033[32m [+] groupIfNotRoot : $groupIfNotRoot \033[0m"
			else
				echo -e "\033[31m [-] groupIfNotRoot : $groupIfNotRoot \033[0m"
			fi
			if $serverRootPermLE744 ; then
				echo -e "\033[32m [+] serverRootPermLE744 : $serverRootPermLE744 \033[0m"
			else
				echo -e "\033[31m [-] serverRootPermLE744 : $serverRootPermLE744 \033[0m"
			fi
			if $errorlogPermLE744 ; then
				echo -e "\033[32m [+] errorlogPermLE744 : $errorlogPermLE744 \033[0m"
			else
				echo -e "\033[31m [-] errorlogPermLE744 : $errorlogPermLE744 \033[0m"
			fi
			if $logLevelGENotice ; then
				echo -e "\033[32m [+] logLevelGENotice : $logLevelGENotice \033[0m"
			else
				echo -e "\033[31m [-] logLevelGENotice : $logLevelGENotice \033[0m"
			fi
			if $dirListIfDisable ; then
				echo -e "\033[32m [+] dirListIfDisable : $dirListIfDisable \033[0m"
			else
				echo -e "\033[31m [-] dirListIfDisable : $dirListIfDisable \033[0m"
			fi
			if $requestMethodIfLimit ; then
				echo -e "\033[32m [+] requestMethodIfLimit : $requestMethodIfLimit \033[0m"
			else
				echo -e "\033[31m [-] requestMethodIfLimit : $requestMethodIfLimit \033[0m"
			fi
			if $defaultIndexFileIfDel ; then
				echo -e "\033[32m [+] defaultIndexFileIfDel : $defaultIndexFileIfDel \033[0m"
			else
				echo -e "\033[31m [-] defaultIndexFileIfDel : $defaultIndexFileIfDel \033[0m"
			fi
			if $serverTokenIfChange ; then
				echo -e "\033[32m [+] serverTokenIfChange : $serverTokenIfChange \033[0m"
			else
				echo -e "\033[31m [-] serverTokenIfChange : $serverTokenIfChange \033[0m"
			fi
			if $serverSignatureIfDisable ; then
				echo -e "\033[32m [+] serverSignatureIfDisable : $serverSignatureIfDisable \033[0m"
			else
				echo -e "\033[31m [-] serverSignatureIfDisable : $serverSignatureIfDisable \033[0m"
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
			if $permLE600 ; then
				echo -e "\033[32m [+] permLE600 : $permLE600 \033[0m"
			else
				echo -e "\033[31m [-] permLE600 : $permLE600 \033[0m"
			fi
			apacheScanResult+="\"permLE600\":\"${permLE600}\""
			apacheScanResult+='}'
			apacheScanResult+='}'
		done
		apacheScanResult+=']'
		apacheScanResult="{\"apacheScanResultList\":${apacheScanResult},\"RootUserIfDisable\":\"${RootUserIfDisable}\"}"
		#echo $apacheScanResult 
		echo $apacheScanResult |jq
	
	else
		apacheScanResult={}
	fi
	export apacheScanResult=$apacheScanResult
}
#apacheScan
