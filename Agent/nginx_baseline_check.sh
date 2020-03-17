#!/bin/bash
function get_nginx_status {
	#a. 判断是否有正在运行的进程
	while read row; do
		return 1;
	done < <(ps -ef|grep -v "grep"|grep "nginx")
	return 0;
}
function get_conf_file {
	local fileList=()
	fileList=("/etc/nginx/nginx.conf")
	echo ${fileList[@]}
}
function nginxScan {
	userList=()
	while read -r tmp; do
		userList+=($tmp)	
	done < <(ps -ef|grep -v grep|grep nginx-|sed -e 's/\s\{1,\}/ /g'|cut -d" " -f1)
	for user in ${userList[@]}; do #"root" in ${user[@]} ]]; then
		if [[ $user == "root" ]]; then
			RootUserIfDisable=false
		fi
	done
	get_nginx_status
	if [[ $? -eq 1 ]]; then
		nginxScanResult="["
		fileList=()
		for file in $(get_conf_file); do
			fileList+=($file)
		done
		for i in ${!fileList[@]}; do
			if [[ $i == 0 ]]; then
				nginxScanResult+="{\"filename\":\"${fileList[$i]}\",\"detail\":{"
			else
				nginxScanResult+=",{\"filename\":\"${fileList[$i]}\",\"detail\":{"
			fi
			portID=6379
			bindIP=127.0.0.1
			protectMode=no
			requirePass=false
			renameCommand=()
			perm=$(stat -c %a ${fileList[$i]})
			while read row; do
				row=$(echo $row|sed -e 's/^[ ]*//g')
				if [[ "$row" =~ ("#".*)|(^$) ]]; then
					continue
				fi
				if [[ "$row" =~ server_tokens[:blank:]* ]]; then
					serverToken=$(echo $row|cut -d" " -f2)
				fi
				if [[ "$row" =~ ssl[:blank:]* ]]; then
					ssl=$(echo $row|cut -d" " -f2)
				fi
				if [[ "$row" =~ "$request_method".* ]]; then
					requestMethodIfSet=true
				fi
				if [[ "$row" =~ limit_conn_zone.* ]]; then
					connectionNumIfSet=true
				fi
				if [[ "$row" =~ .*buffer_size.* ]]; then
					bufferSizeIfSet=true
				fi
			done < <(cat ${fileList[$i]})
			if [[ serverToken =~ off ]]; then
				serverTokenIfDisable=true
			else
				serverTokenIfDisable=false
			fi
			if [[ ssl =~ on ]]; then
				sslIfEnable=true
			else
				sslIfEnable=false
			fi
			if [[ $requestMethodIfSet != true ]]; then
				requestMethodIfSet=false
			fi
			if [[ $connectionNumIfSet != true ]]; then
				connectionNumIfSet=false
			fi
			if [[ $bufferSizeIfSet != true ]]; then
				bufferSizeIfSet=false
			fi
			nginxScanResult+="\"serverTokenIfDisable\":\"${serverTokenIfDisable}\","
			nginxScanResult+="\"sslIfEnable\":\"${sslIfEnable}\","
			nginxScanResult+="\"requestMethodIfSet\":\"${requestMethodIfSet}\","
			nginxScanResult+="\"connectionNumIfSet\":\"${connectionNumIfSet}\","
			nginxScanResult+="\"bufferSizeIfSet\":\"${bufferSizeIfSet}\","
			if $serverTokenIfDisable ; then
				echo -e "\033[32m [+] serverTokenIfDisable : $serverTokenIfDisable \033[0m"
			else
				echo -e "\033[31m [-] serverTokenIfDisable : $serverTokenIfDisable \033[0m"
			fi
			if $sslIfEnable ; then
				echo -e "\033[32m [+] sslIfEnable: $sslIfEnable \033[0m"
			else
				echo -e "\033[31m [-] sslIfEnable: $sslIfEnable \033[0m"
			fi
			if $requestMethodIfSet ; then
				echo -e "\033[32m [+] requestMethodIfSet : $requestMethodIfSet \033[0m"
			else
				echo -e "\033[31m [-] requestMethodIfSet : $requestMethodIfSet \033[0m"
			fi
			if $connectionNumIfSet ; then
				echo -e "\033[32m [+] connectionNumIfSet : $connectionNumIfSet \033[0m"
			else
				echo -e "\033[31m [-] connectionNumIfSet : $connectionNumIfSet \033[0m"
			fi
			if $bufferSizeIfSet ; then
				echo -e "\033[32m [+] bufferSizeIfSet : $bufferSizeIfSet \033[0m"
			else
				echo -e "\033[31m [-] bufferSizeIfSet : $bufferSizeIfSet \033[0m"
			fi
			if [ ${perm} -le 600 -a ${perm:0-2} -le 0 ]; then
			#if [ ${perm:0-2} -le 0 ]; then
				permLE600=true
			else
				permLE600=false
			fi
			if $permLE600 ; then
				echo -e "\033[32m [+] perm less than or equal 600 : $permLE600 \033[0m"
			else
				echo -e "\033[31m [-] perm less than or equal 600 : $permLE600 \033[0m"
			fi
			nginxScanResult+="\"permLE600\":\"${permLE600}\""
			nginxScanResult+='}'
			nginxScanResult+='}'
		done
		nginxScanResult+=']'
		nginxScanResult="{\"nginxScanResultList\":${nginxScanResult},\"RootUserIfDisable\":\"${RootUserIfDisable}\"}"
		#echo $nginxScanResult 
		#echo $nginxScanResult |jq
	else
		nginxScanResult={}
	fi
	export nginxScanResult=$nginxScanResult
}
#nginxScan
