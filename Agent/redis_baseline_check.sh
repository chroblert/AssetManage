#!/bin/bash
function get_redis_status {
	#a. 判断是否有正在运行的进程
	while read row; do
		return 1;
	#done < <(ps -ef|grep -v "grep"|grep "redis")
	done < <(ps -ef|grep -v "grep"|grep "redis")
	return 0;
}
function get_redis_conf_file {
	local fileList=()
	fileList=("/etc/redis.conf")
	echo ${fileList[@]}
}
userList=()
while read -r tmp; do
	userList+=($tmp)	
done < <(ps -ef|grep -v grep|grep redis-|sed -e 's/\s\{1,\}/ /g'|cut -d" " -f1)
for user in ${userList[@]}; do #"root" in ${user[@]} ]]; then
	if [[ $user == "root" ]]; then
		RootUserIfDisable=false
	fi
done
function redisScan {
	get_redis_status
	if [[ $? -eq 1 ]]; then
		redisScanResult="["
		fileList=()
		for file in $(get_redis_conf_file); do
			fileList+=($file)
		done
		for i in ${!fileList[@]}; do
			if [[ $i == 0 ]]; then
				redisScanResult+="{\"filename\":\"${fileList[$i]}\",\"detail\":{"
			else
				redisScanResult+=",{\"filename\":\"${fileList[$i]}\",\"detail\":{"
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
				if [[ "$row" =~ port[:blank:]*[:digit:]* ]]; then
					portID=$(echo $row|cut -d" " -f2)
				fi
				if [[ "$row" =~ bind[:blank:]*[[:digit:].]* ]]; then
					bindIP=$(echo $row|cut -d" " -f2)
				fi
				if [[ "$row" =~ protected-mode[:blank:]*[:lower:]* ]]; then
					protectMode=$(echo $row|cut -d" " -f2)
				fi
				if [[ "$row" =~ requirepass[:blank:]*[:lower:]* ]]; then
					requirePass=$(echo $row|cut -d" " -f2)
				fi
				if [[ "$row" =~ rename-command[:blank:]* ]]; then
					tmpCommand=$(echo $row|cut -d" " -f2)
					renameCommand+=($tmpCommand)
				fi
			done < <(cat ${fileList[$i]})
			if [[ "$portID" == "6379" ]]; then
				portIDIfNotUse6379=false
			else
				portIDIfNotUse6379=true
			fi
			if $portIDIfNotUse6379 ; then
				echo -e "\033[32m [+] portIDIfNotUse6379 : $portIDIfNotUse6379 \033[0m"
			else
				echo -e "\033[31m [-] portIDIfNotUse6379 : $portIDIfNotUse6379 \033[0m"
			fi
			redisScanResult+="\"portIDIfNotUse6379\":\"${portIDIfNotUse6379}\","
			if [[ "$bindIP" =~ "127.0.0.1"|192.168.*|172.16.* ]]; then
				bindIPIfLocal=true
			else
				bindIPIfLocal=false
			fi
			if $bindIPIfLocal ; then
				echo -e "\033[32m [+] bindIPIfLocal : $bindIPIfLocal \033[0m"
			else
				echo -e "\033[31m [-] bindIPIfLocal : $bindIPIfLocal \033[0m"
			fi
			redisScanResult+="\"bindIPIfLocal\":\"${bindIPIfLocal}\","
			if [[ "$protectMode" == "yes" ]]; then
				protectModeIfEnable=true
			else
				protectModeIfEnable=false
			fi
			if $protectModeIfEnable ; then
				echo  -e "\033[32m [+] protectModeIfEnable : $protectModeIfEnable \033[0m"
			else
				echo  -e "\033[31m [-] protectModeIfEnable : $protectModeIfEnable \033[0m"
			fi
			redisScanResult+="\"protectModeIfEnable\":\"${protectModeIfEnable}\","
			if [[ -n "$requirePass" ]]; then
				requirePassIfEnable=true
			else
				requirePassIfEnable=false
			fi
			if $requirePassIfEnable ; then
				echo -e "\033[32m [+] requirePassIfEnable : $requirePassIfEnable \033[0m"
			else
				echo -e "\033[31m [-] requirePassIfEnable : $requirePassIfEnable \033[0m"
			fi
			redisScanResult+="\"requirePassIfEnable\":\"${requirePassIfEnable}\","
			configCommandIfDisable=false
			for renamecommand in ${renameCommand[@]}; do
				if [[ "$renamecommand" =~ "config"|"CONFIG" ]]; then
					configCommandIfDisable=true
					break
				fi
				configCommandIfDisable=false
			done
			redisScanResult+="\"configCommandIfDisable\":\"${configCommandIfDisable}\","
			if $configCommandIfDisable ; then
				echo -e "\033[32m [+] configCommandIfDisable : $configCommandIfDisable \033[0m"
			else
				echo -e "\033[31m [-] configCommandIfDisable : $configCommandIfDisable \033[0m"
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
			redisScanResult+="\"permLE600\":\"${permLE600}\""
			redisScanResult+='}'
			redisScanResult+='}'
		done
		redisScanResult+=']'
		redisScanResult="{\"redisScanResultList\":${redisScanResult},\"RootUserIfDisable\":\"${RootUserIfDisable}\"}"
		#echo $redisScanResult 
		#echo $redisScanResult |jq
	else
		redisScanResult={}
	fi
	export redisScanResult=$redisScanResult

}
