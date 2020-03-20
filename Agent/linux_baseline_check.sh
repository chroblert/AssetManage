#!/bin/bash
function get_ip_info {
    local ipList=`ifconfig | grep inet |grep -v inet6|grep -v 127|sed 's/^[ ]*//g'|cut -d" " -f2`
    echo $ipList
}
function get_basic_info {
    echo [·] collect basic info
    scanTime=$(date "+%Y-%m-%d %H:%M:%S")
    hostname=`hostname`
    macaddr=$(echo $(ifconfig|grep "ether"|sed 's/^[ ]*//g'|cut -d" " -f2)|sed 's/ /;/g')
    ipList=$(get_ip_info|sed 's/ /;/g')
    kernelVersion=`uname -r`
    if [[ $(cat /proc/version) =~ "Red Hat" ]]; then
        osVersion=`cat /etc/redhat-release|cut -f1,4 -d" "`
    fi
    basic_info={\"scanTime\":\"$scanTime\",\"hostname\":\"$hostname\",\"macaddr\":\"$macaddr\",\"ipList\":\"$ipList\",\"kernelVersion\":\"$kernelVersion\",\"osVersion\":\"$osVersion\"}
    echo $basic_info
}

function init_check {
    # 1. init configuration
    echo [·] check init configuration
    # 1.1 file system configuration
    # 1.1.1 /tmp separate mount
    local tmpIfSeparate #=""
    local tmpIfNoexec #=""
    local tmpIfNosuid #=""
    local res=$(mount|grep "/tmp ") 
    if [[ -z $res ]]; then
        echo -e "\033[31m-[-] /tmp/ not mounted on separate dick\033[0m"
        tmpIfSeparate="False"
        tmpIfNoexec="False"
        tmpIfNosuid="False"
    else
        tmpIfSeparate="True"
        tmpIfNoexec="True"
        tmpIfNosuid="True"
    fi
    if [[ $tmpIfSeparate == "True" ]]; then
        #mount|grep "/sys/kernel/debug " |while read res;do
        while read res;do
            #echo "mount | grep /sys --result-->" $res
            # 1.1.2 /tmp noexec nosuid
            local diskPart=$(echo $res|cut -d" " -f3)
            if [[ ! $res =~ "noexec" ]];then
                echo -e "\033[31m-[-] no noexec option on $diskPart partion\033[0m"
                tmpIfNoexec="False"
                if [[ ! $res =~ "nosuid" ]];then
                    echo -e "\033[31m-[-] no nosuid option on $diskPart partion\033[0m"
                    tmpIfNosuid="False"
                fi
            elif [[ ! $res =~ "nosuid" ]];then
                echo -e "\033[31m-[-] no nosuid option on $diskPart partion\033[0m"
                tmpIfNosuid="False"
            fi
        done < <(mount | grep "/tmp ")
    fi
    tmp_partition_info={\"tmpIfSeparate\":\"$tmpIfSeparate\",\"tmpIfNoexec\":\"$tmpIfNoexec\",\"tmpIfNosuid\":\"$tmpIfNosuid\"}
    #echo $tmp_partition_info
    # 1.2 secure boot configuration
    if [[ -f /boot/grub2/grub.cfg ]];then
        grubcfgIfExist="True"
        grubcfgPermission="0600"
        grubcfgIfSetPasswd="True"
    else
        grubcfgIfExist="False"
        grubcfgPermission="0000"
        grubcfgIfSetPasswd="False"
    fi
    if [[ $grubcfgIfExist == "True" ]]; then
        # 1.2.1 /boot/grub2/grub.cfg permission /boot/grub2/user.cfg permission 0600 root:root
        res=$(stat /boot/grub2/grub.cfg |while read x;do if [[ $x =~ "Uid" ]] && [[ $x =~ "(" ]]; then echo $x;fi;done|cut -d"(" -f2,3,4)
        grubcfgPermission=$(echo $res|cut -d"/" -f1)
        if [[ $(echo $res|cut -d"/" -f1) = "0600" ]]; then
            echo -e "\033[32m-[+] /boot/grub2/grub.cfg permission is 0600 \033[0m"
        else
            echo -e "\033[31m-[-] /boot/grub2/grub.cfg permission is not 0600 \033[0m"
        fi
        # 1.2.2 Ensure bootloader password is set
        res=$(grep "^GRUB2 PASSWORD" /boot/grub2/grub.cfg)
        if [[ -n $res ]]; then
            echo -e "\033[32m-[+] /boot/grub2/grub.cfg seted password \033[0m"
            grubcfgIfSetPasswd="True"
        else
            echo -e "\033[31m-[-] /boot/grub2/grub.cfg not set password \033[0m"
            grubcfgIfSetPasswd="False"
        fi
    fi
        
    # 1.2.3 single user mode need authentication
    if [[ -f /usr/lib/systemd/system/rescue.service ]] && [[ -f /usr/lib/systemd/system/emergency.service ]]; then
        res1=`grep /sbin/sulogin /usr/lib/systemd/system/rescue.service`
        res2=`grep /sbin/sulogin /usr/lib/systemd/system/emergency.service`
        if [[ $res1 = "ExecStart=-/bin/sh -c \"/usr/sbin/sulogin; /usr/bin/systemctl --fail --no-block default\"" ]] && [[ $res2 = "ExecStart=-/bin/sh -c \"/usr/sbin/sulogin; /usr/bin/systemctl --fail --no-block default\"" ]]; then
            echo -e "\033[32m-[+] single user mode need authentication \033[0m"
            singleUserModeIfNeedAuth="True"
        else
            echo -e "\033[31m-[+] single user mode does not need authentication \033[0m"
            singleUserModeIfNeedAuth="False"
        fi
    fi
    # 1.3 Mantary Access Control
    # 1.3.1 ensure the SELinux state is enforcing
    if [[ -f /etc/selinux/config ]]; then
        local num=$(sestatus|grep -c enforcing)
        if [[ $num -gt 1 ]]; then
            echo -e "\033[32m-[+] SELinux state is enforcing \033[0m"
            selinuxStateIfEnforcing="True"
        else
            echo -e "\033[31m-[-] SELinux state is not enforcing \033[0m"
            selinuxStateIfEnforcing="False"
        fi
    fi
    # 1.3.2 ensure selinux policy is configured
    if [[ -f /etc/selinux/config ]]; then
        res=$(sestatus|grep targeted)
        if [[ -n $res ]]; then
            echo -e "\033[32m-[+] SELinux policy is configured \033[0m"
            selinuxPolicyIfConfigured="True"
        else
            echo -e "\033[31m-[-] SELinux policy is not configure to targeted \033[0m"
            selinuxPolicyIfConfigured="False"
        fi
    fi
    boot_secure_info={\"grubcfgIfExist\":\"$grubcfgIfExist\",\"grubcfgPermission\":\"$grubcfgPermission\",\"grubcfgIfSetPasswd\":\"$grubcfgIfSetPasswd\",\"singleUserModeIfNeedAuth\":\"$singleUserModeIfNeedAuth\",\"selinuxStateIfEnforcing\":\"$selinuxStateIfEnforcing\",\"selinuxPolicyIfConfigured\":\"$selinuxPolicyIfConfigured\"}
    #echo $boot_secure_info
    init_check_res={\"tmp_partition_info\":$tmp_partition_info,\"boot_secure_info\":$boot_secure_info}
}
function service_check {
    # 2. service configuration
    echo [·] check service configuration
    # 2.1 time sync
    # 2.1.1 time sync service is installed
    if $(rpm -q ntp 1>/dev/null||rpm -q chrony 1>/dev/null) ; then
        if $(rpm -q ntp 1>/dev/null) ; then
            if [[ -f /etc/ntp.conf ]]; then
                local res=$(egrep "^(server|pool)" /etc/ntp.conf)
                if [[ -n $res ]]; then
                    echo -e "\033[32m-[+] remote ntp server is configured \033[0m"
                    timeSyncServerIfConfigured="True"
                else
                    echo -e "\033[31m-[-] remote ntp server is not configured \033[0m"
                    timeSyncServerIfConfigured="False"
                fi
            fi
        fi
        if $(rpm -q chrony 1>/dev/null); then
            if [[ -f /etc/chrony.conf ]]; then
                local res=$(egrep "^(server|pool)" /etc/chrony.conf)
                if [[ -n $res ]]; then
                    echo -e "\033[32m-[+] remote chrony server is configured \033[0m"
                    timeSyncServerIfConfigured="True"
                else
                    echo -e "\033[31m-[-] remote chrony server is not configured \033[0m"
                    timeSyncServerIfConfigured="False"
                fi
                
            fi
        fi
    fi        
    # 2.1.2 x-window
    local res=$(rpm -qa xorg-x11*)
    if [[ -z $res ]]; then
        echo -e "\033[32m-[+] x11-windows is not installed \033[0m"
        x11windowIfNotInstalled="True"
    else
        echo -e "\033[31m-[-] x11-windows is installed \033[0m"
        x11windowIfNotInstalled="False"
    fi
    service_check_res={\"timeSyncServerIfConfigured\":\"$timeSyncServerIfConfigured\",\"x11windowIfNotInstalled\":\"$x11windowIfNotInstalled\"}
}
function network_check {
    # 3. network configuration
    echo [·] check network configuration
    # 3.1 hosts file configuration
    # 3.1.1 check /etc/hosts.deny file
    if [[ -f /etc/hosts.deny ]]; then
        hostsDenyFileIfExist="True"
        echo -e "\033[32m-[+] file /etc/hosts.deny exists \033[0m"
        local res=$(stat /etc/hosts.deny |while read x;do if [[ $x =~ "Uid" ]] && [[ $x =~ "(" ]]; then echo $x;fi;done|cut -d"(" -f2,3,4)
        hostsDenyFilePermission=$(echo $res|cut -d"/" -f1)
        if [[ $(echo $res|cut -d"/" -f1) = "0644" ]];then
            echo -e "\033[32m-[+] file /etc/hosts.deny permission is 0644 \033[0m"
        else
            echo -e "\033[31m-[-] file /etc/hosts.deny permission is not 0644 \033[0m"
        fi

        local res=$(egrep "^[^#].+" /etc/hosts.deny)
        if [[ -n $res ]]; then
            hostsDenyFileIfConfigured="True"
            echo -e "\033[32m-[+] file /etc/hosts.deny is configured \033[0m"
        else
            hostsDenyFileIfConfigured="False"
            echo -e "\033[31m-[-] file /etc/hosts.deny is not configured \033[0m"
        fi
    else
        hostsDenyFileIfExist="False"
        echo -e "\033[31m-[-] file /etc/hosts.deny does not exists \033[0m"
    fi
    # 3.1.2 check /etc/hosts.allow file
    if [[ -f /etc/hosts.allow ]]; then
        hostsAllowFileIfExist="True"
        echo -e "\033[32m-[+] file /etc/hosts.allow exists \033[0m"
        local res=`stat /etc/hosts.allow |while read x;do if [[ $x =~ "Uid" ]] && [[ $x =~ "(" ]]; then echo $x;fi;done|cut -d"(" -f2,3,4`
        hostsAllowFilePermission=$(echo $res|cut -d"/" -f1)
        if [[ $(echo $res|cut -d"/" -f1) = "0644" ]];then
            echo -e "\033[32m-[+] file /etc/hosts.allow permission is 0644 \033[0m"
        else
            echo -e "\033[31m-[-] file /etc/hosts.allow permission is not 0644 \033[0m"
        fi

        local res=$(egrep "^[^#].+" /etc/hosts.deny)
        if [[ -n $res ]]; then
            hostsAllowFileIfConfigured="True"
            echo -e "\033[32m-[+] file /etc/hosts.allow is configured \033[0m"
        else
            hostsAllowFileIfConfigured="False"
            echo -e "\033[31m-[-] file /etc/hosts.allow is not configured \033[0m"
        fi
    else
        hostsAllowFileIfExist="False"
        echo -e "\033[31m-[-] file /etc/hosts.allow does not exists \033[0m"
    fi

    # 3.2 firewall configuration
    # 3.2.1 ensure iptables is installed
    if $(rpm -q iptables 1>/dev/null); then
        iptablesIfInstalled="True"
        echo -e "\033[32m-[+] iptables is installed \033[0m"
        # 3.2.2 ensure INPUT OUTPUT chain policy is DROP
        #iptables -L|grep policy|while read x;do
        while read x;do
            if [[ $x =~ "INPUT" ]] && [[ $x =~ "DROP" ]]; then
                iptablesInputPolicyIfDrop="True"
                echo -e "\033[32m-[+] INPUT chain policy is DROP \033[0m"
            elif [[ $x =~ "INPUT" ]] && [[ ! $x =~ "DROP" ]]; then
                iptablesInputPolicyIfDrop="False"
                echo -e "\033[31m-[-] INPUT chain policy is not DROP \033[0m"
            fi
            if [[ $x =~ "OUTPUT" ]] && [[ $x =~ "DROP" ]]; then
                iptablesOutputPolicyIfDrop="True"
                echo -e "\033[32m-[+] OUTPUT chain policy is DROP \033[0m"
            elif [[ $x =~ "OUTPUT" ]] && [[ ! $x =~ "DROP" ]]; then
                iptablesOutputPolicyIfDrop="False"
                echo -e "\033[31m-[-] OUTPUT chain policy is not DROP \033[0m"
            fi
        done < <(iptables -L|grep policy)
    else
        iptablesIfInstalled="False"
        echo -e "\033[31m-[-] iptables is not installed \033[0m"
    fi
    network_check_res={\"hostsAllowFileIfExist\":\"$hostsAllowFileIfExist\",\"hostsAllowFilePermission\":\"$hostsAllowFilePermission\",\"hostsAllowFileIfConfigured\":\"$hostsAllowFileIfConfigured\",\"hostsDenyFileIfExist\":\"$hostsDenyFileIfExist\",\"hostsDenyFilePermission\":\"$hostsDenyFilePermission\",\"hostsDenyFileIfConfigured\":\"$hostsDenyFileIfConfigured\",\"iptablesIfInstalled\":\"$iptablesIfInstalled\",\"iptablesInputPolicyIfDrop\":\"$iptablesInputPolicyIfDrop\",\"iptablesOutputPolicyIfDrop\":\"$iptablesOutputPolicyIfDrop\"}
}

function auditd_check {
	# 4. auditd configuration
	echo [·] check auditd configuration
	# 4.1 ensure auditd is enabled
    echo "-[·] check auditd if is enabled"
	if [[ $(systemctl is-enabled auditd) = "enabled" ]]; then
		echo -e "\033[32m-[+] auditd is enabled \033[0m"
        auditdIfEnabled="True"
	else
        auditdIfEnabled="False"
		echo -e "\033[31m-[-] auditd is not enabled \033[0m"
	fi
	# 4.2 some settings in /etc/audit/auditd.conf
    echo "-[·] settings in /etc/audit/auditd.conf"	
    if [[ -f /etc/audit/auditd.conf ]]; then
        auditdconfIfExist="True"
        maxLogFile=$(grep "^max_log_file[[:blank:]]=" /etc/audit/auditd.conf|sed "s/ //g"|cut -d"=" -f 2)
        maxLogFileAction=$(grep "^max_log_file_action" /etc/audit/auditd.conf|sed "s/ //g"|cut -d"=" -f 2)
        spaceLeftAction=$(grep "^space_left_action" /etc/audit/auditd.conf|sed "s/ //g"|cut -d"=" -f 2)
        numLogs=$(grep "^num_logs" /etc/audit/auditd.conf|sed "s/ //g"|cut -d"=" -f 2)
        if [[ -n $maxLogFile ]]; then
            auditdIfSetMaxLogFile=$maxLogFile
            echo -e "\033[32m-[+] max_log_file size is ${maxLogFile} M \033[0m"
        else
            auditdIfSetMaxLogFile="False"
            echo -e "\033[31m-[-] max_log_file size is not setted \033[0m"
        fi
        if [[ -n $maxLogFileAction ]]; then
            auditdIfSetMaxLogFileAction="$maxLogFileAction"
            echo -e "\033[32m-[+] max_log_file_action is ${maxLogFileAction}\033[0m"
        else
            auditdIfSetMaxLogFileAction="False"
            echo -e "\033[31m-[-] max_log_file_action is not setted \033[0m"
        fi
        if [[ -n $spaceLeftAction ]]; then
            auditdIfSetSpaceLeftAction="$spaceLeftAction"
            echo -e "\033[32m-[+] space_left_action is ${spaceLeftAction}\033[0m"
        else
            auditdIfSetSpaceLeftAction="False"
            echo -e "\033[31m-[-] space_left_action is not setted \033[0m"
        fi
        if [[ -n $numLogs ]]; then
            auditdIfSetNumLogs="$numLogs"
            echo -e "\033[32m-[+] the num of logs is ${numLogs} \033[0m"
        else
            auditdIfSetNumLogs="False"
            echo -e "\033[31m-[-] num_logs is not setted \033[0m"
        fi
    else
        auditdconfIfExist="False"
    fi
    auditd_config_info={\"auditdIfEnabled\":\"$auditdIfEnabled\",\"auditdconfIfExist\":\"$auditdconfIfExist\",\"auditdIfSetMaxLogFile\":\"$auditdIfSetMaxLogFile\",\"auditdIfSetMaxLogFileAction\":\"$auditdIfSetMaxLogFileAction\",\"auditdIfSetSpaceLeftAction\":\"$auditdIfSetSpaceLeftAction\",\"auditdIfSetNumLogs\":\"$auditdIfSetNumLogs\"}
    #echo $auditd_config_info
    # 4.3 rules in /etc/audit/audit.rules
    # arch 64
    echo "-[·] time-change" 
    if [[ -f /etc/audit/audit.rules ]]; then
        auditdRulesIfExist="True"
        echo -e "\033[32m-[+] /etc/audit/audit.rules is exist \033[0m"
        if [[ ! -n $(grep time /etc/audit/audit.rules) ]]; then
            auditdRulesIfNotNull="False"
            echo -e "\033[31m-[-] not set rule about audit the change of date and time \033[0m"
        else
            auditdRulesIfNotNull="True"
            # 4.3.1 time-change
            local timeChangeList=$(egrep "(stime|clock_settime|adjtimex|settimeofday|/etc/localtime)" /etc/audit/audit.rules|wc -l)
            if [[ ${timeChangeList} -gt 3 ]]; then
                auditdIfCheckTimechange="True"
                echo -e "\033[32m-[+] audith the change of date and time \033[0m"
            elif [[ ${timeChangeList} -gt 1 ]]; then
                auditdIfCheckTimechange="False"
                echo -e "\033[31m-[-] not fully set rule about audit the change of date and time \033[0m"
            else 
                auditdIfCheckTimechange="False"
                echo -e "\033[31m-[-] not set rule about audit the change of date and time \033[0m"
            fi
            # 4.3.2 user and group change
            echo "-[·] user and group change"
            local keyArray=("/etc/passwd" "/etc/group" "/etc/gshadow" "/etc/shadow" "/etc/security/opasswd")
            tmpArray1=()
            tmpArray2=()
            for i in ${keyArray[@]} ; do
                if [[ -n $(grep $i /etc/audit/audit.rules) ]]; then
                    tmpArray1+=($i\;)
                    echo -e "\033[32m-[+] audit the change of $i \033[0m"
                else
                    tmpArray2+=($i\;)
                    echo -e "\033[31m-[-] not audit the change of $i \033[0m"
                fi
            done
            auditdRulesCheckedUserandgroupfile=$(echo ${tmpArray1[@]}|sed 's/ //g')
            auditdRulesNotCheckedUserandgroupfile=$(echo ${tmpArray2[@]}|sed 's/ //g')
            # 4.3.3 system's network environment change
            echo "-[·] system's network environment change"
            local keyArray=("/etc/issue" "/etc/issue.net" "/etc/hosts" "/etc/sysconfig/network" "/etc/sysconfig/network-scripts/" )
            tmpArray1=()
            tmpArray2=()
            for i in ${keyArray[@]} ; do
                    if [[ -n $(grep $i /etc/audit/audit.rules) ]]; then
                    tmpArray1+=($i\;)
                    echo -e "\033[32m-[+] audit the change of $i \033[0m"
                else
                    tmpArray2+=($i\;)
                    echo -e "\033[31m-[-] not audit the change of $i \033[0m"
                fi
            done
            local keyArray=("sethostname" "setdomainname")
            for i in ${keyArray[@]} ; do
                if [[ -n $(grep $i /etc/audit/audit.rules) ]]; then
                    tmpArray1+=($i\;)
                    echo -e "\033[32m-[+] audit the use of syscall  $i \033[0m"
                else
                    echo -e "\033[31m-[-] not audit the use of syscall $i \033[0m"
                    tmpArray2+=($i\;)
                fi
            done
            auditdRulesCheckedNetworkenv=$(echo ${tmpArray1[@]}|sed 's/ //g')
            auditdRulesNotCheckedNetworkenv=$(echo ${tmpArray2[@]}|sed 's/ //g')
            # 4.3.4 system's Mandatory Access Controls change
            echo "-[·] system's Mandatory Access Controls change"
            local keyArray=("/etc/selinux" "/usr/share/selinux")
            tmpArray1=()
            tmpArray2=()
            for i in ${keyArray[@]} ; do
                if [[ -n $(grep $i /etc/audit/audit.rules) ]]; then
                    tmpArray1+=($i\;)
                    echo -e "\033[32m-[+] audit the change of   $i \033[0m"
                else
                    tmpArray2+=($i\;)
                    echo -e "\033[31m-[-] not audit the change of $i \033[0m"
                fi
            done
            auditdRulesCheckedMACchange=$(echo ${tmpArray1[@]}|sed 's/ //g')
            auditdRulesNotCheckedMACchange=$(echo ${tmpArray2[@]}|sed 's/ //g')
            # 4.3.5 audit events of login and logout
            echo "-[·] audit events of login and logout"
            local keyArray=("/var/log/lastlog" "/var/run/faillock/")
            tmpArray1=()
            tmpArray2=()
            for i in ${keyArray[@]} ; do
                if [[ -n $(grep $i /etc/audit/audit.rules) ]]; then
                    tmpArray1+=($i\;)
                    echo -e "\033[32m-[+] audit the change of   $i \033[0m"
                else
                    tmpArray2+=($i\;)
                    echo -e "\033[31m-[-] not audit the change of $i \033[0m"
                fi
            done
            auditdRulesCheckedLoginoutEvents=$(echo ${tmpArray1[@]}|sed 's/ //g')
            auditdRulesNotCheckedLoginoutEvents=$(echo ${tmpArray2[@]}|sed 's/ //g')
            # 4.3.6 audit the change of discretionary access control
            echo "-[·] audit the change of discretionary access control"
            local keyArray=("(chmod|fchmod|fchmodat)" "(chown|fchown|fchownat)" "(setxattr|lsetxattr|removexattr)" "(lock|time)")
            tmpArray1=()
            tmpArray2=()
            for i in ${keyArray[@]} ; do
                if [[ -n $(egrep $i /etc/audit/audit.rules) ]]; then
                    i=$(echo $i|sed 's/|/ /g'|sed 's/(//g'|sed 's/)//g')
                    echo -e "\033[32m-[+] audit the use of systemcall  $i \033[0m"
                    tmpArray1+=($i\;)
                else
                    tmpArray2+=($i\;)
                    i=$(echo $i|sed 's/|/ /g'|sed 's/(//g'|sed 's/)//g')
                    echo -e "\033[31m-[-] not audit the use of systemcall $i \033[0m"
                fi
            done
            auditdRulesCheckedDACChangeSyscall=$(echo ${tmpArray1[@]}|sed 's/ //g')
            auditdRulesNotCheckedDACChangeSyscall=$(echo ${tmpArray2[@]}|sed 's/ //g')
            # 4.3.7 audit the events of unsuccessful unauthorized file access attempts
            echo "-[·] audit the events of unsuccessful unauthorized file access attempts"
            local keyArray=("(create|open|openat|truncate|ftruncate).*?exit=-EACCESS" "(create|open|openat|truncate|ftruncate).*?exit=-EPERM" )
            tmpArray1=()
            tmpArray2=()
            for i in ${keyArray[@]} ; do
                if [[ -n $(egrep $i /etc/audit/audit.rules) ]]; then
                    tmpArray1+=($i\;)
                    i=$(echo $i|sed 's/|/ /g'|sed 's/(//g'|sed 's/)//g'|sed 's/\.\*?/ /g')
                    echo -e "\033[32m-[+] audit the use of systemcall  $i \033[0m"
                else
                    tmpArray2+=($i\;)
                    i=$(echo $i|sed 's/|/ /g'|sed 's/(//g'|sed 's/)//g'|sed 's/\.\*?/ /g')
                    echo -e "\033[31m-[-] not audit the use of systemcall $i \033[0m"
                fi
            done
            auditdRulesCheckedFileAccessAttemptSyscall=$(echo ${tmpArray1[@]}|sed 's/ //g')
            auditdRulesNotCheckedFileAccessAttemptSyscall=$(echo ${tmpArray2[@]}|sed 's/ //g')
            # 4.3.8 audit the use of privileged commands
            echo "-[·] audit the use of privileged commands"
            #find / -name "passwd"
            local res=$(find / -xdev \( -perm -4000 -o -perm -2000 \) -type f) #|awk '{print "-a always,exit -F path="$1"-F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged"}'
            tmpArray1=()
            tmpArray2=()
            for i in ${res[@]} ; do
                if [[ -n $(egrep $i /etc/audit/audit.rules) ]]; then
                    tmpArray1+=($i\;)
                    i=$(echo $i|sed 's/|/ /g'|sed 's/(//g'|sed 's/)//g'|sed 's/\.\*?/ /g')
                    echo -e "\033[32m-[+] audit the use of command  $i \033[0m"
                else
                    tmpArray2+=($i\;)
                    i=$(echo $i|sed 's/|/ /g'|sed 's/(//g'|sed 's/)//g'|sed 's/\.\*?/ /g')
                    echo -e "\033[31m-[-] not audit the use of command $i \033[0m"
                fi
            done
            auditdRulesCheckedPrivilegedCommand=$(echo ${tmpArray1[@]}|sed 's/ //g')
            auditdRulesNotCheckedPrivilegedCommand=$(echo ${tmpArray2[@]}|sed 's/ //g')
            # 4.3.9 audit the change of file sudoer
            echo "-[·] audit the change of file sudoer"
            local keyArray=("/etc/sudoers" "/etc/sudoers.d/")
            tmpArray1=()
            tmpArray2=()
            for i in ${keyArray[@]} ; do
                if [[ -n $(egrep $i /etc/audit/audit.rules) ]]; then
                    tmpArray1+=($i\;)
                    i=$(echo $i|sed 's/|/ /g'|sed 's/(//g'|sed 's/)//g'|sed 's/\.\*?/ /g')
                    echo -e "\033[32m-[+] audit the change of file  $i \033[0m"
                else
                    tmpArray2+=($i\;)
                    i=$(echo $i|sed 's/|/ /g'|sed 's/(//g'|sed 's/)//g'|sed 's/\.\*?/ /g')
                    echo -e "\033[31m-[-] not audit the change of file $i \033[0m"
                fi
            done
            auditdRulesCheckedSudoerFile=$(echo ${tmpArray1[@]}|sed 's/ //g')
            auditdRulesNotCheckedSudoerFile=$(echo ${tmpArray2[@]}|sed 's/ //g')
            # 4.3.10 check the audit configuration is setted to immutable unless reboot the server
            echo "-[·] check the audit configuration is setted to immutable unless reboot the server"
            local res=$(grep "^\s*[^#]" /etc/audit/audit.rules|tail -1|egrep "-e.*?2")
            if [[ -n $res ]]; then
                auditdRulesIfImmutable="True"
                echo -e "\033[32m-[+] auditd setted -e 2 \033[0m"
            else
                auditdRulesIfImmutable="False"
                echo -e "\033[31m-[-] auditd not setted -e 2 \033[0m"
            fi
        fi
    else
        auditdRulesIfExist="False"
        echo -e "\033[32m-[+] /etc/audit/audit.rules is not exist \033[0m"
    fi
    auditd_rules_info={\"auditdRulesIfExist\":\"$auditdRulesIfExist\",\"auditdRulesIfNotNull\":\"$auditdRulesIfNotNull\",\"auditdIfCheckTimechange\":\"$auditdIfCheckTimechange\",\"auditdRulesCheckedUserandgroupfile\":\"$auditdRulesCheckedUserandgroupfile\",\"auditdRulesNotCheckedUserandgroupfile\":\"$auditdRulesNotCheckedUserandgroupfile\",\"auditdRulesCheckedNetworkenv\":\"$auditdRulesCheckedNetworkenv\",\"auditdRulesNotCheckedNetworkenv\":\"$auditdRulesNotCheckedNetworkenv\",\"auditdRulesCheckedMACchange\":\"$auditdRulesCheckedMACchange\",\"auditdRulesNotCheckedMACchange\":\"$auditdRulesNotCheckedMACchange\",\"auditdRulesCheckedLoginoutEvents\":\"$auditdRulesCheckedLoginoutEvents\",\"auditdRulesNotCheckedLoginoutEvents\":\"$auditdRulesNotCheckedLoginoutEvents\",\"auditdRulesCheckedDACChangeSyscall\":\"$auditdRulesCheckedDACChangeSyscall\",\"auditdRulesNotCheckedDACChangeSyscall\":\"$auditdRulesNotCheckedDACChangeSyscall\",\"auditdRulesCheckedFileAccessAttemptSyscall\":\"$auditdRulesCheckedFileAccessAttemptSyscall\",\"auditdRulesNotCheckedFileAccessAttemptSyscall\":\"$auditdRulesNotCheckedFileAccessAttemptSyscall\",\"auditdRulesCheckedPrivilegedCommand\":\"$auditdRulesCheckedPrivilegedCommand\",\"auditdRulesNotCheckedPrivilegedCommand\":\"$auditdRulesNotCheckedPrivilegedCommand\",\"auditdRulesCheckedSudoerFile\":\"$auditdRulesCheckedSudoerFile\",\"auditdRulesNotCheckedSudoerFile\":\"$auditdRulesNotCheckedSudoerFile\",\"auditdRulesIfImmutable\":\"$auditdRulesIfImmutable\"}
    auditd_check_res={\"auditd_config_info\":$auditd_config_info,\"auditd_rules_info\":$auditd_rules_info}
}

function log_check {
    echo "[·] check log configuration"
	# 5.1 ensure auditd is enabled
    echo "-[·] check rsyslog if is enabled"
	if [[ $(systemctl is-enabled rsyslog) = "enabled" ]]; then
        rsyslogIfEnabled="True"
		echo -e "\033[32m-[+] rsyslog is enabled \033[0m"
	else
        rsyslogIfEnabled="False"
		echo -e "\033[31m-[-] rsyslog is not enabled \033[0m"
	fi
    
    log_check_res={\"rsyslogIfEnabled\":\"$rsyslogIfEnabled\"}

}

function authentication_check {
    echo "[·] check cron ssh pam and env configuration"
    # 6.1 cron configuration
    echo "-[·] check cron configuration"
    # 6.1.1 check cron service is enabled
    echo "-[·] check crond if is enabled"
	if [[ $(systemctl is-enabled crond) = "enabled" ]]; then
		echo -e "\033[32m-[+] crond is enabled \033[0m"
        crondIfEnabled="True"
	else
        crondIfEnabled="False"
		echo -e "\033[31m-[-] crond is not enabled \033[0m"
	fi
    # 6.1.2 check cron's configuration file permission
    echo "-[·] check cron's configuration file permission"
    local keyArray=("/etc/crontab" "/etc/cron.hourly" "/etc/cron.daily" "/etc/cron.weekly" "/etc/cron.monthly" "/etc/cron.d")
    crondConfigFilenameArray=$(echo ${keyArray[@]}|sed 's/ /;/g')
    tmpArray=()
    for i in ${keyArray[@]} ; do
        local res=$(stat $i |while read x;do if [[ $x =~ "Uid" ]] && [[ $x =~ "(" ]]; then echo $x;fi;done|cut -d"(" -f2,3,4|cut -d"/" -f1)
        tmpArray+=($res\;)
        if [[ $res = "0600" ]] || [[ $res = "0700" ]]; then
            echo -e "\033[32m-[+] file $i's permission is $res \033[0m"
        else
            echo -e "\033[31m-[-] file $i's permission is $res ,not 0600 or 0700 \033[0m"
        fi
    done
    crondConfigFilePermissionArray=$(echo ${tmpArray[@]}|sed 's/ //g')
    # 6.1.3 check cron.allow cron.deny permission and owner
    echo "-[·] check cron.allow cron.deny configuration file permission"
    local keyArray=("/etc/cron.allow" "/etc/cron.deny")
    crondallowdenyFilenameArray=$(echo ${keyArray[@]}|sed 's/ /;/g')
    tmpArray1=()
    tmpArray2=()
    tmpArray3=()
    for i in ${keyArray[@]} ; do
        if [[ ! -f $i ]]; then
            tmpArray1+=("False;")
            tmpArray2+=("False;")
            tmpArray3+=("False;")
            echo -e "\033[31m-[-] file $i not exist \033[0m"
            continue
        else
            tmpArray1+=("True;")
        fi
        local res1=$(stat $i |while read x;do if [[ $x =~ "Uid" ]] && [[ $x =~ "(" ]]; then echo $x;fi;done|cut -d"(" -f2,3,4|cut -d"/" -f1)
        tmpArray2+=($res1\;)
        local res2=$(stat $i |while read x;do if [[ $x =~ "Uid" ]] && [[ $x =~ "(" ]]; then echo $x;fi;done|cut -d"(" -f3,4|sed 's/)//g'|cut -d" " -f3,6)
        tmpArray3+=($res2\;)
        if [[ $res1 = "0600" ]] || [[ $res1 = "0700" ]]; then
            echo -e "\033[32m-[+] file $i's permission is $res \033[0m"
        else
            echo -e "\033[31m-[-] file $i's permission is $res ,not 0600 or 0700 \033[0m"
        fi
        if [[ $res2 = "root root" ]]; then
            echo -e "\033[32m-[+] file $i's owner is $res2 \033[0m"
        else
            echo -e "\033[31m-[-] file $i's owner is not root \033[0m"
        fi
    done
    crondallowdenyFileIfExistArray=$(echo ${tmpArray1[@]}|sed 's/ //g')
    crondallowdenyFilePermissionArray=$(echo ${tmpArray2[@]}|sed 's/ //g')
    crondallowdenyFileOwnerArray=$(echo ${tmpArray3[@]}|sed 's/; /;/g')
    crond_config_info={\"crondIfEnabled\":\"$crondIfEnabled\",\"crondConfigFilenameArray\":\"$crondConfigFilenameArray\",\"crondConfigFilePermissionArray\":\"$crondConfigFilePermissionArray\",\"crondallowdenyFilenameArray\":\"$crondallowdenyFilenameArray\",\"crondallowdenyFileIfExistArray\":\"$crondallowdenyFileIfExistArray\",\"crondallowdenyFilePermissionArray\":\"$crondallowdenyFilePermissionArray\",\"crondallowdenyFileOwnerArray\":\"$crondallowdenyFileOwnerArray\"}
    # 6.2 SSH configuration
    echo "-[·] check ssh configuration"
	if [[ $(systemctl is-enabled sshd) = "enabled" ]]; then
        sshdIfEnabled="True"
        # 6.2.1 /etc/ssh/sshd_config permission 0600
        local file="/etc/ssh/sshd_config"
        local res=$(stat $file |while read x;do if [[ $x =~ "Uid" ]] && [[ $x =~ "(" ]]; then echo $x;fi;done|cut -d"(" -f2,3,4|cut -d"/" -f1)
        if [[ $res = "0600" ]]; then
            sshdConfigFilePermission=$res
            echo -e "\033[32m-[+] file $file's access permission is $res \033[0m"
        else
            sshdConfigFilePermission="False"
            echo -e "\033[3-m-[-] file $file's access permission is $res \033[0m"
        fi
        # 6.2.2 check ssh x11 forwarding if is disabled
        local res=$(grep "^X11Forwaring" /etc/ssh/sshd_config)
        if [[ -n $(echo $res|grep no) ]]; then
            sshdIfDisableX11forwarding="True"
            echo -e "\033[32m-[+] X11Forwarding no \033[0m"
        else
            sshdIfDisableX11forwarding="False"
            echo -e "\033[31m-[-] not set X11Forwarding no \033[0m"
        fi
        # 6.2.3 check ssh MaxAUTHTries if is 4
        local res=$(grep "^MaxAuthTries" /etc/ssh/sshd_config)
        if [[ -n $res ]]; then
            sshdIfSetMaxAuthTries=$(echo $res|sed -r 's/([^1234567890]*)([[:digit:]]+)/\2/')
            echo -e "\033[32m-[+] $res \033[0m"
        else
            sshdIfSetMaxAuthTries="False"
            echo -e "\033[31m-[-] not set MaxAuthTries \033[0m"
        fi
        # 6.2.4 check ssh IgnoreRhosts if is enabled
        local res=$(grep "^IgnoreRhosts" /etc/ssh/sshd_config)
        if [[ -n $(echo $res|grep yes) ]]; then
            sshdIfEnableIgnoreRhosts="True"
            echo -e "\033[32m-[+] IgnoreRhosts yes \033[0m"
        else
            sshdIfEnableIgnoreRhosts="False"
            echo -e "\033[31m-[-] not set IgnoreRhosts no\033[0m"
        fi
        # 6.2.5 check ssh HostbasedAuthentication if is disabled
        local res=$(grep "^HostbasedAuthentication" /etc/ssh/sshd_config)
        if [[ -n $(echo $res|grep no) ]]; then
            sshdIfDisableHostbasedAuthentication="True"
            echo -e "\033[32m-[+] HostbasedAuthentication no \033[0m"
        else
            sshdIfDisableHostbasedAuthentication="False"
            echo -e "\033[31m-[-] not set HostbasedAuthentication no\033[0m"
        fi
        # 6.2.6 check ssh root login if is diabled
        local res=$(grep "^PermitRootLogin" /etc/ssh/sshd_config)
        if [[ -n $(echo $res|grep no) ]]; then
            sshdIfDisablePermitRootLogin="True"
            echo -e "\033[32m-[+] PermitRootLogin no \033[0m"
        else
            sshdIfDisablePermitRootLogin="False"
            echo -e "\033[31m-[-] not set PermitRootLogin no\033[0m"
        fi
        # 6.2.7 check ssh PermitEmptyPasswords if is diabled
        local res=$(grep "^PermitEmptyPasswords" /etc/ssh/sshd_config)
        if [[ -n $(echo $res|grep no) ]]; then
            sshdIfDisablePermitEmptyPasswords="True"
            echo -e "\033[32m-[+] PermitEmptyPasswords no \033[0m"
        else
            sshdIfDisablePermitEmptyPasswords="False"
            echo -e "\033[31m-[-] not set PermitEmptyPasswords no\033[0m"
        fi
        # 6.2.8 check ssh PermitUserEnvironment if is diabled
        local res=$(grep "^PermitUserEnvironment" /etc/ssh/sshd_config)
        if [[ -n $(echo $res|grep no) ]]; then
            sshdIfDisablePermitUserEnvironment="True"
            echo -e "\033[32m-[+] PermitUserEnvironment no \033[0m"
        else
            sshdIfDisablePermitUserEnvironment="False"
            echo -e "\033[31m-[-] not set PermitUserEnvironment no\033[0m"
        fi
        # 6.2.9 check if set specific MAC algorithms
        local res=$(grep "^MACs" /etc/ssh/sshd_config)
        if [[ -n $res ]]; then
            sshdIfSpecificMACs="True"
            echo -e "\033[32m-[+] will use specific MAC algorithms $res \033[0m"
        else
            sshdIfSpecificMACs="False"
            echo -e "\033[31m-[-] not set specific MAC algorithms\033[0m"
        fi
        # 6.2.10 check SSH idle Timeout Interval if is configured
        local res=$(grep "^ClientAliveInterval" /etc/ssh/sshd_config)
        if [[ -n $res ]]; then
            sshdIfSetClientAliveInterval=$(echo $res|sed -r 's/([^1234567890]*)([[:digit:]]+)/\2/')
            echo -e "\033[32m-[+] $res \033[0m"
        else
            sshdIfSetClientAliveInterval="False"
            echo -e "\033[31m-[-] not set ClientAliveInterval \033[0m"
        fi
        # 6.2.11 check SSH LoginGrace Time
        local res=$(grep "^LoginGraceTime" /etc/ssh/sshd_config)
        if [[ -n $res ]]; then
            sshdIfSetLoginGraceTime=$(echo $res|sed -r 's/([^1234567890]*)([[:digit:]]+)/\2/')
            echo -e "\033[32m-[+] $res \033[0m"
        else
            sshdIfSetLoginGraceTime="False"
            echo -e "\033[31m-[-] not set LoginGraceTime \033[0m"
        fi
	else
        sshdIfEnabled="False"
		echo -e "\033[32m-[+] sshd is not enabled \033[0m"
	fi
    sshd_config_info={\"sshdIfEnabled\":\"$sshdIfEnabled\",\"sshdConfigFilePermission\":\"$sshdConfigFilePermission\",\"sshdIfDisableX11forwarding\":\"$sshdIfDisableX11forwarding\",\"sshdIfSetMaxAuthTries\":\"$sshdIfSetMaxAuthTries\",\"sshdIfEnableIgnoreRhosts\":\"$sshdIfEnableIgnoreRhosts\",\"sshdIfDisableHostbasedAuthentication\":\"$sshdIfDisableHostbasedAuthentication\",\"sshdIfDisablePermitRootLogin\":\"$sshdIfDisablePermitRootLogin\",\"sshdIfDisablePermitEmptyPasswords\":\"$sshdIfDisablePermitEmptyPasswords\",\"sshdIfDisablePermitUserEnvironment\":\"$sshdIfDisablePermitUserEnvironment\",\"sshdIfSpecificMACs\":\"$sshdIfSpecificMACs\",\"sshdIfSetClientAliveInterval\":\"$sshdIfSetClientAliveInterval\",\"sshdIfSetLoginGraceTime\":\"$sshdIfSetLoginGraceTime\"}

    # 6.3 PAM configuration
    echo "-[·] check pam configuration"
    # 6.3.1 password creation policy
    if [[ -f /etc/security/pwquality.conf ]]; then
        pamPwqualityconfIfExist="True"
        local minlen=$(grep ^minlen /etc/security/pwquality.conf | sed 's/ //g')
        local minclass=$(grep ^minclass /etc/security/pwquality.conf |sed 's/ //g')
        if [[ -n $minlen ]]; then
            pamIfSetMinlen=$(echo $minlen|cut -d= -f2)
            echo -e "\033[32m-[+] minimime length of password is $(echo $minlen|cut -d= -f2) \033[0m"
        else
            pamIfSetMinlen="False"
            echo -e "\033[31m-[-] not set minlen \033[0m"
        fi
        if [[ -n $minclass ]]; then
            pamIfSetMinclass=$(echo $minclass|cut -d= -f2)
            echo -e "\033[32m-[+] minclass of password is $(echo $minclass|cut -d= -f2) \033[0m"
        else
            local keyArray=("^dcredit" "^lcredit" "^ocredit" "^ucredit")
            local tmpCount=0
            for i in ${keyArray[@]}; do
                if [[ -n  $(grep $i /etc/security/pwquality.conf) ]]; then
                    tmpCount=$(expr 1 + $tmpCount)
                fi
            done
            if [[ $tmpCount = 0 ]]; then
                pamIfSetMinclass="False"
            else
                pamIfSetMinclass=$tmpCount
            fi
            if [[ tmpCount -ge 2 ]]; then
                echo -e "\033[32m-[+] minclass of passwd is $tmpCount \033[0m"
            else
                echo -e "\033[31m-[-] not set minclass \033[0m"
            fi
        fi
    else
        pamPwqualityconfIfExist="False"
    fi
    # 6.3.2 lock account and unlock time
    local files=("/etc/pam.d/password-auth" "/etc/pam.d/system-auth")
    local keyArray=("pam_faillock\.so.*?unlock_time")
    tmpArray1=()
    tmpArray2=()
    for i in ${files[@]}; do
        for k in ${keyArray[@]}; do
            if [[ -n $(egrep $k $i ) ]]; then
                echo -e "\033[32m-[+] set lock and unlock_time in $i \033[0m"
                tmpArray1+=($i\;)
            else
                tmpArray2+=($i\;)
                echo -e "\033[31m-[-] not set lock and unlock_time in $i \033[0m"
            fi
        done
    done
    sshdSetedLockAndUnlockTimeFiles=$(echo ${tmpArray1[@]}|sed 's/; /;/g')
    sshdNotSetedLockAndUnlockTimeFiles=$(echo ${tmpArray2[@]}|sed 's/; /;/g')
    # 6.3.3 check password reuse if is limited
    sshdPamdFileArray=$(echo ${files[@]}|sed 's/ /;/g')
    tmpArray=()
    for i in ${files[@]}; do
        local res=$(egrep '^password\s+sufficient\s+pam_unix.so' $i)
        if [[ -n $res ]] && [[ $res =~ "remember=" ]]; then
            local tmp=$(echo $res|sed 's/.*\(remember=[[:digit:]]\).*/\1/g'|sed 's/ //g'|cut -d= -f2)
            tmpArray+=($tmp\;)
            echo -e "\033[32m-[+] password reuse limit is $tmp in $i \033[0m"
        else
            tmpArray+=("False;")
            echo -e "\033[31m-[-] passowrd reuse limit not set in $i \033[0m"
        fi
    done
    sshdPamdFileReuseLimitArray=$(echo ${tmpArray[@]}|sed 's/; /;/g')
    # 6.3.4 check the algorithm of store password if is sha512
    tmpArray=()
    for i in ${files[@]}; do
        local res=$(egrep '^password\s+sufficient\s+pam_unix.so' $i)
        if [[ -n $res ]] && [[ $res =~ "sha512" ]]; then
            tmpArray+=("True;")
            echo -e "\033[32m-[+] password storage algorithm is set to sha512 in $i \033[0m"
        else
            tmpArray+=("False;")
            echo -e "\033[31m-[-] password storage algorithm is not specific to sha512 in $i \033[0m"
        fi
    done
    sshdPamdFileIfSetSha512Array=$(echo ${tmpArray[@]}|sed 's/; /;/g')
    pam_config_info={\"pamPwqualityconfIfExist\":\"$pamPwqualityconfIfExist\",\"pamIfSetMinlen\":\"$pamIfSetMinlen\",\"pamIfSetMinclass\":\"$pamIfSetMinclass\",\"sshdSetedLockAndUnlockTimeFiles\":\"$sshdSetedLockAndUnlockTimeFiles\",\"sshdNotSetedLockAndUnlockTimeFiles\":\"$sshdNotSetedLockAndUnlockTimeFiles\",\"sshdPamdFileArray\":\"$sshdPamdFileArray\",\"sshdPamdFileReuseLimitArray\":\"$sshdPamdFileReuseLimitArray\",\"sshdPamdFileIfSetSha512Array\":\"$sshdPamdFileIfSetSha512Array\"}
    # 6.4 user accounts and environment
    echo "-[·] check user accounts and environment"
    if [[ -f /etc/login.defs ]]; then
        accountLogindefsIfExist="True"
        # 6.4.1 basic settings
        local file='/etc/login.defs'
        passMaxDays=$(grep ^PASS_MAX_DAYS $file|sed -r 's/[^1234567890]*([1234567890]{1,})/\1/g')
        passMinDays=$(grep ^PASS_MIN_DAYS $file|sed -r 's/[^1234567890]*([1234567890]{1,})/\1/g')
        passWarnAge=$(grep ^PASS_WARN_DAYS $file|sed -r 's/[^1234567890]*([1234567890]{1,})/\1/g')
        inactive=$(useradd -D|grep INACTIVE|sed 's/ //g'|cut -d= -f2)
        accountPassMaxDays=$passMaxDays
        accountPassMinDays=$passMinDays
        accountPassWarnDays=$passWarnAge
        accountPassAutolockInactiveDays=$inactive
        if [[ $passMaxDays -le 90 ]]; then
            echo -e "\033[32m-[+] the maximume days of password have to change is $passMaxDays \033[0m"
        else
            echo -e "\033[31m-[-] the maximume days of password have to change is $passMaxDays ,should less than 90 day\033[0m"
        fi
        if [[ $passMinDays -ge 7 ]]; then
            echo -e "\033[32m-[+] the minimume days of password have to change is $passMinDays \033[0m"
        else
            echo -e "\033[31m-[-] the minimume days of password have to change is $passMinDays ,should great than 7 day\033[0m"
        fi
        if [[ $passWarnAge -ge 7 ]]; then
            echo -e "\033[32m-[+] the minimume days of warn password need to change is $passWarnAge \033[0m"
        else
            echo -e "\033[31m-[-] the minimume days of warn password need to change is $passWarnAge ,should greate than 7 day\033[0m"
        fi
        if [[ $inactive != -1 ]]; then
            echo -e "\033[32m-[+] auto lock account when the  $inactive day haven't login \033[0m"
        else
            echo -e "\033[31m-[-] haven't set day of auto lock accounts \033[0m"
        fi
        # 6.4.2 check system's account if is unlogin
        local res=$(egrep -v "^\+" /etc/passwd | awk -F: '($1!="root" && $1!="sync" && $1!="shutdown" && $1!="halt" && $3<1000 && $7!="/sbin/nologin" && $7!="/bin/false") {print $1}')
        tmpArray=()
        if [[ -z $res ]]; then
            tmpArray+=("False;")
            echo -e "\033[32m-[+] system account can't login \033[0m"
        else
            tmpArray+=($(echo $res|sed 's/\n/ /g'))
            echo -e "\033[31m-[-]  ($(echo $res|sed 's/\n/ /g'))user's shell need set to /sbin/nologin \033[0m"
        fi
        accountShouldUnloginAray=$(echo ${tmpArray[@]}|sed 's/ /;/g')
        # 6.4.3 check default group for the root account if is GID 0
        local res=$(grep "^root:" /etc/passwd|cut -d: -f4)
        accountGIDOfRoot=$res
        if [[ $res = 0 ]]; then
            echo -e "\033[32m-[+] default group for the root account is GID 0 \033[0m"
        else
            echo -e "\033[31m-[-]] default group for the root account is is GID $res,not GID 0 \033[0m"
        fi
        # 6.4.4 check default user shell timeout if is 900 seconds or less
        local files=("/etc/bashrc" "/etc/profile")
        tmpArray1=()
        tmpArray2=()
        for file in ${files[@]}; do
            if [[ ! -f $file ]]; then
                continue
            else
                tmpArray1+=($file\;)
            fi
            local res=$(grep "^TMOUT" $file|sed 's/ //g'|cut -d= -f2)
            if [[ -z $res ]]; then
                tmpArray2+=("False;")
                echo -e "\033[31m-[-] not set TMOUT in file $file \033[0m"
                continue
            fi
            tmpArray2+=($res\;)
            if [[ $res -le 900 ]]; then
                echo -e "\033[32m-[+] when idle time great than $res seconds will close connection \033[0m"
            else
                echo -e "\033[31m-[-] when idle time great than $res seconds will close connection,the time should less than 900 seconds \033[0m"
            fi
        done
        accountProfileFileArray=$(echo ${tmpArray1[@]}|sed 's/; /;/g')
        accountProfileTMOUTArray=$(echo ${tmpArray2[@]}|sed 's/; /;/g')
        # 6.4.5 check access to su command if is restricted
        local res=$(grep pam_wheel.so /etc/pam.d/su)
#        accountIfSetUsersCanAccessSuCommand=
        if [[ -n $res ]]; then
            local res=$(grep wheel /etc/group|cut -d: -f4)
            if [[ -n $res ]]; then
                accountIfSetUsersCanAccessSuCommand=$(echo $res|sed 's/\n/;/g')
                echo -e "\033[32m-[+] access to su command is specific to $(echo $res|sed 's/\n/;/g') \033[0m"
            else
                accountIfSetUsersCanAccessSuCommand="False"
                echo -e "\033[31m-[-] access to su command is not restricted \033[0m"
            fi
        else
            accountIfSetUsersCanAccessSuCommand="False"
            echo -e "\033[31m-[-] access to su command is not restricted \033[0m"
        fi
    else
        accountLogindefsIfExist="False"
        echo -e "\033[31m-[-] file /etc/login.defs is not exist \033[0m"
    fi
    account_config_info={\"accountPassMaxDays\":\"$accountPassMaxDays\",\"accountPassMinDays\":\"$accountPassMinDays\",\"accountPassWarnDays\":\"$accountPassWarnDays\",\"accountPassAutolockInactiveDays\":\"$accountPassAutolockInactiveDays\",\"accountShouldUnloginArray\":\"$accountShouldUnloginArray\",\"accountGIDOfRoot\":\"$accountGIDOfRoot\",\"accountProfileFileArray\":\"$accountProfileFileArray\",\"accountProfileTMOUTArray\":\"$accountProfileTMOUTArray\",\"accountIfSetUsersCanAccessSuCommand\":\"$accountIfSetUsersCanAccessSuCommand\"}
    authentication_check_res={\"crond_config_info\":$crond_config_info,\"sshd_config_info\":$sshd_config_info,\"pam_config_info\":$pam_config_info,\"account_config_info\":$account_config_info}
}

function system_check {
    echo "[·] check permission of important file and configuration of user and group"
    # 7.1 check permission of important file and uid gid
    echo "-[·] check permission of important file"
    local files=("/etc/passwd" "/etc/shadow" "/etc/group" "/etc/gshadow" "/etc/passwd-" "/etc/shadow-" "/etc/group-" "/etc/gshadow-")
    importantFilenameArray=$(echo ${files[@]}|sed 's/ /;/g')
    tmpArray1=()
    tmpArray2=()
    for file in ${files[@]}; do
        local perm=$(stat $file |while read x;do if [[ $x =~ "Uid" ]] && [[ $x =~ "(" ]]; then echo $x;fi;done|cut -d"(" -f2,3,4|cut -d"/" -f1)
        local uidGid=$(stat /etc/passwd |while read x;do if [[ $x =~ "Uid" ]] && [[ $x =~ "(" ]]; then echo $x;fi;done|cut -d"(" -f3,4|sed 's/ //g'|sed -r 's/([[:digit:]]{1,}).*([[:digit:]]{1,}).*/\1 \2/g'|cut -d" " -f1,2)
        tmpArray1+=($perm\;)
        tmpArray2+=($uidGid\;)
        if [[ $file =~ "shadow" ]]; then
            if [[ $perm = "0000" ]]; then
                echo -e "\033[32m-[+] file $file's permission is $perm \033[0m"
            else
                echo -e "\033[31m-[-] file $file's permission is $perm,should set to 0000 \033[0m"
            fi
        else
            if [[ $perm = "0644" ]]; then
                echo -e "\033[32m-[+] file $file's permission is $perm \033[0m"
            else
                echo -e "\033[31m-[-] file $file's permission is $perm,should set to 0644 \033[0m"

            fi
        fi
        if [[ $uidGid = "0 0" ]]; then
            echo -e "\033[32m-[+] file $file's uid gid is $uidGid \033[0m"
        else
            echo -e "\033[31m-[-] file $file's uid gid is $uidGid,should set to 0 0 \033[0m"
        fi
    done
    importantFilePermissionArray=$(echo ${tmpArray1[@]}|sed 's/; /;/g')
    importantFileUidgidArray=$(echo ${tmpArray2[@]}|sed 's/; /;/g')
    file_permission_info={\"importantFilenameArray\":\"$importantFilenameArray\",\"importantFilePermissionArray\":\"$importantFilePermissionArray\",\"importantFileUidgidArray\":\"$importantFileUidgidArray\"}
    # 7.2 check configuration of user and group
    echo "-[·] check configuration of user and group"
    # 7.2.1 check if user's password is empty
    users=$(cat /etc/shadow |awk -F: '($2=="!!"){print $1}'|while read x;do 
        res=$(grep ${x} /etc/passwd|cut -d: -f7)
        if [[ $res != "/sbin/nologin" ]] && [[ $res != "/sbin/shutdown" ]] && [[ $res != "/sbin/halt" ]]; then 
            echo $x
            #echo -e "\033[31m-[-] $x should have a passwd,not empty \033[0m"; 
            fi;
        done)
    if [[ -z $users ]]; then
        userIfSetPasswdOrArray="True"
        echo -e "\033[32m-[+] all user account have set password \033[0m"
    else
        userIfSetPasswdOrArray=$(echo $users|sed 's/ /;/g')
        echo -e "\033[31m-[-] user:$(echo $users|sed 's/\n/ /g') should set a password ,rather than empty \033[0m"
    fi
    # 7.2.2 check if root is the only UID 0 account
    local users=$(cat /etc/passwd|awk -F: '($3==0){print $1}')
    if [[ $users = 'root' ]]; then
        uid0OnlyRootOrArray="True"
        echo -e "\033[32m-[+] root is the only account that uid is 0 \033[0m"
    else
        uid0OnlyRootOrArray=$(echo $users|sed 's/root //g'|sed 's/ /;/g')
        echo -e "\033[31m-[-] $(echo $users|sed 's/root //g'|sed 's/\n/ /g') uid should not be 0 \033[0m"
    fi
    # 7.2.3 check root PATH integrith
    if [ "$(echo $PATH|grep ::)" != "" ]; then
        echo -e "\033[31m-[-] Empty Directory in PATH (::) \033[0m"
    fi
    if [ "$(echo $PATH|grep :$)" != "" ]; then
        echo -e "\033[31m-[-] Trailing : in PATH \033[0m"
    fi
    path=$( echo $PATH|sed -e 's/::/:/' -e 's/:$//' -e 's/:/ /g')
    tmpArray1=()
    tmpArray2=()
    tmpArray3=()
    tmpArray4=()
    tmpArray5=()
    set -- $path
    while [[ $1 != "" ]]; do
        if [[ $1 = "." ]]; then
            echo -e "\033[31m-[-] PATH contains . \033[0m"
            tmpArray1+=(".")
            shift
            continue
        fi
        if [[ -d $1 ]]; then
            local dirperm=$(ls -ldH $1|cut -d" " -f1)
            if [[ $(echo $dirperm|cut -c6) != "-" ]]; then
                tmpArray2+=($1\;)
                echo -e "\033[31m-[-] Group Write permission should not set on directory $1 \033[0m"
            fi
            if [[ $(echo $dirperm|cut -c9) != "-" ]]; then
                tmpArray3+=($1\;)
                echo -e "\033[31m-[-] Other Write permission should not set on directory $1 \033[0m"
            fi
            local dirown=$(ls -ldH $1|awk '{print $3}')
            if [[ $dirown != "root" ]]; then
                tmpArray4+=($1\;)
                echo -e "\033[31m-[-] dir $1's owner is $dirown,should be root \033[0m"
            fi
        else
            tmpArray5+=($1\;)
            echo -e "\033[31m-[-] $1 is not a directory or not exist \033[0m"
        fi
        shift
    done
    if [[ ${#tmpArray1[@]} = 0 ]]; then
        pathDirIfNotHasDot="True"
    else
        pathDirIfNotHasDot="False"
    fi
    pathDirPermissionHasGWArray=$(echo ${tmpArray2[@]}|sed 's/; /;/g')
    pathDirPermissionHasOWArray=$(echo ${tmpArray3[@]}|sed 's/; /;/g')
    pathDirOwnerIsNotRootArray=$(echo ${tmpArray4[@]}|sed 's/; /;/g')
    pathDirDoesNotExistOrNotDirArray=$(echo ${tmpArray5[@]}|sed 's/; /;/g')
    # 7.2.4 check if is all users' home directories exist
    #cat /etc/passwd|egrep -v '^(root|halt|sync|shutdown)'|awk -F: '($7 != "/sbin/nologin" && $7 != "/bin/false"){print $1 " " $6}'|while read user dir; do
    tmpArray1=()
    tmpArray2=()
    tmpArray3=()
    tmpArray4=()
    tmpArray5=()
    tmpArray6=()
    while read user dir; do
        tmpArray1+=($dir\;)
        if [[ ! -d $dir ]]; then
            tmpArray2+=("False;")
            tmpArray3+=("False;")
            echo -e "\033[31m-[-] the home directory ($dir) of user $user does not exist \033[0m"

        else
            tmpArray2+=("True;")
            # 7.2.5 check if users' home directories permissions are 750 or more restrictive
            #local dirperm=$(ls -ld $dir|cut -d" " -f1)
            local dirperm=$(stat -c %a $dir)
            tmpArray3+=($dirperm\;)
            if [[ $(echo $dirperm |cut -c6) != "-" ]]; then
                echo -e "\033[31m-[-] Group Write permission set on the home directory ($dir) of user $user \033[0m"
            fi
            if [[ $(echo $dirperm |cut -c8) != "-" ]]; then
                echo -e "\033[31m-[-] Other Read permission set on the home directory ($dir) of user $user \033[0m"
            fi
            if [[ $(echo $dirperm |cut -c9) != "-" ]]; then
                echo -e "\033[31m-[-] Other Write permission set on the home directory ($dir) of user $user \033[0m"
            fi
            if [[ $(echo $dirperm |cut -c10) != "-" ]]; then
                echo -e "\033[31m-[-] Other Execute permission set on the home directory ($dir) of user $user \033[0m"
            fi
            # 7.2.6 check if is users own their home directory
            local owner=$(stat -L -c "%U" $dir)
            if [[ $owner != $user ]]; then
                tmpArray4+=("False;")
                echo -e "\033[31m-[-]The home directory ($dir) of user $user is owned by $owner \033[0m"
            else
                tmpArray4+=("True;")
            fi
            # 7.2.7 check users' dot files are not group or world  writable
            local tmpc=0
            for file in $dir/.[A-Za-z0-9]*; do
                if [[ ! -h $file ]] && [[ -f $file ]]; then
                    local fileperm=$(ls -ld $file|cut -d" " -f1)
                    if [[ $(echo $fileperm|cut -c6) != "-" ]]; then
                        tmpc=$(expr $tmpc + 1)
                        echo -e "\033[31m-[-] Group Write permission set on file $file \033[0m"
                    fi
                    if [[ $(echo $fileperm|cut -c9) != "-" ]]; then
                        tmpc=$(expr $tmpc + 1)
                        echo -e "\033[31m-[-] Other Write permission set on file $file \033[0m"
                    fi
                fi
            done
            if [[ $tmpc = 0 ]]; then
                tmpArray5+=("True;")
            else
                tmpArray5+=("False;")
            fi
            # 7.2.8 check if no usrs have .netrc .rhosts .forward file
            tmpc=0
            if [[ ! -h $dir/.netrc ]] && [[ -f $dir/.netrc ]]; then
                tmpc=$(expr $tmpc + 1)
                echo -e "\033[31m-[-] .netrc file $dir/.netrc exists \033[0m"
            fi
            if [[ ! -h $dir/.rhosts ]] && [[ -f $dir/.rhosts ]]; then
                tmpc=$(expr $tmpc + 1)
                echo -e "\033[31m-[-] .rhosts file $dir/.rhosts exists \033[0m"
            fi
            if [[ ! -h $dir/.forward ]] && [[ -f $dir/.forward ]]; then
                tmpc=$(expr $tmpc + 1)
                echo -e "\033[31m-[-] .forward file $dir/.forward exists \033[0m"
            fi
            if [[ $tmpc = 0 ]]; then
                tmpArray6+=("True;")
            else
                tmpArray6+=("False;")
            fi
        fi
    done < <(cat /etc/passwd|egrep -v '^(root|halt|sync|shutdown)'|awk -F: '($7 != "/sbin/nologin" && $7 != "/bin/false"){print $1 " " $6}')
    userArray=$(echo ${tmpArray1[@]}|sed 's/; /;/g')
    userHomeDirIfExistArray=$(echo ${tmpArray2[@]}|sed 's/; /;/g')
    userHomeDirPermissionArray=$(echo ${tmpArray3[@]}|sed 's/; /;/g')
    userIfOwnTheirHomeDirArray=$(echo ${tmpArray4[@]}|sed 's/; /;/g')
    userHomeDirIfHasGWorOWDotFileArray=$(echo ${tmpArray5[@]}|sed 's/; /;/g')
    userHomeDirIfHasOtherFileArray=$(echo ${tmpArray6[@]}|sed 's/; /;/g')
    # 7.2.9 check if all groups in /etc/passwd exist in /etc/group
    tmpArray=()
    for i in $(cut -d: -s -f4 /etc/passwd|sort -u); do
        grep -q -P "^.*?:[^:]*:$i" /etc/group
        if [[ $? -ne 0 ]]; then
        tmpArray+=($i\;)
            echo -e "\033[31m-[-] Group $i is referenced by /etc/passwd but does not exist in /etc/group \033[0m"
        fi
    done
    groupNotExistInetcgroup=$(echo ${tmpArray[@]}|sed 's/; /;/g')
    # 7.2.10 check if every user has a unique UID
    #cat /etc/passwd|cut -d":" -f3|sort -n|uniq -c|while read x; do
    tmpArray=()
    while read x; do
        [[ -z $x ]] && break
        set - $x
        if [[ $1 -gt 1 ]]; then
            local users=$(awk -F: '($3==n){print $1}' n=$2 /etc/passwd|xargs)
            tmpArray+=($2:$users\;)
            echo -e "\033[31m-[-] Duplicate UID $2 : $users \033[0m"
        fi
    done < <(cat /etc/passwd|cut -d":" -f3|sort -n|uniq -c)
    usersIfHasUniqueUIDArray=$(echo ${tmpArray[@]}|sed 's/; /;/g')
    # 7.2.11 check if every group has a unique GID
    tmpArray=()
    #cat /etc/group|cut -d":" -f3|sort -n|uniq -c|while read x; do
    while read x; do
        [[ -z $x ]] && break
        set - $x
        if [[ $1 -gt 1 ]]; then
            local groups=$(awk -F: '($3==n){print $1}' n=$2 /etc/group|xargs)
            tmpArray+=($2:$groups\;)
            echo -e "\033[31m-[-] Duplicate GID $2 : $groups \033[0m"
        fi
    done < <(cat /etc/group|cut -d":" -f3|sort -n|uniq -c)
    groupsIfHasUniqueGIDArray=${tmpArray[@]}
    # 7.2.12 check if user name is unique
    tmpArray=()
    #cat /etc/passwd|cut -d":" -f1|sort -n|uniq -c|while read x; do
    while read x; do
        [[ -z $x ]] && break
        set - $x11
        if [[ $1 -gt 1 ]]; then
            local uids=$(awk -F: '($1 == n){print $3}' n=$2 /etc/passwd|xargs)
            tmpArray+=($2:$uids\;)
            echo -e "\033[31m-[-] Duplicate user name $2 : $uids \033[0m"
        fi
    done < <(cat /etc/passwd|cut -d":" -f1|sort -n|uniq -c)
    usersIfHasUniqueNameArray=${tmpArray[@]}
    # 7.2.13 check if group name is unique
    tmpArray=()
    #cat /etc/group|cut -d":" -f1|sort -n|uniq -c|while read x; do
    while read x; do
        [[ -z $x ]] && break
        set - $x11
        if [[ $1 -gt 1 ]]; then
            local gids=$(awk -F: '($1 == n){print $3}' n=$2 /etc/group|xargs)
            tmpArray+=($2:$gids\;)
            echo -e "\033[31m-[-] Duplicate group name $2 : $gids \033[0m"
        fi
    done < <(cat /etc/group|cut -d":" -f1|sort -n|uniq -c)
    groupsIfHasUniqueNameArray=${tmpArray[@]}
    usergroup_config_info={\"userIfSetPasswdOrArray\":\"$userIfSetPasswdOrArray\",\"uid0OnlyRootOrArray\":\"$uid0OnlyRootOrArray\",\"pathDirIfNotHasDot\":\"$pathDirIfNotHasDot\",\"pathDirPermissionHasGWArray\":\"$pathDirPermissionHasGWArray\",\"pathDirPermissionHasOWArray\":\"$pathDirPermissionHasOWArray\",\"pathDirOwnerIsNotRootArray\":\"$pathDirOwnerIsNotRootArray\",\"pathDirDoesNotExistOrNotDirArray\":\"$pathDirDoesNotExistOrNotDirArray\",\"userArray\":\"$userArray\",\"userHomeDirIfExistArray\":\"$userHomeDirIfExistArray\",\"userHomeDirPermissionArray\":\"$userHomeDirPermissionArray\",\"userIfOwnTheirHomeDirArray\":\"$userIfOwnTheirHomeDirArray\",\"userHomeDirIfHasGWorOWDotFileArray\":\"$userHomeDirIfHasGWorOWDotFileArray\",\"userHomeDirIfHasOtherFileArray\":\"$userHomeDirIfHasOtherFileArray\",\"groupNotExistInetcgroup\":\"$groupNotExistInetcgroup\",\"usersIfHasUniqueUIDArray\":\"$usersIfHasUniqueUIDArray\",\"groupsIfHasUniqueGIDArray\":\"$groupsIfHasUniqueGIDArray\"}
    system_check_res={\"file_permission_info\":$file_permission_info,\"usergroup_config_info\":$usergroup_config_info}

}

echo """
==================================
|        Linux 基线检查工具       |
|        wechat:JC_SecNotes      |
|        author:JC0o0l           |
|        version:3.0             |
==================================
"""
echo "========================Get Basic Info========================="
get_basic_info
echo "========================Linux OS Scan=========================="
init_check
service_check
network_check
auditd_check
log_check
authentication_check
system_check
if [[ -z $authentication_check_res ]]; then
    authentication_check_res={}
fi
if [[ -z $system_check_res ]]; then
    system_check_res={}
fi
#check_result={\"basic_info\":$basic_info,\"init_check_res\":$init_check_res,\"service_check_res\":$service_check_res,\"network_check_res\":$network_check_res,\"auditd_check_res\":$auditd_check_res,\"log_check_res\":$log_check_res,\"authentication_check_res\":$authentication_check_res,\"system_check_res\":$system_check_res}
#curl -X POST "http://192.168.3.24:8888/baseline/linux_scan_res_report/" -H "accept:application/json" -H "content-type:application/json" -d "$check_result" 1>/dev/null 2>/dev/null
echo "===========================Middleware Scan========================="
source nginx_baseline_check.sh
source redis_baseline_check.sh
source tomcat_baseline_check.sh
source apache_baseline_check.sh
source vuln_scan.sh
nginxScan
redisScan
tomcatScan
apacheScan
vulnScan

os_scan_result={\"basic_info\":$basic_info,\"init_check_res\":$init_check_res,\"service_check_res\":$service_check_res,\"network_check_res\":$network_check_res,\"auditd_check_res\":$auditd_check_res,\"log_check_res\":$log_check_res,\"authentication_check_res\":$authentication_check_res,\"system_check_res\":$system_check_res}
echo $os_scan_result|jq 
middleware_check_result={\"basic_info\":$basic_info,\"redis_check_res\":$redisScanResult,\"nginx_check_res\":$nginxScanResult,\"tomcat_check_res\":$tomcatScanResult,\"apache_check_res\":$apacheScanResult}
#echo $middleware_check_result
echo $middleware_check_result|jq
vuln_scan_result={\"basic_info\":$basic_info,\"vuln_scan_res\":$vulnScanResult}
echo $vuln_scan_result
#echo $vuln_scan_result|jq
check_result={\"os_scan_result\":$os_scan_result,\"middleware_check_result\":$middleware_check_result,\"vuln_scan_result\":$vuln_scan_result}
echo "==========================Upload Check Result======================"
curl -X POST "http://192.168.3.111:8000/baseline/linux_scan_res_report/" -H "accept:application/json" -H "content-type:application/json" -d "$check_result" 1>/dev/null 2>/dev/null
