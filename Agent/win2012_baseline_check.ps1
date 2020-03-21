<#
Author: JC (@chroblert)
Author: JC0o0l (@chroblert)
Mail: jerryzvs@163.com
wechat: Chroblert_Jerrybird(信安札记)
#>
chcp 65001
function Get-BasicInfo{
	$scanTime=Get-date -Format 'yyyy-M-d H:m:s'
	$hostname = hostname
	$osVersion=Get-WmiObject -Class Win32_OperatingSystem | Select-Object -ExpandProperty Caption
	$ipList = ""
	$macaddr = ""
	foreach($line in ipconfig /all|Select-String -Pattern "^\s*IPv4"){ 
		$line=$line.ToString().split(":")[1].replace("(","\(").replace(")","\)")
		$context = (ipconfig /all |Select-String -Pattern $line -Context 10,0).Context[0]
		if ($context.Precontext|Select-String "VMware" -Quiet){
			continue	
		}
		foreach ($lline in $context.Precontext.split("\n")){
			#Write-Host $lline
			if ($lline.ToString().contains("Physical")){
				#Write-Host $lline.ToString() dddd
				$macaddr = $macaddr + $lline.ToString().split(":")[1].Trim() + ";"
				break
			}
		}
		$ipList = $ipList + $line.ToString().split("\")[0].trim() + ";"
	}
	Write-Host scanTime:$scanTime
	Write-Host osVersion:$osVersion
	Write-Host hostname:$hostname
	Write-Host macaddr: $macaddr 
	Write-Host ipList : $ipList 
	$basic_info="{""scanTime"":""$scanTime"",""osVersion"":""$osVersion"",""hostname"":""$hostname"",""macaddr"":""$macaddr"",""ipList"":""$ipList""}"
	return $basic_info
}
function Get-SecInfo{
	$secinfo=""
	SecEdit.exe /export /cfg sec.inf /Quiet
	$secInfoArray=Get-Content .\sec.inf
	foreach ($line in $secInfoArray){
		$secinfo = $secinfo + $line.ToString() + ";"
	}
	return $secInfoArray
}
function Check-PasswordPolicy{
	<#
	.SYNOPSIS
	检查密码策略是否符合预定策略

	.DESCRIPTION
	预定策略：
		密码历史：5
		密码最长使用期限：90
		密码最短使用期限：1
		密码复杂度是否开启：1开启
		是否以可还原的方式加密存储密码：0否
		密码最小长度：8位
	.EXAMPLE
	Check-PasswordPolicy secInfoArray

	.NOTES
	General notes
	#>
	Param(
		[System.Collections.ArrayList]$secInfoArray
	)
	$stPasswordHistorySize=5
	$stMaximumPasswordAge=90
	$stMinimumPasswordAge=1
	$stPasswordComplexity=1
	$stClearTextPassword=0
	$stMinimumPasswordLength=8
	$passwordHistorySize=(Write-Output $secInfoArray|Select-String -pattern "^PasswordHistorySize").ToString().Split("=")[1] -replace "\s",""
	if($passwordHistorySize -lt $stPasswordHistorySize){
		Write-Host [-] PasswordHistorySize less than $stPasswordHistorySize -ForegroundColor Red
	}
	$maximumPasswordAge=(Write-Output $secInfoArray|Select-String -Pattern "^MaximumPasswordAge" ).ToString().Split("=")[1]  -replace "\s",""
	if($maximumPasswordAge -lt $stMaximumPasswordAge){
		Write-Host [-] MaximumPasswordAge less than $stMaximumPasswordAge -ForegroundColor Red
	}
	$minimumPasswordAge=(Write-Output $secInfoArray|Select-String -Pattern "^MinimumPasswordAge").ToString().Split("=")[1] -replace "\s",""
	if($minimumPasswordAge -lt $stMinimumPasswordAge){
		Write-Host [-] MinimumPasswordAge less than $stMinimumPasswordAge -ForegroundColor Red
	}
	$passwordComplexity=(Write-Output $secInfoArray|Select-String -Pattern "^PasswordComplexity").ToString().Split("=")[1] -replace "\s",""
	if($passwordComplexity -ne $stPasswordComplexity){
		Write-Host [-] PasswordComplexity value is not $stPasswordComplexity -ForegroundColor Red
	}
	$clearTextPassword=(Write-Output $secInfoArray|Select-String -Pattern "^ClearTextPassword").ToString().Split("=")[1] -replace "\s",""
	if($clearTextPassword -ne $stClearTextPassword){
		Write-Host [-] ClearTextPassword value is not stCclearTextPassword -ForegroundColor Red
	}
	$minimumPasswordLength=(Write-Output $secInfoArray|Select-String -Pattern "^MinimumPasswordLength").ToString().Split("=")[1] -replace "\s",""
	if($minimumPasswordLength -lt $stMinimumPasswordLength){
		Write-Host [-] MinimumPasswordLength less than $stMinimumPasswordLength -ForegroundColor Red
	}
	$password_check_info="{""passwordHistorySize"":""$passwordHistorySize"",""maximumPasswordAge"":""$maximumPasswordAge"",""minimumPasswordAge"":""$minimumPasswordAge"",""passwordComplexity"":""$passwordComplexity"",""clearTextPassword"":""$clearTextPassword"",""minimumPasswordLength"":""$minimumPasswordLength""}"
	#Write-Host $password_check_info
	return $password_check_info

}
function Check-AccountLockoutPolicy{
	<#
	.SYNOPSIS
	检查账户锁定的相关策略
	
	.DESCRIPTION
	预定策略：
		账户锁定时间：15 Or more
		账户锁定阈值: 5 or less
		重置账户锁定: 15 or more,但值要小于账户锁定时间
	
	.PARAMETER secInfoArray
	使用secedit /export /cfg sec.inf 导出的文件，再输出到secInfoArray中

	.EXAMPLE
	Check-AccountLockoutPolicy $secInfoArray
	
	.NOTES
	General notes
	#>
	
	Param(
		[System.Collections.ArrayList]$secInfoArray
	)
	$stLockoutDuration=15
	$stLockoutBadCount=5
	$stResetLockoutCount=15
	$lockoutDuration=(Write-Output $secInfoArray|Select-String -Pattern "^LockoutDuration" -Quiet)
	if($lockoutDuration){
		$lockoutDuration=(Write-Output $secInfoArray|Select-String -Pattern "^LockoutDuration").ToString().Split("=")[1] -replace "\s",""
		if($lockoutDuration -lt $stLockoutDuration){
			Write-Host [-] LockoutDuration less than $stLockoutDuration -ForegroundColor Red
		}
	}else{
		$lockoutDuration=0
	}
	
	$lockoutBadCount=(Write-Output $secInfoArray|Select-String -Pattern "^LockoutBadCount").ToString().Split("=")[1] -replace "\s",""
	if($lockoutBadCount -lt $stLockoutBadCount){
		Write-Host [-] LockoutBadCount less than $stLockoutBadCount -ForegroundColor Red
	}

	$resetLockoutCount=(Write-Output $secInfoArray|Select-String -Pattern "^ResetLockoutCount" -Quiet)
	if($resetLockoutCount){
		$resetLockoutCount=(Write-Output $secInfoArray|Select-String -Pattern "^ResetLockoutCount").ToString().Split("=")[1] -replace "\s",""
		if($resetLockoutCount -lt $stLockoutDuration -or  $resetLockoutCount -gt $lockoutDuration){
			Write-Host [-] ResetLockoutCount great than $stResetLockoutCount or less than $stLockoutDuration
		}
	}else{
		$resetLockoutCount=0
	}
	
	$account_lockout_info="{""lockoutDuration"":""$lockoutDuration"",""lockoutBadCount"":""$lockoutBadCount"",""resetLockoutCount"":""$resetLockoutCount""}"
	return $account_lockout_info


}
function Get-AccountPolicyCheckRes{
	Param(
		[System.Collections.ArrayList] $secInfoArray
	)
	$password_check_info=(Check-PasswordPolicy $secInfoArray)
	$account_lockout_info=(Check-AccountLockoutPolicy $secInfoArray)
	$account_check_res="{""password_check_info"":$password_check_info,""account_lockout_info"":$account_lockout_info}"
	return $account_check_res
}
function  Get-AuditPolicyCheckRes {
	<#
	.SYNOPSIS
     获取策略中关于审计策略的部分
	
	.DESCRIPTION
	预定策略：
		 审核策略更改：成功
		 审核登录事件：成功，失败
		 审核对象访问：成功
		 审核进程跟踪：成功，失败
		 审核目录服务访问：成功，失败
		 审核系统事件：成功，失败
		 审核账户登录事件：成功，失败
		 审核账户管理事件：成功，失败
	预设值的含义：
		0：没有开启审计
		1：审计成功事件
		2：审计失败事件
		3：审计成功和失败事件
	
	.PARAMETER secInfoArray
	Parameter description
	
	.EXAMPLE
	An example
	
	.NOTES
	General notes
	#>
	
	param (
		[System.Collections.ArrayList]$secInfoArray
	)

	$stAuditPolicyChange=1
	$stAuditLogonEvents=3
	$stAuditObjectAccess=1
	$stAuditProcessTracking=3
	$stAuditDSAccess=3
	$stAuditSystemEvents=3
	$stAuditAccountLogon=3
	$stAuditAccountManage=3
	$auditPolicyChange=(Write-Output $secInfoArray|Select-String -Pattern "^AuditPolicyChange").ToString().Split("=")[1] -replace "\s",""
	if($auditPolicyChange -lt $stAuditPolicyChange){
		Write-Host [-] AuditPolicyChange value should be $stAuditPolicyChange -ForegroundColor Red
	}
	$auditLogonEvents=(Write-Output $secInfoArray|Select-String -Pattern "^AuditLogonEvents").ToString().Split("=")[1] -replace "\s",""
	if($auditLogonEvents -lt $stAuditLogonEvents){
		Write-Host [-] AuditLogonEvents value should be $stAuditLogonEvents -ForegroundColor Red
	}
	$auditObjectAccess=(Write-Output $secInfoArray|Select-String -Pattern "^AuditObjectAccess").ToString().Split("=")[1] -replace "\s",""
	if($auditObjectAccess -lt $stAuditObjectAccess){
		Write-Host [-] AuditObjectAccess value should be $stAuditObjectAccess -ForegroundColor Red
	}
	$auditProcessTracking=(Write-Output $secInfoArray|Select-String -Pattern "^AuditProcessTracking").ToString().Split("=")[1] -replace "\s",""
	if($auditProcessTracking -lt $stAuditProcessTracking){
		Write-Host [-] AuditProcessTracking value should be $stAuditProcessTracking -ForegroundColor Red
	}
	$auditDSAccess=(Write-Output $secInfoArray|Select-String -Pattern "^AuditDSAccess").ToString().Split("=")[1] -replace "\s",""
	if($auditDSAccess -lt $stAuditDSAccess){
		Write-Host [-] AuditDSAccess value should be $stAuditDSAccess -ForegroundColor Red
	}
	$auditSystemEvents=(Write-Output $secInfoArray|Select-String -Pattern "^AuditSystemEvents").ToString().Split("=")[1] -replace "\s",""
	if($auditSystemEvents -lt $stAuditSystemEvents){
		Write-Host [-] AuditSystemEvents value should be $stAuditSystemEvents -ForegroundColor Red
	}
	$auditAccountLogon=(Write-Output $secInfoArray|Select-String -Pattern "^AuditAccountLogon").ToString().Split("=")[1] -replace "\s",""
	if($auditAccountLogon -lt $stAuditAccountLogon){
		Write-Host [-] AuditAccountLogon value should be $stAuditAccountLogon -ForegroundColor Red
	}
	$auditAccountManage=(Write-Output $secInfoArray|Select-String -Pattern "^AuditAccountManage").ToString().Split("=")[1] -replace "\s",""
	if($auditAccountManage -lt $stAuditAccountManage){
		Write-Host [-] AuditAccountManage value should be $stAuditAccountManage -ForegroundColor Red
	}
	$audit_check_res="{""auditPolicyChange"":""$auditPolicyChange"",""auditLogonEvents"":""$auditLogonEvents"",""auditObjectAccess"":""$auditObjectAccess"",""auditProcessTracking"":""$auditProcessTracking"",""auditDSAccess"":""$auditDSAccess"",""auditSystemEvents"":""$auditSystemEvents"",""auditAccountLogon"":""$auditAccountLogon"",""auditAccountManage"":""$auditAccountManage""}"
	#Write-Host $audit_check_res
	return $audit_check_res
	
}
function Get-UserRightPolicyCheckRes{
	Param(
		[System.Collections.ArrayList]$secInfoArray
	)
	# 确保“作为受信任的呼叫放访问凭据管理器”值为空
	$seTrustedCredManAccessPrivilege=(Write-Output $secInfoArray|Select-String -Pattern "^SeTrustedCredManAccessPrivilege" -Quiet) 
	if(-not $seTrustedCredManAccessPrivilege){
		$seTrustedCredManAccessPrivilegeIFNone="True"
	}else{
		$seTrustedCredManAccessPrivilegeIFNone=(Write-Output $secInfoArray|Select-String -Pattern "^SeTrustedCredManAccessPrivilege").ToString().Split("=")[1] -replace "\s",""
		Write-Host "[-] SeTrustedCredManAccessPrivilege value should be None" -ForegroundColor Red
	}
	# 确保“以操作系统方式运行”值为空
	$seTcbPrivilege=(Write-Output $secInfoArray|Select-String -Pattern "^SeTcbPrivilege" -Quiet) 
	if(-not $seTcbPrivilege){
		$seTcbPrivilegeIFNone="True"
	}else{
		$seTcbPrivilegeIFNone=(Write-Output $secInfoArray|Select-String -Pattern "^SeTcbPrivilege").ToString().Split("=")[1] -replace "\s",""
		Write-Host "[-] SeTcbPrivilege value should be None" -ForegroundColor Red
	}
	# 确保“将工作站添加到域”值仅为特定的几个用户，不得为域账户、guest账户及域计算机
	$seMachineAccountPrivilegeIFOnlySpecifiedUserOrArray=(Write-Output $secInfoArray|Select-String "^SeMachineAccountPrivilege" -Quiet)
	if(-not $seMachineAccountPrivilegeIFOnlySpecifiedUserOrArray){
		$seMachineAccountPrivilegeIFOnlySpecifiedUserOrArray="True"
	}else{
		$flag=0
		$seMachineAccountPrivilegeIFOnlySpecifiedUserOrArray=""
		foreach($sid in ((Write-Output $secInfoArray|Select-String -Pattern "^SeMachineAccountPrivilege").ToString().Split("=")[1].Trim()).Split(",")){
			$sidSuffix=$sid.split("-")[-1].ToString()
			#Write-Host $sidSuffix
			$seMachineAccountPrivilegeIFOnlySpecifiedUserOrArray=$seMachineAccountPrivilegeIFOnlySpecifiedUserOrArray.ToString()+ $sidSuffix +";"
			if($sidSuffix.contains("513") -or $sidSuffix.contains("514") -or $sidSuffix.contains("515") -or $sidSuffix.contains("501")){
				$flag=1
			}
		} 
		if ($flag){
			Write-Host "[-] SeMachineAccountPrivilege value should only be specified user or group ,cannot be guest ,domain user or domain computer" -ForegroundColor Red
		}else{
			$seMachineAccountPrivilegeIFOnlySpecifiedUserOrArray="True"
		}
	}
	# 确保“创建全局对象”值为空
	$seCreateGlobalPrivilegeIFNone=(Write-Output $secInfoArray|Select-String -Pattern "^SeCreateGlobalPrivilege" -Quiet)
	if(-not $seCreateGlobalPrivilegeIFNone){
		$seCreateGlobalPrivilegeIFNone="True"
	}else{
		$seCreateGlobalPrivilegeIFNone=(Write-Output $secInfoArray|Select-String -Pattern "^SeCreateGlobalPrivilege" ).ToString().Split("=")[1] -replace "\s",""
		Write-Host "[-] SeCreateGlobalPrivilege value should be None" -ForegroundColor Red
	}
	# 确保“拒绝作为批处理作业登录”包含“Guests"
	$seDenyBatchLogonRightIFContainGuests=(Write-Output $secInfoArray|Select-String -Pattern "^SeDenyBatchLogonRight" -Quiet)
	if(-not $seDenyBatchLogonRightIFContainGuests){
		$seDenyBatchLogonRightIFContainGuests="False"
		Write-Host "[-] SeDenyBatchLogonRight value should contains 501(guest account)" -ForegroundColor Red
	}else{
		$flag=0
		foreach($sid in ((Write-Output $secInfoArray|Select-String -Pattern "^SeDenyBatchLogonRight").ToString().Split("=")[1].Trim()).Split(",")){
			$sidSuffix=$sid.Split("-")[-1].ToString()
			if($sidSuffix.Contains("501")){
				$seDenyBatchLogonRightIFContainGuests="True"
				$flag=1
			}
		}
		if(-not $flag){
			$seDenyBatchLogonRightIFContainGuests="False"
			Write-Host "[-] SeDenyBatchLogonRight value should contains 501(guest account)" -ForegroundColor Red
		}
	}
	# 确保”拒绝以服务身份登录”值包含“Guest”
	$seDenyServiceLogonRightIFContainGuests=(Write-Output $secInfoArray|Select-String -Pattern "^SeDenyServiceLogonRight" -Quiet)
	if(-not $seDenyServiceLogonRightIFContainGuests){
		$seDenyServiceLogonRightIFContainGuests="False"
		Write-Host "[-] SeDenyServiceLogonRight value should contains 501(guest account)" -ForegroundColor Red
	}else{
		$flag=0
		foreach($sid in ((Write-Output $secInfoArray|Select-String -Pattern "^SeDenyServiceLogonRight").ToString().Split("=")[1].Trim()).Split(",")){
			$sidSuffix=$sid.Split("-")[-1].ToString()
			if($sidSuffix.Contains("501")){
				$seDenyServiceLogonRightIFContainGuests="True"
				$flag=1
			}
		}
		if(-not $flag){
			$seDenyServiceLogonRightIFContainGuests="False"
			Write-Host "[-] SeDenyServiceLogonRight value should contains 501(guest account)" -ForegroundColor Red
		}
	}
	# 确保“拒绝本地登录”值包含“Guests”
	$seDenyInteractiveLogonRightIFContainGuests=(Write-Output $secInfoArray|Select-String -Pattern "^SeDenyInteractiveLogonRight" -Quiet)
	if(-not $seDenyInteractiveLogonRightIFContainGuests){
		$seDenyInteractiveLogonRightIFContainGuests="False"
		Write-Host "[-] SeDenyInteractiveLogonRight value should contains 501(guest account)" -ForegroundColor Red
	}else{
		$flag=0
		foreach($sid in ((Write-Output $secInfoArray|Select-String -Pattern "^SeDenyInteractiveLogonRight").ToString().Split("=")[1].Trim()).Split(",")){
			$sidSuffix=$sid.Split("-")[-1].ToString()
			if($sidSuffix.Contains("501")){
				$seDenyInteractiveLogonRightIFContainGuests="True"
				$flag=1
			}
		}
		if(-not $flag){
			$seDenyInteractiveLogonRightIFContainGuests="False"
			Write-Host "[-] SeDenyInteractiveLogonRight value should contains 501(guest account)" -ForegroundColor Red
		}
	}
	# 确保“从远程强制关机”值为“administrator”本地组s-1-5-32-544和“s-1-5-32-549”（域控的一个内置组）
	$seRemoteShutdownPrivilegeIFOnlySpecifiedUserOrArray=(Write-Output $secInfoArray|Select-String "^SeRemoteShutdownPrivilege" -Quiet)
	if(-not $seRemoteShutdownPrivilegeIFOnlySpecifiedUserOrArray){
		$seRemoteShutdownPrivilegeIFOnlySpecifiedUserOrArray="True"
	}else{
		$flag=0
		$count=0
		$seRemoteShutdownPrivilegeIFOnlySpecifiedUserOrArray=""
		foreach($sid in ((Write-Output $secInfoArray|Select-String -Pattern "^SeRemoteShutdownPrivilege").ToString().Split("=")[1].Trim()).Split(",")){
			$count=$count+1
			$sidSuffix=$sid.split("-")[-1].ToString()
			#Write-Host $sidSuffix
			$seRemoteShutdownPrivilegeIFOnlySpecifiedUserOrArray=$seRemoteShutdownPrivilegeIFOnlySpecifiedUserOrArray.ToString()+ $sidSuffix +";"
			if($sidSuffix.contains("513") -or $sidSuffix.contains("514") -or $sidSuffix.contains("515") -or $sidSuffix.contains("501")){
				$flag=1
			}
		} 
		if ($flag -or $count -gt 2){
			Write-Host "[-] SeRemoteShutdownPrivilege value should only be specified user or group ,cannot be guest ,domain user or domain computer" -ForegroundColor Red
		}else{
			$seRemoteShutdownPrivilegeIFOnlySpecifiedUserOrArray="True"
		}
	}
	# 确保“修改对象标签”值为空
	$seRelabelPrivilegeIFNone=(Write-Output $secInfoArray|Select-String -Pattern "^SeRelabelPrivilege" -Quiet)
	if(-not $seRelabelPrivilegeIFNone){
		$seRelabelPrivilegeIFNone="True"
	}else{
		$seRelabelPrivilegeIFNone=(Write-Output $secInfoArray|Select-String -Pattern "^SeRelabelPrivilege" ).ToString().Split("=")[1] -replace "\s",""
		Write-Host "[-] SeRelabelPrivilege value should be None" -ForegroundColor Red
	}
	# 确保“同步目录服务数据”值为空
	$seSyncAgentPrivilegeIFNone=(Write-Output $secInfoArray|Select-String -Pattern "^SeSyncAgentPrivilege" -Quiet)
	if(-not $seSyncAgentPrivilegeIFNone){
		$seSyncAgentPrivilegeIFNone="True"
	}else{
		$seSyncAgentPrivilegeIFNone=(Write-Output $secInfoArray|Select-String -Pattern "^SeSyncAgentPrivilege" ).ToString().Split("=")[1] -replace "\s",""
		Write-Host "[-] SeSyncAgentPrivilege value should be None" -ForegroundColor Red
	}
	$userright_check_res="{""seTrustedCredManAccessPrivilegeIFNone"":""$seTrustedCredManAccessPrivilegeIFNone"",""seTcbPrivilegeIFNone"":""$seTcbPrivilegeIFNone"",""seMachineAccountPrivilegeIFOnlySpecifiedUserOrArray"":""$seMachineAccountPrivilegeIFOnlySpecifiedUserOrArray"",""seCreateGlobalPrivilegeIFNone"":""$seCreateGlobalPrivilegeIFNone"",""seDenyBatchLogonRightIFContainGuests"":""$seDenyBatchLogonRightIFContainGuests"",""seDenyServiceLogonRightIFContainGuests"":""$seDenyServiceLogonRightIFContainGuests"",""seDenyInteractiveLogonRightIFContainGuests"":""$seDenyInteractiveLogonRightIFContainGuests"",""seRemoteShutdownPrivilegeIFOnlySpecifiedUserOrArray"":""$seRemoteShutdownPrivilegeIFOnlySpecifiedUserOrArray"",""seRelabelPrivilegeIFNone"":""$seRelabelPrivilegeIFNone"",""seSyncAgentPrivilegeIFNone"":""$seSyncAgentPrivilegeIFNone""}"
	#Write-Host $userright_check_res
	return $userright_check_res
}
function Get-SecureOptionCheckRes{
	Param(
		[System.Collections.ArrayList]$secInfoArray
	)
	$stEnableGuestAccount=0
	$stLimitBlankPasswordUse=1
	$stNewAdministratorName="administrator"
	$stNewGuestName="guest"
	$stDontDisplayLastUserName=1
	$stDisableCAD=0
	$stInactivityTimeoutSecs=900
	$stEnablePlainTextPassword=0
	$stAutoDisconnect=15
	$stNoLMHash=1
	$stLSAAnonymousNameLookup=0
	$stRestrictAnonymousSAM=1
	$stRestrictAnonymous=1
	$stClearPageFileAtShutdown=0
	# 确保“账户：来宾账户状态”值为已禁用
	$enableGuestAccount=(Write-Output $secInfoArray|Select-String -Pattern "^EnableGuestAccount").ToString().Split("=")[1].Trim()
	if($enableGuestAccount -eq $stEnableGuestAccount){
		$enableGuestAccount="False"
		Write-Host "[-] EnableGuestAccount value should be $stEnableGuestAccount" -ForegroundColor Red
	}else{
		$enableGuestAccount="True"
	}
	# 确保“账户：限制使用空密码的本地账户只能使用控制台登录”值为“enabled”
	$limitBlankPasswordUse=(Write-Output $secInfoArray|Select-String -Pattern "MACHINE\\System\\CurrentControlSet\\Control\\Lsa\\LimitBlankPasswordUse" -Quiet)
	if($limitBlankPasswordUse){
		$limitBlankPasswordUse=(Write-Output $secInfoArray|Select-String -Pattern "MACHINE\\System\\CurrentControlSet\\Control\\Lsa\\LimitBlankPasswordUse").ToString().Split("=")[1].Split(",")[1]
		if($limitBlankPasswordUse -eq $stLimitBlankPasswordUse){
			$limitBlankPasswordUse="True"
		}else{
			$limitBlankPasswordUse="False"
			Write-Host "[-] LimitBlankPasswordUse value should be $stLimitBlankPasswordUse" -ForegroundColor Red
		}
	}else{
		$limitBlankPasswordUse="False"
		Write-Host "[-] LimitBlankPasswordUse value should be $stLimitBlankPasswordUse" -ForegroundColor Red
	}
	# 配置“账户：重命名系统管理员账户” True:已重命名；False：未重命名
	$newAdministratorName=(Write-Output $secInfoArray|Select-String -Pattern "^NewAdministratorName" -Quiet)
	if($newAdministratorName){
		$newAdministratorName=(Write-Output $secInfoArray|Select-String -Pattern "^NewAdministratorName").ToString().Split("=")[1].Split("""")[1].Split("""")[0]
		if($newAdministratorName -eq $stNewAdministratorName){
			$newAdministratorName="False"
			Write-Host [-] "NewAdministratorName value should not be $stNewAdministratorName" -ForegroundColor Red
		}else{
			$newAdministratorName="True"
		}
	}else{
		$newAdministratorName="False"
		Write-Host [-] "NewAdministratorName value should not be $stNewAdministratorName" -ForegroundColor Red
	}
	# 配置“账户：重命名来宾账户” True:已重命名；False：未重命名
	$newGuestName=(Write-Output $secInfoArray|Select-String -Pattern "^NewGuestName" -Quiet)
	if($newGuestName){
		$newGuestName=(Write-Output $secInfoArray|Select-String -Pattern "^NewGuestName").ToString().Split("=")[1].Split("""")[1].Split("""")[0]
		if($newGuestName -eq $stNewGuestName){
			$newGuestName="False"
			Write-Host [-] "NewGuestName value should not be $stNewGuestName" -ForegroundColor Red
		}else{
			$newGuestName="True"
		}
	}else{
		$newGuestName="False"
		Write-Host [-] "NewGuestName value should not be $stNewGuestName" -ForegroundColor Red
	}
	# 确保“交互式登录：不显示上次登录用户名”值为“Enabled”
	$dontDisplayLastUserName=(Write-Output $secInfoArray|Select-String -Pattern "MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\DontDisplayLastUserName" -Quiet)
	if($dontDisplayLastUserName){
		$dontDisplayLastUserName=(Write-Output $secInfoArray|Select-String -Pattern "MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\DontDisplayLastUserName").ToString().Split("=")[1].Split(",")[1]
		if($dontDisplayLastUserName -eq $stDontDisplayLastUserName){
			$dontDisplayLastUserName="True"
		}else{
			$dontDisplayLastUserName="False"
			Write-Host "[-] DontDisplayLastUserName value should be $stDontDisplayLastUserName" -ForegroundColor Red
		}
	}else{
		$dontDisplayLastUserName="False"
		Write-Host "[-] DontDisplayLastUserName value should be $stDontDisplayLastUserName" -ForegroundColor Red
	}
	# 确保”交互式登录：无需按Ctrl+Alt+Del”值为“Disabled”
	$disableCAD=(Write-Output $secInfoArray|Select-String -Pattern "MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\DisableCAD" -Quiet)
	if($disableCAD){
		$disableCAD=(Write-Output $secInfoArray|Select-String -Pattern "MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\DisableCAD").ToString().Split("=")[1].Split(",")[1]
		if($disableCAD -eq $stDisableCAD){
			$disableCAD="True"
		}else{
			$disableCAD="False"
			Write-Host "[-] DisableCAD value should be $stDisableCAD" -ForegroundColor Red
		}
	}else{
		$disableCAD="False"
		Write-Host "[-] DisableCAD value should be $stDisableCAD" -ForegroundColor Red
	}
	# 确保“交互式登录：计算机不活动限制”值为900或更少 False:该项值不存在
	$inactivityTimeoutSecs=(Write-Output $secInfoArray|Select-String -Pattern "MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\InactivityTimeoutSecs" -Quiet)
	if($inactivityTimeoutSecs){
		$inactivityTimeoutSecs=(Write-Output $secInfoArray|Select-String -Pattern "MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\InactivityTimeoutSecs").ToString().Split("=")[1].Split(",")[1]
		if($inactivityTimeoutSecs -gt $stInactivityTimeoutSecs){
			Write-Host "[-] InactivityTimeoutSecs value should less than $stInactivityTimeoutSecs" -ForegroundColor Red
		}
	}else{
		Write-Host "[-] InactivityTimeoutSecs value should less than $stInactivityTimeoutSecs" -ForegroundColor Red
		$inactivityTimeoutSecs="False"
	}
	# 确保“Microsoft网络客户端：将未加密的密码发送到第三方SMB服务器”值为“Disabled”
	$enablePlainTextPassword=(Write-Output $secInfoArray|Select-String -Pattern "MACHINE\\System\\CurrentControlSet\\Services\\LanmanWorkstation\\Parameters\\EnablePlainTextPassword" -Quiet)
	if($enablePlainTextPassword){
		$enablePlainTextPassword=(Write-Output $secInfoArray|Select-String -Pattern "MACHINE\\System\\CurrentControlSet\\Services\\LanmanWorkstation\\Parameters\\EnablePlainTextPassword").ToString().Split("=")[1].Split(",")[1]
		if($enablePlainTextPassword -eq $stEnablePlainTextPassword){
			$enablePlainTextPassword="True"
		}else{
			$enablePlainTextPassword="False"
			Write-Host "[-] EnablePlainTextPassword value should be $stEnablePlainTextPassword" -ForegroundColor Red
		}
	}else{
		$enablePlainTextPassword="False"
		Write-Host "[-] EnablePlainTextPassword value should be $stEnablePlainTextPassword" -ForegroundColor Red
	}
	# 确保“Microsoft网络服务器：暂停会话前所需的空闲时间数量”值为15分钟或更少，但不为0 False:该项值不存在
	$autoDisconnect=(Write-Output $secInfoArray|Select-String -Pattern "MACHINE\\System\\CurrentControlSet\\Services\\LanmanWorkstation\\Parameters\\AutoDisconnect" -Quiet)
	if($autoDisconnect){
		$autoDisconnect=(Write-Output $secInfoArray|Select-String -Pattern "MACHINE\\System\\CurrentControlSet\\Services\\LanmanWorkstation\\Parameters\\AutoDisconnect").ToString().Split("=")[1].Split(",")[1]
		if($autoDisconnect -gt $stAutoDisconnect){
			Write-Host "[-] InactivityTimeoutSecs value should less than $stInactivityTimeoutSecs" -ForegroundColor Red
		}
	}else{
		$autoDisconnect="False"
		Write-Host "[-] AutoDisconnect value should be $stAutoDisconnect" -ForegroundColor Red
	}
	# 确保“网络安全：在下一次改变密码时不存储LAN管理器哈希值”值为“Enabled”
	$noLMHash=(Write-Output $secInfoArray|Select-String -Pattern "MACHINE\\System\\CurrentControlSet\\Control\\Lsa\\NoLMHash" -Quiet)
	if($noLMHash){
		$noLMHash=(Write-Output $secInfoArray|Select-String -Pattern "MACHINE\\System\\CurrentControlSet\\Control\\Lsa\\NoLMHash").ToString().Split("=")[1].Split(",")[1]
		if($noLMHash -eq $stNoLMHash){
			$noLMHash="True"
		}else{
			$noLMHash="False"
			Write-Host "[-] NoLMHash value should be $stNoLMHash" -ForegroundColor Red
		}
	}else{
		$noLMHash="False"
		Write-Host "[-] NoLMHash value should be $stNoLMHash" -ForegroundColor Red
	}
	# 确保“网络访问：允许匿名SID/名称转换”值为“Disabled" False:Disabled True:Enabled
	$lsaAnonymousNameLookup=(Write-Output $secInfoArray|Select-String -Pattern "LSAAnonymousNameLookup" -Quiet)
	if($lsaAnonymousNameLookup){
		$lsaAnonymousNameLookup=(Write-Output $secInfoArray|Select-String -Pattern "LSAAnonymousNameLookup").ToString().Split("=")[1].Trim()
		if($lsaAnonymousNameLookup -eq $stLSAAnonymousNameLookup){
			$lsaAnonymousNameLookup="False"
		}else{
			$lsaAnonymousNameLookup="True"
			Write-Host "[-] LSAAnonymousNameLookup value should be $stLSAAnonymousNameLookup" -ForegroundColor Red
		}
	}else{
		$lsaAnonymousNameLookup="True"
		Write-Host "[-] LSAAnonymousNameLookup value should be $stLSAAnonymousNameLookup" -ForegroundColor Red
	}
	# 确保“网络访问：不允许SAM账户的匿名枚举”值为“Enabled”
	$restrictAnonymousSAM=(Write-Output $secInfoArray|Select-String -Pattern "^MACHINE\\System\\CurrentControlSet\\Control\\Lsa\\RestrictAnonymousSAM" -Quiet)
	if($restrictAnonymousSAM){
		$restrictAnonymousSAM=(Write-Output $secInfoArray|Select-String -Pattern "^MACHINE\\System\\CurrentControlSet\\Control\\Lsa\\RestrictAnonymousSAM").ToString().Split("=")[1].Split(",")[1]
		if($restrictAnonymousSAM -eq $stRestrictAnonymousSAM){
			$restrictAnonymousSAM="True"
		}else{
			$restrictAnonymousSAM="False"
			Write-Host "[-] RestrictAnonymousSAM value should be $stRestrictAnonymousSAM" -ForegroundColor Red
		}
	}else{
		$restrictAnonymousSAM="False"
		Write-Host "[-] RestrictAnonymousSAM value should be $stRestrictAnonymousSAM" -ForegroundColor Red
	}
	# 确保“网络访问：不允许SAM账户和共享的匿名枚举”值为“Enabled”
	$restrictAnonymous=(Write-Output $secInfoArray|Select-String -Pattern "MACHINE\\System\\CurrentControlSet\\Control\\Lsa\\RestrictAnonymous=" -Quiet)
	if($restrictAnonymous){
		$restrictAnonymous=(Write-Output $secInfoArray|Select-String -Pattern "MACHINE\\System\\CurrentControlSet\\Control\\Lsa\\RestrictAnonymous=").ToString().Split("=")[1].Split(",")[1]
		if($restrictAnonymous -eq $stRestrictAnonymous){
			$restrictAnonymous="True"
		}else{
			$restrictAnonymous="False"
			Write-Host "[-] RestrictAnonymous value should be $stRestrictAnonymous" -ForegroundColor Red
		}
	}else{
		$restrictAnonymous="False"
		Write-Host "[-] RestrictAnonymous value should be $stRestrictAnonymous" -ForegroundColor Red
	}
	# 确保“关机：允许系统在未登录前关机”值未“Disabled”
	$clearPageFileAtShutdown=(Write-Output $secInfoArray|Select-String -Pattern "MACHINE\\System\\CurrentControlSet\\Control\\Session Manager\\Memory Management\\ClearPageFileAtShutdown" -Quiet)
	if($clearPageFileAtShutdown){
		$clearPageFileAtShutdown=(Write-Output $secInfoArray|Select-String -Pattern "MACHINE\\System\\CurrentControlSet\\Control\\Session Manager\\Memory Management\\ClearPageFileAtShutdown").ToString().Split("=")[1].Split(",")[1]
		if($clearPageFileAtShutdown -eq $stClearPageFileAtShutdown){
			$clearPageFileAtShutdown="False"
		}else{
			$clearPageFileAtShutdown="True"
			Write-Host "[-] ClearPageFileAtShutdown value should be $stClearPageFileAtShutdown" -ForegroundColor Red
		}
	}else{
		$clearPageFileAtShutdown="True"
		Write-Host "[-] ClearPageFileAtShutdown value should be $stClearPageFileAtShutdown" -ForegroundColor Red
	}
	$secureoption_check_res="{""enableGuestAccount"":""$enableGuestAccount"",""limitBlankPasswordUse"":""$limitBlankPasswordUse"",""newAdministratorName"":""$newAdministratorName"",""newGuestName"":""$newGuestName"",""dontDisplayLastUserName"":""$dontDisplayLastUserName"",""disableCAD"":""$disableCAD"",""inactivityTimeoutSecs"":""$inactivityTimeoutSecs"",""enablePlainTextPassword"":""$enablePlainTextPassword"",""autoDisconnect"":""$autoDisconnect"",""noLMHash"":""$noLMHash"",""lsaAnonymousNameLookup"":""$lsaAnonymousNameLookup"",""restrictAnonymousSAM"":""$restrictAnonymousSAM"",""restrictAnonymous"":""$restrictAnonymous"",""clearPageFileAtShutdown"":""$clearPageFileAtShutdown""}"

	return $secureoption_check_res
}

function Get-PortSecureCheckRes{
	$key="HKLM\SYSTEM\CurrentControlSet\Control\Terminal server\WinStations\RDP-Tcp"
	$name="Portnumber"
	$rdpPort=(Get-ItemProperty -Path "Registry::$key" -ErrorAction:SilentlyContinue).$name
	if($rdpPort -eq "3389"){
		Write-Host "[-] RDPPort should not be 3389" -ForegroundColor Red
	}
	$portsecure_check_res="{""rdpPort"":""$rdpPort""}"
	return $portsecure_check_res
}
function Get-SystemSecureCheckRes{
	$key="HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer"
	$name="NoDriveTypeAutoRun"
	$autoRunRes=(Get-ItemProperty -Path "Registry::$key" -ErrorAction:SilentlyContinue).$name
	if(-not $autoRunRes){
		$autoRunRes="False"
	}
	$systemsecure_check_res="{""autoRunRes"":""$autoRunRes""}"
	return $systemsecure_check_res
}

function Get-CollectKB(){
    # 1. 搜集所有的KB补丁
    $KBArray = @()
    $KBArray = Get-HotFix|ForEach-Object {$_.HotFixId}
    $test = $KBArray|ConvertTo-Json
    return $test
}
function Get-ABasicInfo(){
    # 1. 操作系统
    # $windowsProductName = (Get-ComputerInfo).WindowsProductName
    $windowsProductName = (Get-CimInstance Win32_OperatingSystem).Caption
    # 2. 操作系统版本
	# $windowsVersion = (Get-ComputerInfo).WindowsVersion
	$windowsVersion=(Get-Item "HKLM:SOFTWARE\Microsoft\Windows NT\CurrentVersion").GetValue('ReleaseID')
    $basicInfo = "{""windowsProductName"":""$windowsProductName"",""windowsVersion"":""$windowsVersion""}"
    return $basicInfo
    
}


Write-Host "=================================="
Write-Host "|       Windows baseline check   |"
Write-Host "|         Author:JC0o0l          |"
Write-Host "|         wechat:JC_SecNotes     |"
Write-Host "|         version:3.0            |"
Write-Host "|         Mail:jerryzvs@163.com  |"
Write-Host "=================================="
$basic_info=Get-BasicInfo
$secInfoArray=Get-SecInfo
$account_check_res=Get-AccountPolicyCheckRes $secInfoArray
#Write-Host $account_check_res
$audit_check_res=Get-AuditPolicyCheckRes $secInfoArray
#Write-Host $audit_check_res
$userright_check_res=Get-UserRightPolicyCheckRes $secInfoArray
#Write-Host $userright_check_res
$secureoption_check_res=Get-SecureOptionCheckRes $secInfoArray
#Write-Host $secureoption_check_res
$portsecure_check_res=Get-PortSecureCheckRes
#Write-Host $portsecure_check_res
$systemsecure_check_res=Get-SystemSecureCheckRes
#Write-Host $systemsecure_check_res
$basicInfo = Get-ABasicInfo
$KBList = Get-CollectKB
$KBResult = "{""basicInfo"":$basicInfo,""KBList"":$KBList}"
$KBResult|Out-File KB.json -encoding utf8
#$window_check_res="{""secInfoArray"":$secInfoArray,""account_check_res"":$account_check_res,""audit_check_res"":$audit_check_res,""userright_check_res"":$userright_check_res,""secureoption_check_res"":$secureoption_check_res,""portsecure_check_res"":$portsecure_check_res,""systemsecure_check_res"":$systemsecure_check_res}"
$window_check_res="{""basic_info"":$basic_info,""account_check_res"":$account_check_res,""audit_check_res"":$audit_check_res,""userright_check_res"":$userright_check_res,""secureoption_check_res"":$secureoption_check_res,""portsecure_check_res"":$portsecure_check_res,""systemsecure_check_res"":$systemsecure_check_res,""vuln_scan_res"":$KBResult}"
#Write-Host $window_check_res
Invoke-RestMethod -Uri "http://10.0.1.104:8000/baseline/windows_scan_res_report/" -Method Post -ContentType "application/json" -Body $window_check_res