from django.shortcuts import render
from django.http import HttpResponse
import json
import time
from CMDB import settings 
from baseline import models
from django.views.decorators.csrf import csrf_exempt,csrf_protect
# Create your views here.
def scan_res_display(request):
    scanResAll = models.LinuxScanRes.objects.all()
    #scanResList = []
    #for scanRes in scanResAll:

    #    pass

    return render(request,'baseline/scan_res_display.html',locals())


@csrf_exempt
def linux_scan_res_report(request):

    if request.method == "POST":
        bodyData=request.body
        # 从post的body体中读取并反序列化为dict数据
        linuxScanResDict=json.loads(bodyData)
        #scanTime = time.strftime('%Y-%m-%d %H:%M:%S')
        # 从dict数据中解析并读取数据
        basic_info=linuxScanResDict['basic_info']
        scanTime=basic_info['scanTime']
        hostname=basic_info['hostname']
        macaddr=basic_info['macaddr']
        ipList=basic_info['ipList']
        kernelVersion=basic_info['kernelVersion']
        osVersion=basic_info['osVersion']
        init_check_res=linuxScanResDict['init_check_res']
        tmp_partition_info=init_check_res['tmp_partition_info']
        tmpIfSeparate=tmp_partition_info['tmpIfSeparate']
        tmpIfNoexec=tmp_partition_info['tmpIfNoexec']
        tmpIfNosuid=tmp_partition_info['tmpIfNosuid']
        boot_secure_info=init_check_res['boot_secure_info']
        grubcfgIfExist=boot_secure_info['grubcfgIfExist']
        grubcfgPermission=boot_secure_info['grubcfgPermission']
        grubcfgIfSetPasswd=boot_secure_info['grubcfgIfSetPasswd']
        singleUserModeIfNeedAuth=boot_secure_info['singleUserModeIfNeedAuth']
        selinuxStateIfEnforcing=boot_secure_info['selinuxStateIfEnforcing']
        selinuxPolicyIfConfigured=boot_secure_info['selinuxPolicyIfConfigured']
        service_check_res=linuxScanResDict['service_check_res']
        timeSyncServerIfConfigured=service_check_res['timeSyncServerIfConfigured']
        x11windowIfNotInstalled=service_check_res['x11windowIfNotInstalled']
        network_check_res=linuxScanResDict['network_check_res']
        hostsAllowFileIfExist=network_check_res['hostsAllowFileIfExist']
        hostsAllowFilePermission=network_check_res['hostsAllowFilePermission']
        hostsAllowFileIfConfigured=network_check_res['hostsAllowFileIfConfigured']
        hostsDenyFileIfExist=network_check_res['hostsDenyFileIfExist']
        hostsDenyFilePermission=network_check_res['hostsDenyFilePermission']
        hostsDenyFileIfConfigured=network_check_res['hostsDenyFileIfConfigured']
        iptablesIfInstalled=network_check_res['iptablesIfInstalled']
        iptablesInputPolicyIfDrop=network_check_res['iptablesInputPolicyIfDrop']
        iptablesOutputPolicyIfDrop=network_check_res['iptablesOutputPolicyIfDrop']
        auditd_check_res=linuxScanResDict['auditd_check_res']
        auditd_config_info=auditd_check_res['auditd_config_info']
        auditdIfEnabled=auditd_config_info['auditdIfEnabled']
        auditdconfIfExist=auditd_config_info['auditdconfIfExist']
        auditdIfSetMaxLogFile=auditd_config_info['auditdIfSetMaxLogFile']
        auditdIfSetMaxLogFileAction=auditd_config_info['auditdIfSetMaxLogFileAction']
        auditdIfSetSpaceLeftAction=auditd_config_info['auditdIfSetSpaceLeftAction']
        auditdIfSetNumLogs=auditd_config_info['auditdIfSetNumLogs']
        auditd_rules_info=auditd_check_res['auditd_rules_info']
        auditdRulesIfExist=auditd_rules_info['auditdRulesIfExist']
        auditdRulesIfNotNull=auditd_rules_info['auditdRulesIfNotNull']
        auditdIfCheckTimechange=auditd_rules_info['auditdIfCheckTimechange']
        auditdRulesCheckedUserandgroupfile=auditd_rules_info['auditdRulesCheckedUserandgroupfile']
        auditdRulesNotCheckedUserandgroupfile=auditd_rules_info['auditdRulesNotCheckedUserandgroupfile']
        auditdRulesCheckedNetworkenv=auditd_rules_info['auditdRulesCheckedNetworkenv']
        auditdRulesNotCheckedNetworkenv=auditd_rules_info['auditdRulesNotCheckedNetworkenv']
        auditdRulesCheckedMACchange=auditd_rules_info['auditdRulesCheckedMACchange']
        auditdRulesNotCheckedMACchange=auditd_rules_info['auditdRulesNotCheckedMACchange']
        auditdRulesCheckedLoginoutEvents=auditd_rules_info['auditdRulesCheckedLoginoutEvents']
        auditdRulesNotCheckedLoginoutEvents=auditd_rules_info['auditdRulesNotCheckedLoginoutEvents']
        auditdRulesCheckedDACChangeSyscall=auditd_rules_info['auditdRulesCheckedDACChangeSyscall']
        auditdRulesNotCheckedDACChangeSyscall=auditd_rules_info['auditdRulesNotCheckedDACChangeSyscall']
        auditdRulesCheckedFileAccessAttemptSyscall=auditd_rules_info['auditdRulesCheckedFileAccessAttemptSyscall']
        auditdRulesNotCheckedFileAccessAttemptSyscall=auditd_rules_info['auditdRulesNotCheckedFileAccessAttemptSyscall']
        auditdRulesCheckedPrivilegedCommand=auditd_rules_info['auditdRulesCheckedPrivilegedCommand']
        auditdRulesNotCheckedPrivilegedCommand=auditd_rules_info['auditdRulesNotCheckedPrivilegedCommand']
        auditdRulesCheckedSudoerFile=auditd_rules_info['auditdRulesCheckedSudoerFile']
        auditdRulesNotCheckedSudoerFile=auditd_rules_info['auditdRulesNotCheckedSudoerFile']
        auditdRulesIfImmutable=auditd_rules_info['auditdRulesIfImmutable']
        log_check_res=linuxScanResDict['log_check_res']
        rsyslogIfEnabled=log_check_res['rsyslogIfEnabled']
        authentication_check_res=linuxScanResDict['authentication_check_res']
        crond_config_info=authentication_check_res['crond_config_info']
        crondIfEnabled=crond_config_info['crondIfEnabled']
        crondConfigFilenameArray=crond_config_info['crondConfigFilenameArray']
        crondConfigFilePermissionArray=crond_config_info['crondConfigFilePermissionArray']
        crondallowdenyFilenameArray=crond_config_info['crondallowdenyFilenameArray']
        crondallowdenyFileIfExistArray=crond_config_info['crondallowdenyFileIfExistArray']
        crondallowdenyFilePermissionArray=crond_config_info['crondallowdenyFilePermissionArray']
        crondallowdenyFileOwnerArray=crond_config_info['crondallowdenyFileOwnerArray']
        sshd_config_info=authentication_check_res['sshd_config_info']
        sshdIfEnabled=sshd_config_info['sshdIfEnabled']
        sshdConfigFilePermission=sshd_config_info['sshdConfigFilePermission']
        sshdIfDisableX11forwarding=sshd_config_info['sshdIfDisableX11forwarding']
        sshdIfSetMaxAuthTries=sshd_config_info['sshdIfSetMaxAuthTries']
        sshdIfEnableIgnoreRhosts=sshd_config_info['sshdIfEnableIgnoreRhosts']
        sshdIfDisableHostbasedAuthentication=sshd_config_info['sshdIfDisableHostbasedAuthentication']
        sshdIfDisablePermitRootLogin=sshd_config_info['sshdIfDisablePermitRootLogin']
        sshdIfDisablePermitEmptyPasswords=sshd_config_info['sshdIfDisablePermitEmptyPasswords']
        sshdIfDisablePermitUserEnvironment=sshd_config_info['sshdIfDisablePermitUserEnvironment']
        sshdIfSpecificMACs=sshd_config_info['sshdIfSpecificMACs']
        sshdIfSetClientAliveInterval=sshd_config_info['sshdIfSetClientAliveInterval']
        sshdIfSetLoginGraceTime=sshd_config_info['sshdIfSetLoginGraceTime']
        pam_config_info=authentication_check_res['pam_config_info']
        pamPwqualityconfIfExist=pam_config_info['pamPwqualityconfIfExist']
        pamIfSetMinlen=pam_config_info['pamIfSetMinlen']
        pamIfSetMinclass=pam_config_info['pamIfSetMinclass']
        sshdSetedLockAndUnlockTimeFiles=pam_config_info['sshdSetedLockAndUnlockTimeFiles']
        sshdNotSetedLockAndUnlockTimeFiles=pam_config_info['sshdNotSetedLockAndUnlockTimeFiles']
        sshdPamdFileArray=pam_config_info['sshdPamdFileArray']
        sshdPamdFileReuseLimitArray=pam_config_info['sshdPamdFileReuseLimitArray']
        sshdPamdFileIfSetSha512Array=pam_config_info['sshdPamdFileIfSetSha512Array']
        account_config_info=authentication_check_res['account_config_info']
        accountPassMaxDays=account_config_info['accountPassMaxDays']
        accountPassMinDays=account_config_info['accountPassMinDays']
        accountPassWarnDays=account_config_info['accountPassWarnDays']
        accountPassAutolockInactiveDays=account_config_info['accountPassAutolockInactiveDays']
        accountShouldUnloginArray=account_config_info['accountShouldUnloginArray']
        accountGIDOfRoot=account_config_info['accountGIDOfRoot']
        accountProfileFileArray=account_config_info['accountProfileFileArray']
        accountProfileTMOUTArray=account_config_info['accountProfileTMOUTArray']
        accountIfSetUsersCanAccessSuCommand=account_config_info['accountIfSetUsersCanAccessSuCommand']
        system_check_res=linuxScanResDict['system_check_res']
        file_permission_info=system_check_res['file_permission_info']
        importantFilenameArray=file_permission_info['importantFilenameArray']
        importantFilePermissionArray=file_permission_info['importantFilePermissionArray']
        importantFileUidgidArray=file_permission_info['importantFileUidgidArray']
        usergroup_config_info=system_check_res['usergroup_config_info']
        userIfSetPasswdOrArray=usergroup_config_info['userIfSetPasswdOrArray']
        uid0OnlyRootOrArray=usergroup_config_info['uid0OnlyRootOrArray']
        pathDirIfNotHasDot=usergroup_config_info['pathDirIfNotHasDot']
        pathDirPermissionHasGWArray=usergroup_config_info['pathDirPermissionHasGWArray']
        pathDirPermissionHasOWArray=usergroup_config_info['pathDirPermissionHasOWArray']
        pathDirOwnerIsNotRootArray=usergroup_config_info['pathDirOwnerIsNotRootArray']
        pathDirDoesNotExistOrNotDirArray=usergroup_config_info['pathDirDoesNotExistOrNotDirArray']
        userArray=usergroup_config_info['userArray']
        userHomeDirIfExistArray=usergroup_config_info['userHomeDirIfExistArray']
        userHomeDirPermissionArray=usergroup_config_info['userHomeDirPermissionArray']
        userIfOwnTheirHomeDirArray=usergroup_config_info['userIfOwnTheirHomeDirArray']
        userHomeDirIfHasGWorOWDotFileArray=usergroup_config_info['userHomeDirIfHasGWorOWDotFileArray']
        userHomeDirIfHasOtherFileArray=usergroup_config_info['userHomeDirIfHasOtherFileArray']
        groupNotExistInetcgroup=usergroup_config_info['groupNotExistInetcgroup']
        usersIfHasUniqueUIDArray=usergroup_config_info['usersIfHasUniqueUIDArray']
        groupsIfHasUniqueGIDArray=usergroup_config_info['groupsIfHasUniqueGIDArray'] 
        # 向LinuxScanResMeta表中插入数据
        models.LinuxScanResMeta.objects.get_or_create(scanTime=scanTime,macaddr=macaddr,linuxScanResMetaData=bodyData)
        models.LinuxScanRes.objects.get_or_create(scanTime=scanTime,hostname=hostname,macaddr=macaddr,ipList=ipList,kernelVersion=kernelVersion,osVersion=osVersion,tmpIfSeparate=tmpIfSeparate,tmpIfNoexec=tmpIfNoexec,tmpIfNosuid=tmpIfNosuid,grubcfgIfExist=grubcfgIfExist,grubcfgPermission=grubcfgPermission,grubcfgIfSetPasswd=grubcfgIfSetPasswd,singleUserModeIfNeedAuth=singleUserModeIfNeedAuth,selinuxStateIfEnforcing=selinuxStateIfEnforcing,selinuxPolicyIfConfigured=selinuxPolicyIfConfigured,timeSyncServerIfConfigured=timeSyncServerIfConfigured,x11windowIfNotInstalled=x11windowIfNotInstalled,hostsAllowFileIfExist=hostsAllowFileIfExist,hostsAllowFilePermission=hostsAllowFilePermission,hostsAllowFileIfConfigured=hostsAllowFileIfConfigured,hostsDenyFileIfExist=hostsDenyFileIfExist,hostsDenyFilePermission=hostsDenyFilePermission,hostsDenyFileIfConfigured=hostsDenyFileIfConfigured,iptablesIfInstalled=iptablesIfInstalled,iptablesInputPolicyIfDrop=iptablesInputPolicyIfDrop,iptablesOutputPolicyIfDrop=iptablesOutputPolicyIfDrop,auditdIfEnabled=auditdIfEnabled,auditdconfIfExist=auditdconfIfExist,auditdIfSetMaxLogFile=auditdIfSetMaxLogFile,auditdIfSetMaxLogFileAction=auditdIfSetMaxLogFileAction,auditdIfSetSpaceLeftAction=auditdIfSetSpaceLeftAction,auditdIfSetNumLogs=auditdIfSetNumLogs,auditdRulesIfExist=auditdRulesIfExist,auditdRulesIfNotNull=auditdRulesIfNotNull,auditdIfCheckTimechange=auditdIfCheckTimechange,auditdRulesCheckedUserandgroupfile=auditdRulesCheckedUserandgroupfile,auditdRulesNotCheckedUserandgroupfile=auditdRulesNotCheckedUserandgroupfile,auditdRulesCheckedNetworkenv=auditdRulesCheckedNetworkenv,auditdRulesNotCheckedNetworkenv=auditdRulesNotCheckedNetworkenv,auditdRulesCheckedMACchange=auditdRulesCheckedMACchange,auditdRulesNotCheckedMACchange=auditdRulesNotCheckedMACchange,auditdRulesCheckedLoginoutEvents=auditdRulesCheckedLoginoutEvents,auditdRulesNotCheckedLoginoutEvents=auditdRulesNotCheckedLoginoutEvents,auditdRulesCheckedDACChangeSyscall=auditdRulesCheckedDACChangeSyscall,auditdRulesNotCheckedDACChangeSyscall=auditdRulesNotCheckedDACChangeSyscall,auditdRulesCheckedFileAccessAttemptSyscall=auditdRulesCheckedFileAccessAttemptSyscall,auditdRulesNotCheckedFileAccessAttemptSyscall=auditdRulesNotCheckedFileAccessAttemptSyscall,auditdRulesCheckedPrivilegedCommand=auditdRulesCheckedPrivilegedCommand,auditdRulesNotCheckedPrivilegedCommand=auditdRulesNotCheckedPrivilegedCommand,auditdRulesCheckedSudoerFile=auditdRulesCheckedSudoerFile,auditdRulesNotCheckedSudoerFile=auditdRulesNotCheckedSudoerFile,auditdRulesIfImmutable=auditdRulesIfImmutable,rsyslogIfEnabled=rsyslogIfEnabled,crondIfEnabled=crondIfEnabled,crondConfigFilenameArray=crondConfigFilenameArray,crondConfigFilePermissionArray=crondConfigFilePermissionArray,crondallowdenyFilenameArray=crondallowdenyFilenameArray,crondallowdenyFileIfExistArray=crondallowdenyFileIfExistArray,crondallowdenyFilePermissionArray=crondallowdenyFilePermissionArray,crondallowdenyFileOwnerArray=crondallowdenyFileOwnerArray,sshdIfEnabled=sshdIfEnabled,sshdConfigFilePermission=sshdConfigFilePermission,sshdIfDisableX11forwarding=sshdIfDisableX11forwarding,sshdIfSetMaxAuthTries=sshdIfSetMaxAuthTries,sshdIfEnableIgnoreRhosts=sshdIfEnableIgnoreRhosts,sshdIfDisableHostbasedAuthentication=sshdIfDisableHostbasedAuthentication,sshdIfDisablePermitRootLogin=sshdIfDisablePermitRootLogin,sshdIfDisablePermitEmptyPasswords=sshdIfDisablePermitEmptyPasswords,sshdIfDisablePermitUserEnvironment=sshdIfDisablePermitUserEnvironment,sshdIfSpecificMACs=sshdIfSpecificMACs,sshdIfSetClientAliveInterval=sshdIfSetClientAliveInterval,sshdIfSetLoginGraceTime=sshdIfSetLoginGraceTime,pamPwqualityconfIfExist=pamPwqualityconfIfExist,pamIfSetMinlen=pamIfSetMinlen,pamIfSetMinclass=pamIfSetMinclass,sshdSetedLockAndUnlockTimeFiles=sshdSetedLockAndUnlockTimeFiles,sshdNotSetedLockAndUnlockTimeFiles=sshdNotSetedLockAndUnlockTimeFiles,sshdPamdFileArray=sshdPamdFileArray,sshdPamdFileReuseLimitArray=sshdPamdFileReuseLimitArray,sshdPamdFileIfSetSha512Array=sshdPamdFileIfSetSha512Array,accountPassMaxDays=accountPassMaxDays,accountPassMinDays=accountPassMinDays,accountPassWarnDays=accountPassWarnDays,accountPassAutolockInactiveDays=accountPassAutolockInactiveDays,accountShouldUnloginArray=accountShouldUnloginArray,accountGIDOfRoot=accountGIDOfRoot,accountProfileFileArray=accountProfileFileArray,accountProfileTMOUTArray=accountProfileTMOUTArray,accountIfSetUsersCanAccessSuCommand=accountIfSetUsersCanAccessSuCommand,importantFilenameArray=importantFilenameArray,importantFilePermissionArray=importantFilePermissionArray,importantFileUidgidArray=importantFileUidgidArray,userIfSetPasswdOrArray=userIfSetPasswdOrArray,uid0OnlyRootOrArray=uid0OnlyRootOrArray,pathDirIfNotHasDot=pathDirIfNotHasDot,pathDirPermissionHasGWArray=pathDirPermissionHasGWArray,pathDirPermissionHasOWArray=pathDirPermissionHasOWArray,pathDirOwnerIsNotRootArray=pathDirOwnerIsNotRootArray,pathDirDoesNotExistOrNotDirArray=pathDirDoesNotExistOrNotDirArray,userArray=userArray,userHomeDirIfExistArray=userHomeDirIfExistArray,userHomeDirPermissionArray=userHomeDirPermissionArray,userIfOwnTheirHomeDirArray=userIfOwnTheirHomeDirArray,userHomeDirIfHasGWorOWDotFileArray=userHomeDirIfHasGWorOWDotFileArray,userHomeDirIfHasOtherFileArray=userHomeDirIfHasOtherFileArray,groupNotExistInetcgroup=groupNotExistInetcgroup,usersIfHasUniqueUIDArray=usersIfHasUniqueUIDArray,groupsIfHasUniqueGIDArray=groupsIfHasUniqueGIDArray)
        return HttpResponse("Success.")
        #return render(request,'baseline/show.html',locals())
    else:
        #return render(request,'baseline/show.html',locals())
        return HttpResponse("0oops,something is wrong")
        #return render(request,'baseline/show.html',locals())