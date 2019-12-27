from django.db import models

# Create your models here.
class LinuxScanRes(models.Model):
    # basic_info
    publicIP=models.CharField(max_length=30,verbose_name="publicIP")
    privateIP=models.CharField(max_length=30,verbose_name="privateIP")
    hostname=models.CharField(max_length=30,verbose_name="hostname")
    osVersion=models.CharField(max_length=30,verbose_name="osVersion")
    kernelVersion=models.CharField(max_length=30,verbose_name="kernelVersion")

    # init_check_res
    ## tmp_partition_info
    tmpIfSeparate=models.BooleanField(default=False, verbose_name="tmpIfSeparate")
    tmpIfNoexec=models.BooleanField(default=False,verbose_name="tmpIfNoexec")
    tmpIfNosuid=models.BooleanField(default=False,verbose_name="tmpIfNosuid")
    ## boot_secure_info
    grubcfgIfExist=models.BooleanField(default=True,verbose_name="grubcfgIfExist")
    grubcfgPermission=models.CharField(max_length=5,verbose_name="grubcfgPermission")
    grubcfgIfSetPasswd=models.BooleanField(default=False,verbose_name="grubcfgIfSetPasswd")
    singleUserModeIfNeedAuth=models.BooleanField(default=False,verbose_name="singleUserModeIfNeedAuth")
    selinuxStateIfEnforcing=models.BooleanField(default=True,verbose_name="selinuxStateIfEnforcing")
    selinuxPolicyIfConfigured=models.BooleanField(default=True,verbose_name="selinuxPolicyIfConfigured")

    # service_check_res
    timeSyncServerIfConfigured=models.BooleanField(default=True,verbose_name="timeSyncServerIfConfigured")
    x11windowIfNotInstalled=models.BooleanField(default=False,verbose_name="x11windowIfNotInstalled")

    # network_check_res
    hostsAllowFileIfExist=models.BooleanField(default=True,verbose_name="hostsAllowFileIfExist")
    hostsAllowFilePermission=models.CharField(max_length=5,verbose_name="hostsAllowFilePermission")
    hostsAllowFileIfConfigured=models.BooleanField(default=False,verbose_name="hostsAllowFileIfConfigured")
    hostsDenyFileIfExist=models.BooleanField(default=True,verbose_name="hostsDenyFileIfExist")
    hostsDenyFilePermission=models.CharField(max_length=5,verbose_name="hostsDenyFilePermission")
    hostsDenyFileIfConfigured=models.BooleanField(default=False,verbose_name="hostsDenyFileIfConfigured")
    iptablesIfInstalled=models.BooleanField(default=True,verbose_name="iptablesIfInstalled")
    iptablesInputPolicyIfDrop=models.BooleanField(default=False,verbose_name="iptablesInputPolicyIfDrop")
    iptabledOutputPolicyIfDrop=models.BooleanField(default=False,verbose_name="iptablesOutputPolicyIfDrop")

    # auditd_check_res
    ## auditd_config_info
    auditdIfEnabled=models.BooleanField(default=True,verbose_name="auditdIfEnabled")
    auditdconfIfExist=models.BooleanField(default=True,verbose_name="aditdconfIfExist")
    auditdIfSetMaxLogFile=models.CharField(max_length=5,verbose_name="auditdIfSetMaxLogFile")
    auidtdIfSetMaxLogFileAction=models.CharField(max_length=10,verbose_name="auditdIfSetMaxLogFileAction")
    auditdIfSetSpaceLeftAction=models.CharField(max_length=10,verbose_name="auditdIfSetSpaceLeftAction")
    auidtdIfSetNumLogs=models.CharField(max_length=5,verbose_name="auditdIfSetNumLogs")
    ## auditd_rules_info
    auditdRulesIfExist=models.BooleanField(default=True,verbose_name="auditdRulesIfExist")
    auidtdRulesIfNotNull=models.BooleanField(default=True,verbose_name="auditdRulesIfNotNull")
    auditdIfCheckTimechange=models.BooleanField(default=False,verbose_name="auditdIfCheckTimechange")
    auditdRulesCheckedUserandgroupfile=models.CharField(max_length=600,verbose_name="auditdRulesCheckUserandgroupfile")
    auditdRulesNotCheckedUserandgroupfile=models.CharField(max_length=600,verbose_name="auditdRulesNotCheckUserandgroupfile")
    auditdRulesCheckedNetworkenv=models.CharField(max_length=600,verbose_name="auditdRulesCheckedNetworkenv")
    auditdRulesNotCheckedNetworkenv=models.CharField(max_length=600,verbose_name="auditdRulesNotCheckedNetworkenv")
    auditdRulesCheckedMACchange=models.CharField(max_length=600,verbose_name="auditdRulesCheckedMACchange")
    auditdRulesNotCheckedMACchange=models.CharField(max_length=600,verbose_name="auditdRulesNotCheckedMACchange")
    auditdRulesCheckedLoginoutEvents=models.CharField(max_length=600,verbose_name="auditdRulesCheckedLoginoutEvents")
    auditdRulesNotCheckedLoginoutEvents=models.CharField(max_length=600,verbose_name="auditdRulesNotCheckedLoginoutEvents")
    auditdRulesCheckedDACChangeSyscall=models.CharField(max_length=600,verbose_name="auditdRulesCheckedDACChangeSyscall")
    auditdRulesNotCheckedDACChangeSyscall=models.CharField(max_length=600,verbose_name="auditdRulesNotCheckedDACChangeSyscall")
    auditdRulesCheckedFileAccessAttemptSyscall=models.CharField(max_length=600,verbose_name="auditdRulesCheckedFileAccessAttemptSyscall")
    auditdRulesNotCheckedFileAccessAttemptSyscall=models.CharField(max_length=600,verbose_name="auditdRulesNotCheckedFileAccessAttemptSyscall")
    auditdRulesCheckedPrivilegedCommand=models.CharField(max_length=600,verbose_name="auditdRulesCheckedPrivilegedCommand")
    auditdRulesNotCheckedPrivilegedCommand=models.CharField(max_length=600,verbose_name="auditdRulesNotCheckedPrivilegedCommand")
    auditdRulesCheckedSudoerFile=models.CharField(max_length=600,verbose_name="auditdRulesCheckedSudoerFile")
    auditdRulesNotCheckedSudoerFile=models.CharField(max_length=600,verbose_name="auditdRulesNotCheckedSudoerFile")
    auditdRulesIfImmutable=models.BooleanField(default=False,verbose_name="auditdRulesIfImmutable")

    # log_check_res
    rsyslogIfEnabled=models.BooleanField(default=True,verbose_name="rsyslogIfEnabled")

    # authentication_check_res
    ## crond_config_info
    crondIfEnabled=models.BooleanField(default=True,verbose_name="crondIfEnabled")
    crondConfigFilenameArray=models.CharField(max_length=600,verbose_name="crondConfigFilenameArray")
    crondConfigFilePermissionArray=models.CharField(max_length=600,verbose_name="crondConfigFilePermissionArray")
    crondallowdenyFilenameArray=models.CharField(max_length=600,verbose_name="crondallowdenyFilenameArray")
    crondallowdenyFileIfExistArray=models.CharField(max_length=600,verbose_name="crondallowdenyFileIfExist")
    crondallowdenyFilePermissionArray=models.CharField(max_length=600,verbose_name="crondallowdenyFilePermissionArray")
    crondallowdenyFileOwnerArray=models.CharField(max_length=600,verbose_name="crondallowdenyFileOwnerArray")
    ## sshd_config_info
    sshdIfEnabled=models.BooleanField(default=True,verbose_name="sshdIfEnabled")
    sshdConfigFilePermission=models.CharField(max_length=5,verbose_name="sshdConfigFilePermission")
    sshdIfDisableX11forwarding=models.BooleanField(default=False,verbose_name="sshdIfDisableX11forwarding")
    sshdIfSetMaxAuthTries=models.CharField(max_length=5 ,verbose_name="sshdIfSetMaxAuthTries")
    sshdIfEnableIgnoreRhosts=models.BooleanField(default=False,verbose_name="sshdIfEnableIgnoreRhosts")
    sshdIfDisableHostbasedAuthentication=models.BooleanField(default=False,verbose_name="sshdIfDisableHostbasedAuthentication")
    sshdIfDisablePermitRootLogin=models.BooleanField(default=False,verbose_name="sshdIfDisablePermitRootLogin")
    sshdIfDisablePermitEmptyPasswords=models.BooleanField(default=False,verbose_name="sshdIfDisablePermitEmptyPasswords")
    sshdIfDisablePermitUserEnvironment=models.BooleanField(default=False,verbose_name="sshdIfDisablePermitUserEnvironment")
    sshdIfSpecificMACs=models.BooleanField(default=False,verbose_name="sshdIfSpecificMACs")
    sshdIfSetClientAliveInterval=models.BooleanField(default=False,verbose_name="sshdIfSetClientAliveInterval")
    sshdIfSetLoginGraceTime=models.BooleanField(default=False,verbose_name="sshdIfSetLoginGraceTime")
    ## pam_config
    pamPwqualityconfIfExist=models.BooleanField(default=False,verbose_name="pamPwqualityconfIfExist")
    pamIfSetMinlen=models.CharField(max_length=6,verbose_name="pamIfSetMinlen")
    pamIfSetMinclass=models.CharField(max_length=6,verbose_name="pamIfSetMinclass")
    sshdSetedLockAndUnlockTimeFiles=models.CharField(max_length=600,verbose_name="sshdSetedLockAndUnlockTimeFiles")
    sshdNotSetedLockAndUnlockTimeFiles=models.CharField(max_length=600,verbose_name="sshdNotSetedLockAndUnlockTimeFiles")
    sshdPamdFileArray=models.CharField(max_length=600,verbose_name="sshdPamdFileArray")
    sshdPamdFileReuseLimitArray=models.CharField(max_length=600,verbose_name="sshdPamdFileReuseLimitArray")
    sshdPamdFileIfSetSha512Array=models.CharField(max_length=600,verbose_name="sshdPamdFileIfSetSha512Array")
    ## account_config_info
    accountPassMaxDays=models.CharField(max_length=6,verbose_name="accountPassMaxDays")
    accountPassMinDays=models.CharField(max_length=6,verbose_name="accountPassMinDays")
    accountPassWarnDays=models.CharField(max_length=6,verbose_name="accountPassWarnDays")
    accountPassAutolockInactiveDays=models.CharField(max_length=6,verbose_name="accountPassAutolockInactinveDays")
    accountShouldUnloginArray=models.CharField(max_length=600,verbose_name="accountShouldUnloginArray")
    accountGIDOfRoot=models.CharField(max_length=6,verbose_name="accountGIDOfRoot")
    accountProfileFileArray=models.CharField(max_length=600,verbose_name="accountProfileFileArray")
    accountProfileTMOUTArray=models.CharField(max_length=600,verbose_name="accountProfileTMOUTArray")
    accountIfSetUsersCanAccessSuCommand=models.CharField(max_length=600,verbose_name="accountIfSetUsersCanAccessSuCommand")

    # system_check_res
    ## file_permission_info
    importantFilenameArray=models.CharField(max_length=600,verbose_name="importantFilenameArray")
    importantFilePermissionArray=models.CharField(max_length=300,verbose_name="importantFilePermissionArray")
    importantFileUidgidArray=models.CharField(max_length=300,verbose_name="importantFileUidgidArray")
    ## usergroup_config_info
    userIfSetPasswdOrArray=models.CharField(max_length=300,verbose_name="userIfSetPasswdOrArray")
    uid0OnlyRootOrArray=models.CharField(max_length=300,verbose_name="uid0OnlyRootOrArray")
    pathDirIfNotHasDot=models.CharField(max_length=600,verbose_name="pathDirIfNotHasDot")
    pathDirPermissionHasGWArray=models.CharField(max_length=600,verbose_name="pathDirPermissionHasGWArray")
    pathDIrPermissionHasOWArray=models.CharField(max_length=600,verbose_name="pathDirPermissionHasOWArray")
    pathDirOwnerIsNotRootArray=models.CharField(max_length=600,verbose_name="pathDirOwnerIsNotRootArray")
    userArray=models.CharField(max_length=300,verbose_name="userArray")
    userHomeDirIfExistArray=models.CharField(max_length=600,verbose_name="userHomeDirIfExistArray")
    userHomeDirPermissionArray=models.CharField(max_length=600,verbose_name="userHomeDirPermissionArray")
    userIfOwnTheirHomeDirArray=models.CharField(max_length=300,verbose_name="userIfOwnTheirHomeDirArray")
    userHomeDirIfHasGWorOWDotFileArray=models.CharField(max_length=600,verbose_name="userHomeDirIfHasGWorOWDotFileArray")
    userHomeDirIfHasOtherFileArray=models.CharField(max_length=600,verbose_name="userHomeDirIfHasOtherFileArray")
    groupNotExistInetcgroup=models.CharField(max_length=300,verbose_name="groupNotExistInetcgroup")
    usersIfHasUniqueUIDArray=models.CharField(max_length=300,verbose_name="userIfHasUniqueUIDArray")
    groupsIfHasUniqueGIDArray=models.CharField(max_length=300,verbose_name="groupsIfHasUniqueGIDArray")

    def __str__(self):
        return '%s' % "LinuxScanResult"