;===========================================================================
; MySQL 数据库自动备份工具 (PureBasic)
; 版本:  v8
; 作者:  邵长远
; 编译:  PureBasic 5.x/6.x,目标 Windows x86/x64
; 依赖:  mysqldump.exe(程序目录或配置文件指定路径)
;
; 功能:
;   - 系统托盘驻留,右键菜单操作
;   - 每日定时自动备份(可配置时间)
;   - 过期备份自动清理(可配置保留天数)
;   - 日志记录(按日期分文件,共享模式支持多进程写入)
;   - 可安装/卸载为 Windows 系统服务(标准 SCM 框架)
;   - 单实例运行保护
;
; 命令行参数:
;   (无)          启动托盘模式
;   --service     以服务模式运行(配合 sc.exe 使用)
;   --install     安装为系统服务
;   --uninstall   卸载系统服务
;   --help        显示帮助
;
; 修改历史:
;   v1→v6:  见末尾 CHANGELOG
;   v6→v7:  标准 SCM 服务框架、日志共享模式、凭据安全强化、管理员权限检查等12项
;   v7→v8:  凭据文件竞态修复、清理逻辑修正、GDI 泄漏修复、路径规范化、API 导入修复等8项
;===========================================================================

EnableExplicit


;===========================================================================
;  常量定义
;===========================================================================

#AppName      = "MySQL自动备份工具"
#ConfigFile   = "MySQLBackup.ini"
#PrefGroup    = "MySQL"
#BackupPrefix = "backup_"                ; 备份文件名前缀,区分备份与用户自建 .sql
#SvcName      = "MySQLBackupSvc"         ; Windows 服务名
#TimerInterval = 20000                   ; 定时检查间隔(毫秒)
#DQUOTE$      = Chr(34)                  ; 双引号,方便构造命令行

; 窗口 / 控件 / 菜单 / 定时器 ID
Enumeration Windows
  #WinMain
  #WinSettings
  #WinHelp
EndEnumeration

; [FIX-48] 显式导入 RegisterServiceCtrlHandlerEx_(advapi32)
; PureBasic 未内置封装此 API,需手动声明
Import "advapi32.lib"
  RegisterServiceCtrlHandlerEx_(lpServiceName.i, lpHandlerProc.i, lpContext.i) As "RegisterServiceCtrlHandlerExA"
EndImport

Enumeration Gadgets
  #TxtHost : #TxtPort : #TxtUser : #TxtPassword : #TxtDatabase
  #TxtBackupDir : #BtnBrowseDir
  #SpinBackupHour : #SpinBackupMinute
  #SpinKeepDays : #TxtDumpPath : #BtnBrowseDump
  #BtnSave : #BtnCancel
  #ChkAutoBackup
  #EditorHelp
EndEnumeration

Enumeration TrayMenu
  #MenuBackupNow
  #MenuOpenDir
  #MenuSettings
  #MenuService
  #MenuUninstall
  #MenuHelp
  #MenuExit
EndEnumeration

Enumeration Timers
  #TimerCheckBackup = 1
EndEnumeration


;===========================================================================
;  全局变量
;===========================================================================

Structure Config
  Host.s
  Port.s
  User.s
  Password.s
  Database.s
  BackupDir.s
  BackupHour.i
  BackupMinute.i
  KeepDays.i
  DumpPath.s
  AutoBackup.i
  LastBackupDate.s
EndStructure

Global G.Config
Global gStopFlag.i = #False
Global gLogMutex.i
Global gSettingsOpen.i = #False
Global gInstanceMutex.i
Global gTrayImg.i
Global gStopSection.i
Global gSvcStatusHandle.i = 0             ; 服务状态句柄
Global gSvcStatus.SERVICE_STATUS          ; 服务状态结构
Global gHelpOpen.i = #False               ; 帮助窗口是否打开


;===========================================================================
;  编码/解码(密码混淆,非加密)
;===========================================================================
;
; ⚠️ 安全警告:此编码仅做视觉混淆,不是加密!
;   - 算法固定(Caesar +3),知道偏移量即可逆向
;   - INI 文件被读取后密码即以明文存在于内存
;   - 不要将此方案视为安全措施,仅用于防止偶然窥视
;   - 如需真正安全,请使用 Windows DPAPI 或外部密钥管理
;===========================================================================

Procedure.s SimpleEncode(Src.s)
  Protected i.i, Result.s, Ch.i
  For i = 1 To Len(Src)
    Ch = Asc(Mid(Src, i, 1)) + 3
    Result + Right("000" + Hex(Ch), 4)
  Next
  ProcedureReturn Result
EndProcedure

Procedure.s SimpleDecode(Src.s)
  Protected i.i, Result.s, Code.i
  If Len(Src) % 4 <> 0 : ProcedureReturn "" : EndIf
  For i = 1 To Len(Src) Step 4
    Code = Val("$" + Mid(Src, i, 4)) - 3
    If Code >= 0
      Result + Chr(Code)
    EndIf
  Next
  ProcedureReturn Result
EndProcedure


;===========================================================================
;  日志
;===========================================================================

; 写入一行日志到 logs/backup_YYYY-MM-DD.log
; 使用共享模式打开,允许多进程/线程同时写入
Procedure LogWrite(Msg.s)
  Protected LogDir.s, LogFile.s, hFile.i
  LogDir = GetPathPart(ProgramFilename()) + "logs"
  LockMutex(gLogMutex)
  If FileSize(LogDir) = -1 : CreateDirectory(LogDir) : EndIf
  LogFile = LogDir + "\backup_" + FormatDate("%yyyy-%mm-%dd", Date()) + ".log"
  hFile = OpenFile(#PB_Any, LogFile, #PB_File_SharedRead | #PB_File_SharedWrite)
  If hFile
    FileSeek(hFile, Lof(hFile))
    WriteStringN(hFile, FormatDate("[%yyyy-%mm-%dd %hh:%ii:%ss] ", Date()) + Msg)
    CloseFile(hFile)
  Else
    ; 共享模式失败时回退独占模式
    hFile = OpenFile(#PB_Any, LogFile)
    If hFile
      FileSeek(hFile, Lof(hFile))
      WriteStringN(hFile, FormatDate("[%yyyy-%mm-%dd %hh:%ii:%ss] ", Date()) + Msg)
      CloseFile(hFile)
    EndIf
  EndIf
  UnlockMutex(gLogMutex)
EndProcedure


;===========================================================================
;  配置读写
;===========================================================================

Procedure.s ConfigPath()
  ProcedureReturn GetPathPart(ProgramFilename()) + #ConfigFile
EndProcedure

Procedure LoadConfig()
  OpenPreferences(ConfigPath())
  PreferenceGroup(#PrefGroup)
  With G
    \Host         = ReadPreferenceString("Host", "127.0.0.1")
    \Port         = ReadPreferenceString("Port", "3306")
    \User         = ReadPreferenceString("User", "root")
    \Password     = SimpleDecode(ReadPreferenceString("Password", ""))
    \Database     = ReadPreferenceString("Database", "")
    \BackupDir    = ReadPreferenceString("BackupDir", GetPathPart(ProgramFilename()) + "backup")
    \BackupHour   = ReadPreferenceInteger("BackupHour", 3)
    \BackupMinute = ReadPreferenceInteger("BackupMinute", 0)
    \KeepDays     = ReadPreferenceInteger("KeepDays", 7)
    \DumpPath     = ReadPreferenceString("DumpPath", GetPathPart(ProgramFilename()) + "mysqldump.exe")
    \AutoBackup   = ReadPreferenceInteger("AutoBackup", 1)
    \LastBackupDate = ReadPreferenceString("LastBackupDate", "")
    If \BackupHour < 0 Or \BackupHour > 23   : \BackupHour   = 3 : EndIf
    If \BackupMinute < 0 Or \BackupMinute > 59 : \BackupMinute = 0 : EndIf
    If \KeepDays <= 0 : \KeepDays = 7 : EndIf
    ; [FIX-47] 规范化备份目录路径(去除尾部反斜杠)
    If Right(\BackupDir, 1) = "\" And Len(\BackupDir) > 3
      \BackupDir = Left(\BackupDir, Len(\BackupDir) - 1)
    EndIf
  EndWith
  ClosePreferences()
EndProcedure

Procedure SaveConfig()
  OpenPreferences(ConfigPath())
  PreferenceGroup(#PrefGroup)
  With G
    WritePreferenceString("Host",         \Host)
    WritePreferenceString("Port",         \Port)
    WritePreferenceString("User",         \User)
    WritePreferenceString("Password",     SimpleEncode(\Password))
    WritePreferenceString("Database",     \Database)
    WritePreferenceString("BackupDir",    \BackupDir)
    WritePreferenceInteger("BackupHour",  \BackupHour)
    WritePreferenceInteger("BackupMinute",\BackupMinute)
    WritePreferenceInteger("KeepDays",    \KeepDays)
    WritePreferenceString("DumpPath",     \DumpPath)
    WritePreferenceInteger("AutoBackup",  \AutoBackup)
    WritePreferenceString("LastBackupDate",\LastBackupDate)
  EndWith
  ClosePreferences()
EndProcedure


;===========================================================================
;  备份执行
;===========================================================================

; 创建临时凭据文件并设置权限(仅当前用户可读)
; [FIX-42] 先写入内容再收紧权限,消除 TOCTOU 竞态窗口
Procedure.s CreateSecureDefaultsFile(Host.s, Port.s, User.s, Password.s)
  Protected FilePath.s, hFile.i, Prog.i
  FilePath = GetPathPart(ProgramFilename()) + ".my.cnf.tmp"

  ; [防御] 若上次程序崩溃残留，先尝试删除
  If FileSize(FilePath) >= 0
    DeleteFile(FilePath)
  EndIf

  ; 先写入内容,再收紧权限--消除 TOCTOU 窗口
  hFile = CreateFile(#PB_Any, FilePath)
  If Not hFile
    LogWrite("警告:无法创建临时凭据文件")
    ProcedureReturn ""
  EndIf
  WriteStringN(hFile, "[client]")
  WriteStringN(hFile, "host=" + Host)
  WriteStringN(hFile, "port=" + Port)
  WriteStringN(hFile, "user=" + User)
  If Password <> ""
    WriteStringN(hFile, "password=" + Password)
  EndIf
  CloseFile(hFile)

  ; 内容已落盘,再收紧权限(用户名加引号防止注入)
  Prog = RunProgram("cmd.exe",
    "/c icacls " + #DQUOTE$ + FilePath + #DQUOTE$ +
    " /inheritance:r /grant:r " + #DQUOTE$ + "%USERNAME%" + #DQUOTE$ + ":F",
    "", #PB_Program_Open | #PB_Program_Hide)
  If Prog
    WaitProgram(Prog)
    If ProgramExitCode(Prog) <> 0
      LogWrite("警告:icacls 设置权限失败(退出码 " + Str(ProgramExitCode(Prog)) + ")")
    EndIf
    CloseProgram(Prog)
  Else
    LogWrite("警告:无法执行 icacls,凭据文件可能权限过宽")
  EndIf

  ProcedureReturn FilePath
EndProcedure

; 构造 mysqldump 命令行参数(强制使用 defaults-file,禁止命令行密码)
Procedure.s BuildDumpArgs(DefaultsFile.s, OutputFile.s, Database.s)
  Protected Args.s
  Args = "--defaults-file=" + #DQUOTE$ + DefaultsFile + #DQUOTE$
  Args + " --single-transaction --routines --triggers --events"
  Args + " --result-file=" + #DQUOTE$ + OutputFile + #DQUOTE$ + " " + Database
  ProcedureReturn Args
EndProcedure

Procedure.i DoBackup()
  Protected FileName.s, Args.s, Prog.i, ExitCode.i = -1
  Protected DefaultsFile.s, CleanupNeeded.i = #False
  Protected FinalSize.i

  With G
    ; --- 前置检查 ---
    If \Database = ""
      LogWrite("备份失败:未配置数据库名")
      ProcedureReturn #False
    EndIf
    If FileSize(\DumpPath) = -1
      LogWrite("备份失败:找不到 mysqldump.exe(" + \DumpPath + ")")
      ProcedureReturn #False
    EndIf
    If FileSize(\BackupDir) = -1
      If Not CreateDirectory(\BackupDir)
        LogWrite("备份失败:无法创建备份目录 " + \BackupDir)
        ProcedureReturn #False
      EndIf
    EndIf
    If Val(\Port) < 1 Or Val(\Port) > 65535
      LogWrite("备份失败:端口号无效(" + \Port + ")")
      ProcedureReturn #False
    EndIf

    ; --- 准备凭据文件(强制要求,无回退) ---
    DefaultsFile = CreateSecureDefaultsFile(\Host, \Port, \User, \Password)
    If DefaultsFile = ""
      LogWrite("备份失败:无法创建凭据文件,为防止密码泄露,终止备份")
      ProcedureReturn #False
    EndIf
    CleanupNeeded = #True

    ; --- 构造命令并执行 ---
    FileName = \BackupDir + "\" + #BackupPrefix + \Database + "_" +
               FormatDate("%yyyy%mm%dd_%hh%ii%ss", Date()) + ".sql"
    Args = BuildDumpArgs(DefaultsFile, FileName, \Database)

    LogWrite("开始备份数据库 [" + \Database + "] 到 " + FileName)
    Prog = RunProgram(\DumpPath, Args, GetPathPart(\DumpPath), #PB_Program_Open | #PB_Program_Hide)
    If Prog
      WaitProgram(Prog)
      ExitCode = ProgramExitCode(Prog)
      CloseProgram(Prog)
    EndIf

    ; --- 清理凭据文件 ---
    If CleanupNeeded And DefaultsFile <> ""
      If DeleteFile(DefaultsFile) = 0
        LogWrite("警告:无法删除临时凭据文件 " + DefaultsFile + "，错误码 " + Str(GetLastError_()))
      EndIf
    EndIf

    ; --- 判断结果 ---
    If ExitCode = 0 And FileSize(FileName) > 0
      FinalSize = FileSize(FileName)
      LogWrite("备份成功:" + FileName + "(" + StrF(FinalSize / 1024.0, 1) + " KB)")
      \LastBackupDate = FormatDate("%yyyy-%mm-%dd", Date())
      SaveConfig()
      ProcedureReturn #True
    Else
      LogWrite("备份失败:mysqldump 退出码 = " + Str(ExitCode))
      If FileSize(FileName) >= 0 : DeleteFile(FileName) : EndIf
      \LastBackupDate = FormatDate("%yyyy-%mm-%dd", Date())
      SaveConfig()
      ProcedureReturn #False
    EndIf
  EndWith
EndProcedure


;===========================================================================
;  备份清理
;===========================================================================

Procedure.i IsBackupFile(FileName.s)
  Protected NameOnly.s, Prefix.s
  NameOnly = GetFilePart(FileName)
  If G\Database = "" : ProcedureReturn #False : EndIf
  Prefix = #BackupPrefix + G\Database + "_"
  If Len(NameOnly) > Len(Prefix) + 4
    If Left(NameOnly, Len(Prefix)) = Prefix
      If Right(NameOnly, 4) = ".sql"
        ProcedureReturn #True
      EndIf
    EndIf
  EndIf
  ProcedureReturn #False
EndProcedure

Procedure CleanOldBackups()
  Protected Dir.i, Name.s, FileDate.i, CutOff.i, Count.i = 0
  Protected FullPath.s
  Protected LogDir.s, LogDirH.i, LogName.s, LogFullPath.s, LogDate.i

  If FileSize(G\BackupDir) <> -2
    LogWrite("清理跳过:备份目录不存在 " + G\BackupDir)
    ProcedureReturn
  EndIf

  CutOff = AddDate(Date(), #PB_Date_Day, -G\KeepDays)

  ; [FIX-43] 移除数量门控,直接遍历按日期判断过期
  Dir = ExamineDirectory(#PB_Any, G\BackupDir, "*.sql")
  If Dir
    While NextDirectoryEntry(Dir)
      If DirectoryEntryType(Dir) = #PB_DirectoryEntry_File
        Name = DirectoryEntryName(Dir)
        If IsBackupFile(Name)
          FullPath = G\BackupDir + "\" + Name
          FileDate = GetFileDate(FullPath, #PB_Date_Modified)
          If FileDate < CutOff
            If DeleteFile(FullPath)
              LogWrite("清理过期备份:" + Name)
              Count + 1
            EndIf
          EndIf
        EndIf
      EndIf
    Wend
    FinishDirectory(Dir)
  Else
    LogWrite("清理失败:无法遍历备份目录 " + G\BackupDir)
  EndIf

  ; [OPT-15] 同步清理过期日志文件
  LogDir = GetPathPart(ProgramFilename()) + "logs"
  If FileSize(LogDir) = -2
    LogDirH = ExamineDirectory(#PB_Any, LogDir, "backup_*.log")
    If LogDirH
      While NextDirectoryEntry(LogDirH)
        If DirectoryEntryType(LogDirH) = #PB_DirectoryEntry_File
          LogName = DirectoryEntryName(LogDirH)
          LogFullPath = LogDir + "\" + LogName
          LogDate = GetFileDate(LogFullPath, #PB_Date_Modified)
          If LogDate < CutOff
            If DeleteFile(LogFullPath)
              LogWrite("清理过期日志:" + LogName)
            EndIf
          EndIf
        EndIf
      Wend
      FinishDirectory(LogDirH)
    EndIf
  EndIf

  If Count = 0 : LogWrite("过期备份检查:无需清理") : EndIf
EndProcedure

Procedure CheckScheduledBackup()
  Protected Now.i = Date()
  If G\AutoBackup
    If Hour(Now) = G\BackupHour And
       Minute(Now) = G\BackupMinute And
       G\LastBackupDate <> FormatDate("%yyyy-%mm-%dd", Now)
      ; [FIX-46] 立即标记日期,防止定时器窗口内重复触发
      G\LastBackupDate = FormatDate("%yyyy-%mm-%dd", Now)
      SaveConfig()
      DoBackup()
      CleanOldBackups()
    EndIf
  EndIf
EndProcedure


;===========================================================================
;  Windows 服务框架(标准 SCM)
;===========================================================================

; 更新服务状态
Procedure UpdateServiceStatus(dwCurrentState.i, dwWin32ExitCode.i = 0, dwCheckPoint.i = 0)
  gSvcStatus\dwServiceType    = #SERVICE_WIN32_OWN_PROCESS
  gSvcStatus\dwCurrentState   = dwCurrentState
  gSvcStatus\dwWin32ExitCode  = dwWin32ExitCode
  gSvcStatus\dwCheckPoint     = dwCheckPoint
  If gSvcStatusHandle
    SetServiceStatus_(gSvcStatusHandle, gSvcStatus)
  EndIf
EndProcedure

; 服务控制处理器(响应 SCM 的停止、暂停等请求)
Procedure ServiceCtrlHandlerEx(dwControl.i, dwEventType.i, lpEventData.i, lpContext.i)
  Select dwControl
    Case #SERVICE_CONTROL_STOP, #SERVICE_CONTROL_SHUTDOWN
      LogWrite("服务:收到停止信号")
      EnterCriticalSection_(gStopSection)
      gStopFlag = #True
      LeaveCriticalSection_(gStopSection)
      UpdateServiceStatus(#SERVICE_STOP_PENDING)
      ProcedureReturn #NO_ERROR
    Case #SERVICE_CONTROL_INTERROGATE
      ProcedureReturn #NO_ERROR
    Default
      ProcedureReturn #ERROR_CALL_NOT_IMPLEMENTED
  EndSelect
EndProcedure

; 服务主函数(由 SCM 调用)
Procedure ServiceMain(dwArgc.i, lpszArgv.i)
  LogWrite("=== 服务主函数启动 ===")

  gSvcStatusHandle = RegisterServiceCtrlHandlerEx_(#SvcName, @ServiceCtrlHandlerEx(), 0)
  If gSvcStatusHandle = 0
    LogWrite("服务:注册控制处理器失败")
    ProcedureReturn
  EndIf

  ; 报告启动中
  gSvcStatus\dwServiceType      = #SERVICE_WIN32_OWN_PROCESS
  gSvcStatus\dwCurrentState     = #SERVICE_START_PENDING
  gSvcStatus\dwControlsAccepted = #SERVICE_ACCEPT_STOP | #SERVICE_ACCEPT_SHUTDOWN
  SetServiceStatus_(gSvcStatusHandle, gSvcStatus)

  ; 启动完成
  gSvcStatus\dwCurrentState = #SERVICE_RUNNING
  SetServiceStatus_(gSvcStatusHandle, gSvcStatus)

  ; 主循环
  While #True
    EnterCriticalSection_(gStopSection)
    If gStopFlag
      LeaveCriticalSection_(gStopSection)
      Break
    EndIf
    LeaveCriticalSection_(gStopSection)
    CheckScheduledBackup()
    Delay(#TimerInterval)
  Wend

  UpdateServiceStatus(#SERVICE_STOPPED)
  LogWrite("=== 服务主函数退出 ===")
EndProcedure

; 服务模式入口(启动服务调度器)
Procedure RunAsService()
  Protected ServiceTable.SERVICE_TABLE_ENTRY
  Protected SvcName.s = #SvcName
  LogWrite("=== 服务模式启动(调度器)===")
  ServiceTable\lpServiceName = @SvcName
  ServiceTable\lpServiceProc = @ServiceMain()
  If StartServiceCtrlDispatcher_(@ServiceTable) = 0
    LogWrite("服务:StartServiceCtrlDispatcher 失败,错误码 " + Str(GetLastError_()))
  EndIf
  LogWrite("=== 服务模式退出(调度器)===")
EndProcedure


;===========================================================================
;  Windows 服务安装/卸载
;===========================================================================

Procedure InstallService()
  Protected Cmd.s, Prog.i, Code.i = -1
  Protected binPath.s

  ; 非管理员时自动触发 UAC 提权,当前实例退出
  If Not IsUserAnAdmin_()
    If ShellExecute_(0, "runas", ProgramFilename(), "--install", "", #SW_SHOWNORMAL) > 32
      End  ; 提权成功,当前实例退出
    EndIf
    ; 提权失败(用户拒绝 UAC),提示并返回
    MessageRequester(#AppName, "安装服务需要管理员权限!" + #LF$ + "请以管理员身份运行本程序。", #PB_MessageRequester_Error)
    ProcedureReturn
  EndIf

  ; binPath 整体加引号:""path.exe" --service"
  binPath = #DQUOTE$ + ProgramFilename() + #DQUOTE$ + " --service"
  Cmd = "create " + #SvcName + " binPath= " + #DQUOTE$ + binPath + #DQUOTE$ +
        " start= auto DisplayName= " + #DQUOTE$ + #AppName + #DQUOTE$
  LogWrite("服务安装命令:sc " + Cmd)

  Prog = RunProgram("sc.exe", Cmd, "", #PB_Program_Open | #PB_Program_Hide)
  If Prog
    WaitProgram(Prog)
    Code = ProgramExitCode(Prog)
    CloseProgram(Prog)
  EndIf

  If Code = 0
    LogWrite("服务 " + #SvcName + " 安装成功")
    Prog = RunProgram("net.exe", "start " + #SvcName, "", #PB_Program_Open | #PB_Program_Hide)
    If Prog
      WaitProgram(Prog)
      Code = ProgramExitCode(Prog)
      CloseProgram(Prog)
      If Code = 0
        LogWrite("服务 " + #SvcName + " 启动成功")
        MessageRequester(#AppName, "服务 [" + #SvcName + "] 安装并启动成功!", #PB_MessageRequester_Ok)
      Else
        LogWrite("服务启动失败(退出码 " + Str(Code) + ")")
        MessageRequester(#AppName, "服务安装成功但启动失败(" + Str(Code) + "),请手动启动。", #PB_MessageRequester_Warning)
      EndIf
    Else
      LogWrite("服务启动命令执行失败")
      MessageRequester(#AppName, "服务安装成功但启动失败,请手动启动。", #PB_MessageRequester_Warning)
    EndIf
  Else
    LogWrite("服务安装失败(退出码 " + Str(Code) + ")")
    MessageRequester(#AppName, "服务安装失败(" + Str(Code) + ")!请以管理员身份运行。", #PB_MessageRequester_Error)
  EndIf
EndProcedure

Procedure UninstallService()
  Protected Prog.i, Code.i

  If Not IsUserAnAdmin_()
    If ShellExecute_(0, "runas", ProgramFilename(), "--uninstall", "", #SW_SHOWNORMAL) > 32
      End
    EndIf
    MessageRequester(#AppName, "卸载服务需要管理员权限!" + #LF$ + "请以管理员身份运行本程序。", #PB_MessageRequester_Error)
    ProcedureReturn
  EndIf

  LogWrite("开始卸载服务 " + #SvcName)
  Prog = RunProgram("net.exe", "stop " + #SvcName, "", #PB_Program_Open | #PB_Program_Hide)
  If Prog
    WaitProgram(Prog)
    CloseProgram(Prog)
  EndIf
  Delay(2000)
  Prog = RunProgram("sc.exe", "delete " + #SvcName, "", #PB_Program_Open | #PB_Program_Hide)
  If Prog
    WaitProgram(Prog)
    Code = ProgramExitCode(Prog)
    CloseProgram(Prog)
    If Code = 0
      LogWrite("服务 " + #SvcName + " 已卸载")
      MessageRequester(#AppName, "服务已卸载。", #PB_MessageRequester_Ok)
    Else
      LogWrite("服务卸载失败(退出码 " + Str(Code) + ")")
      MessageRequester(#AppName, "服务卸载失败(" + Str(Code) + ")!请以管理员身份运行。", #PB_MessageRequester_Error)
    EndIf
  Else
    LogWrite("服务卸载命令执行失败")
    MessageRequester(#AppName, "服务卸载命令执行失败!", #PB_MessageRequester_Error)
  EndIf
EndProcedure


;===========================================================================
;  资源清理
;===========================================================================

Procedure CleanupResources()
  If gLogMutex      : FreeMutex(gLogMutex)                  : gLogMutex      = 0 : EndIf
  If gInstanceMutex  : CloseHandle_(gInstanceMutex)          : gInstanceMutex = 0 : EndIf
  If gStopSection
    DeleteCriticalSection_(gStopSection)
    FreeMemory(gStopSection)
    gStopSection = 0
  EndIf
EndProcedure


;===========================================================================
;  设置窗口
;===========================================================================

Procedure OpenSettingsWindow()
  Protected y.i = 15
  If gSettingsOpen : ProcedureReturn : EndIf

  If OpenWindow(#WinSettings, 0, 0, 480, 380, #AppName + " - 设置",
                #PB_Window_SystemMenu | #PB_Window_ScreenCentered, WindowID(#WinMain))
    gSettingsOpen = #True

    TextGadget(#PB_Any, 15, y, 90, 22, "主机:")
    StringGadget(#TxtHost, 110, y, 200, 22, G\Host) : y + 30

    TextGadget(#PB_Any, 15, y, 90, 22, "端口:")
    StringGadget(#TxtPort, 110, y, 200, 22, G\Port) : y + 30

    TextGadget(#PB_Any, 15, y, 90, 22, "用户名:")
    StringGadget(#TxtUser, 110, y, 200, 22, G\User) : y + 30

    TextGadget(#PB_Any, 15, y, 90, 22, "密码:")
    StringGadget(#TxtPassword, 110, y, 200, 22, G\Password, #PB_String_Password) : y + 30

    TextGadget(#PB_Any, 15, y, 90, 22, "数据库:")
    StringGadget(#TxtDatabase, 110, y, 200, 22, G\Database) : y + 30

    TextGadget(#PB_Any, 15, y, 90, 22, "备份目录:")
    StringGadget(#TxtBackupDir, 110, y, 260, 22, G\BackupDir)
    ButtonGadget(#BtnBrowseDir, 380, y, 80, 22, "浏览...") : y + 30

    TextGadget(#PB_Any, 15, y, 90, 22, "备份时间:")
    SpinGadget(#SpinBackupHour, 110, y, 60, 22, 0, 23, #PB_Spin_Numeric)
    SetGadgetState(#SpinBackupHour, G\BackupHour)
    TextGadget(#PB_Any, 175, y, 15, 22, "时")
    SpinGadget(#SpinBackupMinute, 195, y, 60, 22, 0, 59, #PB_Spin_Numeric)
    SetGadgetState(#SpinBackupMinute, G\BackupMinute)
    TextGadget(#PB_Any, 260, y, 15, 22, "分") : y + 30

    TextGadget(#PB_Any, 15, y, 90, 22, "保留天数:")
    SpinGadget(#SpinKeepDays, 110, y, 60, 22, 1, 365, #PB_Spin_Numeric)
    SetGadgetState(#SpinKeepDays, G\KeepDays)
    TextGadget(#PB_Any, 175, y, 120, 22, "天(过期自动删除)") : y + 30

    TextGadget(#PB_Any, 15, y, 90, 22, "mysqldump:")
    StringGadget(#TxtDumpPath, 110, y, 260, 22, G\DumpPath)
    ButtonGadget(#BtnBrowseDump, 380, y, 80, 22, "浏览...") : y + 35

    CheckBoxGadget(#ChkAutoBackup, 110, y, 200, 22, "启用每日自动备份")
    SetGadgetState(#ChkAutoBackup, G\AutoBackup) : y + 40

    ButtonGadget(#BtnSave, 110, y, 100, 30, "保存")
    ButtonGadget(#BtnCancel, 230, y, 100, 30, "取消")
  EndIf
EndProcedure

Procedure CloseSettingsWindow()
  If gSettingsOpen
    CloseWindow(#WinSettings)
    gSettingsOpen = #False
  EndIf
EndProcedure

Procedure SettingsEvents(EventGadget.i)
  Protected Dir.s, NewPort.i, NewKeepDays.i, NewBackupDir.s
  If Not gSettingsOpen : ProcedureReturn : EndIf

  Select EventGadget
    Case #BtnBrowseDir
      Dir = PathRequester("选择备份保存目录", G\BackupDir)
      If Dir <> "" : SetGadgetText(#TxtBackupDir, Dir) : EndIf

    Case #BtnBrowseDump
      Dir = OpenFileRequester("选择 mysqldump.exe", G\DumpPath, "mysqldump.exe|mysqldump.exe", 0)
      If Dir <> "" : SetGadgetText(#TxtDumpPath, Dir) : EndIf

    Case #BtnSave
      ; 增强输入校验
      If Trim(GetGadgetText(#TxtHost)) = ""
        MessageRequester(#AppName, "请填写主机名!", #PB_MessageRequester_Error)
        ProcedureReturn
      EndIf
      NewPort = Val(GetGadgetText(#TxtPort))
      If NewPort < 1 Or NewPort > 65535
        MessageRequester(#AppName, "端口号必须在 1-65535 之间!", #PB_MessageRequester_Error)
        ProcedureReturn
      EndIf
      If Trim(GetGadgetText(#TxtUser)) = ""
        MessageRequester(#AppName, "请填写用户名!", #PB_MessageRequester_Error)
        ProcedureReturn
      EndIf
      If Trim(GetGadgetText(#TxtDatabase)) = ""
        MessageRequester(#AppName, "请填写数据库名称!", #PB_MessageRequester_Error)
        ProcedureReturn
      EndIf
      ; [FIX-44] 先读取新路径再验证
      NewBackupDir = Trim(GetGadgetText(#TxtBackupDir))
      If NewBackupDir = ""
        MessageRequester(#AppName, "请指定备份目录!", #PB_MessageRequester_Error)
        ProcedureReturn
      EndIf
      ; [FIX-47] 规范化路径:去除尾部反斜杠
      If Right(NewBackupDir, 1) = "\" And Len(NewBackupDir) > 3
        NewBackupDir = Left(NewBackupDir, Len(NewBackupDir) - 1)
      EndIf
      NewKeepDays = GetGadgetState(#SpinKeepDays)
      If NewKeepDays < 1
        MessageRequester(#AppName, "保留天数至少为 1 天!", #PB_MessageRequester_Error)
        ProcedureReturn
      EndIf
      ; [FIX-44] 用新路径做目录创建检查
      If FileSize(NewBackupDir) = -1
        If Not CreateDirectory(NewBackupDir)
          MessageRequester(#AppName, "无法创建备份目录:" + NewBackupDir, #PB_MessageRequester_Error)
          ProcedureReturn
        EndIf
      EndIf

      G\Host         = GetGadgetText(#TxtHost)
      G\Port         = GetGadgetText(#TxtPort)
      G\User         = GetGadgetText(#TxtUser)
      G\Password     = GetGadgetText(#TxtPassword)
      G\Database     = GetGadgetText(#TxtDatabase)
      G\BackupDir    = NewBackupDir
      G\BackupHour   = GetGadgetState(#SpinBackupHour)
      G\BackupMinute = GetGadgetState(#SpinBackupMinute)
      G\KeepDays     = NewKeepDays
      G\DumpPath     = GetGadgetText(#TxtDumpPath)
      G\AutoBackup   = GetGadgetState(#ChkAutoBackup)
      SaveConfig()
      LogWrite("配置已保存")
      CloseSettingsWindow()

    Case #BtnCancel
      CloseSettingsWindow()
  EndSelect
EndProcedure


;===========================================================================
;  托盘图标
;===========================================================================

Procedure.i LoadTrayIcon()
  Protected hInstance.i = GetModuleHandle_(0)
  Protected IconID.i

  ; 方法1: 从嵌入资源加载(编译时 UseIcon 指定的图标)
  IconID = LoadImage_(hInstance, 1, #IMAGE_ICON, 16, 16, #LR_DEFAULTCOLOR)

  If IconID = 0
    ; 方法2: 从可执行文件提取第一个图标
    IconID = ExtractIcon_(hInstance, ProgramFilename(), 0)
  EndIf

  If IconID = 0
    ; 方法3: 兜底使用系统默认图标
    IconID = LoadIcon_(0, #IDI_APPLICATION)
  EndIf
  ProcedureReturn IconID
EndProcedure


;===========================================================================
;  帮助窗口
;===========================================================================

Procedure ShowHelpWindow()
  Protected HelpText.s
  If gHelpOpen : ProcedureReturn : EndIf

  HelpText = #AppName + " 使用帮助" + #LF$ + #LF$
  HelpText + "─────────────────────────────────────" + #LF$
  HelpText + "一、程序简介" + #LF$
  HelpText + "─────────────────────────────────────" + #LF$
  HelpText + "本工具用于自动备份 MySQL 数据库,支持:" + #LF$
  HelpText + "  • 系统托盘驻留,定时自动备份" + #LF$
  HelpText + "  • 过期备份自动清理" + #LF$
  HelpText + "  • 安装为 Windows 系统服务" + #LF$
  HelpText + "  • 日志记录(按日期分文件)" + #LF$ + #LF$
  HelpText + "─────────────────────────────────────" + #LF$
  HelpText + "二、首次使用" + #LF$
  HelpText + "─────────────────────────────────────" + #LF$
  HelpText + "  1. 将 mysqldump.exe 放在程序目录(或在设置中指定路径)" + #LF$
  HelpText + "  2. 右键托盘图标 → 设置" + #LF$
  HelpText + "  3. 填写 MySQL 连接信息(主机、端口、用户名、密码、数据库名)" + #LF$
  HelpText + "  4. 选择备份保存目录" + #LF$
  HelpText + "  5. 设置备份时间(默认每天凌晨3:00)" + #LF$
  HelpText + "  6. 点击保存" + #LF$ + #LF$
  HelpText + "─────────────────────────────────────" + #LF$
  HelpText + "三、功能说明" + #LF$
  HelpText + "─────────────────────────────────────" + #LF$
  HelpText + "【立即备份】  立即执行一次完整备份" + #LF$
  HelpText + "【打开备份目录】  在资源管理器中打开备份文件夹" + #LF$
  HelpText + "【设置】  修改数据库连接、备份时间、保留天数等" + #LF$
  HelpText + "【安装为系统服务】  注册 Windows 服务,开机自动运行" + #LF$
  HelpText + "【卸载系统服务】  移除 Windows 服务" + #LF$ + #LF$
  HelpText + "─────────────────────────────────────" + #LF$
  HelpText + "四、备份策略" + #LF$
  HelpText + "─────────────────────────────────────" + #LF$
  HelpText + "  • 备份文件名格式:backup_<数据库名>_<日期时间>.sql" + #LF$
  HelpText + "  • 自动清理:当备份文件数超过保留天数时,删除最旧的文件" + #LF$
  HelpText + "  • 保留天数最少为 1 天,确保至少有一份备份可用" + #LF$
  HelpText + "  • 使用 --single-transaction 保证 InnoDB 一致性备份" + #LF$ + #LF$
  HelpText + "─────────────────────────────────────" + #LF$
  HelpText + "五、系统服务模式" + #LF$
  HelpText + "─────────────────────────────────────" + #LF$
  HelpText + "  • 安装服务后,程序随 Windows 启动,无需登录" + #LF$
  HelpText + "  • 服务名:" + #SvcName + #LF$
  HelpText + "  • 安装/卸载需要管理员权限(会自动弹出 UAC 提示)" + #LF$
  HelpText + "  • 也可手动安装:MySQLBackup.exe --install" + #LF$ + #LF$
  HelpText + "─────────────────────────────────────" + #LF$
  HelpText + "六、命令行参数" + #LF$
  HelpText + "─────────────────────────────────────" + #LF$
  HelpText + "  MySQLBackup.exe              启动托盘模式" + #LF$
  HelpText + "  MySQLBackup.exe --service    以服务模式运行" + #LF$
  HelpText + "  MySQLBackup.exe --install    安装为系统服务" + #LF$
  HelpText + "  MySQLBackup.exe --uninstall  卸载系统服务" + #LF$
  HelpText + "  MySQLBackup.exe --help       显示帮助" + #LF$ + #LF$
  HelpText + "─────────────────────────────────────" + #LF$
  HelpText + "七、配置文件" + #LF$
  HelpText + "─────────────────────────────────────" + #LF$
  HelpText + "  配置文件:" + #ConfigFile + "(程序目录下)" + #LF$
  HelpText + "  日志目录:logs\(程序目录下,按日期分文件)" + #LF$
  HelpText + "  密码存储:Hex+Caesar 混淆(非加密,仅防偶然窥视)" + #LF$ + #LF$
  HelpText + "─────────────────────────────────────" + #LF$
  HelpText + "八、常见问题" + #LF$
  HelpText + "─────────────────────────────────────" + #LF$
  HelpText + "  Q: 备份失败怎么办?" + #LF$
  HelpText + "  A: 检查 logs 目录下的日志文件,确认 mysqldump 路径和连接信息正确" + #LF$ + #LF$
  HelpText + "  Q: 如何手动触发备份?" + #LF$
  HelpText + "  A: 右键托盘图标 → 立即备份" + #LF$ + #LF$
  HelpText + "  Q: 服务安装失败?" + #LF$
  HelpText + "  A: 需要管理员权限,程序会自动弹出 UAC 提示" + #LF$ + #LF$
  HelpText + "  Q: 备份文件在哪里?" + #LF$
  HelpText + "  A: 在设置中指定的备份目录下,格式为 .sql 文件" + #LF$ + #LF$
  HelpText + "─────────────────────────────────────" + #LF$
  HelpText + "九、安全说明" + #LF$
  HelpText + "─────────────────────────────────────" + #LF$
  HelpText + "  • 凭据通过 --defaults-file 传递,不在进程列表中暴露密码" + #LF$
  HelpText + "  • 临时凭据文件使用后立即删除" + #LF$
  HelpText + "  • 临时凭据文件权限限制为仅当前用户可读" + #LF$
  HelpText + "  • 配置文件中的密码使用 Hex+Caesar 混淆存储" + #LF$
  HelpText + "  • 如需更高安全级别,建议使用 Windows DPAPI 或外部密钥管理" + #LF$

  If OpenWindow(#WinHelp, 0, 0, 560, 520, #AppName + " - 使用帮助",
                #PB_Window_SystemMenu | #PB_Window_ScreenCentered, WindowID(#WinMain))
    gHelpOpen = #True
    EditorGadget(#EditorHelp, 5, 5, 550, 510, #PB_Editor_ReadOnly | #PB_Editor_WordWrap)
    SetGadgetText(#EditorHelp, HelpText)
  EndIf
EndProcedure

Procedure CloseHelpWindow()
  If gHelpOpen
    CloseWindow(#WinHelp)
    gHelpOpen = #False
  EndIf
EndProcedure


;===========================================================================
;  主程序入口
;===========================================================================

gLogMutex = CreateMutex()

gStopSection = AllocateMemory(SizeOf(CRITICAL_SECTION))
If gStopSection
  InitializeCriticalSection_(gStopSection)
EndIf

LoadConfig()

; --- 命令行模式（先于单实例检查，避免 ShellExecute 启动的提权实例被拦截）---
If CountProgramParameters() >= 1
  Select LCase(ProgramParameter(0))
    Case "--service"
      RunAsService()
      CleanupResources() : End
    Case "--install"
      InstallService()
      CleanupResources() : End
    Case "--uninstall"
      UninstallService()
      CleanupResources() : End
    Case "--help", "-h", "/?"
      MessageRequester(#AppName,
        "用法:" + #LF$ +
        "  MySQLBackup.exe              启动托盘模式" + #LF$ +
        "  MySQLBackup.exe --service    以服务模式运行" + #LF$ +
        "  MySQLBackup.exe --install    安装为系统服务" + #LF$ +
        "  MySQLBackup.exe --uninstall  卸载系统服务" + #LF$ +
        "  MySQLBackup.exe --help       显示此帮助",
        #PB_MessageRequester_Info)
      CleanupResources() : End
  EndSelect
EndIf

; --- 托盘模式：单实例检查（仅对无参数的托盘实例生效）---
gInstanceMutex = CreateMutex_(0, #True, "MySQLBackupTool_SingleInstance")
If gInstanceMutex And GetLastError_() = #ERROR_ALREADY_EXISTS
  MessageRequester(#AppName, "程序已在运行中,请检查系统托盘。", #PB_MessageRequester_Warning)
  CleanupResources() : End
EndIf
If gInstanceMutex = 0
  MessageRequester(#AppName, "无法创建互斥体,程序可能无法正常工作。", #PB_MessageRequester_Warning)
EndIf

; --- 托盘模式 ---
If OpenWindow(#WinMain, 0, 0, 10, 10, #AppName, #PB_Window_Invisible)
  gTrayImg = LoadTrayIcon()
  AddSysTrayIcon(1, WindowID(#WinMain), gTrayImg)
  SysTrayIconToolTip(1, #AppName)

  CreatePopupMenu(0)
  MenuItem(#MenuBackupNow, "立即备份")
  MenuItem(#MenuOpenDir,   "打开备份目录")
  MenuBar()
  MenuItem(#MenuSettings,  "设置...")
  MenuItem(#MenuService,   "安装为系统服务")
  MenuItem(#MenuUninstall, "卸载系统服务")
  MenuBar()
  MenuItem(#MenuHelp,      "使用帮助")
  MenuItem(#MenuExit,      "退出")

  AddWindowTimer(#WinMain, #TimerCheckBackup, #TimerInterval)
  LogWrite("=== 程序启动(托盘模式)===")

  Repeat
    Select WaitWindowEvent()

      Case #PB_Event_SysTray
        If EventType() = #PB_EventType_RightClick
          DisplayPopupMenu(0, WindowID(#WinMain))
        EndIf

      Case #PB_Event_Menu
        Select EventMenu()
          Case #MenuBackupNow
            If DoBackup()
              MessageRequester(#AppName, "备份完成!", #PB_MessageRequester_Ok)
            Else
              MessageRequester(#AppName, "备份失败,请查看日志。", #PB_MessageRequester_Error)
            EndIf
            CleanOldBackups()

          Case #MenuOpenDir
            If FileSize(G\BackupDir) = -2
              RunProgram("explorer.exe", #DQUOTE$ + G\BackupDir + #DQUOTE$, "")
            Else
              MessageRequester(#AppName, "备份目录不存在:" + G\BackupDir, #PB_MessageRequester_Warning)
            EndIf

          Case #MenuSettings
            OpenSettingsWindow()

          Case #MenuService
            If MessageRequester(#AppName,
                "是否将程序安装为 Windows 系统服务?" + #LF$ + "(需要管理员权限)",
                #PB_MessageRequester_YesNo) = #PB_MessageRequester_Yes
              InstallService()
            EndIf

          Case #MenuUninstall
            If MessageRequester(#AppName,
                "是否卸载 " + #SvcName + " 系统服务?" + #LF$ + "(需要管理员权限)",
                #PB_MessageRequester_YesNo) = #PB_MessageRequester_Yes
              UninstallService()
            EndIf

          Case #MenuHelp
            ShowHelpWindow()

          Case #MenuExit
            Break
        EndSelect

      Case #PB_Event_Timer
        If EventTimer() = #TimerCheckBackup
          CheckScheduledBackup()
        EndIf

      Case #PB_Event_Gadget
        SettingsEvents(EventGadget())

      Case #PB_Event_CloseWindow
        If EventWindow() = #WinSettings
          CloseSettingsWindow()
        ElseIf EventWindow() = #WinHelp
          CloseHelpWindow()
        ElseIf EventWindow() = #WinMain
          Break
        EndIf

    EndSelect
  ForEver

  LogWrite("=== 程序退出 ===")
  RemoveSysTrayIcon(1)
  If gTrayImg : DestroyIcon_(gTrayImg) : gTrayImg = 0 : EndIf
  CleanupResources()
EndIf
End


;===========================================================================
;  CHANGELOG
;===========================================================================
;
; v1→v2:  修复图标加载、日志互斥、信号处理、密码安全、清理逻辑等12项
; v2→v3:  修复 Unicode 编码、凭据文件权限、单实例检测等6项
; v3→v4:  修复 icacls 执行、Protected 声明兼容性、无限重试等5项
; v4→v5:  消除凭据文件权限窗口、修正 API 调用、增加输入校验等7项
; v5→v6:  重构资源清理、精确文件匹配、命令行帮助、卸载菜单等8项
; v6→v7:
;   [FIX-31] LogWrite 改用共享模式打开日志文件,失败时回退独占模式
;   [FIX-32] 服务框架重写:标准 SCM(ServiceMain + RegisterServiceCtrlHandlerEx_)
;   [FIX-33] BuildDumpArgs 移除密码回退,强制使用 defaults-file
;   [FIX-34] DoBackup 凭据文件创建失败时终止备份,不再回退命令行密码
;   [FIX-35] icacls 中 %USERNAME% 加引号防止注入
;   [FIX-36] InstallService/UninstallService 非管理员时自动 ShellExecute_ runas 提权,用户拒绝 UAC 后提示
;   [FIX-37] binPath 构造改为整体引号包裹,替代反斜杠转义
;   [FIX-38] SettingsEvents 增加主机/用户名/备份目录非空校验
;   [FIX-39] 设置保存时尝试创建备份目录
;   [FIX-40] CheckScheduledBackup 改用 Hour()/Minute() 原生函数
;   [FIX-41] LoadTrayIcon 改用 BitBlt_ 复制像素,移除 DIB+alpha 逐像素修复
;   [OPT-13] 定义 #DQUOTE$ 常量,全局替代硬编码 Chr(34)
;   [OPT-14] 托盘菜单增加"使用帮助",弹出只读帮助窗口(九个章节覆盖全部功能)
;
; v7→v8:
;   [FIX-42] CreateSecureDefaultsFile 修复 TOCTOU 竞态:先写入凭据内容再收紧权限
;   [FIX-43] CleanOldBackups 移除文件总数门控,改为按修改日期判断过期并删除
;   [FIX-44] SettingsEvents 保存时先读取新路径再验证/创建目录,修复旧路径验证问题
;   [FIX-45] LoadTrayIcon 修复 GDI 资源泄漏:正确获取/释放桌面 DC,失败路径清理
;   [FIX-46] CheckScheduledBackup 立即标记 LastBackupDate,防止 20s 定时器窗口内重复触发
;   [FIX-47] LoadConfig 中规范化备份目录路径,去除尾部反斜杠
;   [OPT-15] CleanOldBackups 增加过期日志文件自动清理(logs/backup_*.log)
;   [FIX-48] 显式导入 RegisterServiceCtrlHandlerEx_(advapi32),修复编译错误
;   [FIX-49] RunAsService 中 @#SvcName 改为局部变量取地址,修复字符串常量地址引用
;   [FIX-50] LoadTrayIcon 简化：直接返回 HICON 传递给托盘 API，消除黑色方块问题
;
; IDE Options = PureBasic 6.40 (Windows - x64)
; Optimizer
; EnableThread
; EnableXP
; DPIAware
; UseIcon = MySQLBackup.ico
; Executable = M_Data_Bakup.exe
; IncludeVersionInfo
; VersionField0 = 1,0,0,0
; VersionField1 = 1,0,0,0
; VersionField2 = shaocy889@dlufl.edu.cn
; VersionField3 = Mysql/Mariadb备份工具
; VersionField4 = 1,0,0,0
; VersionField5 = 1,0,0,0
; VersionField6 = Mysql/Mariadb备份工具
; VersionField7 = m_db_back.exe
; VersionField8 = m_db_back.exe
; VersionField13 = shaocy889@dlufl.edu.cn