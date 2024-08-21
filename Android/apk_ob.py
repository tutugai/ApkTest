from cryptography import x509  
from cryptography.hazmat.backends import default_backend  
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from androguard.core.apk import APK
from androguard.misc import AnalyzeAPK
from androguard.core.analysis.analysis import ExternalMethod
from androguard.util import get_certificate_name_string
from Tools.pathTool import pathTool
import sys
import os
import subprocess
from Check import *
from jinja2 import Environment, FileSystemLoader

class apk_ob:
    def __init__(self,APKPath) -> None:
        '''
        参数:
            APKPath：apk路径
        '''
        self.APKPath = pathTool.replace_path(APKPath)
        self.apk_name = os.path.splitext(os.path.basename(APKPath))[0]
        self.apk_ob = APK(self.APKPath)
        self.vulnerability_checks = []
        if self.apk_ob.is_valid_APK():
            #APK 的路径 get_filename
            self.apk_path = self.apk_ob.get_filename()
            #APK 的应用程序名称 get_app_name
            self.app_name = self.apk_ob.get_app_name()
            #apk包名 get_package
            self.apk_package = self.apk_ob.get_package()
            #app内部版本号 get_androidversion_code
            self.androidcode_version = self.apk_ob.get_androidversion_code()
            #app用户版本号 get_androidversion_name
            self.app_version = self.apk_ob.get_androidversion_name()
            #min sdkversion
            self.minSdk_Version = self.apk_ob.get_min_sdk_version()
            #targetSdkVersion
            self.targetSdk_Version = self.apk_ob.get_effective_target_sdk_version()
            #apk AndroidManifest.xml 文件中明确声明的权限名称列表。这包括应用程序直接请求以执行特定功能的权限。
            self.permissions = self.apk_ob.get_permissions()
            #返回 AndroidManifest.xml 文件中由应用程序明确声明的自定义权限列表。这些权限通常用于应用程序组件之间的通信或控制对特定功能的访问。
            self.declared_permissions = self.apk_ob.get_declared_permissions()
            #返回基于目标 SDK 版本或其他因素自动隐含给应用程序的权限列表。这些权限不是由应用程序直接声明的，但根据应用程序的其他设置或特性，它们被系统授予给应用程序。
            self.implied_permission = self.apk_ob.get_uses_implied_permission_list()
            #返回 AOSP 项目中声明的请求权限列表。
            self.requested_aosp_permissions = self.apk_ob.get_requested_aosp_permissions()
            #返回 AOSP 项目中未声明的请求权限列表，这些可能是由第三方库或代码引入的。
            self.requested_third_party_permissions = self.apk_ob.get_requested_third_party_permissions()
            #Janus签名机制漏洞安全风险
            self.is_janus = False
        else:
            print('***********无效apk，请确认apk是否有效！***************')
            sys.exit()
    @property
    def out_info(self) -> None:
        '''
        输出run扫描结果
        '''
        #获取apk分析对象
        self.a,self.dex,self.dx = AnalyzeAPK(self.APKPath)
        #获取manifest——xml对象
        et = self.apk_ob.get_android_manifest_xml()
        #基本检测项
        results = self.check_AndroidManifest(et)
        #权限信息格式化
        normalArray, dangerousArray, coreArray, specialArray, newPermissionList = self.get_PermissionList(self.AndroidManifest_PermissionList(et))
        # 设置模板目录
        file_loader = FileSystemLoader(os.getcwd())
        env = Environment(loader=file_loader)
        # 加载模板
        template = env.get_template('template.html')
        # 定义要插入的数据
        data = {
            'title': 'APK扫描报告！',
            'apk_path': self.apk_path,
            'app_name': self.app_name,
            'apk_package': self.apk_package,
            'androidcode_version': self.androidcode_version,
            'app_version': self.app_version,
            'minSdk_Version': self.minSdk_Version,
            'targetSdk_Version': self.targetSdk_Version,
            'certs': self.get_certificate_infos,
            #AndroidManifest.xml 文件中明确声明的权限名称列表
            'permissions': '\n\t'.join(self.permissions),
            #AndroidManifest.xml 文件中由应用程序明确声明的自定义权限列表
            'declared_permissions': '\n\t'.join(self.declared_permissions),
            #基于目标 SDK 版本或其他因素自动隐含给应用程序的权限列表
            'implied_permission': '\n\t'.join(self.implied_permission),
            #AOSP 项目中声明的请求权限列表
            'aosp_permissions': '\n\t'.join(self.requested_aosp_permissions),
            #AOSP 项目中未声明的请求权限列表
            'party_permissions': '\n\t'.join(self.requested_third_party_permissions),
            #权限信息分类
            'normal': '\n\t'.join(' '.join(sub_tuple) for sub_tuple in normalArray),
            'dangerous': '\n\t'.join(' '.join(sub_tuple) for sub_tuple in dangerousArray),
            'core': '\n\t'.join(' '.join(sub_tuple) for sub_tuple in coreArray),
            'special': '\n\t'.join(' '.join(sub_tuple) for sub_tuple in specialArray),
            'newPermission': '\n\t'.join(''.join(sub_tuple) for sub_tuple in newPermissionList),
            #基本漏洞检测项
            'unit': '\n\t'.join(results['unit']),
            'tiaoshi': results['tiaoshi'],
            'beifen': results['beifen'],
            'janus': self.is_janus
        }
        #加入方法漏洞检测项
        data.update(self.MethodsCheck())
        # 渲染模板
        output = template.render(data)

        # 输出渲染结果
        with open(self.apk_name+'.html', 'w',encoding='utf-8') as file:
            file.write(output)
        print('HTML file has been generated.')

    #xpath 匹配AndroidManifest 相关安全性匹配检测
    def check_AndroidManifest(self,et) -> dict:
        xpath_rule = {
            'activity':'//activity[@android:exported="true"]',
            'service':'//service[@android:exported="true"]',
            'receiver':'//receiver[@android:exported="true"]',
            'provider':'//provider[@android:exported="true"]',
            'tiaoshi':'//*[@android:Debugable="true"] | //*[@android:debugable="true"]',
            'beifen':'//*[@android:allowBackup="true"]',

        }
        results = {
            'unit':[],
            'tiaoshi':'',
            'beifen':'',
        }
        for key,value in xpath_rule.items():
            r = et.xpath(value, namespaces={'android': 'http://schemas.android.com/apk/res/android'})
            for element in  r:
                if key == 'tiaoshi':
                    results['tiaoshi'] = 'Debugable='+(element.get('{http://schemas.android.com/apk/res/android}Debugable'))
                elif key == 'beifen':
                    results['beifen'] = 'allowBackup='+(element.get('{http://schemas.android.com/apk/res/android}allowBackup'))
                else:
                    results['unit'].append(element.get('{http://schemas.android.com/apk/res/android}name'))
        return results
    
    #各类型漏洞检测--基于方法
    def MethodsCheck(self) -> dict:
        dxclass = self.dx.classes
        dxmethods = self.dx.get_methods()
        results = {
            'DBCheck': "",
            'DexLoadCheck': "",
            'LogCheck': "",
            'PortCheck': "",
            'ReadFileCheck': "",
            'SQLInjectCheck': "",
            'WebPasswordCheck': "",
            'WebSSLCheck': "",
            'WebjavaCheck': "",
            'WebHiddenCheck': "",
            'WebDebugCheck': "",

        }
        #DBCheck: "数据库文件任意读写检测-检测App是否存在数据库文件任意读写风险"
        DBCheck = []
        if 'Landroid/content/Context;' in dxclass:
            for meth in dxclass['Landroid/content/Context;'].get_methods():
                if 'openOrCreateDatabase' in meth.name:
                    DBCheck.append(f"{meth.full_name};")
        if DBCheck:
            results['DBCheck'] = '\n\t'.join(DBCheck)
        #DexLoadCheck: SDCARD加载dex检测-检测App程序中的是否存在从sdcard动态加载dex的风险
        DexLoadCheck = []
        if 'Ldalvik/system/DexClassLoader;' in dxclass:
            for meth in dxclass['Ldalvik/system/DexClassLoader;'].get_methods():
                if '<init>' in meth.name:
                    DexLoadCheck.append(f"{meth.full_name};")
        if DexLoadCheck:
            results['DexLoadCheck'] = '\n\t'.join(DexLoadCheck)
        #LogCheck: 日志泄漏风险检测--检测Apk中是否存在日志泄露风险，重点检测Log与print函数
        LogCheck = []
        if 'Landroid/util/Log;' in dxclass:
            for meth in dxclass['Landroid/util/Log;'].get_methods():
                if 'd' in meth.name or 'v' in meth.name:
                    LogCheck.append(f"{meth.full_name};")
        if 'Ljava/io/PrintStream;' in dxclass:
            for meth in dxclass['Ljava/io/PrintStream;'].get_methods():
                if 'print' in meth.name:
                    LogCheck.append(f"{meth.full_name};")
        if LogCheck:
            results['LogCheck'] = '\n\t'.join(LogCheck)
        #PortCheck: 网络端口开放威胁检测--检测App中是否存在网络端口开放风险
        PortCheck = []
        if 'Ljava/net/DatagramSocket;' in dxclass:
            for meth in dxclass['Ljava/net/DatagramSocket;'].get_methods():
                if any(m in meth.name for m in ['<init>','receive','connect']):
                    PortCheck.append(f"UDP : {meth.full_name}")
        if 'Ljava/net/DatagramPacket;' in dxclass:
            for meth in dxclass['Ljava/net/DatagramPacket;'].get_methods():
                if '<init>' in meth.name:
                    PortCheck.append(f"UDP : {meth.full_name}")
        if 'Ljava/net/ServerSocket;' in dxclass:
            for meth in dxclass['Ljava/net/ServerSocket;'].get_methods():
                if 'accept' in meth.name or '<init>' in meth.name:
                    PortCheck.append(f"TCP : {meth.full_name}")
        if 'Ljava/net/Socket;' in dxclass:
            for meth in dxclass['Ljava/net/Socket;'].get_methods():
                if 'connect' in meth.name or '<init>' in meth.name:
                    PortCheck.append(f"TCP : {meth.full_name}")
        if PortCheck:
            results['PortCheck'] = '\n\t'.join(PortCheck)
        #ReadFileCheck: 全局可读写风险检测--检测App的SharedPreferences,getDir,openFileOutput函数是否存在全局可读写风险
        ReadFileCheck = []
        for meth in dxmethods:
            if 'getSharedPreferences(Ljava/lang/String;I)Landroid/content/SharedPreferences' in meth.full_name:
                ReadFileCheck.append(f'{meth.full_name}')
        if 'Landroid/content/Context;' in dxclass:
            for meth in dxclass['Landroid/content/Context;'].get_methods():
                if 'openFileOutput' in meth.name or 'getDir' in meth.name:
                    ReadFileCheck.append(f'{meth.full_name}')
        if ReadFileCheck:
            results['ReadFileCheck'] = '\n\t'.join(ReadFileCheck)
        #SQLInjectCheck: SQL注入检测--检测App是否存在SQL注入的利用条件
        SQLInjectCheck = []
        if 'Landroid/database/sqlite/SQLiteDatabase;' in dxclass:
            for meth in dxclass['Landroid/database/sqlite/SQLiteDatabase;'].get_methods():
                if 'rawQuery' in meth.name or 'execSQL' in meth.name:
                    SQLInjectCheck.append(f'{meth.full_name}')
        if SQLInjectCheck:
            results['SQLInjectCheck'] = '\n\t'.join(SQLInjectCheck)
        #WebViewCheck: WebView明文存储密码检测--检测App程序是否存在WebView明文存储密码风险;
        WebPasswordCheck = []
        if any([int(self.targetSdk_Version) < 18,int(self.minSdk_Version) < 18]):
            if 'Landroid/webkit/WebSettings;' in dxclass:
                for meth in dxclass['Landroid/webkit/WebSettings;'].get_methods():
                    if 'setSavePassword' in meth.name:
                        WebPasswordCheck.append(f'{meth.full_name}')
        if WebPasswordCheck:
            results['WebPasswordCheck'] = '\n\t'.join(WebPasswordCheck)
        #Webview绕过证书校验漏洞--检测App应用的Webview组件是否在发现https网页证书错误后继续加载页面
        WebSSLCheck = []
        if any([int(self.targetSdk_Version) < 18,int(self.minSdk_Version) < 18]):
            if 'Landroid/webkit/SslErrorHandler;' in dxclass:
                for meth in dxclass['Landroid/webkit/SslErrorHandler;'].get_methods():
                    if 'proceed' in meth.name:
                        WebSSLCheck.append(f'{meth.full_name}')
        if WebSSLCheck:
            results['WebSSLCheck'] = '\n\t'.join(WebSSLCheck)
        #WebView远程代码执行检测CVE-2012-6636--检测App应用的Webview组件中是否存在远程代码执行漏洞
        #WebView远程调试检测--检测App程序是否存在Webview远程调试风险
        #webview隐藏接口--组件包含3个隐藏的系统接口,恶意程序可以通过反射机制利用它们实现远程代码执行；
        WebjavaCheck = []
        WebDebugCheck = []
        WebHiddenCheck = []
        if any([int(self.targetSdk_Version) < 18,int(self.minSdk_Version) < 18]):
            if 'Landroid/webkit/WebView;' in dxclass:
                for meth in dxclass['Landroid/webkit/WebView;'].get_methods():
                    if 'setWebContentsDebuggingEnabled' in meth.name:
                        WebjavaCheck.append(f'{meth.full_name}')
                    if 'addJavascriptInterface' in meth.name:
                        WebDebugCheck.append(f'{meth.full_name}')
                    if 'removeJavascriptInterface' in meth.name:
                        WebHiddenCheck.append(f'{meth.full_name}')
        if WebDebugCheck:
            results['WebDebugCheck'] = '\n\t'.join(WebDebugCheck)
        if WebjavaCheck:
            results['WebjavaCheck'] = '\n\t'.join(WebjavaCheck)
        if WebHiddenCheck:
            results['WebHiddenCheck'] = '\n\t'.join(WebHiddenCheck)
        return results
    
    #权限信息分类处理：
    def AndroidManifest_PermissionList(self,et) -> list:
        ns = {'android': 'http://schemas.android.com/apk/res/android'}
        permissionList = {p.get('{http://schemas.android.com/apk/res/android}name') for p in et.xpath('//uses-permission', namespaces=ns)}
        for p in et.xpath('//permission', namespaces=ns):
            permissionList.add(p.get('{http://schemas.android.com/apk/res/android}name'))
        return permissionList
    def get_PermissionList(self,permissionList) -> tuple:
        normal = {
            '访问额外位置 (ACCESS_LOCATION_EXTRA_COMMANDS)': '允许应用软件访问额外的位置提供指令',
            '获取网络连接(ACCESS_NETWORK_STATE)': '允许获取网络连接信息',
            '设置通知(ACCESS_NOTIFICATION_POLICY)': '允许设置通知策略',
            '蓝牙(BLUETOOTH)': '允许应用软件连接配对过的蓝牙设备',
            '管理蓝牙(BLUETOOTH_ADMIN)': '允许应用软件管理蓝牙，搜索和配对新的蓝牙设备',
            '发送持久广播(BROADCAST_STICKY)': '允许应用发送持久广播',
            '更改网络连接状态(CHANGE_NETWORK_STATE)': '允许应用更改网络连接状态，自动切换网络',
            '改变WIFI多播模式 (CHANGE_WIFI_MULTICAST_STATE)': '允许应用进入WIFI多播模式，允许应用使多播地址接收发送到无线 网络上所有设备(而不仅是用户手机)数据包。',
            '更改WIFI连接状态(CHANGE_WIFI_STATE)': '允许应用改变WIFI连接状态',
            '禁用锁屏(DISABLE_KEYGUARD)': '允许应用禁用系统锁屏。允许应用停用键锁以及任何关联的密码安 全措施。例如让手机在接听来电时停用键锁，在通话结束后重新启用键锁。',
            '展开或折叠状态栏(EXPAND_STATUS_BAR)': '允许应用展开和折叠状态栏',
            '前台服务(FOREGROUND_SERVICE)': '允许应用使用前台服务',
            '获取包大小(GET_PACKAGE_SIZE)': '允许应用获取安装包占空间大小',
            '安装桌面快捷方式(INSTALL_SHORTCUT)': '允许应用在桌面安装快捷方式',
            '使用互联网(INTERNET)': '允许应用打开网络接口',
            '后台杀进程(KILL_BACKGROUND_PROCESSES)': '允许应用调用特定方法结束其他应用的后台进程',
            '管理自身通话(MANAGE_OWN_CALLS)': '允许拥有通话功能的应用通过自身连接管理服务接口处理自身的 通话行为',
            '修改音频设置(MODIFY_AUDIO_SETTINGS)': '允许该应用修改移动智能终端音频设置',
            '使用NFC(NFC)': '允许应用使用NFC进行I/O操作，与其他NFC标签、卡和读卡器通信',
            '读取帐户同步设置(READ_SYNC_SETTINGS)': '允许该应用读取某个帐户的同步设置。例如，此权限可确定“联系 人”是否与允许该应用读取某个帐户的同步设置',
            '读取帐户同步统计信息(READ_SYNC_STATS)': '允许该应用读取某个帐户的同步统计信息，包括活动历史记录和数据量',
            '接收启动完成广播(RECEIVE_BOOT_COMPLETED)': '允许应用接收系统启动完成广播',
            '重新排序正在运行的应用(REORDER_TASKS)': '允许应用对正在运行的应用重新排序',
            '请求后台运行(REQUEST_COMPANION_RUN_IN_BACKGROUND)': '允许应用在后台运行',
            '请求后台使用数据(REQUEST_COMPANION_USE_DATA_IN_BACKGROUND )': '允许应用在后台使用数据',
            '请求卸载应用(REQUEST_DELETE_PACKAGES)': '允许应用卸载其他应用',
            '忽略电池优化策略(REQUEST_IGNORE_BATTERY_OPTIMIZATIONS)': '允许应用忽略系统电池优化策略',
            '设置闹钟(SET_ALARM)': '允许应用设置闹钟',
            '设置时区(SET_TIME_ZONE)': '允许应用设置系统时区',
            '设置壁纸(SET_WALLPAPER)': '允许应用设置系统壁纸',
            '设置壁纸提示(SET_WALLPAPER_HINTS)': '允许应用设置有关系统壁纸大小的提示',
            '使用红外线发射器(TRANSMIT_IR)': '允许应用使手机的红外线发射器',
            '删除桌面快捷方式(UNINSTALL_SHORTCUT)': '允许应用删除桌面快捷方式',
            '使用指纹(USE_FINGERPRINT)': '允许应用使手机指纹设备',
            '振动(VIBRATE)': '允许应用使手机振动',
            '唤醒锁(WAKE_LOCK)': '允许应用持有系统唤醒锁，防止进程进入睡眠状态或息屏',
            '修改帐户同步设置(WRITE_SYNC_SETTINGS)': '允许该应用修改某个帐户的同步设置，包括启用和停用同步',
            '读取应用列表(QUERY_ALL_PACKAGES)': '允许应用读取手机上的应用列表，仅适用于target sdk大于等于30以上的Android设备和应用软件'
        }
        dangerous = {
            '读取日历(READ_CALENDAR)': '读取日历内容',
            '写入或删除日历(WRITE_CALENDAR)': '修改日历内容',
            '读取手机识别码(READ_PHONE_STATE)': '允许应用软件读取电话状态',
            '读取联系人(READ_CONTACTS)': '允许应用软件读取联系人通讯录信息',
            '写入或删除联系人(WRITE_CONTACTS)': '允许应用软件写入联系人，但不可读取',
            '访问手机账户列表(GET_ACCOUNTS)': '允许应用软件访问当前手机的账户列表信息',
            '读取传感器(BODY_SENSORS)': '允许应用软件访问用户用来衡量身体内发生的情况的传感器的数据，例如心率',
            '发送短信(SEND_SMS)': '允许应用软件发送短信',
            '接收短信(RECEIVE_SMS)': '允许应用软件接收短信 ',
            '读取短信(READ_SMS)': '允许应用软件读取短信内容 ',
            '接收WAP PUSH(RECEIVE_WAP_PUSH)': '允许应用软件接收WAP PUSH信息 ',
            '接收彩信(RECEIVE_MMS)': '允许应用软件接收彩信 ',
            '读取外部存储空间(READ_EXTERNAL_STORAGE)': '允许应用软件读取扩展存 ',
            '写入外部存储空间(WRITE_EXTERNAL_STORAGE)': '允许应用软件写入外部存储，如SD卡上写文件 ',
            '获取无线状态(ACCESS_WIFI_STATE)': '允许获取无线网络相关信息',
            '读取电话号码(READ_PHONE_NUMBERS)': '允许该应用访问设备上的电话号码',
            '读取小区广播消息(READ_CELL_BROADCASTS)': '允许应用读取您的设备收到的小区广播消息。小区广播消息是在某些地区发送的、用于发布紧急情况警告的提醒信息。恶意应用可能会在您收到小区紧急广播时干扰您设备的性能或操作',
            '从您的媒体收藏中读取位置信息(ACCESS_MEDIA_LOCATION)': '允许该应用从您的媒体收藏中读取位置信息',
            '接听来电(ANSWER_PHONE_CALLS)': '允许该应用接听来电',
            '继续进行来自其他应用的通话(ACCEPT_HANDOVER)': '允许该应用继续进行在其他应用中发起的通话',
            '身体活动(ACTIVITY_RECOGNITION)': '获取您的身体活动数据'
        }
        core = {
            '使用摄像头(CAMERA)': '允许应用软件调用设备的摄像头进行拍摄、录像',
            '访问精确位置(ACCESS_FINE_LOCATION)': '允许应用软件通过GPS获取精确的位置信息 ',
            '访问大致位置(ACCESS_COARSE_LOCATION)': '允许应用软件通过WiFi或移动基站获取粗略的位置信息',
            '在后台使用位置信息(ACCESS_BACKGROUND_LOCATION)': '即使未在前台使用此应用，此应用也可以随时访问位置信息',
            '录音或通话录音(RECORD_AUDIO)': '允许应用获取麦克风输入数据信息 ',
            '使用SIP(USE_SIP)': '允许应用软件使用SIP视频服务 ',
            '拨打电话(CALL_PHONE)': '允许应用软件拨打电话,从非系统拨号器里初始化一个电话拨号',
            '读取通话记录(READ_CALL_LOG)': '允许应用软件读取通话记录',
            '写入通话记录(WRITE_CALL_LOG)': '允许应用软件写入通话记录',
            '使用语音邮件(ADD_VOICEMAIL)': '允许应用软件使用语音邮件',
            '修改外拨电话(PROCESS_OUTGOING_CALLS)': '允许应用软件监视、修改外拨电话'
        }
        sepical = {
            '设备管理器(BIND_DEVICE_ADMIN)': '激活使用设备管理器',
            '辅助模式(BIND_ACCESSIBILITY_SERVICE)': '使用无障碍功能',
            '读写系统设置(WRITE_SETTINGS)': '允许应用读取或写入系统设置',
            '读取应用通知(BIND_NOTIFICATION_LISTENER_SERVICE)': '允许应用读取应用的通知内容',
            '悬浮窗(SYSTEM_ALERT_WINDOW)': '允许应用显示在其他应用之上，或后台弹出界面 ',
            '读取应用使用情况(PACKAGE_USAGE_STATS)': '允许应用读取本机的应用使用情况 ',
            '请求安装应用(REQUEST_INSTALL_PACKAGES)': '允许应用安装其他应用 ',
            '访问所有文件(MANAGE_EXTERNAL_STORAGE)': '允许应用访问分区存储模式下SD卡上的所有文件',
            '应用软件列表(GET_INSTALLED_APPS)': '允许应用读取手机上的应用软件列表'
        }
        normalArray = []
        dangerousArray = []
        coreArray = []
        specialArray = []
        newPermissionList = permissionList.copy()
        for p in permissionList:
            for key in normal:
                names = key.split('(')
                if names[-1].strip().replace(')', '') in p.split('.')[-1]:
                    normalArray.append((p, names[0], normal[key]))
                    newPermissionList.remove(p)
                    break
            for key in dangerous:
                names = key.split('(')
                if names[-1].strip().replace(')', '') in p.split('.')[-1]:
                    dangerousArray.append((p, names[0], dangerous[key]))
                    newPermissionList.remove(p)
                    break
            for key in core:
                names = key.split('(')
                if names[-1].strip().replace(')', '') in p.split('.')[-1]:
                    coreArray.append((p, names[0], core[key]))
                    newPermissionList.remove(p)
                    break
            for key in sepical:
                names = key.split('(')
                if names[-1].strip().replace(')', '') in p.split('.')[-1]:
                    specialArray.append((p, names[0], sepical[key]))
                    newPermissionList.remove(p)
                    break
        return normalArray, dangerousArray, coreArray, specialArray, newPermissionList
    
    #证书处理：
    #1. get_certificate_V1
    #2. get_certificate_V2
    #3. get_certificate_V3
    #4. get_certificate_infos 获取当前证书信息
    @property
    def get_certificate_V1(self) -> str:
        '''
        处理V1证书方法
        '''
        results = ''
        certificates = self.apk_ob.get_certificates_v1()
        for i in certificates:
            results += "有效签名版本：V1\nSHA1 Fingerprint: {}\nSHA256 Fingerprint: {}\nIssuer: {}\nSubject: {}\n\n".format(\
                i.sha1_fingerprint,i.sha256_fingerprint,get_certificate_name_string(i.issuer.native, short=False)\
                ,get_certificate_name_string(i.subject.native, short=False))
        return results
    @property
    def get_certificate_V2(self) -> str:
        '''
        处理V2证书方法
        '''
        results = ''
        der_certs = self.apk_ob.get_certificates_der_v2()
        for der_cert in der_certs:
            cert = x509.load_der_x509_certificate(der_cert, default_backend())
            results += "有效签名版本：V2\n颁发者: {}\n主题: {}\n有效期开始时间: {}\n有效期结束时间: {}\n序列号: {}\n版本: {}\n".format(\
                cert.issuer.rfc4514_string(),cert.subject.rfc4514_string(),cert.not_valid_before_utc,cert.not_valid_after_utc,\
                cert.serial_number,cert.version)
            public_key = cert.public_key()
            if isinstance(public_key, rsa.RSAPublicKey):
                results +="公钥类型: RSA\n公钥大小（位）:{}\n\n".format(public_key.key_size)
            elif isinstance(public_key, ec.EllipticCurvePublicKey):
                results +="公钥类型: ECC\n公钥曲线:{}\n\n".format(public_key.curve.name)
        return results
    @property
    def get_certificate_V3(self) -> str:
        '''
        处理V3证书方法
        '''
        results = "有效签名版本：V3\n\n"
        return results

    @property
    def get_certificate_infos(self) -> str:
        '''
        格式化明文证书信息
        '''
        certificate_result = ''
        if self.apk_ob.is_signed():
            if self.apk_ob.is_signed_v1():
                self.is_janus = True
                certificate_result += self.get_certificate_V1
            if self.apk_ob.is_signed_v2():
                certificate_result += self.get_certificate_V2
            if self.apk_ob.is_signed_v3():
                certificate_result += self.get_certificate_V3
        else:
            certificate_result = "apk未签名！"
        return certificate_result

    def decompile_apk(self,OutSourcePath,jadxpath) -> None:
        """
        描述：USE JADX Decompile APK
        参数：
        OutSourcePath -反编译后文件存放位置-字符串
        jadxpath -jadx位置-字符串
        """
        try:
            print("*************开始反编译**************")
            jadxpath = pathTool.replace_path(jadxpath)
            OutSourcePath = pathTool.replace_path(OutSourcePath)
            if pathTool.check_paths(jadxpath,self.APKPath):
                if pathTool.check_paths(OutSourcePath):
                    pass
                else:
                    os.mkdir(OutSourcePath)
                command = jadxpath+"/jadx "+self.APKPath+" -d "+OutSourcePath
                print('执行：'+command)
                subprocess.run(command,check=True,shell=True)
                print("*************反编译结束**************")
            elif not os.path.exists(self.APKPath):
                print('*************反编译失败：APK路径不存在**************')
                sys.exit()
            elif not os.path.exists(jadxpath):
                print('*************反编译失败：jadx路径不存在**************')
                sys.exit()
        except subprocess.CalledProcessError as e:
            # 处理 CalledProcessError 异常
            print("Error executing command:", e)
        except FileNotFoundError:
            # 处理 FileNotFoundError 异常
            print("Executable file not found.")
        except PermissionError:
            # 处理 PermissionError 异常
            print("Permission denied to execute the command.")
        except OSError as e:
            # 处理 OSError 异常
            print("OS error:", e)

    def add_check(self, check) -> None:
        '''
        添加漏洞扫描对象
        '''
        if isinstance(check, checkBase.checkBase):
            self.vulnerability_checks.append(check)
        else:
            raise TypeError("Check must be an instance of VulnerabilityCheck")

    def run_checks(self) -> None:
        '''
        执行漏洞扫描
        '''
        for check in self.vulnerability_checks:
            check.scan()