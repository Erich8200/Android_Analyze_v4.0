import hashlib
import os
import re
import DBManager
import time
from zipfile import *
import subprocess

from androguard.core.bytecodes import apk, dvm # 导入androguard的模块需要将工程解释器配置成系统解释器
from androguard.core.analysis import analysis # 才能用pip安装的库
from androguard.misc import AnalyzeAPK


# AAPT absolute path
aapt_path = r'C:\Users\JYQ\AppData\Local\Android\Sdk\build-tools\30.0.2\aapt.exe' # 要用绝对路径 + shell=True


class APKAnalysis:

    # Basic attributes
    __filename = ""
    __path = ""
    __md5 = ""
    __size = 0
    __packer = []
    __useNative = -1
    __classCount = 0
    __methodCount = 0
    __useMultidex = -1
    __minSDK = 0
    __tgtSDK = 0
    __maxSDK = 0
    __signedV1 = -1
    __signedV2 = -1
    __signedV3 = -1
    __pkgName = ""
    __appName = ""
    __mainActivity = ""
    __ActivityCount = -1
    __ReceiverCount = -1
    __ServiceCount = -1
    __ProviderCount = -1
    __build_time = ""

    # Androguard analysis objects
    __gotAgObjs = False
    __a = None
    __d = None
    __x = None

    # Permission attributes
    permissionCount = 0
    READ_PHONE_STATE = False
    READ_EXTERNAL_STORAGE = False
    SYSTEM_ALERT_WINDOW = False
    GET_TASKS = False
    WRITE_SETTINGS = False
    BIND_DEVICE_ADMIN = False
    INTERNET = False
    BLUETOOTH = False
    CAMERA = False
    READ_CONTACTS = False
    READ_LOGS = False
    ACCESS_FINE_LOCATION = False
    READ_FRAME_BUFFER = False
    BRICK = False
    INSTALL_PACKAGES = False
    MOUNT_FORMAT_FILESYSTEMS = False
    RECEIVE_BOOT_COMPLETED = False
    WRITE_EXTERNAL_STORAGE = False
    CALL_PHONE = False
    READ_CALL_LOG = False
    WRITE_CALL_LOG = False
    ADD_VOICEMAIL = False
    USE_SIP = False
    PROCESS_OUTGOING_CALLS = False
    SEND_SMS = False
    RECEIVE_SMS = False
    READ_SMS = False
    RECEIVE_WAP_PUSH = False
    RECEIVE_MMS = False
    ACCESS_COARSE_LOCATION = False
    RECORD_AUDIO = False
    WRITE_CONTACTS = False
    GET_ACCOUNTS = False
    READ_CALENDAR = False
    WRITE_CALENDAR = False

    def __init__(self, path = ""):
        if path != "" and os.path.exists(path):
            self.__packer = []
            self.__path = path
            self.calc_androguard_objs()

    def calc_androguard_objs(self):
        if self.__checkPath():
            if not self.__gotAgObjs:
                try:
                    # self.__a = apk.APK(self.__path)
                    # self.__d = dvm.DalvikVMFormat(self.__a)
                    # self.__x = analysis.Analysis(self.__d)
                    self.__a, self.__d, self.__x = AnalyzeAPK(self.__path) # 用官方api，直接解决了multidex的情况
                    self.__gotAgObjs = True
                except:
                    print("Get Androguard objects failed")

    def __check360Packer(self):
        if self.__a is not None:
            fileList = self.__a.get_files()
            for file in fileList:
                file = os.path.basename(file)
                if "libprotectClass.so" == file or "libjiagu.so" == file or "libjiagu_a64.so" == file or "libjiagu_art.so" == file or "libjiagu_x86.so" == file or "libjiagu_x64.so" == file:
                    fileList_ = self.__a.get_files()
                    for file_ in fileList_:
                        if ".appkey" in file_:
                            for d in self.__d:
                                for c in d.get_classes():
                                    if "QVMProtect;" in str(c):
                                        self.__packer.append("Qihoo360[DEXVMP_Customized]")
                                        return
                            self.__packer.append("Qihoo360")
                            return
                    for d in self.__d:
                        for c in d.get_classes():
                            if "QVMProtect;" in str(c):
                                self.__packer.append("Qihoo360[DEXVMP_Customized no_appkey]")
                                return
                    self.__packer.append("Qihoo360[no_appkey]")
                    return

    def __check360Java2CPacker(self):
        if self.__a is not None:
            # fileList = self.__a.get_files()
            # for file in fileList:
            #     file = os.path.basename(file)
            #     if "libjgdtc.so" == file or "libjgdtc_a64.so" == file or "libjgdtc_x86.so" == file or "libjgdtc_x64.so" == file:
            #
            for d in self.__d:
                for c in d.get_classes():
                    if "QDTCProtect" in str(c) or "com/qihoo/util/DtcLoader" in str(c) or "qdtc" in str(c).lower():
                        self.__packer.append("Qihoo360[Dex2C]")
                        return
    
    def __checkIjiamiPacker(self):
        if self.__a is not None:
            fileList = self.__a.get_files()
            for file in fileList:
                file = os.path.basename(file)
                if "libsecmain.so" == file or "libSecShell.so" == file or "libSecShell-x86.so" == file or "libexec.so" == file or "ijiami.dat" == file:
                    fileList_ = self.__a.get_files()
                    for file_ in fileList_:
                        if "ijiami.ajm" in file_:
                            self.__packer.append("Ijiami_pro")
                            return
                    self.__packer.append("Ijiami")
                    return

    def __checkBangclePacker(self):
        if self.__a is not None:
            fileList = self.__a.get_files()
            for file in fileList:
                file = os.path.basename(file)
                if "libsecexe.so" == file or "libsecmain.so" == file or "libSecShell.so" == file or "libSecShell-x86.so" == file:
                    self.__packer.append("Bangcle")
                    break
            for file in fileList:
                file = os.path.basename(file)
                if "libDexHelper.so" == file or "libDexHelper-x86.so" == file or "DexHelper.so" == file:
                    fileList_ = self.__a.get_files()
                    for file_ in fileList_:
                        if "dexjni.so" in file_:
                            self.__packer.append("Bangcle_pro[VMP]")
                            return
                    self.__packer.append("Bangcle_pro")
                    return

    def __checkAliPacker(self):
        if self.__a is not None:
            fileList = self.__a.get_files()
            for file in fileList:
                file = os.path.basename(file)
                if "aliprotect.dat" == file or "libsgmain.so" == file or "libsgsecuritybody.so" == file or "libmobisec.so" == file or "libfakejni.so" == file \
                or "libzuma.so" == file or "libzumadata.so" == file or "libpreverify1.so" == file:
                    fileList_ = self.__a.get_files()
                    for file_ in fileList_:
                        if "libsgavmp.so" in file_:
                            self.__packer.append("Ali[ARM_VMP]")
                            return
                    self.__packer.append("Ali")
                    return

    def __checkTencentPacker(self):
        if self.__a is not None:
            fileList = self.__a.get_files()
            for file in fileList:
                file = os.path.basename(file)
                if "libtup.so" == file or "libshell.so" == file or "mix.dex" == file or "mixz.dex" == file or "libshella" in file or "libshellx" in file:
                    self.__packer.append("Tencent")
                    break
            for file in fileList:
                file = os.path.basename(file)
                if "libtosprotection.armeabi-v7a.so" == file or "libtosprotection.armeabi.so" == file or "libtosprotection.x86.so" == file:
                    self.__packer.append("Tencent_Yu") # 腾讯御安全
                    break

    def __checkBaiduPacker(self):
        if self.__a is not None:
            fileList = self.__a.get_files()
            for file in fileList:
                file = os.path.basename(file)
                if "libbaiduprotect.so" == file or "baiduprotect1.jar" == file or "baiduprotect.jar" == file:
                    self.__packer.append("Baidu")
                    return

    def __checkNagaPacker(self):
        if self.__a is not None:
            fileList = self.__a.get_files()
            for file in fileList:
                file = os.path.basename(file)
                if "libchaosvmp.so" == file or "libddog.so" == file or "libfdog.so" == file or "libedog.so" == file or "main.data" in file \
                or "libvdog" in file or "libvdog-x86" in file or "libvdog64" in file:
                    fileList_ = self.__a.get_files()
                    for file_ in fileList_:
                        file_ = os.path.basename(file_)
                        if "libvdog" in file_ or "libvdog-x86" in file_ or "libvdog64" in file_:
                            self.__packer.append("Naga[susp_VMP]")
                            return
                    self.__packer.append("Naga")
                    return

    def __checkKiwiPacker(self):
        if self.__a is not None:
            fileList = self.__a.get_files()
            for file in fileList:
                so_name = os.path.basename(file)
                if "libkwscmm.so" == so_name or "libkwscr.so" == so_name or "libkwslinker.so" == so_name or "kdpdata.so" == so_name or "dex.dat" == so_name or "libkdp.so" == so_name \
                or "libbug.so" == so_name or "libnllvm.so" == so_name or "libxloader.so" == so_name:
                    if "libnllvm.so" == so_name or "libxloader.so" == so_name:
                        self.__packer.append("Kiwi[Java2C]")
                    else:
                        self.__packer.append("Kiwi")
                    return

    def __checkPayEgis(self): # 通付盾
        if self.__a is not None:
            fileList = self.__a.get_files()
            for file in fileList:
                file = os.path.basename(file)
                if "libegis.so" == file or "libNSaferOnly.so" == file:
                    self.__packer.append("Pay Egis")
                    return

    def __checkNetQin(self): # 网秦
        if self.__a is not None:
            fileList = self.__a.get_files()
            for file in fileList:
                file = os.path.basename(file)
                if "libnqshield.so" == file:
                    self.__packer.append("Netqin")
                    return

    def __checkCMCC(self): # 中国移动安全加固
        if self.__a is not None:
            fileList = self.__a.get_files()
            for file in fileList:
                file = os.path.basename(file)
                if "libmogosec_dex.so" == file or "libmogosec_sodecrypt.so" == file or "libmogosecurity.so" == file:
                    fileList_ = self.__a.get_files()
                    for file_ in fileList_:
                        if "libcmvmp.so" in file_:
                            self.__packer.append("CMCC[susp_VMP]")
                            return
                    self.__packer.append("CMCC")
                    return

    def __checkEdunPacker(self): # 网易易盾
        if self.__a is not None:
            fileList = self.__a.get_files()
            for file in fileList:
                file = os.path.basename(file)
                if "libnesec.so" == file:
                    self.__packer.append("Edun")
                    return

    def __checkAPKProtectPacker(self):
        if self.__a is not None:
            fileList = self.__a.get_files()
            for file in fileList:
                file = os.path.basename(file)
                if "libAPKProtect.so" == file:
                    self.__packer.append("APKProtect")
                    return

    def __checkDingxiangPacker(self):
        if self.__a is not None:
            fileList = self.__a.get_files()
            for file in fileList:
                file = os.path.basename(file)
                if "libx3g.so" == file or "libcsn.so" == file or "libdx-ind.so" == file or "libdx-ld.so" == file or "libcsn2.so" == file or "libcsn2_x86.so" == file or "libcsn_x86.so" == file:
                    self.__packer.append("Dingxiang")
                    return

    def __checkPackerProtection(self):
        if self.__a is not None:

            self.__check360Packer()
            self.__check360Java2CPacker()
            self.__checkIjiamiPacker()
            self.__checkBangclePacker()
            self.__checkAliPacker()
            self.__checkTencentPacker()
            self.__checkBaiduPacker()
            self.__checkNagaPacker()
            self.__checkKiwiPacker()
            self.__checkPayEgis()
            self.__checkCMCC()
            self.__checkNetQin()
            self.__checkAPKProtectPacker()
            self.__checkDingxiangPacker()
            self.__checkEdunPacker()
            if self.__packer == []: # No matching packer
                self.__packer = ["no known protection detected"]

            return self.__packer

    def calcPermissions(self):
        if self.__a is not None:
            permissions = self.__a.get_permissions()
            self.permissionCount = len(permissions)
            self.READ_PHONE_STATE = 'android.permission.READ_PHONE_STATE' in permissions
            self.READ_EXTERNAL_STORAGE = 'android.permission.READ_EXTERNAL_STORAGE' in permissions
            self.SYSTEM_ALERT_WINDOW = 'android.permission.SYSTEM_ALERT_WINDOW' in permissions
            self.GET_TASKS = 'android.permission.GET_TASKS' in permissions
            self.WRITE_SETTINGS = 'android.permission.WRITE_SETTINGS' in permissions
            self.BIND_DEVICE_ADMIN = 'android.permission.BIND_DEVICE_ADMIN' in permissions
            self.INTERNET = 'android.permission.INTERNET' in permissions
            self.BLUETOOTH = 'android.permission.BLUETOOTH' in permissions
            self.CAMERA = 'android.permission.CAMERA' in permissions
            self.READ_LOGS = 'android.permission.READ_LOGS' in permissions
            self.ACCESS_FINE_LOCATION = 'android.permission.ACCESS_FINE_LOCATION' in permissions
            self.READ_FRAME_BUFFER = 'android.permission.READ_FRAME_BUFFER' in permissions
            self.BRICK = 'android.permission.BRICK' in permissions
            self.INSTALL_PACKAGES = 'android.permission.INSTALL_PACKAGES' in permissions
            self.MOUNT_FORMAT_FILESYSTEMS = 'android.permission.MOUNT_FORMAT_FILESYSTEMS' in permissions
            self.RECEIVE_BOOT_COMPLETED = 'android.permission.RECEIVE_BOOT_COMPLETED' in permissions
            self.WRITE_EXTERNAL_STORAGE = 'android.permission.WRITE_EXTERNAL_STORAGE' in permissions
            self.CALL_PHONE = 'android.permission.CALL_PHONE' in permissions
            self.READ_CALL_LOG = 'android.permission.READ_CALL_LOG' in permissions
            self.WRITE_CALL_LOG = 'android.permission.WRITE_CALL_LOG' in permissions
            self.ADD_VOICEMAIL = 'android.permission.ADD_VOICEMAIL' in permissions
            self.USE_SIP = 'android.permission.USE_SIP' in permissions
            self.PROCESS_OUTGOING_CALLS = 'android.permission.PROCESS_OUTGOING_CALLS' in permissions
            self.SEND_SMS = 'android.permission.SEND_SMS' in permissions
            self.RECEIVE_SMS = 'android.permission.RECEIVE_SMS' in permissions
            self.READ_SMS = 'android.permission.READ_SMS' in permissions
            self.RECEIVE_WAP_PUSH = 'android.permission.RECEIVE_WAP_PUSH' in permissions
            self.RECEIVE_MMS = 'android.permission.RECEIVE_MMS' in permissions
            self.ACCESS_COARSE_LOCATION = 'android.permission.ACCESS_COARSE_LOCATION' in permissions
            self.RECORD_AUDIO = 'android.permission.RECORD_AUDIO' in permissions
            self.READ_CONTACTS = 'android.permission.READ_CONTACTS' in permissions
            self.WRITE_CONTACTS = 'android.permission.WRITE_CONTACTS' in permissions
            self.GET_ACCOUNTS = 'android.permission.GET_ACCOUNTS' in permissions
            self.READ_CALENDAR = 'android.permission.READ_CALENDAR' in permissions
            self.WRITE_CALENDAR = 'android.permission.WRITE_CALENDAR' in permissions

    def setPath(self, path):
        self.__path = path

    def getPath(self):
        return self.__path

    def getMD5(self):
        if self.__md5 == "":
            self.calcMd5()
        return self.__md5

    def getSize(self):
        if self.__size == 0:
            self.calcFileSize()
        return self.__size

    def getApkObj(self):
        return self.__a

    def getVmObj(self):
        return self.__d

    def getAnaObj(self):
        return self.__x

    def getPackerProtection(self):
        if self.__packer == []:
            self.__checkPackerProtection()
        return self.__packer

    def calcFileSize(self): #计算文件大小，以B为单位
        if self.__checkPath():
            fsize = os.path.getsize(self.__path)
            self.__size = fsize
            return fsize

    def __checkPath(self):
        return self.__path != ""

    def calcMd5(self): # 计算文件MD5校验值
        if self.__checkPath():
            if self.calcFileSize()/float(1024)/float(1024) <= 100: # 小于100MB的文件，直接计算
                with open(self.__path, 'rb') as f:
                    data = f.read()
                    d5 = hashlib.md5(data)
                    self.__md5 = d5.hexdigest()
                    return  d5.hexdigest()
            else:                            # 大文件计算
                d5 = hashlib.md5()
                with open(self.__path, 'rb') as f:
                    while True:
                        data = f.read(2048)
                        if not data:
                            break
                        d5.update(data)  # update添加时会进行计算
                    self.__md5 = d5.hexdigest()
                    return d5.hexdigest()

    def getFileName(self):
        if self.__filename == "":
            if self.__path != "":
                self.__filename = os.path.basename(self.__path)
            else:
                return ""
        return self.__filename

    def getUseNative(self):
        if self.__useNative == -1:
            dexes = self.getVmObj()
            for dex in dexes:
                for method in dex.get_methods():
                    m_str = str(method)
                    reg = re.compile("access_flags=.*native")
                    res = reg.findall(m_str)
                    if len(res) > 0:
                        self.__useNative = True
                        return True
            self.__useNative = False
        return self.__useNative

    def getClassCount(self):
        if self.__d is not None:
            for d in self.__d:
                self.__classCount += len(d.get_classes())
        return self.__classCount

    def getMethodCount(self):
        if self.__methodCount <= 0:
            for dex in self.__d:
                self.__methodCount += len(dex.get_methods())
        return self.__methodCount

    def getUseMultidex(self):
        if self.__useMultidex < 0:
            self.__useMultidex = self.__a.is_multidex()
        return self.__useMultidex

    def getMinSDK(self):
        if self.__minSDK <= 0:
            self.__minSDK = self.__a.get_min_sdk_version()
        return self.__minSDK

    def getTgtSDK(self):
        if self.__tgtSDK <= 0:
            self.__tgtSDK = self.__a.get_target_sdk_version()
        return  self.__tgtSDK

    def getMaxSDK(self):
        if self.__maxSDK <= 0:
            self.__maxSDK = self.__a.get_max_sdk_version()
        return self.__maxSDK

    def getSignedV1(self):
        if self.__signedV1 == -1:
            self.__signedV1 = self.__a.is_signed_v1()
        return self.__signedV1

    def getSignedV2(self):
        if self.__signedV2 == -1:
            self.__signedV2 = self.__a.is_signed_v2()
        return self.__signedV2

    def getSignedV3(self):
        if self.__signedV3 == -1:
            self.__signedV3 = self.__a.is_signed_v3()
        return self.__signedV3

    def getPkgName(self):
        if self.__pkgName == "":
            cmd_line = aapt_path + " dump badging %s" % self.__path
            p = subprocess.Popen(cmd_line, stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.PIPE, shell=True) # 要用绝对路径 + shell=True
            (output, err) = p.communicate()
            t = output.decode().split("\n")
            for item in t:
                # 此处的apk包名我是取得中文名称。具体信息可以在dos下用aapt查看详细信息后，修改正则获取自己想要的name
                match = re.compile("package: name='([\u4e00-\u9fa5_a-zA-Z0-9-\S]+)'").search(item)
                if match is not None:
                    self.__pkgName = match.group(1)
        return self.__pkgName

    def read_node_details(self, node) -> dict:
        result = {
            'name': node.get("{http://schemas.android.com/apk/res/android}name"),
            'action': [],
            'category': []
        }
        if result["name"] is None:
            # raise ValueError("Component Name Error!")
            # print("Component Name Error!")
            pass
        try:
            intent_filter = node.iterchildren("intent-filter").__next__()
        except:
            intent_filter = None

        if intent_filter is not None:
            for action_node in intent_filter.iterchildren("action"):
                name = action_node.get("{http://schemas.android.com/apk/res/android}name")
                if name is not None:
                    result['action'].append(name)
            for category_node in intent_filter.iterchildren("category"):
                name = category_node.get("{http://schemas.android.com/apk/res/android}name")
                if name is not None:
                    result['category'].append(name)
        return result

    # Patched get_activities
    def get_activities(self):
        ret = []
        xmlContent = self.__a.get_android_manifest_xml()
        if xmlContent is None:
            return ret
        applicationNode = xmlContent.iterchildren("application").__next__()
        if applicationNode is None:
            return ret
        for activityNode in applicationNode.iterchildren("activity"):
            ret.append(self.read_node_details(activityNode))
        for activityAliasNode in applicationNode.iterchildren("activity-alias"):
            ret.append(self.read_node_details(activityAliasNode))
        return ret

    def getMainActivity(self):
        if self.__mainActivity == "":
            cmd_line = aapt_path + " dump badging %s" % self.__path
            p = subprocess.Popen(cmd_line, stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.PIPE, shell=True)
            (output, err) = p.communicate()
            t = output.decode().split("\n")
            for item in t:
                match = re.compile("launchable-activity: name='([\u4e00-\u9fa5_a-zA-Z0-9-\S]+)'").search(item)
                if match is not None:
                    self.__mainActivity = match.group(1)
        return self.__mainActivity

    def getActivityCount(self):
        if self.__ActivityCount == -1:
            self.__ActivityCount = len(self.get_activities())
        return self.__ActivityCount

    def getReceiverCount(self):
        if self.__ReceiverCount == -1:
            self.__ReceiverCount = len(self.__a.get_receivers())
        return self.__ReceiverCount

    def getServiceCount(self):
        if self.__ServiceCount == -1:
            self.__ServiceCount = len(self.__a.get_services())
        return self.__ServiceCount

    def getProviderCount(self):
        if self.__ProviderCount == -1:
            self.__ProviderCount = len(self.__a.get_providers())
        return self.__ProviderCount

    def getClassList(self): # 输出格式： Lxxxxxx;->Lyyyyy;
        classList = []
        classListOnly = []
        ds = self.__d
        for d in ds:
            for c in d.get_classes():
                classList.append(str(c))
        for c in classList:
            reg = re.compile("[^;>-]+")
            res = reg.findall(str(c))
            if res[0] != "" and res[1] != "":
                classListOnly.append(res[1])
        return classListOnly

    def getAppName(self):
        if self.__appName == "":
            self.__appName = self.__a.get_app_name()
        return self.__appName

    def getBuildTime(self):
        if self.__path != "" and self.__build_time == "":
            zip_info = ZipInfo.from_file(self.__path)
            self.__build_time = str(zip_info.date_time[0]) + "-" + str(zip_info.date_time[1]) + "-" + str(zip_info.date_time[2])
        return self.__build_time


def basic_info_to_DB(conn, ana): # 参数：sqlite3.connect, APKAnalyze
    ana.calcPermissions() # 获取应用权限信息

    sql = "INSERT INTO APK_basic_info (filename, md5, size, shellProtection, native," \
          "classCount, methodCount, multidex, minSDK, tgtSDK, maxSDK, signedV1," \
          "signedV2, signedV3, packageName, mainActivity, ActivityCount, ReceiverCount," \
          "ServiceCount, ProviderCount, appName," \
          "READ_PHONE_STATE, READ_EXTERNAL_STORAGE, SYSTEM_ALERT_WINDOW, GET_TASKS, WRITE_SETTINGS, BIND_DEVICE_ADMIN, INTERNET, BLUETOOTH," \
          "CAMERA, READ_CONTACTS, READ_LOGS, ACCESS_FINE_LOCATION, READ_FRAME_BUFFER, BRICK, INSTALL_PACKAGES, MOUNT_FORMAT_FILESYSTEMS," \
          "RECEIVE_BOOT_COMPLETED, WRITE_EXTERNAL_STORAGE, CALL_PHONE, READ_CALL_LOG, WRITE_CALL_LOG, ADD_VOICEMAIL, USE_SIP," \
          "PROCESS_OUTGOING_CALLS, SEND_SMS, RECEIVE_SMS, READ_SMS, RECEIVE_WAP_PUSH, RECEIVE_MMS, ACCESS_COARSE_LOCATION, RECORD_AUDIO," \
          "WRITE_CONTACTS, GET_ACCOUNTS, READ_CALENDAR, WRITE_CALENDAR, permissionCount, buildTime, recordTime)" \
          "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)"

    record_time = time.strftime("%Y-%m-%d", time.localtime())

    values = (ana.getFileName(), ana.getMD5(), ana.getSize(), ' '.join(s for s in ana.getPackerProtection()), ana.getUseNative(),
              ana.getClassCount(), ana.getMethodCount(), ana.getUseMultidex(), ana.getMinSDK(), ana.getTgtSDK(), ana.getMaxSDK(),
              ana.getSignedV1(), ana.getSignedV2(), ana.getSignedV3(), ana.getPkgName(), ana.getMainActivity(), ana.getActivityCount(),
              ana.getReceiverCount(), ana.getServiceCount(), ana.getProviderCount(), ana.getAppName(),

              ana.READ_PHONE_STATE, ana.READ_EXTERNAL_STORAGE, ana.SYSTEM_ALERT_WINDOW, ana.GET_TASKS, ana.WRITE_SETTINGS, ana.BIND_DEVICE_ADMIN, ana.INTERNET, ana.BLUETOOTH,
              ana.CAMERA, ana.READ_CONTACTS, ana.READ_LOGS, ana.ACCESS_FINE_LOCATION, ana.READ_FRAME_BUFFER, ana.BRICK, ana.INSTALL_PACKAGES, ana.MOUNT_FORMAT_FILESYSTEMS,
              ana.RECEIVE_BOOT_COMPLETED, ana.WRITE_EXTERNAL_STORAGE, ana.CALL_PHONE, ana.READ_CALL_LOG, ana.WRITE_CALL_LOG, ana.ADD_VOICEMAIL, ana.USE_SIP,
              ana.PROCESS_OUTGOING_CALLS, ana.SEND_SMS, ana.RECEIVE_SMS, ana.READ_SMS, ana.RECEIVE_WAP_PUSH, ana.RECEIVE_MMS, ana.ACCESS_COARSE_LOCATION, ana.RECORD_AUDIO,
              ana.WRITE_CONTACTS, ana.GET_ACCOUNTS, ana.READ_CALENDAR, ana.WRITE_CALENDAR, ana.permissionCount, ana.getBuildTime(), record_time)

    # t0 = time.clock()
    DBManager.sqlInserter(conn, sql, values) # 应用基本信息写入数据库
    # t1 = time.clock() - t0
    # print("应用基本信息写入数据库用时：" + str(t1) + "秒")

    

def activities_to_DB(conn, ana): # Activity名列表写入数据库
    activities = ana.get_activities()
    # t0 = time.clock()
    for activity in activities:
        DBManager.sqlInserter(conn, sql = "INSERT INTO Activities (filename, md5, Activity) VALUES (?,?,?)", values = (ana.getFileName(), ana.getMD5(), activity))
    # t1 = time.clock() - t0
    # print("Activity名列表写入数据库用时：" + str(t1) + "秒")

def receivers_to_DB(conn, ana): # Receiver名列表写入数据库
    receivers = ana.getApkObj().get_receivers()
    # t0 = time.clock()
    for receiver in receivers:
        DBManager.sqlInserter(conn, sql = "INSERT INTO Receivers (filename, md5, Receiver) VALUES (?,?,?)", values = (ana.getFileName(), ana.getMD5(), receiver))
    # t1 = time.clock() - t0
    # print("Receiver名列表写入数据库用时：" + str(t1) + "秒")

def services_to_DB(conn, ana): # Service名列表写入数据库
    services = ana.getApkObj().get_services()
    # t0 = time.clock()
    for service in services:
        DBManager.sqlInserter(conn, sql = "INSERT INTO Services (filename, md5, service) VALUES (?,?,?)", values = (ana.getFileName(), ana.getMD5(), service))
    # t1 = time.clock() - t0
    # print("Service名列表写入数据库用时：" + str(t1) + "秒")

def providers_to_DB(conn, ana): # Provider名列表写入数据库
    providers = ana.getApkObj().get_providers()
    # t0 = time.clock()
    for provider in providers:
        DBManager.sqlInserter(conn, sql = "INSERT INTO Providers (filename, md5, provider) VALUES (?,?,?)", values = (ana.getFileName(), ana.getMD5(), provider))
    # t1 = time.clock() - t0
    # print("Provider名列表写入数据库用时：" + str(t1) + "秒")

def classes_to_DB(conn, ana): # 类名列表写入数据库
    classes = ana.getClassList()
    # count = 0
    # t0 = time.clock()
    if classes is not None:
        for c in classes:
            reg = re.compile("[^;>-]+")
            res = reg.findall(str(c))
            if res[0] != "" and res[1] != "":
                # count += 1
                DBManager.sqlInserter(conn, sql = "INSERT INTO class_list (filename, md5, className, baseClassName) VALUES (?,?,?,?)", values = (ana.getFileName(), ana.getMD5(), res[1], res[0]))
    # t1 = time.clock() - t0
    # print("类名列表写入数据库用时：" + str(t1) + "秒")
    # print("类名列表写入数据库方法中的类数量为： " + str(count))