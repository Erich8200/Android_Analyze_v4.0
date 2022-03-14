import zipfile
import os
import shutil
import re


# Check packer only according to file features
class PackerCheckerFast:

    __fileList = []
    __packer = []

    def __init__(self, path=''):
        zipfiles = zipfile.ZipFile(path)
        self.__fileList = zipfiles.namelist()
        self.__packer = []
        zipfiles.close()

    def __check360Packer(self):
        for file in self.__fileList:
            file = os.path.basename(file)
            if "libprotectClass.so" == file or "libjiagu.so" == file or "libjiagu_a64.so" == file or "libjiagu_art.so" == file or "libjiagu_x86.so" == file or "libjiagu_x64.so" == file:
                self.__packer.append("Qihoo360")
                return

    def __check360Java2CPacker(self):
        for file in self.__fileList:
            file = os.path.basename(file)
            if "libjgdtc.so" == file or "libjgdtc_a64.so" == file or "libjgdtc_x86.so" == file or "libjgdtc_x64.so" == file:
                self.__packer.append("Qihoo360[Java2C]")
                return

    def __checkIjiamiPacker(self):
        for file in self.__fileList:
            file = os.path.basename(file)
            if "libsecmain.so" == file or "libSecShell.so" == file or "libSecShell-x86.so" == file or "libexec.so" == file or "ijiami.dat" == file:
                for file_ in self.__fileList:
                    if "ijiami.ajm" in file_:
                        self.__packer.append("Ijiami_pro")
                        return
                self.__packer.append("Ijiami")
                return

    def __checkBangclePacker(self):
        for file in self.__fileList:
            file = os.path.basename(file)
            if "libsecexe.so" == file or "libsecmain.so" == file or "libSecShell.so" == file or "libSecShell-x86.so" == file:
                self.__packer.append("Bangcle")
                break
        for file in self.__fileList:
            file = os.path.basename(file)
            if "libDexHelper.so" == file or "libDexHelper-x86.so" == file or "DexHelper.so" == file:
                for file_ in self.__fileList:
                    if "dexjni.so" in file_:
                        self.__packer.append("Bangcle_pro[VMP]")
                        return
                self.__packer.append("Bangcle_pro")
                return

    def __checkAliPacker(self):
        for file in self.__fileList:
            file = os.path.basename(file)
            if "aliprotect.dat" == file or "libsgmain.so" == file or "libsgsecuritybody.so" == file or "libmobisec.so" == file or "libfakejni.so" == file \
                    or "libzuma.so" == file or "libzumadata.so" == file or "libpreverify1.so" == file:
                for file_ in self.__fileList:
                    if "libsgavmp.so" in file_:
                        self.__packer.append("Ali[ARM_VMP]")
                        return
                self.__packer.append("Ali")
                return

    def __checkTencentPacker(self):
        for file in self.__fileList:
            file = os.path.basename(file)
            if "libtup.so" == file or "libshell.so" == file or "mix.dex" == file or "mixz.dex" == file or "libshella" in file or "libshellx" in file:
                self.__packer.append("Tencent")
                break
        for file in self.__fileList:
            file = os.path.basename(file)
            if "libtosprotection.armeabi-v7a.so" == file or "libtosprotection.armeabi.so" == file or "libtosprotection.x86.so" == file:
                self.__packer.append("Tencent_Yu")  # 腾讯御安全
                break

    def __checkBaiduPacker(self):
        for file in self.__fileList:
            file = os.path.basename(file)
            if "libbaiduprotect.so" == file or "baiduprotect1.jar" == file or "baiduprotect.jar" == file:
                self.__packer.append("Baidu")
                return

    def __checkNagaPacker(self):
        for file in self.__fileList:
            file = os.path.basename(file)
            if "libchaosvmp.so" == file or "libddog.so" == file or "libfdog.so" == file or "libedog.so" == file or "main.data" in file \
                    or "libvdog" in file or "libvdog-x86" in file or "libvdog64" in file:
                for file_ in self.__fileList:
                    file_ = os.path.basename(file_)
                    if "libvdog" in file_ or "libvdog-x86" in file_ or "libvdog64" in file_:
                        self.__packer.append("Naga[susp_VMP]")
                        return
                self.__packer.append("Naga")
                return

    def __checkKiwiPacker(self):
        for file in self.__fileList:
            so_name = os.path.basename(file)
            if "libkwscmm.so" == so_name or "libkwscr.so" == so_name or "libkwslinker.so" == so_name or "kdpdata.so" == so_name:
                self.__packer.append("Kiwi[old]")
                return
            if "libnllvm.so" == so_name or "libxloader.so" == so_name or "libnMg.so" == so_name:
                if "libnllvm.so" == so_name:
                    self.__packer.append("Kiwi[Java2C]")
                else:
                    self.__packer.append("Kiwi")
                return
            mat_res = re.match(r'libnllvm\d+\.so', so_name)
            if mat_res:
                self.__packer.append("Kiwi[Java2C]")
                return

    def __checkPayEgis(self):  # 通付盾
        for file in self.__fileList:
            file = os.path.basename(file)
            if "libegis.so" == file or "libNSaferOnly.so" == file:
                self.__packer.append("Pay Egis")
                return

    def __checkNetQin(self):  # 网秦
        for file in self.__fileList:
            file = os.path.basename(file)
            if "libnqshield.so" == file:
                self.__packer.append("Netqin")
                return

    def __checkCMCC(self):  # 中国移动安全加固
        for file in self.__fileList:
            file = os.path.basename(file)
            if "libmogosec_dex.so" == file or "libmogosec_sodecrypt.so" == file or "libmogosecurity.so" == file:
                for file_ in self.__fileList:
                    if "libcmvmp.so" in file_:
                        self.__packer.append("CMCC[susp_VMP]")
                        return
                self.__packer.append("CMCC")
                return

    def __checkEdunPacker(self):  # 网易易盾
        for file in self.__fileList:
            file = os.path.basename(file)
            if "libnesec.so" == file:
                self.__packer.append("Edun")
                return

    def __checkAPKProtectPacker(self):
        for file in self.__fileList:
            file = os.path.basename(file)
            if "libAPKProtect.so" == file:
                self.__packer.append("APKProtect")
                return

    def __checkDingxiangPacker(self):
        for file in self.__fileList:
            file = os.path.basename(file)
            if "libx3g.so" == file or "libcsn.so" == file or "libdx-ind.so" == file or "libdx-ld.so" == file or "libcsn2.so" == file or "libcsn2_x86.so" == file or "libcsn_x86.so" == file:
                self.__packer.append("Dingxiang")
                return

    def checkPackerProtection(self):
        if self.__fileList is not []:
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
            return self.__packer

    def checkJava2CProtection(self):
        if self.__fileList is not []:
            self.__check360Java2CPacker()
            self.__checkKiwiPacker()
            self.__checkEdunPacker()
            return self.__packer