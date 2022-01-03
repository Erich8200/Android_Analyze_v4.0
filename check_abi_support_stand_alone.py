import zipfile
import os
import shutil
import re

if __name__ == '__main__':
    ApkNo = 0

    if not os.path.exists('Ijiami'):
        print('未找到输入文件夹')
        exit(1)
    if not os.path.exists('Ijiami_pro'):
        print('未找到输入文件夹')
        exit(2)
    for dir in ['Ijiami', 'Ijiami_pro']:
        for root, dirs, files in os.walk(dir):
            for f in files:
                ApkNo += 1
                print("正在分析第" + str(ApkNo) + "个APK")
                file_path = os.path.join(root, f) # 文件完整路径
                zipfiles=zipfile.ZipFile(file_path)
                nameList=zipfiles.namelist()
                zipfiles.close()
                for fileName in nameList:
                    pattern = re.compile("lib/x86/[\x20-\x7f]+\.so")
                    # pattern = re.compile("lib/arm64-v8a/[\x20-\x7f]+\.so")
                    if pattern.match(fileName) is not None:
                        print(fileName)
                        os.rename(file_path, file_path.split('.apk')[0] + '_x86.apk')
                        break