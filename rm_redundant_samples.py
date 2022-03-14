import os
import hashlib
import shutil
import DBManager

sampleAPKDir = r"H:\APK_samples\APK\2022.3_zhushou.360.cn_Benign"
dbPath = "database/Android_app_database.db"
analyzed_samples = set()


def calcMd5(file_path:str):  # 计算文件MD5校验值
    with open(file_path, 'rb') as f:
        data = f.read()
        d5 = hashlib.md5(data)
        return d5.hexdigest()

conn = DBManager.connectDB(dbPath)

for root, dirs, files in os.walk(sampleAPKDir):
    for apk_name in files:
        apk_path = os.path.join(root, apk_name)
        # print(apk_path)
        md5 = calcMd5(os.path.join(root, apk_name))
        query_ret = DBManager.sqlQueryer(conn, 'SELECT filename FROM APK_basic_info WHERE md5 = \'' + md5 + '\'')
        # query_ret = DBManager.sqlQueryer(conn, '''SELECT * FROM APK_basic_info WHERE md5 = \'%s\' '''.format(md5))
        for cur in query_ret:
            if cur[0] is not None and cur[0] != '':
                print('Redundant sample ' + apk_path)
                os.remove(apk_path)
