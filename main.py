import APKAnalyze
import DBManager
import time
import Lists
import os
import threading
from concurrent.futures import ThreadPoolExecutor

# sampleAPKDir = "H:\\APK_samples\\APK\\2021.7_zhushou.360.cn_Benign\\security"
sampleAPKDir = "samples"
dbPath = "database/Android_app_database.db"
cur = 1
APK_count = 0
analyzed_samples = set()

# 打开数据库
def connect_DB():
    conn = DBManager.connectDB(dbPath)
    return conn

# 关闭数据库
def close_DB(conn):
    conn.close()

def analyze(filename:str, conn=None):
    global cur
    global APK_count
    global analyzed_samples

    apk_name = os.path.basename(filename)

    if apk_name in analyzed_samples:
        print("<<<<<< Passing " + apk_name + " >>>>>>")
        return

    print("<<<<<< Analyzing " + apk_name + " [{:d}/{:d}] >>>>>>".format(cur, APK_count))
    ana = None
    try:
        ana = APKAnalyze.APKAnalysis(filename)
        APKAnalyze.basic_info_to_DB(conn, ana)
    except Exception as ex:
        print(ex)
    if ana is not None:
        del ana

    print("<<<<<< Finished analyzing " + os.path.basename(filename) + " [{:d}/{:d}] >>>>>>".format(cur, APK_count))
    cur = cur + 1

def main():
    if not os.path.exists(sampleAPKDir):
        print("Sample dir not found! Exiting...")
        exit(1)
    
    conn = connect_DB()
    if conn is None:
        print("Invalid DB connection object!")
        exit(2)

    global analyzed_samples
    global APK_count
    global cur

    cursor = DBManager.sqlQueryer(conn, "select filename from APK_basic_info")
    for row in cursor:
        # analyzed_samples.append(row[0])
        analyzed_samples.add(row[0])
    del cursor

    for root, dirs, files in os.walk(sampleAPKDir):
        for apk_name in files:
            if apk_name.split('.')[-1].lower() == "apk":
                APK_count = APK_count + 1
    print("Found " + str(APK_count) + " APK file(s)")
    
    for root, dirs, files in os.walk(sampleAPKDir):
        for apk_name in files:
            try:
                # threadPool.submit(analyze, os.path.join(root, apk_name), conn)
                analyze(os.path.join(root, apk_name), conn=conn)
                # if cur % 100 == 0: # 每满100条记录就录入数据库
                #     print("<<<<<< Submitting data to DB >>>>>>")
                #     conn.commit()
                print("<<<<<< Submitting data to DB >>>>>>")
                conn.commit()
                # cur = cur + 1
            except  Exception as ex:
                print(ex)
    
    print("<<<<<< Submitting data to DB >>>>>>")
    conn.commit()
    close_DB(conn)
    print("<<<<<< All finished!!! >>>>>>")


if __name__ == '__main__':
    main()