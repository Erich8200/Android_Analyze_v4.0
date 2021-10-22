import APKAnalyze
import DBManager
import time
import Lists
import os
import threading
from concurrent.futures import ThreadPoolExecutor


sampleAPKDir = "samples"
dbPath = "database/Android_app_database.db"
cur = 1
APK_count = 0
analyzed_samples = set()

# 打开数据库
def connect_DB():
    conn = None
    if os.path.exists(dbPath):
        conn = DBManager.connectDB(dbPath)
        print("<<<<<< Database opened >>>>>>")
    else:
        conn = DBManager.connectDB(dbPath)
        DBManager.sqlQueryer(conn, 
                            '''
                                create table APK_basic_info
                                (
                                    filename                 text,
                                    appName                  text,
                                    md5                      text,
                                    size                     integer,
                                    shellProtection          text,
                                    native                   boolean,
                                    classCount               integer,
                                    methodCount              integer,
                                    permissionCount          integer,
                                    ActivityCount            integer,
                                    ReceiverCount            integer,
                                    ServiceCount             integer,
                                    ProviderCount            integer,
                                    multidex                 boolean,
                                    reflection               boolean,
                                    minSDK                   integer,
                                    tgtSDK                   integer,
                                    maxSDK                   integer,
                                    signedV1                 boolean,
                                    signedV2                 boolean,
                                    signedV3                 boolean,
                                    packageName              text,
                                    mainActivity             text,
                                    READ_PHONE_STATE         boolean,
                                    READ_EXTERNAL_STORAGE    boolean,
                                    SYSTEM_ALERT_WINDOW      boolean,
                                    GET_TASKS                boolean,
                                    WRITE_SETTINGS           boolean,
                                    BIND_DEVICE_ADMIN        boolean,
                                    INTERNET                 boolean,
                                    BLUETOOTH                boolean,
                                    CAMERA                   boolean,
                                    READ_CONTACTS            boolean,
                                    READ_LOGS                boolean,
                                    ACCESS_FINE_LOCATION     boolean,
                                    READ_FRAME_BUFFER        boolean,
                                    BRICK                    boolean,
                                    INSTALL_PACKAGES         boolean,
                                    MOUNT_FORMAT_FILESYSTEMS boolean,
                                    RECEIVE_BOOT_COMPLETED   boolean,
                                    WRITE_EXTERNAL_STORAGE   boolean,
                                    CALL_PHONE               boolean,
                                    READ_CALL_LOG            boolean,
                                    WRITE_CALL_LOG           boolean,
                                    ADD_VOICEMAIL            boolean,
                                    USE_SIP                  boolean,
                                    PROCESS_OUTGOING_CALLS   boolean,
                                    SEND_SMS                 boolean,
                                    RECEIVE_SMS              boolean,
                                    READ_SMS                 boolean,
                                    RECEIVE_WAP_PUSH         boolean,
                                    RECEIVE_MMS              boolean,
                                    ACCESS_COARSE_LOCATION   boolean,
                                    RECORD_AUDIO             boolean,
                                    WRITE_CONTACTS           boolean,
                                    GET_ACCOUNTS             boolean,
                                    READ_CALENDAR            boolean,
                                    WRITE_CALENDAR           boolean,
                                    buildTime                date,
                                    recordTime               date,
                                    malware                  boolean
                                );
                            ''')
        print("<<<<<< Database created >>>>>>")
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