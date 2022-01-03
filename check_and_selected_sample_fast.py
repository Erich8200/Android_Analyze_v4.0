import APKAnalyze
import os
import shutil
from fast_packer_checker import PackerCheckerFast
from concurrent.futures import ThreadPoolExecutor, as_completed
from threading import Lock

# Identify target samples, and copy them to out_dir
sampleAPKDir = r"D:\Research2\Android_APP_unpack\2021.12.21\Kiwi_susp_samples"
cur = 1
lock = Lock()
APK_count = 0
out_dir = 'selected_Kiwi_sample'
sample_analyze_result = []
job_count = 20
target_packer = 'Kiwi'
report_file_name = 'Kiwi_samples.txt'


def analyze(filename:str):
    global cur
    global APK_count

    apk_name = os.path.basename(filename)

    lock.acquire()
    print("<<<<<< Analyzing " + apk_name + " [{:d}/{:d}] >>>>>>".format(cur, APK_count))
    lock.release()

    ana = None
    try:
        ana = PackerCheckerFast(filename)
        result = ana.checkPackerProtection()

        for s in result:
            if target_packer in s:
                sample_analyze_result.append(apk_name + '\n')
                print('Got ' + apk_name + '!')
                shutil.copy(filename, out_dir)
                break

    except Exception as ex:
        print(ex)
    finally:
        if ana is not None:
            del ana

    lock.acquire()
    print("<<<<<< Finished analyzing " + os.path.basename(filename) + " [{:d}/{:d}] >>>>>>".format(cur, APK_count))
    cur = cur + 1
    lock.release()


def main():
    pool = ThreadPoolExecutor(max_workers=job_count)

    if not os.path.exists(sampleAPKDir):
        print("Sample dir not found! Exiting...")
        exit(1)

    if not os.path.exists(out_dir):
        os.mkdir(out_dir)

    global APK_count
    global cur

    for root, dirs, files in os.walk(sampleAPKDir):
        for apk_name in files:
            if apk_name.split('.')[-1].lower() == "apk":
                APK_count = APK_count + 1
    print("Found " + str(APK_count) + " APK file(s)")

    obj_list = []

    for root, dirs, files in os.walk(sampleAPKDir):
        for apk_name in files:
                obj = pool.submit(analyze, os.path.join(root, apk_name))
                obj_list.append(obj)

    for _ in as_completed(obj_list):
        pass

    if sample_analyze_result:
        with open(report_file_name, 'w') as f:
            f.writelines(sample_analyze_result)

    print("<<<<<< All finished!!! >>>>>>")


if __name__ == '__main__':
    main()
