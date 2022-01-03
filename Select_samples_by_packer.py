import os
import DBManager
import pathlib
import shutil

def select_samples(db_path:str, select_sql:str):
    if not os.path.exists(db_path):
        return []
    conn =  DBManager.connectDB(db_path)
    if conn is None:
        return []
    cursor = DBManager.sqlQueryer(conn, select_sql)
    return cursor

def find_samples(root_dir:str, file_name_list:list):
    file_path_list = []
    root_dir = pathlib.Path(root_dir)
    for file_name in file_name_list:
        res = root_dir.rglob(file_name)
        for file_path in res:
            # print(file_path)
            file_path_list.append(file_path)
    return file_path_list

def copy_samples(sample_path_list:list, to_dir:str):
    for sample_path in sample_path_list:
        try:
            shutil.copy2(sample_path, to_dir)
            print('Copied sample ' + str(sample_path))
        except Exception as e:
            print(e)

def main():
    packer_name = '%360%'
    cursor = select_samples(r'C:\Users\JYQ\Desktop\Android_app_database.db', 'select filename from APK_basic_info where shellProtection like \'{}\''.format(packer_name))
    file_name_list = []
    file_path_list = []
    for s in cursor:
        file_name_list.append(s[0])
    file_path_list = find_samples(r'H:\APK_samples\APK\2021.7_zhushou.360.cn_Benign', file_name_list)
    print('Found ' + str(len(file_path_list)) + ' samples')
    copy_samples(file_path_list, 'samples')

if __name__ == '__main__':
    main()