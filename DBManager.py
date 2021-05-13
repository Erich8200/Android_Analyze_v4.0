import sqlite3
import os

def connectDB(dbPath): # 返回数据库连接对象
    if os.path.exists(dbPath):
        con = sqlite3.connect(dbPath,check_same_thread=False)
        print("数据库打开成功")
        return con
    return None

def sqlInserter(conn, sql, values): # 执行插入命令
    cur = conn.cursor()
    cur.execute(sql, values)
    # conn.commit()

def sqlQueryer(conn, sql): # 执行查询类命令
    cur = conn.cursor()
    cur.execute(sql)
    return cur

def sqlScriptExec(conn, sql): # 执行脚本
    cur = conn.cursor()
    cur.executescript(sql)
    return cur
