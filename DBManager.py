import sqlite3
import os

def connectDB(dbPath): # 返回数据库连接对象
    con = sqlite3.connect(dbPath,check_same_thread=False)
    return con

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
