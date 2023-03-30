from scan.crawl_spider import judge
from scan.auto_login import webcrack
import asyncio
from celery_main import app
from input_format import txt_excel
import logs.log as Log
import sys

@app.task
def checkRun(url):
    #假设传过来的是一个单个url站点
    try:
        resulturl = judge.spiderRun(url)
        # 启动爆破模块
        if resulturl != []:
            resulturl = list(set(resulturl))  # 列表去重
            username,password = webcrack.run_crack(resulturl)
        if username and password:
            return username,password
        else:
            return "error",""

    except Exception as e:
        print(e)
        return "error",""