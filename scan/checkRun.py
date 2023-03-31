from scan.crawl_spider import judge
from scan.auto_login import webcrack
import asyncio
from celery_main import app
from input_format import txt_excel
import logs.log as Log
import sys
from website.models import Website

@app.task
def checkRun(url, task_id):
    #假设传过来的是一个单个url站点
    try:
        print(url)
        task = Website.objects.get(UID=task_id)
        task.status = 'CRAWLING'
        task.save()
        resulturl = judge.spiderRun(url)
        # 启动爆破模块
        if resulturl != []:
            task.status = 'CRACKING'
            task.save()
            resulturl = list(set(resulturl))  # 列表去重
            username,password = webcrack.run_crack(resulturl)
            if username and password:
                task.status = 'SUCCESS'
                task.is_scan = 1 #已扫描
                task.is_weak = 1 #存在弱密码
                task.username = username
                task.password = password
                task.save()
                return username, password
        else:
            task.status = 'FINISH'
            task.is_scan = 1 #已扫描
            task.is_weak = 0 #存在弱密码
            task.username = ''
            task.password = ''
            task.save()
            return "error",""

    except Exception as e:
        print(e)
        task = Website.objects.get(id=task_id)
        task.status = 'ERROR'
        return "error",""