from scan.crawl_spider import judge
from scan.auto_login import webcrack
import asyncio
from celery_main import app
from celery import shared_task
from django.core.cache import cache

@app.task(bind=True,ignore_result=True)
def checkRun(self,url):
    #假设传过来的是一个单个url站点
    try:
        #爬取模块
        self.update_state(state='CRAWLING')
        resulturl = judge.spiderRun(url)
        # 启动爆破模块
        self.update_state(state='CRACKING')
        if resulturl != []:
            resulturl = list(set(resulturl))  # 列表去重
            username,password = webcrack.run_crack(resulturl)
        if username and password:
            return username,password
        else:
            self.update_state(state='FINISH')
            return "error", ""

    except Exception as e:
        print(e)
        self.update_state(state='ERROR')
        return "error",""