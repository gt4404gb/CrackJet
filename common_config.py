DATABASESConfig = {
        'NAME': 'crackjet',
        'HOST': '127.0.0.1',
        'PORT': '3306',
        'USER': 'root',
        'PASSWORD': 'ZtZ6*wymaTpq',
}

CELERY_BROKER_URL = 'redis://127.0.0.1:6379/0'
CELERY_RESULT_BACKEND = 'redis://127.0.0.1:6379/0'

#日志文件设置
logConfig = {
    "log_filename": "logs.txt",  # 普通日志文件名称
    "error_filename": "error.txt",  # 普通日志文件名称niz
    "success_filename": "success.txt",  # 成功日志文件名称
}

# 请求代理设置

proxis = {
         "http": "",
         "https": ""
    }

#crawlergo爬虫与Chrome浏览器路径设置
crawlergoPath = "crawlergo_windows_amd64.exe"
ChromePath = "chrome-win\\chrome.exe"

#爬虫开启的最大浏览器页面数量
ChromeMaxTab = 10
crawlerFilterMode = "strict"
