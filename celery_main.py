from __future__ import absolute_import, unicode_literals
import os
from celery import Celery

# 设置默认 Django 设置模块
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'djangoALPC.settings')

app = Celery('JetCelery')

# 从Django配置中获取异步处理所需配置
app.config_from_object('django.conf:settings', namespace='CELERY')

# 自动从所有已注册的Django应用程序中发现异步任务
app.autodiscover_tasks(['scan.checkRun', ])