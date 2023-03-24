from django.shortcuts import render

# Create your views here.
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
import json
import os
import sys
from django.http import HttpResponse
import asyncio

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'scan')))
from scan.checkRun import checkRun

def hello(request):
    return HttpResponse("Hello world ! ")

#@csrf_exempt
def scan_websites(request):
    if request.method == 'POST':
        data = json.loads(request.body)
        websites = data['websites']
        result = checkRun(websites)
        return JsonResponse({'result': result})
    elif request.method == 'GET':
        website = request.GET.get('website')
        username, password = checkRun(website)
        return JsonResponse({'username': username, 'password': password})
    else:
        return JsonResponse({'error': 'Invalid request method'})


@csrf_exempt
def start_scan(request):
    if request.method == 'GET':
        website = request.GET.get('website')
        # 异步启动扫描任务
        result = checkRun.delay(website)

        # 返回任务 ID 给客户端
        return JsonResponse({'task_id': result.id})

@csrf_exempt
def get_scan_result(request):
    if request.method == 'GET':
        task_id = request.GET.get('task_id')

        # 获取任务执行结果
        result = checkRun.AsyncResult(task_id)

        if result.successful():
            # 如果任务成功完成，则返回 username 和 password 参数
            username, password = result.get()
            return JsonResponse({'username': username, 'password': password})
            #如果返回error,''则证明爆破失败
        else:
            # 如果任务尚未完成，则返回等待消息
            return JsonResponse({'status': 'waiting'})