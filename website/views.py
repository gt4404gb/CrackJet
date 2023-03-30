from django.shortcuts import render

# Create your views here.
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
import json
import os
import sys
from django.http import HttpResponse
import asyncio
from django.contrib.auth import authenticate, login
from django.contrib.auth.forms import UserCreationForm
from django.shortcuts import render, redirect
from django.views.generic import View
from django.views.decorators.csrf import csrf_exempt
from django.contrib.auth.decorators import login_required
from django.contrib.auth.mixins import LoginRequiredMixin

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'scan')))
from scan.checkRun import checkRun


def hello(request):
    return HttpResponse("Hello world ! ")


def login_view(request):
    if request.method == 'POST':
        username = request.POST['username']
        password = request.POST['password']
        user = authenticate(request, username=username, password=password)
        if user is not None:
            login(request, user)
            return redirect('/')
        else:
            return render(request, 'login.html', {'error': 'Invalid username or password.'})
    else:
        return render(request, 'login.html')


def register_view(request):
    if request.method == 'POST':
        form = UserCreationForm(request.POST)
        if form.is_valid():
            form.save()
            username = form.cleaned_data.get('username')
            raw_password = form.cleaned_data.get('password1')
            user = authenticate(username=username, password=raw_password)
            login(request, user)
            return redirect('/')
    else:
        form = UserCreationForm()
    return render(request, 'register.html', {'form': form})

class logout_View(LoginRequiredMixin, View):
    def get(self, request):
        # 清理session（redis中的会话，请求对象cookie中的sessionid）-request.session.flush()
         #logout(request=request)
        response = JsonResponse({
            'errmsg': 'ok'
        })
        # 可以删除指定cookie
        request.session.clear()
        response.delete_cookie('value')
        return response

class start_scan(LoginRequiredMixin,View):
    def get(self,request):
        website = request.GET.get('website')
        # 异步启动扫描任务
        result = checkRun.delay(website)

        # 返回任务 ID 给客户端
        return JsonResponse({'task_id': result.id})

class get_scan_result(LoginRequiredMixin,View):
    def get(self,request):
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


'''
class start_scan(View):
    def get(self,request):
        website = request.GET.get('website')
        # 异步启动扫描任务
        result = checkRun.delay(website)

        # 返回任务 ID 给客户端
        return JsonResponse({'task_id': result.id})
        return render(request, 'userapp/user_center.html')
'''