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
from django.core.cache import cache
from django.contrib.auth.mixins import LoginRequiredMixin

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'scan')))
from scan.checkRun import checkRun
from website import models


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


#新建项目（扫描文件夹）
class create_project(LoginRequiredMixin,View):
    def get(self,request):
        try:
            # 从请求中获取项目名称
            project_name = request.GET.get('project_name')
            # 创建项目
            project = models.Project.objects.create(projectname=project_name)
            # 返回创建状态和创建的任务id
            return JsonResponse({'status': 'success', 'task_id': project.ID})

        except Exception as e:
            print(e)
            return JsonResponse({'status': 'failed'})

#查询所有项目
class search_all_project(LoginRequiredMixin,View):
    def get(self,request):
        # 从数据库中获取所有项目
        projects = models.Project.objects.all()
        # 构造返回的json格式数据
        project_list = [{'project_id': project.ID, 'project_name': project.projectname} for project in projects]
        # 返回json格式数据
        return JsonResponse({'projects': project_list})

#新建扫描URL
class create_scan(LoginRequiredMixin,View):
    def get(self,request):
        try:
            # 从请求中获取项目id和网址
            project_id = request.GET.get('project_id')
            website = request.GET.get('website')
            # 创建扫描URL
            website = models.Website.objects.create(site=website, project_id=project_id,status="INIT")
            # 返回创建状态和创建的任务id
            return JsonResponse({'status': 'success', 'UID': website.UID})

        except Exception as e:
            return JsonResponse({'status': 'failed'})


#单个URL扫描请求
class start_scan(LoginRequiredMixin,View):
    def get(self,request):
        website = request.GET.get('website')
        # 异步启动扫描任务
        result = checkRun.delay(website)

        # 返回任务 ID 给客户端
        return JsonResponse({'task_id': result.id})

#干脆不要从celery读状态了，直接去数据库读状态
class get_scan_result(LoginRequiredMixin,View):
    def get(self,request):

        task_id = request.GET.get('task_id')

        # 获取任务执行结果
        result = checkRun.AsyncResult(task_id)
        if result is not None:
            if result.successful():
                # 如果任务成功完成，则返回 username 和 password 参数
                username, password = result.get()
                return JsonResponse({'username': username, 'password': password})
                #如果返回error,''则证明爆破失败
            else:
                # 如果任务尚未完成，则返回等待消息
                return JsonResponse({'status': 'waiting'})
        else:
            return JsonResponse({'error': 'task_id is required'})