from django.shortcuts import render

# Create your views here.
from django.http import JsonResponse
import os
import sys
from django.http import HttpResponse
from django.contrib.auth import authenticate, login
from django.contrib.auth.forms import UserCreationForm
from django.shortcuts import render, redirect
from rest_framework import status
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework.authentication import TokenAuthentication
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer
from rest_framework_simplejwt.views import TokenObtainPairView
from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework.permissions import IsAuthenticated
from rest_framework.permissions import AllowAny
from django.contrib.auth.mixins import LoginRequiredMixin
from drf_yasg.utils import swagger_auto_schema
from drf_yasg import openapi
from django.views.decorators.csrf import csrf_exempt

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'scan')))
from scan.checkRun import checkRun
from website import models

from django.middleware.csrf import get_token

class get_csrf_token(APIView):
    def get(self, request):
        csrf_token = get_token(request)  # 获取csrf_token的值
        return JsonResponse({'token': csrf_token})

def hello(request):
    return HttpResponse("Hello world ! ")


class CustomTokenObtainPairSerializer(TokenObtainPairSerializer):
    @classmethod
    def get_token(cls, user):
        token = super().get_token(user)
        # add custom claims
        token['email'] = user.email
        return token

class CustomTokenObtainPairView(TokenObtainPairView):
    serializer_class = CustomTokenObtainPairSerializer
    permission_classes = [AllowAny]


class login_view(APIView):

    authentication_classes = [TokenAuthentication]
    @swagger_auto_schema(
        operation_description="用户登录",
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            required=['username', 'password'],
            properties={
                'username': openapi.Schema(type=openapi.TYPE_STRING, description="用户名"),
                'password': openapi.Schema(type=openapi.TYPE_STRING, description="密码")
            }
        ),
        responses={
            200: openapi.Response(
                description="成功",
                examples={
                    "application/json": {
                        "code": 200,
                        "msg": "ok"
                    }
                }
            ),
            400: openapi.Response(
                description="请求错误",
                examples={
                    "application/json": {
                        "errmsg": "Invalid request."
                    }
                }
            ),
            401: openapi.Response(
                description="用户名或密码错误",
                examples={
                    "application/json": {
                        "errmsg": "Invalid username or password."
                    }
                }
            ),
        }
    )
    def post(self, request):
        try:
            data = request.data
            username = data['username']
            password = data['password']
            user = authenticate(request, username=username, password=password)
            if user is not None:
                login(request, user)
                return JsonResponse({'code': 200, 'msg': 'ok'})
            else:
                return JsonResponse({'code': 401, 'errmsg': 'Invalid username or password.'}, status=status.HTTP_401_UNAUTHORIZED)
        except Exception as e:
            print(e)
            return JsonResponse({'code': 400, 'errmsg': 'Invalid request.'}, status=status.HTTP_400_BAD_REQUEST)

    def get(self, request):
        try:
            return render(request, 'login.html')
        except Exception as e:
            print(e)
            return JsonResponse({'code': 400, 'errmsg': 'Invalid request.'}, status=status.HTTP_400_BAD_REQUEST)


class register_view(APIView):
    @swagger_auto_schema(
        operation_description="用户注册",
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            required=['username', 'password1', 'password2'],
            properties={
                'username': openapi.Schema(type=openapi.TYPE_STRING, description="用户名"),
                'password1': openapi.Schema(type=openapi.TYPE_STRING, description="密码"),
                'password2': openapi.Schema(type=openapi.TYPE_STRING, description="确认密码"),
            }
        ),
        responses={
            200: openapi.Response(
                description="成功",
                examples={
                    "application/json": {
                        "msg": "ok"
                    }
                }
            ),
            400: openapi.Response(
                description="请求错误",
                examples={
                    "application/json": {
                        "errmsg": "Invalid request."
                    }
                }
            ),
        }
    )
    def post(self, request):
        try:
            data = request.data
            form = UserCreationForm(data)
            if form.is_valid():
                form.save()
                username = form.cleaned_data.get('username')
                raw_password = form.cleaned_data.get('password1')
                user = authenticate(username=username, password=raw_password)
                login(request, user)
                return JsonResponse({'code': status.HTTP_200_OK, 'msg': 'ok'})
            else:
                errors = form.errors
                return JsonResponse({'code': status.HTTP_400_BAD_REQUEST, 'errmsg': errors}, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            print(e)
            return JsonResponse({'code': status.HTTP_400_BAD_REQUEST, 'errmsg': 'Invalid request.'}, status=status.HTTP_400_BAD_REQUEST)

    def get(self, request):
        try:
            form = UserCreationForm()
            return render(request, 'register.html', {'form': form})
        except Exception as e:
            print(e)
            return JsonResponse({'code': status.HTTP_400_BAD_REQUEST, 'errmsg': 'Invalid request.'}, status=status.HTTP_400_BAD_REQUEST)

#登出
class logout_View(LoginRequiredMixin, APIView):
    def dispatch(self, request, *args, **kwargs):
        if not request.user.is_authenticated:
            return JsonResponse({'code': status.HTTP_401_UNAUTHORIZED, 'errmsg': 'Authentication credentials were not provided.'}, status=status.HTTP_401_UNAUTHORIZED)
        return super().dispatch(request, *args, **kwargs)

    #authentication_classes = [JWTAuthentication]
    #permission_classes = [IsAuthenticated]
    @swagger_auto_schema(
        operation_description="用户登出",
        responses={
            200: openapi.Response(
                description="成功",
                examples={
                    "application/json": {
                        "msg": "ok"
                    }
                }
            ),
            400: openapi.Response(
                description="请求错误",
                examples={
                    "application/json": {
                        "errmsg": "Invalid request."
                    }
                }
            ),
            401: openapi.Response(
                description="未认证",
                examples={
                    "application/json": {
                        "errmsg": "Authentication credentials were not provided."
                    }
                }
            ),
        }
    )
    def get(self, request):
        try:
            # 清理session（redis中的会话，请求对象cookie中的sessionid）-request.session.flush()
             #logout(request=request)
            response = JsonResponse({
                'code': status.HTTP_200_OK,
                'msg': 'ok'
            })
            # 可以删除指定cookie
            request.session.clear()
            response.delete_cookie('value')
            return response
        except Exception as e:
            print(e)
            return JsonResponse({'code': status.HTTP_400_BAD_REQUEST, 'errmsg': 'Invalid request.'}, status=status.HTTP_400_BAD_REQUEST)


#新建项目（扫描文件夹）
class create_project(LoginRequiredMixin, APIView):
    def dispatch(self, request, *args, **kwargs):
        if not request.user.is_authenticated:
            return JsonResponse({'code': status.HTTP_401_UNAUTHORIZED, 'errmsg': 'Authentication credentials were not provided.'}, status=status.HTTP_401_UNAUTHORIZED)
        return super().dispatch(request, *args, **kwargs)

    @swagger_auto_schema(
        operation_description="新建项目（扫描文件夹）",
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            required=['project_name'],
            properties={
                'project_name': openapi.Schema(type=openapi.TYPE_STRING, description="项目名称"),
            }
        ),
        responses={
            200: openapi.Response(
                description="查询结果",
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        'status': openapi.Schema(type=openapi.TYPE_STRING, description="创建状态"),
                        'task_id': openapi.Schema(type=openapi.TYPE_STRING, description="项目ID")
                    }
                )
            ),
            400: openapi.Response(
                description="请求错误",
                examples={
                    "application/json": {
                        "errmsg": "error",
                        'status': 'failed'
                    }
                }
            ),
            401: openapi.Response(
                description="未认证",
                examples={
                    "application/json": {
                        "errmsg": "Authentication credentials were not provided."
                    }
                }
            ),
            404: "任务ID不存在",
        }
    )
    def post(self,request):
        data = request.data
        try:
            # 从请求中获取项目名称
            project_name = data.get('project_name')
            # 创建项目
            project = models.Project.objects.create(projectname=project_name)
            project.status = "INIT"
            project.save()

            if project_name == None or project_name == '':
                project_name = '项目'+ str(project.ID)
                project.projectname = project_name
                project.save()
            # 返回创建状态和创建的任务id
            return JsonResponse({'code': status.HTTP_200_OK, 'status': 'success', 'task_id': project.ID})

        except Exception as e:
            print(e)
            return JsonResponse({'code': status.HTTP_400_BAD_REQUEST, 'errmsg':e,'status': 'failed'}, status=status.HTTP_400_BAD_REQUEST)

#删除项目
class delete_project(LoginRequiredMixin, APIView):
    def dispatch(self, request, *args, **kwargs):
        if not request.user.is_authenticated:
            return JsonResponse({'code': status.HTTP_401_UNAUTHORIZED, 'errmsg': 'Authentication credentials were not provided.'}, status=status.HTTP_401_UNAUTHORIZED)
        return super().dispatch(request, *args, **kwargs)

    @swagger_auto_schema(
        operation_description="删除项目",
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            required=['project_id'],
            properties={
                'project_id': openapi.Schema(type=openapi.TYPE_STRING, description="项目id"),
            }
        ),
        responses={
            200: openapi.Response(
                description="查询结果",
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        'status': openapi.Schema(type=openapi.TYPE_STRING, description="删除状态")
                    }
                )
            ),
            400: openapi.Response(
                description="请求错误",
                examples={
                    "application/json": {
                        "errmsg": "error",
                        'status': 'failed'
                    }
                }
            ),
            401: openapi.Response(
                description="未认证",
                examples={
                    "application/json": {
                        "errmsg": "Authentication credentials were not provided."
                    }
                }
            ),
            404: "任务ID不存在",
        }
    )
    def delete(self,request):
        try:
            data = request.data
            # 从请求中获取任务id
            ID = data.get('project_id')
            # 从数据库中删除该任务
            project = models.Project.objects.get(ID=ID)
            # 将项目状态设置为 "DELETE"
            project.status = "DELETE"
            project.save()
            # 返回删除成功状态
            return JsonResponse({'code': status.HTTP_200_OK, 'status': 'success'})
        except Exception as e:
            print(e)
            return JsonResponse({'code': status.HTTP_400_BAD_REQUEST, 'errmsg': 'Invalid request.'}, status=status.HTTP_400_BAD_REQUEST)


#查询所有项目
class search_all_project(LoginRequiredMixin, APIView):
    def dispatch(self, request, *args, **kwargs):
        if not request.user.is_authenticated:
            return JsonResponse({'code': status.HTTP_401_UNAUTHORIZED, 'errmsg': 'Authentication credentials were not provided.'}, status=status.HTTP_401_UNAUTHORIZED)
        return super().dispatch(request, *args, **kwargs)

    @swagger_auto_schema(
        operation_description="查询所有项目",
        responses={
            200: openapi.Response(
                description="查询结果",
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        'projects': openapi.Schema(type=openapi.TYPE_ARRAY, description="项目列表", items=openapi.Schema(
                            type=openapi.TYPE_OBJECT,
                            properties={
                                'project_id': openapi.Schema(type=openapi.TYPE_INTEGER, description="项目ID"),
                                'project_name': openapi.Schema(type=openapi.TYPE_STRING, description="项目名称")
                            }
                        ))
                    }
                )
            ),
            400: openapi.Response(
                description="请求错误",
                examples={
                    "application/json": {
                        "errmsg": "Invalid request."
                    }
                }
            ),
            401: openapi.Response(
                description="未认证",
                examples={
                    "application/json": {
                        "errmsg": "Authentication credentials were not provided."
                    }
                }
            ),
            404: "任务ID不存在",
        }
    )
    def get(self,request):
        try:
            # 从数据库中获取所有项目，排除status为DELETE的项目
            projects = models.Project.objects.exclude(status='DELETE')
            # 构造返回的json格式数据
            project_list = [{'project_id': project.ID, 'project_name': project.projectname} for project in projects]
            # 返回json格式数据
            return JsonResponse(project_list, safe=False)
        except Exception as e:
            print(e)
            return JsonResponse({'code': status.HTTP_400_BAD_REQUEST, 'errmsg': 'Invalid request.'}, status=status.HTTP_400_BAD_REQUEST)

#新建扫描URL
class create_scan(LoginRequiredMixin, APIView):
    def dispatch(self, request, *args, **kwargs):
        if not request.user.is_authenticated:
            return JsonResponse({'code': status.HTTP_401_UNAUTHORIZED, 'errmsg': 'Authentication credentials were not provided.'}, status=status.HTTP_401_UNAUTHORIZED)
        return super().dispatch(request, *args, **kwargs)

    @swagger_auto_schema(
        operation_description="新建扫描URL",
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            required=['project_id', 'website'],
            properties={
                'project_id': openapi.Schema(type=openapi.TYPE_STRING, description="项目ID"),
                'website': openapi.Schema(type=openapi.TYPE_STRING, description="网站"),
            }
        ),
        responses={
            200: openapi.Response(
                description="查询结果",
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        'status': openapi.Schema(type=openapi.TYPE_STRING, description="任务状态"),
                        'UID': openapi.Schema(type=openapi.TYPE_STRING, description="任务ID")
                    }
                )
            ),
            400: openapi.Response(
                description="任务创建失败",
                examples={
                    "application/json": {
                        "status": "failed"
                    }
                }
            ),
            401: openapi.Response(
                description="未认证",
                examples={
                    "application/json": {
                        "errmsg": "Authentication credentials were not provided."
                    }
                }
            ),
        }
    )
    def post(self,request):
        try:
            data = request.data
            # 从请求中获取项目id和网址
            project_id = data.get('project_id')
            website = data.get('website')
            # 创建扫描URL
            task = models.Website.objects.create(site=website, project_id=project_id,status="INIT",is_scan=0)
            # 返回创建状态和创建的任务id
            # 将任务的数据库 id 作为参数传递给 Celery
            celery_task = checkRun.apply_async(args=(website, task.UID))
            # 将 Celery 生成的 taskid 保存到任务记录中
            #print(celery_task.id)
            #task.save()
            # 返回任务 id

            return JsonResponse({'code': status.HTTP_200_OK, 'status': 'success', 'UID': task.UID})
        except Exception as e:
            print(e)
            return JsonResponse({'code': status.HTTP_400_BAD_REQUEST, 'errmsg': e, 'status': 'failed'}, status=status.HTTP_400_BAD_REQUEST)


#从txt文件中读取多个扫描URL，依次加入扫描
class create_scan_file(LoginRequiredMixin, APIView):
    def dispatch(self, request, *args, **kwargs):
        if not request.user.is_authenticated:
            return JsonResponse({'code': status.HTTP_401_UNAUTHORIZED, 'errmsg': 'Authentication credentials were not provided.'}, status=status.HTTP_401_UNAUTHORIZED)
        return super().dispatch(request, *args, **kwargs)

    @swagger_auto_schema(
        operation_description="从txt文件中读取多个扫描URL，依次加入扫描",
        manual_parameters=[
            openapi.Parameter(
                'project_id', openapi.IN_QUERY, description="项目ID",
                type=openapi.TYPE_STRING, required=True
            ),
        ],
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            required=['file'],
            properties={
                'file': openapi.Schema(type=openapi.TYPE_STRING, description="txt文件"),
            }
        ),
        responses={
            200: openapi.Response(
                description="上传结果",
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        'status': openapi.Schema(type=openapi.TYPE_STRING, description="任务状态")
                    }
                )
            ),
            400: "请求错误",
            401: openapi.Response(
                description="未认证",
                examples={
                    "application/json": {
                        "errmsg": "Authentication credentials were not provided."
                    }
                }
            ),
            404: "任务ID不存在",
        }
    )
    def post(self, request):
        try:
            # 从请求中获取项目id和txt文件路径
            project_id = request.GET.get('project_id')
            # 从请求中获取上传的文件
            uploaded_file = request.FILES.get('file')

            # 读取 txt 文件中的内容
            if uploaded_file.content_type == 'text/plain':
                urls = uploaded_file.read().decode('utf-8').split('\n')
            else:
                raise ValueError('The uploaded file is not a txt file.')

            # 逐个创建扫描URL
            for url in urls:
                # 创建扫描URL
                task = models.Website.objects.create(site=url.strip(), project_id=project_id,status="INIT",is_scan=0,is_weak=0)
                # 将任务的数据库 id 作为参数传递给 Celery
                celery_task = checkRun.apply_async(args=(url.strip(), task.UID))
            # 返回创建状态和创建的任务id
            return JsonResponse({'code': status.HTTP_200_OK, 'status': 'success'})
        except Exception as e:
            print(e)
            return JsonResponse({'code': status.HTTP_400_BAD_REQUEST, 'errmsg': e,'status': 'failed'}, status=status.HTTP_400_BAD_REQUEST)


#在数据库中查询扫描状态
class scan_status(LoginRequiredMixin, APIView):
    def dispatch(self, request, *args, **kwargs):
        if not request.user.is_authenticated:
            return JsonResponse({'code': status.HTTP_401_UNAUTHORIZED, 'errmsg': 'Authentication credentials were not provided.'}, status=status.HTTP_401_UNAUTHORIZED)
        return super().dispatch(request, *args, **kwargs)

    @swagger_auto_schema(
        operation_description="查询网站扫描状态",
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            required=['UID'],
            properties={
                'UID': openapi.Schema(type=openapi.TYPE_STRING, description="网站id"),
            }
        ),
        responses={
            200: openapi.Response(
                description="查询结果",
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        'status': openapi.Schema(type=openapi.TYPE_STRING, description="任务状态"),
                        'username': openapi.Schema(type=openapi.TYPE_STRING, description="爆破成功的用户名"),
                        'password': openapi.Schema(type=openapi.TYPE_STRING, description="爆破成功的密码")
                    }
                )
            ),
            400: openapi.Response(
                description="请求错误",
                examples={
                    "application/json": {
                        "errmsg": "Invalid request."
                    }
                }
            ),
            401: openapi.Response(
                description="未认证",
                examples={
                    "application/json": {
                        "errmsg": "Authentication credentials were not provided."
                    }
                }
            ),
            404: "任务ID不存在",
        }
    )
    def post(self, request):
        try:
            data = request.data
            raw_UID = data.get('UID')
            UID = raw_UID.replace('-', '')
            # 获取任务执行结果
            task = models.Website.objects.get(UID=UID)
            if task:
                result = task.status
                if result == "SUCCESS":
                    username = task.username
                    password = task.password
                    return JsonResponse({'code': status.HTTP_200_OK, 'status': result,'username': username, 'password': password})
                    #如果返回error,''则证明爆破失败
                elif result == "FINISH":
                    return JsonResponse({'code': status.HTTP_200_OK, 'status': result})
                else:
                    return JsonResponse({'code': status.HTTP_200_OK, 'status': result})
            else:
                return JsonResponse({'code': status.HTTP_400_BAD_REQUEST, 'errmsg': 'task_id is invalid'}, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            print(e)
            return JsonResponse({'code': status.HTTP_400_BAD_REQUEST, 'errmsg': 'Invalid request.'}, status=status.HTTP_400_BAD_REQUEST)

#查询数据库中project所有的webstie记录
class search_all_website(LoginRequiredMixin, APIView):
    def dispatch(self, request, *args, **kwargs):
        if not request.user.is_authenticated:
            return JsonResponse({'code': status.HTTP_401_UNAUTHORIZED, 'errmsg': 'Authentication credentials were not provided.'}, status=status.HTTP_401_UNAUTHORIZED)
        return super().dispatch(request, *args, **kwargs)

    @swagger_auto_schema(
        operation_description="查询数据库中project所有的webstie记录",
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            required=['project_id'],
            properties={
                'project_id': openapi.Schema(type=openapi.TYPE_STRING, description="项目id"),
            }
        ),
        responses={
            200: openapi.Response(
                description="查询结果",
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        'websites': openapi.Schema(type=openapi.TYPE_ARRAY, description="网址列表", items=openapi.Schema(
                            type=openapi.TYPE_OBJECT,
                            properties={
                                'UID': openapi.Schema(type=openapi.TYPE_STRING, description="任务ID"),
                                'address': openapi.Schema(type=openapi.TYPE_STRING, description="网址"),
                                'scanStatus': openapi.Schema(type=openapi.TYPE_STRING, description="任务状态,可能的值为INIT（初始化）、CRAWLING（页面爬取中）、CRACKING（账号爆破中）、FINISH（已完成，未发现弱口令）、SUCCESS（已完成、发现弱口令）、ERROR（扫描错误）"),
                                'loginStatus': openapi.Schema(type=openapi.TYPE_INTEGER, description="是否弱口令"),
                                'username': openapi.Schema(type=openapi.TYPE_STRING, description="用户名"),
                                'password': openapi.Schema(type=openapi.TYPE_STRING, description="密码"),
                            }
                        ))
                    }
                )
            ),
            400: openapi.Response(
                description="请求错误",
                examples={
                    "application/json": {
                        "errmsg": "Invalid request."
                    }
                }
            ),
            401: openapi.Response(
                description="未认证",
                examples={
                    "application/json": {
                        "errmsg": "Authentication credentials were not provided."
                    }
                }
            ),
            404: "任务ID不存在",
        }
    )
    @csrf_exempt
    def post(self,request):
        try:
            data = request.data
            # 从请求中获取项目id
            project_id = data.get('project_id')
            # 从数据库中获取该项目下的所有网址
            websites = models.Website.objects.filter(project_id=project_id)
            # 构造返回的json格式数据
            website_list = [{'UID': website.UID,
                             'address': website.site,
                             'scanStatus': website.status if website.status is not None else '',
                             'loginStatus': str(website.is_weak) if website.is_weak is not None else '',
                             'username': website.username if website.username is not None else '',
                             'password': website.password if website.password is not None else ''
                             } for website in websites]
            return JsonResponse({'code': status.HTTP_200_OK, 'websites': website_list})
        except Exception as e:
            print(e)
            return JsonResponse({'code': status.HTTP_400_BAD_REQUEST, 'errmsg': 'Invalid request.'}, status=status.HTTP_400_BAD_REQUEST)


#删除指定的url扫描记录
class delete_website(LoginRequiredMixin, APIView):
    def dispatch(self, request, *args, **kwargs):
        if not request.user.is_authenticated:
            return JsonResponse({'code': status.HTTP_401_UNAUTHORIZED, 'errmsg': 'Authentication credentials were not provided.'}, status=status.HTTP_401_UNAUTHORIZED)
        return super().dispatch(request, *args, **kwargs)

    @swagger_auto_schema(
        operation_description="删除指定的url扫描记录",
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            required=['UID'],
            properties={
                'UID': openapi.Schema(type=openapi.TYPE_STRING, description="网站id"),
            }
        ),
        responses={
            200: openapi.Response(
                description="查询结果",
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        'status': openapi.Schema(type=openapi.TYPE_STRING, description="任务状态")
                    }
                )
            ),
            400: "请求错误",
            401: openapi.Response(
                description="未认证",
                examples={
                    "application/json": {
                        "errmsg": "Authentication credentials were not provided."
                    }
                }
            ),
            404: "任务ID不存在",
        }
    )
    def delete(self,request):
        try:
            data = request.data
            # 从请求中获取任务id
            raw_UID = data.get('UID')
            UID = raw_UID.replace('-','')
            # 从数据库中删除该任务
            website = models.Website.objects.get(UID=UID)
            print(UID)
            print(website)
            website.delete()
            # 返回删除成功状态
            return JsonResponse({'code': status.HTTP_200_OK, 'status': 'success'})
        except Exception as e:
            print(e)
            return JsonResponse({'code': status.HTTP_400_BAD_REQUEST, 'errmsg': 'Invalid request.'}, status=status.HTTP_400_BAD_REQUEST)

            
#—————————————————以下接口已弃用———————————————————————————————
#单个URL扫描请求
class start_scan(LoginRequiredMixin, APIView):
    def get(self,request):
        website = request.GET.get('website')
        # 异步启动扫描任务
        result = checkRun.delay(website)

        # 返回任务 ID 给客户端
        return JsonResponse({'task_id': result.id})

#干脆不要从celery读状态了，直接去数据库读状态
class get_scan_result(LoginRequiredMixin, APIView):
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
            return JsonResponse({'errmsg': 'task_id is required'})
