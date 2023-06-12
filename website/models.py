import uuid
from django.db import models

# Create your models here.
class TaskInfo(models.Model):
    id = models.AutoField(primary_key=True)
    task = models.CharField(max_length=50)

class Project(models.Model):
    ID = models.AutoField(primary_key=True, verbose_name='项目ID（唯一值）')
    status = models.CharField(max_length=255, null=True, verbose_name='项目运行状态')
    projectname = models.CharField(max_length=255, null=True, verbose_name='项目名称（可自定义）')

    class Meta:
        db_table = 'project'


# Create your models here.
class Website(models.Model):
    UID = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False, verbose_name='网址UUID（唯一值）')
    site = models.CharField(max_length=255, verbose_name='需要扫描的网址')
    status = models.CharField(max_length=255, null=True, verbose_name='URL扫描运行状态')
    is_scan = models.IntegerField(null=True, verbose_name='是否扫描,0是未扫描，1是已扫描')
    is_weak = models.IntegerField(null=True, verbose_name='是否存在弱密码，0是不存在，1是存在')
    username = models.CharField(max_length=255, null=True, verbose_name='可成功登陆的账号')
    password = models.CharField(max_length=255, null=True, verbose_name='可成功登录的密码')
    project = models.ForeignKey(Project, on_delete=models.CASCADE, null=True, verbose_name='所属的项目')

    class Meta:
        db_table = 'website'
