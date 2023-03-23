from django.db import models

# Create your models here.
class Project(models.Model):
    ID = models.IntegerField(primary_key=True, verbose_name='项目ID（唯一值）')
    status = models.IntegerField(null=True, verbose_name='项目运行状态')
    projectname = models.CharField(max_length=255, null=True, verbose_name='项目名称（可自定义）')

    class Meta:
        db_table = 'project'


class User(models.Model):
    ID = models.IntegerField(primary_key=True)
    username = models.CharField(max_length=255, null=True)
    password = models.CharField(max_length=255, null=True)

    class Meta:
        db_table = 'user'


class Website(models.Model):
    UID = models.CharField(max_length=255, primary_key=True, verbose_name='网址ID（唯一值）')
    site = models.CharField(max_length=255, null=True, verbose_name='需要扫描的网址')
    is_scan = models.IntegerField(null=True, verbose_name='是否扫描')
    is_weak = models.IntegerField(null=True, verbose_name='是否存在弱密码')
    username = models.CharField(max_length=255, null=True, verbose_name='可成功登陆的账号')
    password = models.CharField(max_length=255, null=True, verbose_name='可成功登录的密码')
    project = models.ForeignKey(Project, on_delete=models.CASCADE, null=True, verbose_name='所属的项目')

    class Meta:
        db_table = 'website'
