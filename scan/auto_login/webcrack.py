import os
import datetime

from scan.auto_login.crack.crack_task import CrackTask
auto_login_start_info = '''
+---------------------------------------------------+
|                     启动爆破模块                    |
+---------------------------------------------------+
'''


def single_process_crack(url_list):
    all_num = len(url_list)
    cur_num = 1
    print("爆破页面任务数: " + str(all_num))
    for url in url_list:
        username,password = CrackTask().run(cur_num, url)
        if(username):
            return username,password
            break
        cur_num += 1
    return False,False

def run_crack(url_list):
    print(auto_login_start_info)
    try:
        import conf.config
    except:
        print("加载配置文件失败！")
        #exit(0)
    start = datetime.datetime.now()
    username,password = single_process_crack(url_list)
    if username:
        end = datetime.datetime.now()
        print(f'爆破进程结束! 总耗时: {str(end - start)}')
        return username,password
    else:
        return False,False
