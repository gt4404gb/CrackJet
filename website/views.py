from django.shortcuts import render

# Create your views here.
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
import json
import os
import sys
from django.http import HttpResponse

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