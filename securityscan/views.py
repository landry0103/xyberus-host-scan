from django.shortcuts import render
from django.http import HttpResponse
from django.utils.decorators import method_decorator
from django.views.generic import TemplateView, View, FormView, UpdateView
from django.contrib.auth import logout
from django.shortcuts import redirect
from django.contrib.auth.mixins import LoginRequiredMixin
from rest_framework.authtoken.models import Token
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
import json
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
import nmap3
from dashboard.models import Scan, ScanTarget, ScanResult
from django.utils import timezone
from django.utils.dateparse import parse_datetime
from threading import Thread
from django.db.models import F

from gvm.connections import UnixSocketConnection
from gvm.protocols.latest import Gmp
from gvm.transforms import EtreeTransform
from gvm.errors import GvmError
import xml.etree.ElementTree as ET
from lxml import etree
import uuid

from zapv2 import ZAPv2
import time

class BaseView(TemplateView):
    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context['is_logged_in'] = self.request.user.is_authenticated
        return context

class HomeView(BaseView):
    template_name = 'home.html'

class TargetView(BaseView):
    template_name = 'targets.html'

class ScanView(BaseView):
    template_name = 'scan/scan.html'
    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        scans = Scan.objects.all()

        for scan in scans:
            if scan.state == 'running' and scan.openvas_task_id:
                self.update_scan_status_and_results(scan)

        context['scans'] = scans
        return context

    def update_scan_status_and_results(self, scan):
        connection = UnixSocketConnection(path='/run/gvmd/gvmd.sock')
        transform = EtreeTransform()
        with Gmp(connection, transform=transform) as gmp:
            gmp.authenticate('admin', 'admin123')
            
            # Check the status of the task
            task_id = scan.openvas_task_id
            report_id = get_report_id(gmp, task_id)
            if report_id:
                report = gmp.get_report(report_id)
                parse_scan_results(report, scan)
                scan.state = 'succeeded'
            else:
                pass
            
            scan.updated_at = timezone.now()
            scan.save(update_fields=['state', 'updated_at'])
            
        # Close the GVM connection
        connection.disconnect()

class PricingView(BaseView):
    template_name = 'price.html'

class DashboardView(BaseView):
    template_name = 'dashboard.html'

class LoginView(TemplateView):
    template_name = 'login.html'

class SignupView(TemplateView):
    template_name = 'signup.html'

def google_logout(request):
    logout(request)
    return redirect('home')

def create_target(gmp, target_name, target_host, port_range):
    response = gmp.create_target(name=target_name, hosts=[target_host], port_range=port_range)
    target_id_element = response.get('id')
    if target_id_element is not None:
        return target_id_element
    else:
        print("ID element not found in response.")
        return None

def get_scan_config_id(gmp, config_name="Full and fast"):
    configs = gmp.get_scan_configs()
    for config in configs.xpath('config'):
        if config.find('name').text == config_name:
            return config.get('id')
    return None

def create_task(gmp, task_name, config_id, target_id, scanner_id):
    response = gmp.create_task(name=task_name, config_id=config_id, target_id=target_id, scanner_id=scanner_id)
    task_id = response.get('id')
    if task_id:
        return task_id
    else:
        print("ID not found in response.")
        return None

def start_task(gmp, task_id):
    response = gmp.start_task(task_id)

def get_report_id(gmp, task_id):
    task = gmp.get_task(task_id)
    status = task.find('.//status').text
    if status == 'Done':
        report_id = task.find('.//last_report/report').get('id')
        return report_id
    else:
        return None

def parse_scan_results(report, scan):
    results = report.findall('.//result')

    if not results:
        print("No scan results found.")
        return

    for result in results:
        host = result.find('.//host').text
        port_info = result.find('.//port')
        port = int(port_info.text.split('/')[0]) if port_info is not None else None
        description = result.find('.//description').text
        threat = result.find('.//threat').text
        severity = result.find('.//severity').text

        ScanResult.objects.create(
            scan=scan,
            port=port,
            state=threat,  # Or any other state you deem appropriate
        )

        print(f"Host: {host}, Port: {port}, Threat: {threat}, Severity: {severity}, Description: {description}")

@csrf_exempt
def scan_test(request):
    if request.method == 'POST':
        zap_api_key = 'zap-api'
        zap = ZAPv2(apikey=zap_api_key, proxies={'http': 'http://127.0.0.1:8080', 'https': 'http://127.0.0.1:8080'})
        target_url = 'https://www.upwork.com/'

        print('___HERE1')
        zap.urlopen(target_url)
        time.sleep(2)
        print('___HERE2')

        alerts = zap.core.alerts(baseurl=target_url)
        print('___HERE3')

        for alert in alerts:
            print(f"Alert: {alert['alert']}")
            print(f"Risk: {alert['risk']}")
            print(f"URL: {alert['url']}")
            print(f"Param: {alert['param']}")
            print(f"Description: {alert['description']}\n")

        return JsonResponse({'message': 'Data inserted successfully!'}, status=201)

    return JsonResponse({'error': 'Invalid request'}, status=400)

@csrf_exempt
def scan_configuration(request):
    if request.method == 'POST':
        try:
            data = json.loads(request.body)
            selected_scans = data.get('selectedScans', [])
            selected_targets = data.get('selectedTargets', [])
            schedule = data.get('schedule')
            start_time = data.get('startTime')
            email_send = data.get('emailSend', 'no')

            start_time_obj = timezone.now() if start_time == 'now' else parse_datetime(start_time)
            schedule_obj = start_time_obj if schedule == 'oneTime' else None

            if "Nmap TCP Port Scan" in selected_scans:
                scan_type = "Nmap TCP Port Scan"
                scan = Scan.objects.create(
                    type=scan_type.lower().replace(" ", "_"),
                    state='pending',
                    schedule=schedule_obj,
                    start_time=start_time_obj,
                    notification=email_send.lower() == 'yes'
                )
                for target in selected_targets:
                    ScanTarget.objects.create(
                        scan=scan,
                        target=target['body']
                    )
                
                # Start a separate thread for the Nmap TCP Port Scan
                Thread(target=run_nmap_tcp_scan, args=(scan, selected_targets)).start()

            if "Nmap UDP Port Scan" in selected_scans:
                scan_type = "Nmap UDP Port Scan"
                scan = Scan.objects.create(
                    type=scan_type.lower().replace(" ", "_"),
                    state='pending',
                    schedule=schedule_obj,
                    start_time=start_time_obj,
                    notification=email_send.lower() == 'yes'
                )
                for target in selected_targets:
                    ScanTarget.objects.create(
                        scan=scan,
                        target=target['body']
                    )
                
                # Start a separate thread for the Nmap UDP Port Scan
                Thread(target=run_nmap_udp_scan, args=(scan, selected_targets)).start()   

            if "OpenVAS Network Vulnerability Scan" in selected_scans:
                scan_type = "OpenVAS Network Vulnerability Scan"
                scan = Scan.objects.create(
                    type=scan_type.lower().replace(" ", "_"),
                    state='pending',
                    schedule=schedule_obj,
                    start_time=start_time_obj,
                    notification=email_send.lower() == 'yes'
                )      
                for target in selected_targets:
                    ScanTarget.objects.create(
                        scan=scan,
                        target=target['body']
                    )    
                Thread(target=run_openvas_scan, args=(scan, selected_targets)).start()   

            if "OWASP ZAP Passive Web Application Scan" in selected_scans:
                scan_type = "OWASP ZAP Passive Web Application Scan"
                scan = Scan.objects.create(
                    type=scan_type.lower().replace(" ", "_"),
                    state='pending',
                    schedule=schedule_obj,
                    start_time=start_time_obj,
                    notification=email_send.lower() == 'yes'
                )      
                for target in selected_targets:
                    ScanTarget.objects.create(
                        scan=scan,
                        target=target['body']
                    )    
                Thread(target=run_zap_passive_scan, args=(scan, selected_targets)).start()   

            if "OWASP ZAP Active Web Application Scan" in selected_scans:
                scan_type = "OWASP ZAP Active Web Application Scan"
                scan = Scan.objects.create(
                    type=scan_type.lower().replace(" ", "_"),
                    state='pending',
                    schedule=schedule_obj,
                    start_time=start_time_obj,
                    notification=email_send.lower() == 'yes'
                )      
                for target in selected_targets:
                    ScanTarget.objects.create(
                        scan=scan,
                        target=target['body']
                    )    
                Thread(target=run_zap_active_scan, args=(scan, selected_targets)).start()   

            return JsonResponse({'message': 'Data inserted successfully!'}, status=201)
        except Exception as e:
            return JsonResponse({'error': str(e)}, status=400)
    else:
        return JsonResponse({'error': 'Invalid HTTP method'}, status=405)

def run_nmap_tcp_scan(scan, selected_targets):
    nmap = nmap3.NmapScanTechniques()
    scan_state = 'error'

    for target_info in selected_targets:
        target = target_info['body']
        result = nmap.nmap_tcp_scan(target)
        ports_info = result.get(target, {}).get('ports', [])

        for port_info in ports_info:
            if port_info.get('state') == 'open':
                ScanResult.objects.create(
                    scan=scan,
                    port=int(port_info.get('portid')),
                    state=port_info.get('state')
                )
                scan_state = 'succeeded'

    scan.state = scan_state
    scan.updated_at = timezone.now()
    scan.save(update_fields=['state', 'updated_at'])

def run_nmap_udp_scan(scan, selected_targets):
    nmap = nmap3.NmapScanTechniques()
    scan_state = 'error'  # Start with a default state of 'pending'

    for target_info in selected_targets:
        target = target_info['body']
        result = nmap.nmap_udp_scan(target)
        ports_info = result.get(target, {}).get('ports', [])

        for port_info in ports_info:
            if port_info.get('state') in ['open', 'open|filtered']:
                ScanResult.objects.create(
                    scan=scan,
                    port=int(port_info.get('portid')),
                    state=port_info.get('state')
                )

        # If the scan is completed (regardless of whether ports are found), set the state to 'success'
        scan_state = 'succeeded'

    scan.state = scan_state
    scan.updated_at = timezone.now()
    scan.save(update_fields=['state', 'updated_at'])

def run_openvas_scan(scan, selected_targets):
    nmap = nmap3.NmapScanTechniques()
    path = '/run/gvmd/gvmd.sock'
    connection = UnixSocketConnection(path=path)
    transform = EtreeTransform()
    scan_state = 'error'

    try:
        with Gmp(connection, transform=transform) as gmp:
            gmp.authenticate('admin', 'admin123')

            for target_info in selected_targets:
                target = target_info['body']
                result = nmap.nmap_tcp_scan(target)
                ports_info = result.get(target, {}).get('ports', [])

                port_numbers = [str(port_info['portid']) for port_info in ports_info if port_info.get('state') == 'open']
                ports_string = ','.join(port_numbers)

                unique_target_name = f"MyTarget_{uuid.uuid4()}"
                unique_scan_name = f"MyScanTask_{uuid.uuid4()}"

                target_id = create_target(gmp, unique_target_name, target, ports_string)
                scanner_id = gmp.get_scanners()[0].get('id')
                config_id = get_scan_config_id(gmp)

                if target_id and scanner_id and config_id:
                    task_id = create_task(gmp, unique_scan_name, config_id, target_id, scanner_id)
                    print(task_id)
                    start_task(gmp, task_id)
                    scan_state = 'running'
                    scan.openvas_task_id = task_id

        scan.state = scan_state
        scan.updated_at = timezone.now()
        scan.save(update_fields=['state', 'updated_at', 'openvas_task_id'])
        
    except Exception as e:
        print(f"Error during scan: {str(e)}")
        scan.state = 'error'
        scan.updated_at = timezone.now()
        scan.save(update_fields=['state', 'updated_at'])

def run_zap_passive_scan(scan, selected_targets):
    zap_api_key = 'zap-api'
    zap = ZAPv2(apikey=zap_api_key, proxies={'http': 'http://127.0.0.1:8080', 'https': 'http://127.0.0.1:8080'})
    scan_state = 'error'

    try:
        for target_info in selected_targets:
            target = target_info['body']
            zap.urlopen(target)
            time.sleep(2)

            alerts = zap.core.alerts(baseurl=target)

            for alert in alerts:
                ScanResult.objects.create(
                    scan=scan,
                    alert=alert['alert'],
                    risk=alert['risk'],
                    url=alert['url'],
                    param=alert['param'],
                    description=alert['description'],
                    state='completed'  # or any other appropriate state
                )
                scan_state = 'succeeded'

        scan.state = scan_state
        scan.updated_at = timezone.now()
        scan.save(update_fields=['state', 'updated_at'])
    except Exception as e:
        print(f"Error during OWASP ZAP scan: {str(e)}")
        scan.state = 'error'
        scan.updated_at = timezone.now()
        scan.save(update_fields=['state', 'updated_at'])

def run_zap_active_scan(scan, selected_targets):
    zap_api_key = 'zap-api'
    zap = ZAPv2(apikey=zap_api_key, proxies={'http': 'http://127.0.0.1:8080', 'https': 'http://127.0.0.1:8080'})
    scan_state = 'error'

    try:
        for target_info in selected_targets:
            target = target_info['body']

            # Spider the target
            print(f'Spidering target {target}')
            spider_id = zap.spider.scan(target)
            while int(zap.spider.status(spider_id)) < 100:
                time.sleep(2)

            # Active Scanning
            print(f'Active scanning target {target}')
            ascan_id = zap.ascan.scan(target)
            while int(zap.ascan.status(ascan_id)) < 100:
                time.sleep(2)

            # Retrieving alerts generated by both passive and active scanning
            alerts = zap.core.alerts(baseurl=target)

            for alert in alerts:
                ScanResult.objects.create(
                    scan=scan,
                    alert=alert['alert'],
                    risk=alert['risk'],
                    url=alert['url'],
                    param=alert['param'],
                    description=alert['description'],
                    state='completed'  # or any other appropriate state
                )
            scan_state = 'succeeded'

        scan.state = scan_state
        scan.updated_at = timezone.now()
        scan.save(update_fields=['state', 'updated_at'])
    except Exception as e:
        print(f"Error during OWASP ZAP active scan: {str(e)}")
        scan.state = 'error'
        scan.updated_at = timezone.now()
        scan.save(update_fields=['state', 'updated_at'])


