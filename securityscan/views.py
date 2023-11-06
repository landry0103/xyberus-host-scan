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
from gvm.connections import UnixSocketConnection
from gvm.protocols.gmp import Gmp
from dashboard.models import Scan, ScanTarget
from django.utils import timezone
from django.utils.dateparse import parse_datetime

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
        context['scans'] = Scan.objects.all()  # Add the scans to the context
        return context


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


@csrf_exempt
def scan_configuration(request):
    if request.method == 'POST':
        try:
            data = json.loads(request.body)
            selected_scans = data.get('selectedScans')
            selected_target = data.get('selectedTargets')
            schedule = data.get('schedule')
            start_time = data.get('startTime')
            email_send = data.get('emailSend')

            # Assuming 'now' means to set the start time to the current time
            start_time_obj = timezone.now() if start_time == 'now' else parse_datetime(start_time)

            # Assuming 'oneTime' schedule means a one-time scan, so we set it to the same time as `start_time`
            schedule_obj = start_time_obj if schedule == 'oneTime' else None

            # Create new Scan objects
            for scan_type in selected_scans:
                scan = Scan.objects.create(
                    type=scan_type.lower().replace(" ", "_"),  # Adjust type to match your SCAN_TYPES keys
                    state='pending',  # Assuming a new scan is always in 'pending' state initially
                    schedule=schedule_obj,
                    start_time=start_time_obj,
                    notification=email_send.lower() == 'yes'  # Convert string to boolean
                )
                # Create new ScanTarget objects associated with this scan
                for target in selected_target:
                    nmap = nmap3.NmapScanTechniques()
                    result = nmap.nmap_tcp_scan(target)  # Assuming one target for simplicity
                    ports_info = result.get(target, {}).get('ports', [])
                    open_tcp_ports = [int(port.get('portid')) for port in ports_info if port.get('state') == 'open']
                    print("Open TCP Ports:", open_tcp_ports)
                    ScanTarget.objects.create(
                        scan=scan,
                        target=target['body']  # Assuming 'body' is where the target IP or URL is stored
                    )

            return JsonResponse({'message': 'Data inserted successfully!'}, status=201)
        except Exception as e:
            return JsonResponse({'error': str(e)}, status=400)
    else:
        return JsonResponse({'error': 'Invalid HTTP method'}, status=405)


# path to unix socket
# path = '/run/gvmd/gvmd.sock'
# connection = UnixSocketConnection(path=path)

# # using the with statement to automatically connect and disconnect to gvmd
# with Gmp(connection=connection) as gmp:
#     # get the response message returned as a utf-8 encoded string
#     response = gmp.get_version()

#     # print the response message
#     print(response)

# nmap = nmap3.NmapScanTechniques()
# result = nmap.nmap_tcp_scan("65.108.142.188")
# ports_info = result.get('65.108.142.188', {}).get('ports', [])
# open_tcp_ports = [int(port.get('portid')) for port in ports_info if port.get('state') == 'open']
# print("Open TCP Ports:", open_tcp_ports)