from django.db import models

class Scan(models.Model):
    SCAN_TYPES = (
        ('nmap_tcp_port_scan', 'Nmap TCP Port Scan'),
        ('nmap_udp_port_scan', 'Nmap UDP Port Scan'),
        ('openvas_network_vulnerability_scan', 'OpenVAS Network Vulnerability Scan'),
        ('owasp_zap_passive_web_application_scan', 'OWASP ZAP Passive Web Application Scan'),
        ('owasp_zap_active_web_application_scan', 'OWASP ZAP Active Web Application Scan'),
        ('sslyze_tls_ssl_security_scan', 'Sslyze TLS/SSL Security Scan'),
    )
    
    SCAN_STATES = (
        ('pending', 'Pending'),
        ('running', 'Running'),
        ('succeeded', 'SUCCEEDED'),
        ('error', 'Error'),
    )

    type = models.CharField(max_length=50, choices=SCAN_TYPES)
    state = models.CharField(max_length=50, choices=SCAN_STATES)
    schedule = models.DateTimeField(null=True, blank=True)
    start_time = models.DateTimeField(null=True, blank=True)
    notification = models.BooleanField(default=False)
    openvas_task_id = models.CharField(max_length=100, blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"{self.type} scan, status: {self.state}"


class ScanTarget(models.Model):
    scan = models.ForeignKey(Scan, on_delete=models.CASCADE, related_name='targets')
    target = models.CharField(max_length=200)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return self.target


class ScanResult(models.Model):
    scan = models.ForeignKey(Scan, related_name='results', on_delete=models.CASCADE)
    port = models.IntegerField(null=True, blank=True)  # Ports might not be relevant for all scan types
    state = models.CharField(max_length=100)
    description = models.TextField(blank=True, null=True)
    alert = models.CharField(max_length=255, blank=True, null=True)
    risk = models.CharField(max_length=50, blank=True, null=True)
    url = models.CharField(max_length=200, blank=True, null=True)
    param = models.CharField(max_length=200, blank=True, null=True)

    def __str__(self):
        return f"Scan {self.scan.id} - Alert: {self.alert}, Risk: {self.risk}"
