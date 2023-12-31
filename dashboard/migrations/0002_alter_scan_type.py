# Generated by Django 4.2.6 on 2023-11-06 07:49

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('dashboard', '0001_initial'),
    ]

    operations = [
        migrations.AlterField(
            model_name='scan',
            name='type',
            field=models.CharField(choices=[('nmap_tcp_port_scan', 'Nmap TCP Port Scan'), ('nmap_udp_port_scan', 'Nmap UDP Port Scan'), ('openvas_network_vulnerability_scan', 'OpenVAS Network Vulnerability Scan'), ('owasp_zap_passive_web_application_scan', 'OWASP ZAP Passive Web Application Scan'), ('owasp_zap_active_web_application_scan', 'OWASP ZAP Active Web Application Scan'), ('sslyze_tls_ssl_security_scan', 'Sslyze TLS/SSL Security Scan')], max_length=50),
        ),
    ]
