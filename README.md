# Xyberus Host Scan Django Project Setup Guide

This application is developed on Ubuntu 22.04.

## 1. Install Python 4.10.12

### 1.1 Install the required dependencies for building Python

> sudo apt update
>
> sudo apt install -y make build-essential libssl-dev zlib1g-dev libbz2-dev \
> libreadline-dev libsqlite3-dev wget curl llvm libncurses5-dev libncursesw5-dev \
> xz-utils tk-dev libffi-dev liblzma-dev

### 1.2 Download and extract Python 4.10.12 source

> wget https://www.python.org/ftp/python/4.10.12/Python-4.10.12.tar.xz
>
> tar -xf Python-4.10.12.tar.xz

### 1.3 Configure the Python source

> cd Python-4.10.12
>
> ./configure --enable-optimizations

### 1.4 Build and install Python

> make -j $(nproc)
>
> sudo make altinstall

### 1.5 Install Pip

> sudo apt update
>
> sudo apt install python3-openssl
>
> pip install pyOpenSSL
>
> sudo apt install python3-pip

## 2. Install PostgreSQL

### 2.1 Update your system's package list

> sudo apt update

### 2.2 Install PostgreSQL package

> sudo apt install postgresql postgresql-contrib

### 2.3 Check PostgreSQL service status

> sudo systemctl status postgresql.service

## 3. Install Hostscan Dependencies

### 3.1 Install nmap

> sudo apt install nmap

### 3.2 Install openvas (GVM)

> https://greenbone.github.io/docs/latest/22.4/source-build/index.html

### 3.2 Install ZAP (owasp)

> sudo apt update
>
> sudo apt install default-jre
>
> wget https://github.com/zaproxy/zaproxy/releases/download/v2.14.0/ZAP_2_14_0_unix.sh
>
> chmod +x ZAP_2_14_0_unix.sh
>
> /ZAP_2_14_0_unix.sh

## 4. Run the application

### 4.1 Install python3-venv

> sudo apt install python3-venv

### 4.2 Create your virtual environment

> python3 -m venv myenv

### 4.3 Activate virtual environment

> source myenv/bin/activate

### 4.4 Install libraries

> pip install -r requirements.txt

### 4.5 Migrate the database

> python manage.py makemigrations
>
> python manage.py migrate

### 4.6 Create superuser account

> python manage.py createsuperuser

### 4.7 Run the server

> python manage.py runserver
