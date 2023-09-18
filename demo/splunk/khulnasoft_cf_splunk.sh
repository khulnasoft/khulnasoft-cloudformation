#!/bin/bash
# Install Splunk using Cloudformation template
# Support for Splunk

ssh_username=$(cat /tmp/khulnasoft_cf_settings | grep '^SshUsername:' | cut -d' ' -f2)
ssh_password=$(cat /tmp/khulnasoft_cf_settings | grep '^SshPassword:' | cut -d' ' -f2)
splunk_port="8000"
khulnasoft_version=$(cat /tmp/khulnasoft_cf_settings | grep '^KhulnasoftVersion:' | cut -d' ' -f2 | cut -d'_' -f2)
khulnasoft_major=`echo $khulnasoft_version | cut -d'.' -f1`
khulnasoft_minor=`echo $khulnasoft_version | cut -d'.' -f2`
khulnasoft_patch=`echo $khulnasoft_version | cut -d'.' -f3`
splunk_version=$(cat /tmp/khulnasoft_cf_settings | grep '^SplunkVersion:' | cut -d' ' -f2)
splunk_username=$(cat /tmp/khulnasoft_cf_settings | grep '^SplunkUsername:' | cut -d' ' -f2)
splunk_password=$(cat /tmp/khulnasoft_cf_settings | grep '^SplunkPassword:' | cut -d' ' -f2)
eth0_ip=$(/sbin/ifconfig eth0 | grep 'inet addr:' | cut -d: -f2  | cut -d' ' -f1)
khulnasoft_api_user=$(cat /tmp/khulnasoft_cf_settings | grep '^KhulnasoftApiAdminUsername:' | cut -d' ' -f2)
khulnasoft_api_password=$(cat /tmp/khulnasoft_cf_settings | grep '^KhulnasoftApiAdminPassword:' | cut -d' ' -f2)
khulnasoft_api_port=$(cat /tmp/khulnasoft_cf_settings | grep '^KhulnasoftApiPort:' | cut -d' ' -f2)
TAG="v$khulnasoft_version"
APP_TAG="v$khulnasoft_version-$splunk_version"
APP_TAG="v$khulnasoft_version"
# Creating SSH user
adduser ${ssh_username}
echo "${ssh_username} ALL=(ALL)NOPASSWD:ALL" >> /etc/sudoers
usermod --password $(openssl passwd -1 ${ssh_password}) ${ssh_username}
sed -i 's|[#]*PasswordAuthentication no|PasswordAuthentication yes|g' /etc/ssh/sshd_config
systemctl restart sshd

# Install net-tools, wget, git
yum install net-tools wget git curl -y -q

# download splunk
wget -O splunk-7.3.5-86fd62efc3d7-linux-2.6-x86_64.rpm 'https://khulnasoft-demo.s3-us-west-1.amazonaws.com/splunk-7.3.5-86fd62efc3d7-linux-2.6-x86_64.rpm' &> /dev/null

# install splunk
yum install splunk-7.3.5-86fd62efc3d7-linux-2.6-x86_64.rpm -y &> /dev/null

# add admin user
echo "[user_info]" > /opt/splunk/etc/system/local/user-seed.conf
echo "USERNAME = $splunk_username" >> /opt/splunk/etc/system/local/user-seed.conf
echo "PASSWORD = $splunk_password" >> /opt/splunk/etc/system/local/user-seed.conf

# fetching configuration files
curl -so /opt/splunk/etc/system/local/inputs.conf https://raw.githubusercontent.com/khulnasoft/khulnasoft/${TAG}/extensions/splunk/peer-inputs.conf &> /dev/null
curl -so /opt/splunk/etc/system/local/indexes.conf https://raw.githubusercontent.com/khulnasoft/khulnasoft/${TAG}/extensions/splunk/peer-indexes.conf &> /dev/null

# clone app
git clone -b $APP_TAG --single-branch git://github.com/khulnasoft/khulnasoft-splunk.git &> /dev/null

# install app
cp -R ./khulnasoft-splunk/SplunkAppForKhulnasoft/ /opt/splunk/etc/apps/

# restart splunk
/opt/splunk/bin/splunk start --accept-license --answer-yes --no-prompt &> /dev/null

# curl -XPOST http://${eth0_ip}:${splunk_port}/custom/SplunkAppForKhulnasoft/manager/add_api?url=${khulnasoft_master_ip}&portapi=${khulnasoft_api_port}&userapi=${khulnasoft_api_user}&passapi=${khulnasoft_api_password}
