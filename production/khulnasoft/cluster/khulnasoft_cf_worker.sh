#!/bin/bash
# Install Khulnasoft worker instance using Cloudformation template
# Support for Amazon Linux
touch /tmp/log
echo "Starting process." >> /tmp/log

ssh_username=$(cat /tmp/khulnasoft_cf_settings | grep '^SshUsername:' | cut -d' ' -f2)
ssh_password=$(cat /tmp/khulnasoft_cf_settings | grep '^SshPassword:' | cut -d' ' -f2)
elastic_version=$(cat /tmp/khulnasoft_cf_settings | grep '^Elastic_Khulnasoft:' | cut -d' ' -f2 | cut -d'_' -f1)
khulnasoft_version=$(cat /tmp/khulnasoft_cf_settings | grep '^Elastic_Khulnasoft:' | cut -d' ' -f2 | cut -d'_' -f2)
khulnasoft_server_port=$(cat /tmp/khulnasoft_cf_settings | grep '^KhulnasoftServerPort:' | cut -d' ' -f2)
khulnasoft_cluster_key=$(cat /tmp/khulnasoft_cf_settings | grep '^KhulnasoftClusterKey:' | cut -d' ' -f2)
khulnasoft_master_ip=$(cat /tmp/khulnasoft_cf_settings | grep '^KhulnasoftMasterIP:' | cut -d' ' -f2)
elb_elasticsearch=$(cat /tmp/khulnasoft_cf_settings | grep '^ElbElasticDNS:' | cut -d' ' -f2)
InstallType=$(cat /tmp/khulnasoft_cf_settings | grep '^InstallType:' | cut -d' ' -f2)
branch=$(cat /tmp/khulnasoft_cf_settings | grep '^Branch:' | cut -d' ' -f2)
TAG="v$khulnasoft_version"

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   echo "This script must be run as root"
   exit 1
fi

# Creating SSH user
adduser ${ssh_username}
echo "${ssh_username} ALL=(ALL)NOPASSWD:ALL" >> /etc/sudoers
usermod --password $(openssl passwd -1 ${ssh_password}) ${ssh_username}
sed -i 's|[#]*PasswordAuthentication no|PasswordAuthentication yes|g' /etc/ssh/sshd_config
systemctl restart sshd
echo "Created SSH user." >> /tmp/log

if [[ ${InstallType} == 'packages' ]]
then
cat > /etc/yum.repos.d/khulnasoft.repo <<\EOF
[khulnasoft_repo]
gpgcheck=1
gpgkey=https://packages.khulnasoft.com/key/GPG-KEY-KHULNASOFT
enabled=1
name=Khulnasoft repository
baseurl=https://packages.khulnasoft.com/4.x/yum/
protect=1
EOF
yum install khulnasoft-manager -y
elif [[ ${InstallType} == 'sources' ]]
then

  # Compile Khulnasoft manager from sources
  BRANCH=$branch

  yum install make gcc policycoreutils-python automake autoconf libtool -y
  curl -Ls https://github.com/khulnasoft/khulnasoft/archive/$BRANCH.tar.gz | tar zx
  rm -f $BRANCH.tar.gz
  cd khulnasoft-$BRANCH/src
  make TARGET=agent DEBUG=1 -j8

  USER_LANGUAGE="en" \
  USER_NO_STOP="y" \
  USER_INSTALL_TYPE="server" \
  USER_DIR="/var/ossec" \
  USER_ENABLE_EMAIL="n" \
  USER_ENABLE_SYSCHECK="y" \
  USER_ENABLE_ROOTCHECK="y" \
  USER_ENABLE_OPENSCAP="n" \
  USER_WHITE_LIST="n" \
  USER_ENABLE_SYSLOG="n" \
  USER_ENABLE_AUTHD="y" \
  USER_AUTO_START="y" \
  THREADS=2 \
  ../install.sh
  echo "Compiled khulnasoft" >> /tmp/deploy.log

else
	echo 'no repo' >> /tmp/stage
fi

# Configuring Elastic repository
rpm --import https://packages.elastic.co/GPG-KEY-elasticsearch
elastic_major_version=$(echo ${elastic_version} | cut -d'.' -f1)
cat > /etc/yum.repos.d/elastic.repo << EOF
[elasticsearch-${elastic_major_version}.x]
name=Elasticsearch repository for ${elastic_major_version}.x packages
baseurl=https://artifacts.elastic.co/packages/${elastic_major_version}.x/yum
gpgcheck=1
gpgkey=https://artifacts.elastic.co/GPG-KEY-elasticsearch
enabled=1
autorefresh=1
type=rpm-md
EOF

# Installing khulnasoft-manager
yum -y install khulnasoft-manager-$khulnasoft_version-1
systemctl enable khulnasoft-manager
chkconfig --add khulnasoft-manager
manager_config="/var/ossec/etc/ossec.conf"

# Install dependencies
echo "Installed khulnasoft manager package" >> /tmp/log

# Set manager ports for agents communication
sed -i "s/<port>1514<\/port>/<port>${khulnasoft_server_port}<\/port>/" ${manager_config}

# Installing Python Cryptography module for the cluster
pip install cryptography
echo "Installed cryptography with pip" >> /tmp/log

# Configuring cluster section
sed -i '/<cluster>/,/<\/cluster>/d' ${manager_config}

cat >> ${manager_config} << EOF
<ossec_config>
  <cluster>
    <name>khulnasoft</name>
    <node_name>khulnasoft-worker</node_name>
    <node_type>worker</node_type>
    <key>${khulnasoft_cluster_key}</key>
    <port>1516</port>
    <bind_addr>0.0.0.0</bind_addr>
    <nodes>
        <node>${khulnasoft_master_ip}</node>
    </nodes>
    <hidden>no</hidden>
    <disabled>no</disabled>
  </cluster>
</ossec_config>
EOF

# Restart for receiving cluster data
systemctl restart khulnasoft-manager
# Wait for cluster information to be received (rules,lists...)
sleep 60

echo "Cluster configuration" >> /tmp/log

# Restart khulnasoft-manager
systemctl restart khulnasoft-manager

# Installing Filebeat
yum -y install filebeat-${elastic_version}
echo "Installed Filebeat" >> /tmp/log

# Configuring Filebeat
khulnasoft_major=`echo $khulnasoft_version | cut -d'.' -f1`
khulnasoft_minor=`echo $khulnasoft_version | cut -d'.' -f2`
khulnasoft_patch=`echo $khulnasoft_version | cut -d'.' -f3`
elastic_minor_version=$(echo ${elastic_version} | cut -d'.' -f2)
elastic_patch_version=$(echo ${elastic_version} | cut -d'.' -f3)

# Install Filebeat module
curl -s "https://packages.khulnasoft.com/4.x/filebeat/khulnasoft-filebeat-0.1.tar.gz" | tar -xvz -C /usr/share/filebeat/module

# Get Filebeat configuration file
curl -so /etc/filebeat/filebeat.yml https://raw.githubusercontent.com/khulnasoft/khulnasoft/${TAG}/extensions/filebeat/7.x/filebeat.yml

# Elasticsearch template
curl -so /etc/filebeat/khulnasoft-template.json https://raw.githubusercontent.com/khulnasoft/khulnasoft/${TAG}/extensions/elasticsearch/7.x/khulnasoft-template.json

# File permissions
chmod go-w /etc/filebeat/filebeat.yml
chmod go-w /etc/filebeat/khulnasoft-template.json

# Point to Elasticsearch cluster
sed -i "s|'http://YOUR_ELASTIC_SERVER_IP:9200'|'10.0.2.123','10.0.2.124','10.0.2.125'|" /etc/filebeat/filebeat.yml

# Filebeat security
echo "output.elasticsearch.username: "elastic"" >> /etc/filebeat/filebeat.yml
echo "output.elasticsearch.password: "$ssh_password"" >> /etc/filebeat/filebeat.yml

# Create certs folder
mkdir -p /etc/filebeat/certs/ca

amazon-linux-extras install epel -y
yum install -y sshpass
sleep 500
echo $ssh_password >> pass
sshpass -f pass scp -o "StrictHostKeyChecking=no" $ssh_username@10.0.2.124:/home/$ssh_username/certs.zip /home/$ssh_username/
rm pass -f
cp /home/$ssh_username/certs.zip .
unzip certs.zip
cp ca/ca.crt /etc/filebeat/certs/ca
cp khulnasoft-worker/khulnasoft-worker.crt /etc/filebeat/certs
cp khulnasoft-worker/khulnasoft-worker.key /etc/filebeat/certs
chmod 770 -R /etc/filebeat/certs
echo "output.elasticsearch.protocol: https" >> /etc/filebeat/filebeat.yml
echo "output.elasticsearch.ssl.certificate: "/etc/filebeat/certs/khulnasoft-worker.crt"" >> /etc/filebeat/filebeat.yml
echo "output.elasticsearch.ssl.key: "/etc/filebeat/certs/khulnasoft-worker.key"" >> /etc/filebeat/filebeat.yml
echo "output.elasticsearch.ssl.certificate_authorities: ["/etc/filebeat/certs/ca/ca.crt"]" >> /etc/filebeat/filebeat.yml
systemctl enable filebeat
echo "Enabled Filebeat" >> /tmp/log
systemctl restart filebeat
echo "Started Filebeat" >> /tmp/log
echo "Done" >> /tmp/log
