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
VirusTotalKey=$(cat /tmp/khulnasoft_cf_settings | grep '^VirusTotalKey:' | cut -d' ' -f2)
AwsSecretKey=$(cat /tmp/khulnasoft_cf_settings | grep '^AwsSecretKey:' | cut -d' ' -f2)
AwsAccessKey=$(cat /tmp/khulnasoft_cf_settings | grep '^AwsAccessKey:' | cut -d' ' -f2)
SlackHook=$(cat /tmp/khulnasoft_cf_settings | grep '^SlackHook:' | cut -d' ' -f2)
EnvironmentType=$(cat /tmp/khulnasoft_cf_settings | grep '^EnvironmentType:' | cut -d' ' -f2)
splunk_username=$(cat /tmp/khulnasoft_cf_settings | grep '^SplunkUsername:' | cut -d' ' -f2)
splunk_password=$(cat /tmp/khulnasoft_cf_settings | grep '^SplunkPassword:' | cut -d' ' -f2)
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

if [[ ${EnvironmentType} == 'staging' ]]
then
	# Adding Khulnasoft pre_release repository
	echo -e '[khulnasoft_pre_release]\ngpgcheck=1\ngpgkey=https://s3-us-west-1.amazonaws.com/packages-dev.khulnasoft.com/key/GPG-KEY-KHULNASOFT\nenabled=1\nname=EL-$releasever - Khulnasoft\nbaseurl=https://s3-us-west-1.amazonaws.com/packages-dev.khulnasoft.com/pre-release/yum/\nprotect=1' | tee /etc/yum.repos.d/khulnasoft_pre.repo
elif [[ ${EnvironmentType} == 'production' ]]
then
cat > /etc/yum.repos.d/khulnasoft.repo <<\EOF
[khulnasoft_repo]
gpgcheck=1
gpgkey=https://packages.khulnasoft.com/key/GPG-KEY-KHULNASOFT
enabled=1
name=Khulnasoft repository
baseurl=https://packages.khulnasoft.com/3.x/yum/
protect=1
EOF
elif [[ ${EnvironmentType} == 'devel' ]]
then
	echo -e '[khulnasoft_staging]\ngpgcheck=1\ngpgkey=https://s3-us-west-1.amazonaws.com/packages-dev.khulnasoft.com/key/GPG-KEY-KHULNASOFT\nenabled=1\nname=EL-$releasever - Khulnasoft\nbaseurl=https://s3-us-west-1.amazonaws.com/packages-dev.khulnasoft.com/staging/yum/\nprotect=1' | tee /etc/yum.repos.d/khulnasoft_staging.repo
elif [[ ${EnvironmentType} == 'sources' ]]
then

  # Compile Khulnasoft manager from sources
  BRANCH="$branch"

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
yum -y install khulnasoft-manager-$khulnasoft_version
systemctl enable khulnasoft-manager
chkconfig --add khulnasoft-manager
manager_config="/var/ossec/etc/ossec.conf"
# Install dependencies
yum -y install openscap-scanner

echo "Installed khulnasoft manager package" >> /tmp/log

# Change manager protocol to tcp, to be used by Amazon ELB
sed -i "s/<protocol>udp<\/protocol>/<protocol>tcp<\/protocol>/" ${manager_config}

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

# Disabling agent components and cleaning configuration file
sed -i '/<wodle name="open-scap">/,/<\/wodle>/d' ${manager_config}
sed -i '/<wodle name="cis-cat">/,/<\/wodle>/d' ${manager_config}
sed -i '/<ruleset>/,/<\/ruleset>/d' ${manager_config}
sed -i '/<auth>/,/<\/auth>/d' ${manager_config}
sed -i '/<wodle name="syscollector">/,/<\/wodle>/d' ${manager_config}
sed -i '/<wodle name="vulnerability-detector">/,/<\/wodle>/d' ${manager_config}
sed -i '/<localfile>/,/<\/localfile>/d' ${manager_config}
sed -i '/<!--.*-->/d' ${manager_config}
sed -i '/<!--/,/-->/d' ${manager_config}
sed -i '/^$/d' ${manager_config}


# Add ruleset and lists
cat >> ${manager_config} << EOF
<ossec_config>
  <ruleset>
    <!-- Default ruleset -->
    <decoder_dir>ruleset/decoders</decoder_dir>
    <rule_dir>ruleset/rules</rule_dir>
    <rule_exclude>0215-policy_rules.xml</rule_exclude>
    <list>etc/lists/audit-keys</list>
    <list>etc/lists/amazon/aws-eventnames</list>
    <list>etc/lists/security-eventchannel</list>
    <list>etc/lists/blacklist-alienvault</list>
    <!-- User-defined ruleset -->
    <decoder_dir>etc/decoders</decoder_dir>
    <rule_dir>etc/rules</rule_dir>
  </ruleset>
</ossec_config>
EOF

cat >> ${manager_config} << EOF
<ossec_config>
  <wodle name="open-scap">
    <disabled>no</disabled>
    <timeout>1800</timeout>
    <interval>1d</interval>
    <scan-on-start>yes</scan-on-start>
    <content type="xccdf" path="ssg-rhel-7-ds.xml">
      <profile>xccdf_org.ssgproject.content_profile_pci-dss</profile>
      <profile>xccdf_org.ssgproject.content_profile_common</profile>
    </content>
    <content type="xccdf" path="cve-redhat-7-ds.xml"/>
  </wodle>
</ossec_config>
EOF

# Add VirusTotal integration if key already set
if [ "x${VirusTotalKey}" != "x" ]; then
cat >> ${manager_config} << EOF
<ossec_config>
  <integration>
      <name>virustotal</name>
      <api_key>${VirusTotalKey}</api_key>
      <rule_id>100200</rule_id>
      <alert_format>json</alert_format>
  </integration>
</ossec_config>
EOF
fi


# Slack integration
if [ "x${SlackHook}" != "x" ]; then
cat >> ${manager_config} << EOF
<ossec_config>
  <integration>
    <name>slack</name>
    <hook_url>${SlackHook}</hook_url>
    <level>12</level>
    <alert_format>json</alert_format>
  </integration>
</ossec_config>
EOF
fi

the_uid=$(id -u $ssh_username)

# Audit rules
cat >> /etc/audit/rules.d/audit.rules << EOF
-a exit,always -F euid=${the_uid} -F arch=b32 -S execve -k audit-khulnasoft-c
-a exit,always -F euid=${the_uid} -F arch=b64 -S execve -k audit-khulnasoft-c
EOF

auditctl -D
auditctl -R /etc/audit/rules.d/audit.rules
systemctl restart auditd

# Localfiles
cat >> ${manager_config} << EOF
<ossec_config>
  <localfile>
    <log_format>full_command</log_format>
    <alias>process list</alias>
    <command>ps -e -o pid,uname,command</command>
    <frequency>30</frequency>
  </localfile>
  <command>
    <name>firewall-drop</name>
    <executable>firewall-drop.sh</executable>
    <expect>srcip</expect>
    <timeout_allowed>yes</timeout_allowed>
  </command>

  <active-response>
    <command>firewall-drop</command>
    <location>local</location>
    <rules_id>100100</rules_id>
    <timeout>60</timeout>
  </active-response>
</ossec_config>
EOF

# Vuln detector
cat >> ${manager_config} << EOF
<ossec_config>
  <wodle name="vulnerability-detector">
    <disabled>no</disabled>
    <interval>12m</interval>
    <ignore_time>6h</ignore_time>
    <run_on_start>yes</run_on_start>
    <feed name="ubuntu-18">
      <disabled>no</disabled>
      <update_interval>1h</update_interval>
    </feed>
    <feed name="redhat">
      <disabled>no</disabled>
      <update_from_year>2010</update_from_year>
      <update_interval>1h</update_interval>
    </feed>
    <feed name="debian-9">
      <disabled>no</disabled>
      <update_interval>1h</update_interval>
    </feed>
  </wodle>
</ossec_config>
EOF


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
curl -s "https://packages.khulnasoft.com/3.x/filebeat/khulnasoft-filebeat-0.1.tar.gz" | tar -xvz -C /usr/share/filebeat/module

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

# Setting up Splunk Forwarder
yum -y install wget
# download splunkforwarder
echo 'Downloading Splunk Forwarder...'
wget -O splunkforwarder-7.2.3-06d57c595b80-linux-2.6-x86_64.rpm 'https://www.splunk.com/bin/splunk/DownloadActivityServlet?architecture=x86_64&platform=linux&version=7.2.3&product=universalforwarder&filename=splunkforwarder-7.2.3-06d57c595b80-linux-2.6-x86_64.rpm&wget=true' &> /dev/null

# install splunkforwarder
echo 'Installing Splunk Forwarder...'
yum install splunkforwarder-7.2.3-06d57c595b80-linux-2.6-x86_64.rpm -y -q &> /dev/null

echo "Setting up Splunk forwarder..."
# props.conf
curl -so /opt/splunkforwarder/etc/system/local/props.conf https://raw.githubusercontent.com/khulnasoft/khulnasoft/${TAG}/extensions/splunk/props.conf

# inputs.conf
curl -so /opt/splunkforwarder/etc/system/local/inputs.conf https://raw.githubusercontent.com/khulnasoft/khulnasoft/${TAG}/extensions/splunk/inputs.conf

# set hostname
sed -i "s:MANAGER_HOSTNAME:$(hostname):g" /opt/splunkforwarder/etc/system/local/inputs.conf

# create credential file
touch /opt/splunkforwarder/etc/system/local/user-seed.conf

# add admin user
echo "[user_info]" > /opt/splunkforwarder/etc/system/local/user-seed.conf
echo "USERNAME = $splunk_username" >> /opt/splunkforwarder/etc/system/local/user-seed.conf
echo "PASSWORD = $splunk_password" >> /opt/splunkforwarder/etc/system/local/user-seed.conf

echo "Starting Splunk..."
# accept license
/opt/splunkforwarder/bin/splunk start --accept-license --answer-yes --auto-ports --no-prompt &> /dev/null

# forward to index
/opt/splunkforwarder/bin/splunk add forward-server ${splunk_ip}:9997 -auth $splunk_username:$splunk_password &> /dev/null

# restart service
/opt/splunkforwarder/bin/splunk restart &> /dev/null
echo "Done with Splunk." >> /tmp/log


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
