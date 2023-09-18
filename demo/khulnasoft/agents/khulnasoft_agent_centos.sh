#!/bin/bash
# Install Khulnasoft agent using Cloudformation template
# Deployment for Amazon Linux agent

touch /tmp/log
echo "Starting process." > /tmp/log

agent_name=$(cat /tmp/khulnasoft_cf_settings | grep '^AgentName:' | cut -d' ' -f2)
ssh_username=$(cat /tmp/khulnasoft_cf_settings | grep '^SshUsername:' | cut -d' ' -f2)
khulnasoft_version=$(cat /tmp/khulnasoft_cf_settings | grep '^Elastic_Khulnasoft:' | cut -d' ' -f2 | cut -d'_' -f2)
khulnasoft_major=`echo $khulnasoft_version | cut -d'.' -f1`
khulnasoft_minor=`echo $khulnasoft_version | cut -d'.' -f2`
khulnasoft_patch=`echo $khulnasoft_version | cut -d'.' -f3`
branch=$(cat /tmp/khulnasoft_cf_settings | grep '^Branch:' | cut -d' ' -f2)
master_ip=$(cat /tmp/khulnasoft_cf_settings | grep '^KhulnasoftMasterIP:' | cut -d' ' -f2)
elb_khulnasoft_dns=$(cat /tmp/khulnasoft_cf_settings | grep '^ElbKhulnasoftDNS:' | cut -d' ' -f2)
ssh_password=$(cat /tmp/khulnasoft_cf_settings | grep '^SshPassword:' | cut -d' ' -f2)
khulnasoft_server_port=$(cat /tmp/khulnasoft_cf_settings | grep '^KhulnasoftServerPort:' | cut -d' ' -f2)
khulnasoft_registration_password=$(cat /tmp/khulnasoft_cf_settings | grep '^KhulnasoftRegistrationPassword:' | cut -d' ' -f2)
manager_config='/var/ossec/etc/ossec.conf'
EnvironmentType=$(cat /tmp/khulnasoft_cf_settings | grep '^EnvironmentType:' | cut -d' ' -f2)

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   echo "This script must be run as root"
   exit 1
fi
echo "Env vars completed." >> /tmp/log

# Add SSH user
adduser ${ssh_username}
echo "${ssh_username} ALL=(ALL)NOPASSWD:ALL" >> /etc/sudoers
usermod --password $(openssl passwd -1 ${ssh_password}) ${ssh_username}
sed -i 's|[#]*PasswordAuthentication no|PasswordAuthentication yes|g' /etc/ssh/sshd_config
systemctl restart sshd

# Adding Khulnasoft repository
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
  BRANCH=$branch

  yum install make gcc policycoreutils-python automake autoconf libtool -y
  curl -Ls https://github.com/khulnasoft/khulnasoft/archive/$BRANCH.tar.gz | tar zx
  rm -f $BRANCH.tar.gz
  cd khulnasoft-$BRANCH/src
  make TARGET=agent DEBUG=1 -j8
  USER_LANGUAGE="en" \
  USER_NO_STOP="y" \
  USER_INSTALL_TYPE="agent" \
  USER_DIR="/var/ossec" \
  USER_ENABLE_ACTIVE_RESPONSE="y" \
  USER_ENABLE_SYSCHECK="y" \
  USER_ENABLE_ROOTCHECK="y" \
  USER_ENABLE_OPENSCAP="n" \
  USER_AGENT_SERVER_IP="${master_ip}" \
  USER_CA_STORE="/var/ossec/wpk_root.pem" \
  USER_ENABLE_SCA="y" \
  THREADS=2 \
  ../install.sh
  echo "Compiled khulnasoft" >> /tmp/deploy.log

else
	echo 'no repo' >> /tmp/stage
fi

# Installing khulnasoft-manager
yum -y install khulnasoft-agent-$khulnasoft_version
echo "Installed Khulnasoft agent." >> /tmp/log

# Change manager protocol to tcp, to be used by Amazon ELB
sed -i "s/<protocol>udp<\/protocol>/<protocol>tcp<\/protocol>/" ${manager_config}

# Set manager port for agent communications
sed -i "s/<port>1514<\/port>/<port>${khulnasoft_server_port}<\/port>/" ${manager_config}

# Setting password for agents registration
echo "${khulnasoft_registration_password}" > /var/ossec/etc/authd.pass
echo "Set Khulnasoft password registration." >> /tmp/log

# Register agent using authd
/var/ossec/bin/agent-auth -m ${master_ip} -A ${agent_name}
sed -i 's:MANAGER_IP:'${elb_khulnasoft_dns}':g' ${manager_config}
echo "Registered Khulnasoft agent." >> /tmp/log

# Restart khulnasoft-manager
systemctl restart khulnasoft-agent
echo "Restarted Khulnasoft agent." >> /tmp/log
