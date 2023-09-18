#!/bin/bash
# Install Khulnasoft agent using Cloudformation template
# Support for Debian/Ubuntu
touch /tmp/log
echo "Starting process." > /tmp/log
agent_name=$(cat /tmp/khulnasoft_cf_settings | grep '^agent_name:' | cut -d' ' -f2)
ssh_username=$(cat /tmp/khulnasoft_cf_settings | grep '^SshUsername:' | cut -d' ' -f2)
khulnasoft_version=$(cat /tmp/khulnasoft_cf_settings | grep '^Elastic_Khulnasoft:' | cut -d' ' -f2 | cut -d'_' -f2)
khulnasoft_major=`echo $khulnasoft_version | cut -d'.' -f1`
khulnasoft_minor=`echo $khulnasoft_version | cut -d'.' -f2`
khulnasoft_patch=`echo $khulnasoft_version | cut -d'.' -f3`
branch=$(cat /tmp/khulnasoft_cf_settings | grep '^Branch:' | cut -d' ' -f2)
master_ip=$(cat /tmp/khulnasoft_cf_settings | grep '^KhulnasoftMasterIP:' | cut -d' ' -f2)
elb_khulnasoft_dns=$(cat /tmp/khulnasoft_cf_settings | grep '^ElbKhulnasoftDNS:' | cut -d' ' -f2)
ssh_password=$(cat /tmp/khulnasoft_cf_settings | grep '^SshPassword:' | cut -d' ' -f2)
khulnasoft_registration_password=$(cat /tmp/khulnasoft_cf_settings | grep '^KhulnasoftRegistrationPassword:' | cut -d' ' -f2)
khulnasoft_version=$(cat /tmp/khulnasoft_cf_settings | grep '^Elastic_Khulnasoft:' | cut -d' ' -f2 | cut -d'_' -f2)
manager_config='/var/ossec/etc/ossec.conf'
EnvironmentType=$(cat /tmp/khulnasoft_cf_settings | grep '^EnvironmentType:' | cut -d' ' -f2)

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   echo "This script must be run as root"
   exit 1
fi

# Add SSH user
adduser ${ssh_username}
echo "${ssh_username} ALL=(ALL)NOPASSWD:ALL" >> /etc/sudoers
usermod --password $(openssl passwd -1 ${ssh_password}) ${ssh_username}
sed -i 's|[#]*PasswordAuthentication no|PasswordAuthentication yes|g' /etc/ssh/sshd_config
systemctl restart sshd

if [ ! -f /usr/bin/python ]; then ln -s /usr/bin/python3 /usr/bin/python; fi

# Adding Khulnasoft repository
if [[ ${EnvironmentType} == 'staging' ]]
then
    curl -s https://s3-us-west-1.amazonaws.com/packages-dev.khulnasoft.com/key/GPG-KEY-KHULNASOFT | apt-key add -
    echo "deb https://s3-us-west-1.amazonaws.com/packages-dev.khulnasoft.com/pre-release/apt/ unstable main" | tee -a /etc/apt/sources.list.d/khulnasoft_pre_release.list
elif [[ ${EnvironmentType} == 'production' ]]
then
    curl -s https://packages.khulnasoft.com/key/GPG-KEY-KHULNASOFT | apt-key add -
    echo "deb https://packages.khulnasoft.com/3.x/apt/ stable main" | tee -a /etc/apt/sources.list.d/khulnasoft.list
elif [[ ${EnvironmentType} == 'devel' ]]
then
    curl -s https://s3-us-west-1.amazonaws.com/packages-dev.khulnasoft.com/key/GPG-KEY-KHULNASOFT | apt-key add -
    echo "deb https://s3-us-west-1.amazonaws.com/packages-dev.khulnasoft.com/staging/apt/ unstable main" | tee -a /etc/apt/sources.list.d/khulnasoft_staging.list
elif [[ ${EnvironmentType} == 'sources' ]]
then

  # Compile Khulnasoft manager from sources
  BRANCH="$branch"

  apt install make gcc libc6-dev curl policycoreutils automake autoconf libtool -y

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
# Install Khulnasoft agent
apt-get update
apt-get install curl apt-transport-https lsb-release -y
echo "Installed dependencies." > /tmp/log

# Install Khulnasoft agent
apt-get install khulnasoft-agent=$khulnasoft_version-* -y
echo "Installed Khulnasoft agent." > /tmp/log

# Add registration password
echo "${khulnasoft_registration_password}" > /var/ossec/etc/authd.pass
echo "Set registration password." > /tmp/log
echo "Registering agent..." > /tmp/log

# Setting Khulnasoft NLB DNS name
sed -i 's:MANAGER_IP:'${elb_khulnasoft_dns}':g' ${manager_config}

# Change manager protocol to tcp, to be used by Amazon ELB
sed -i "s/<protocol>udp<\/protocol>/<protocol>tcp<\/protocol>/" ${manager_config}

# Register agent using authd
until `cat /var/ossec/logs/ossec.log | grep -q "Valid key created. Finished."`
do
  /var/ossec/bin/agent-auth -m ${master_ip} -A Ubuntu < /tmp/log
  sleep 1
done
echo "Agent registered." > /tmp/log

# Enable and restart the Khulnasoft agent
systemctl enable khulnasoft-agent
systemctl restart khulnasoft-agent
echo "Agent restarted." > /tmp/log
