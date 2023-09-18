# Note

This repository has been archived and is no longer maintained.

# Khulnasoft for Amazon AWS Cloudformation

[![Slack](https://img.shields.io/badge/slack-join-blue.svg)](https://goo.gl/forms/M2AoZC4b2R9A9Zy12)
[![Email](https://img.shields.io/badge/email-join-blue.svg)](https://groups.google.com/forum/#!forum/khulnasoft)
[![Documentation](https://img.shields.io/badge/docs-view-green.svg)](https://documentation.khulnasoft.com)
[![Web](https://img.shields.io/badge/web-view-green.svg)](https://khulnasoft.com)

This repository contains CloudFormation templates and provision scripts to deploy both a Khulnasoft production-ready environment and a Khulnasoft demo environment in Amazon Web Services (AWS):

## Production-ready environment:

* A VPC with two subnets, one for Khulnasoft servers, and another for Elastic Stack
* Khulnasoft managers cluster with two nodes, a master and a worker
* An Elasticsearch cluster with a minimum of 3 data nodes, auto-scalable to a maximum of 6 nodes
* A Kibana node that includes a local elasticsearch client node, and an Nginx for HTTP basic authentication
* Khulnasoft servers sit behind an internet-facing load balancer for agents to communicate with the cluster
* Kibana server sit behind an internet facing load balancer, that optionally loads an SSL Certificate for HTTPS
* Route53 DNS records for the loadbalancer, Khulnasoft and Elastic Stack nodes (optional).

## Demo environment:

* A VPC with two subnets, one for Khulnasoft servers, and another for Elastic Stack
* Khulnasoft managers cluster with two nodes, a master and a worker
* An Elasticsearch cluster with a minimum of 3 data nodes, auto-scalable to a maximum of 6 nodes
* A Kibana node that includes a local elasticsearch client node, and an Nginx for HTTP basic authentication
* Khulnasoft servers sit behind an internet-facing load balancer for agents to communicate with the cluster
* Kibana server sit behind an internet facing load balancer, that optionally loads an SSL Certificate for HTTPS
* A Splunk Indexer instance with a Splunk app for Khulnasoft installed on it.
* Six Khulnasoft agents installed on different operating systems: Red Hat 7, CentOS 7, Ubuntu, Debian, Amazon Linux and Windows.

## Unattendend all-in-one

* Use install script, following [Khulnasoft unattended all-in-one installation](https://documentation.khulnasoft.com/current/installation-guide/open-distro/all-in-one-deployment/unattended-installation.html)
* Resources:
    - KhulnasoftAIO: EC2 instance
    - SecurityGroup: EC2 Security Group. It enables the following ports:
        - 443 ( HTTPS) -> 0.0.0.0
        - 22 (SSH) -> 0.0.0.0

## Unattended distributed 

* Use install script, following [Khulnasoft unattended distributed installation](https://documentation.khulnasoft.com/current/installation-guide/open-distro/distributed-deployment/unattended/index.html)
* Reosurces:
    - KhulnasoftVPC: EC2 VPC
    - SubnetKhulnasoft: EC2 Subnet over KhulnasoftVPC
    - SubnetElasticsearch: EC2 Subnet over KhulnasoftVPC
    - InternetGateway: EC2 InternetGateway between KhulnasoftVPC and public network
    - GatewayToInternet: EC2 VPCGatewayAttachment attached to KhulnasoftVPC
    - PublicRouteTable: EC2 RouteTable for KhulnasoftVPC
    - PublicRoute: EC2 Route of PublicRouteTable with a specific destination CIDR
    - SubnetKhulnasoftPublicRouteTable: EC2 SubnetRouteTableAssociation attached to SubnetKhulnasoft
    - SubnetElasticPublicRouteTable: EC2 SubnetRouteTableAssociation attached to SubnetElasticsearch
    - KhulnasoftSecurityGroup: EC2 SecurityGroup over KhulnasoftVPC. It enables the following ports and protocols:
        -   22 (SSH) -> 0.0.0.0
        -   ICMP -> 0.0.0.0
        -   1514-1516 (Khulnasoft manager) -> KhulnasoftVPC
        -   55000 (Khulnasoft API) -> KhulnasoftVPC
    - ElasticSecurityGroup: EC2 SecurityGroup over KhulnasoftVPC. It enables the following ports and protocols:
        - 22 (SSH) -> 0.0.0.0
        - ICMP -> 0.0.0.0
        - 443 (HTTPS) -> 0.0.0.0
        - 9200-9400 (Khulnasoft manager) -> KhulnasoftVPC
        - 5000 (khulnasoft manager) -> KhulnasoftVPC
    - Elastic1: EC2 Instance Elasticsearch initial node (with Kibana)
    - Elastic2: EC2 Instance Elasticsearch node
    - Elastic3: EC2 Instance Elasticsearch node
    - KhulnasoftMaster: EC2 Instance Khulnasoft master node
    - KhulnasoftWorker: EC2 Instance Khulnasoft worker node
