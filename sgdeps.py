#!/usr/bin/env python3
import boto3

from sys import exit
import argparse
import textwrap
from queue import Queue
from threading import Thread

ec2 = boto3.client('ec2')
regions: set = set(r['RegionName'] for r in ec2.describe_regions()['Regions'])


class sg_obj(object):

    """class to hold object which will use security group"""

    def __init__(self, sgid: str, service: str, id: str,  name: str) -> None:
        self.sgid = sgid
        self.service = service
        self.id = id
        self.name = name

    def __repr__(self) -> str:
        return f'{self.service}: {self.id}{f" ({self.name})" if self.name else ""}'


class sg_deps(object):
    """to list AWS security group dependencies"""

    def __init__(self, region_name: str) -> None:
        """collect info for a region """
        if not region_name or region_name not in regions:
            print("\nError: please specify a valid region name with --region ")
            print("  valid regions: " + ", ".join(regions) + "\n")
            exit(1)

        self.region = region_name
        self.sg_by_id = {}
        self.sg_by_name = {}
        self.queue = Queue()
        self.sgs = []

        self.service_list = [
            "ec2",
            "elb",
            "rds",
            "lambda",
            "redshift",
            "elasticache",
            "eni"
        ]

        try:
            self.sgs = self.list_sg()
        except Exception as e:
            print("\nError: please check your credentials and network connectivity\n")
            print(e)
            exit(1)
        threads = []
        threads.append(Thread(target=self.prepare_sg))
        for service in self.service_list:
            threads.append(
                Thread(
                    target=self.wrap,
                    args=(service,),
                    name=f'{service}-thread'
                )
            )
        [x.start() for x in threads]
        [x.join() for x in threads]
        while not self.queue.empty():
            obj = self.queue.get()
            self.sg_by_id[obj.sgid]["obj"].add(obj)

    def wrap(self, service):
        try:
            getattr(self, f"list_{service}_sg")()
        except AttributeError as e:
            print(e)

    def prepare_sg(self):
        for sg in self.sgs:
            sg_name = sg['GroupName']
            sg_id = sg['GroupId']
            sg_rules = []
            [sg_rules.extend(rule['UserIdGroupPairs']) for rule in sg['IpPermissions']]
            [sg_rules.extend(rule['UserIdGroupPairs']) for rule in sg['IpPermissionsEgress']]
            self.sg_by_name[sg_name] = sg_id
            if sg_id not in self.sg_by_id:
                self.sg_by_id[sg_id] = {}
                self.sg_by_id[sg_id]["deps"] = set()
                self.sg_by_id[sg_id]["obj"] = set()
            self.sg_by_id[sg_id]["name"] = sg_name
            for rule in sg_rules:
                if rule['GroupId'] not in self.sg_by_id:
                    self.sg_by_id[rule['GroupId']] = {}
                    self.sg_by_id[rule['GroupId']]["deps"] = set()
                    self.sg_by_id[rule['GroupId']]["obj"] = set()
                self.sg_by_id[rule['GroupId']]["deps"].add(sg_id)
        print("Prepared all Security Groups...")

    def list_sg(self) -> list:
        client = boto3.client('ec2', region_name=self.region)
        security_groups = []
        response = client.describe_security_groups(MaxResults=1000)
        security_groups.extend(response['SecurityGroups'])
        while response.get('NextToken'):
            response = client.describe_security_groups(
                NextToken=response['NextToken'], MaxResults=1000
            )
            security_groups.extend(response['SecurityGroups'])
        print('Fetched all Security Groups...')
        return security_groups

    def list_eni_sg(self) -> None:
        client = boto3.client('ec2', region_name=self.region)
        instances = []
        response = client.describe_network_interfaces(MaxResults=1000)
        instances.extend(response['NetworkInterfaces'])
        while response.get('NextToken'):
            response = client.describe_network_interfaces(
                NextToken=response['NextToken'], MaxResults=1000
            )
            instances.extend(response['NetworkInterfaces'])
        for instance in instances:
            name = [t['Value'] for t in instance['TagSet'] if t['Key'] == 'Name']
            name = name[0] if len(name) == 1 else ""
            for group in instance['Groups']:
                self.queue.put(sg_obj(group['GroupId'], "eni", instance['NetworkInterfaceId'], name))
        print('Fetched all ENI Security Groups...')

    def list_ec2_sg(self):
        client = boto3.client('ec2', region_name=self.region)
        instances = []
        response = client.describe_instances(MaxResults=1000)
        instances.extend(response['Reservations'][0]['Instances'])
        while response.get('NextToken'):
            response = client.describe_instances(
                NextToken=response['NextToken'], MaxResults=1000
            )
            instances.extend(response['Reservations'][0]['Instances'])
        for instance in instances:
            name = [t['Value'] for t in instance['Tags'] if t['Key'] == 'Name']
            name = name[0] if len(name) == 1 else ""
            insance_id = instance['InstanceId']
            for nwi in instance['NetworkInterfaces']:
                for group in nwi['Groups']:
                    self.queue.put(sg_obj(group['GroupId'], "ec2", insance_id, name))
        print('Fetched all EC2 Security Groups...')

    def list_elb_sg(self):
        client = boto3.client('elbv2', region_name=self.region)
        instances = []
        response = client.describe_load_balancers(PageSize=400)
        instances.extend(response['LoadBalancers'])
        while response.get('NextToken'):
            response = client.describe_load_balancers(
                NextToken=response['NextToken'], PageSize=400
            )
            instances.extend(response['LoadBalancers'])

        for elb in instances:
            for group in elb.get('SecurityGroups', []):
                self.queue.put(sg_obj(group, "elb", elb['LoadBalancerName'], ""))
        print('Fetched all ELBv2 Security Groups...')

    def list_rds_sg(self):
        client = boto3.client('rds', region_name=self.region)
        instances = []
        response = client.describe_db_instances(MaxRecords=100)
        instances.extend(response['DBInstances'])
        while response.get('NextToken'):
            response = client.describe_db_instances(
                NextToken=response['NextToken'], MaxRecords=100
            )
            instances.extend(response['DBInstances'])

        for instance in instances:
            name = instance["DBInstanceIdentifier"]
            for group in instance["DBSecurityGroups"]:
                self.queue.put(sg_obj(group["DBSecurityGroupName"], "rds", name, ""))
            for group in instance["VpcSecurityGroups"]:
                self.queue.put(sg_obj(group["VpcSecurityGroupId"], "rds", name, ""))
        print('Fetched all RDS Security Groups...')

    def list_redshift_sg(self):
        client = boto3.client('redshift', region_name=self.region)
        instances = []
        response = client.describe_clusters(MaxRecords=100)
        instances.extend(response['Clusters'])
        while response.get('NextToken'):
            response = client.describe_clusters(
                NextToken=response['NextToken'], MaxRecords=100
            )
            instances.extend(response['Clusters'])

        for instance in instances:
            name = instance["ClusterIdentifier"]
            for group in instance["VpcSecurityGroups"]:
                self.queue.put(sg_obj(group["VpcSecurityGroupId"], "redshift", name, ""))
            for group in instance["ClusterSecurityGroups"]:
                self.queue.put(sg_obj(group["ClusterSecurityGroupName"], "redshift", name, ""))
        print('Fetched all Redshift Security Groups...')

    def list_elasticache_sg(self):
        client = boto3.client('elasticache', region_name=self.region)
        instances = []
        response = client.describe_cache_clusters(MaxRecords=100)
        instances.extend(response['CacheClusters'])
        while response.get('NextToken'):
            response = client.describe_cache_clusters(
                NextToken=response['NextToken'], MaxRecords=100
            )
            instances.extend(response['CacheClusters'])
        for instance in instances:
            name = instance["CacheClusterId"]
            for group in instance["SecurityGroups"]:
                self.queue.put(sg_obj(group["SecurityGroupId"], "elasticache", name, ""))
            for group in instance["CacheSecurityGroups"]:
                self.queue.put(sg_obj(group["CacheSecurityGroupName"], "elasticache", name, ""))
        print('Fetched all ElastiCache Security Groups...')

    def list_lambda_sg(self):
        client = boto3.client('lambda', region_name=self.region)
        instances = []
        response = client.list_functions(MaxItems=1000)
        instances.extend(response['Functions'])
        while response.get('NextToken'):
            response = client.list_functions(
                NextToken=response['NextToken'], MaxItems=1000
            )
            instances.extend(response['Functions'])
        for instance in instances:
            name = instance["FunctionName"]
            for group in instance.get("VpcConfig", {}).get('SecurityGroupIds', []):
                self.queue.put(sg_obj(group, "lambda", name, ""))
        print('Fetched all Lambda Security Groups...')

    def show_obj(self, sgid):
        if not self.sg_by_id[sgid]["obj"]:
            print("\nNot used by any " + "/".join(self.service_list) + " instance")
        else:
            print("\nUsed by:")
            for obj in sorted(self.sg_by_id[sgid]["obj"], key=lambda x: x.service + x.name.lower() + x.id):
                print("  " + str(obj))

    def show_eni_only_sg(self, showlist=False):
        todo = []
        for sgid in self.sg_by_id:
            if self.sg_by_id[sgid]["obj"] and not filter(lambda x: x.service != "eni", self.sg_by_id[sgid]["obj"]):
                todo.append(sgid)
        if todo:
            print("\nBelow security group(s) are used by eni but not any of " + "/".join(filter(lambda x: x != "eni", self.service_list)) + " service\n")
            if showlist:
                print("\n".join([self._string_sg(x) for x in todo]))
            else:
                for sgid in todo:
                    self.show_sg(sgid)
        else:
            print("\nNot found")

    def show_obsolete_sg(self, showlist=False):
        todo = [sgid for sgid in self.sg_by_id if not self.sg_by_id[sgid]["obj"]]
        if todo:
            print("\nBelow security group(s) are not used by any " + "/".join(self.service_list) + " service\n")
            if showlist:
                print("\n".join([self._string_sg(x) for x in todo]))
            else:
                for sgid in todo:
                    self.show_sg(sgid)
        else:
            print("\nNot found")

    def show_sg(self, sg, showlist=False):
        if sg:
            if sg in self.sg_by_id:
                sgid = sg
            elif sg in self.sg_by_name:
                sgid = self.sg_by_name[sg]
            else:
                print("\nError: cannot find the security group with name or id: " + sg + "\n")
                exit(1)
            if showlist:
                print(self._string_sg(sgid))
            else:
                print("\n" + "-" * 70)
                self._show(sgid, [], [])
                self.show_obj(sgid)
        else:
            for sgid in self.sg_by_id:
                self.show_sg(sgid, showlist=showlist)

    def _show(self, sgid, previous, indent):
        if not previous:
            print(self._string_sg(sgid), end="")
        else:
            pre = "".join(["|  " if x else "   " for x in indent[:-1]])
            if indent[-1]:
                pre += "|--"
            else:
                pre += "`--"
            print(pre + " " + self._string_sg(sgid), end="")
        if sgid in previous:
            print(" ** loop")
            return
        else:
            print()
        deps = list(self.sg_by_id[sgid]["deps"])
        for dep in deps:
            if dep == deps[-1]:
                self._show(dep, previous+[sgid], indent+[False])
            else:
                self._show(dep, previous+[sgid], indent+[True])

    def _string_sg(self, sgid):
        if "name" not in self.sg_by_id[sgid]:
            name = " N/A "
        elif not self.sg_by_id[sgid]["name"]:
            name = " N/A "
        else:
            name = self.sg_by_id[sgid]["name"]
        return sgid + " (" + name + ")"


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description="show AWS security group dependencies",
        epilog=textwrap.dedent('''
        please setup your aws credentials first.
            here's a few options:
             setup environment varialbes: AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY
             or create one or some of below files (boto will evaluate in order):
                /etc/boto.cfg
                ~/.boto
                ~/.aws/credentials
             and put your credentials in the file(s) with below format:
               [Credentials]
               aws_access_key_id = <your_access_key_here>
               aws_secret_access_key = <your_secret_key_here>'''
        )
    )
    parser.add_argument("--region", choices=regions, help="region connect to")
    parser.add_argument("--list",action="store_true", help="only output group id/name")
    g = parser.add_mutually_exclusive_group()
    g.add_argument("--obsolete", action="store_true", help="show security group not used by any service")
    g.add_argument("--eni_only", action="store_true", help="show security group only used by eni (elastic network interface)")
    parser.add_argument("security_group", help="security group id or name, id takes precedence, if you have more than one group with same name, this program will show random one, you should use group id instead. leave empty for all groups", default="", nargs="?")
    args = parser.parse_args()
    if args.obsolete:
        sg_deps(args.region).show_obsolete_sg(showlist=args.list)
    elif args.eni_only:
        sg_deps(args.region).show_eni_only_sg(showlist=args.list)
    else:
        sg_deps(args.region).show_sg(args.security_group, showlist=args.list)
