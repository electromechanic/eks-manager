import json
import logging
import os
import shutil
import sys
import time
from copy import deepcopy

import boto3
import yaml
from ruamel.yaml import YAML

from .utils import objectify, run_command

logger = logging.getLogger(__name__)  #TODO: add more logging


class Eks(object):
    def __init__(self, args, vpc, config):
        """
        Init the object.
        """
        self.account = args.account
        self.cluster = args.cluster
        self.organization = args.organization
        self.region = args.region
        if not vpc: #TODO: force vpc parameter, or deploy to default vpc
            self.vpc = f"{self.organization}-{self.account}-{self.region}"
        else:
            self.vpc = vpc
        self.cluster_name = (
            f"cluster-{self.cluster}-{args.organization}-{args.account}-{args.region}" #TODO: put these in a list then combine so a missing value wont affect name hyphenation
        )

        self.cluster_admins = args.cluster_admins
        self.dry_run = args.dry_run
        self.name = args.name

        self.cfn = boto3.client("cloudformation", region_name=self.region)
        self.eks_client = boto3.client("eks", region_name=self.region)
        sts = boto3.client("sts")
        self.iam = boto3.client("iam")
        self.account_id = sts.get_caller_identity().get("Account")

        with open(config, "r") as f:
            self.config = YAML().load(f)

    def check_cluster_exists(self):
        """
        Check is cluster stack already exists.
        """
        stacks_details = objectify(self.cfn.list_stacks()).StackSummaries
        stack_name = f"eksctl-{self.cluster_name}-cluster"
        stacks = [(s.StackName, s.StackStatus) for s in stacks_details]
        exists = False
        for stack, status in stacks:
            if stack == stack_name:
                if status != "DELETE_COMPLETE":
                    exists = True
                    break
        return exists

    def create_admin_user(self, user):
        schema_path = f"config/{self.account}/{self.region}/{self.cluster_name}/idmap-{user}.yaml"
        if not os.path.exists(schema_path):
            with open(schema_path, "w") as f:
                YAML().dump(self.create_admin_user_schema(user), f)
                logger.info("Saved cluster schema file to %s", schema_path)
        if self.dry_run:
            command = f"eksctl create iamidentitymapping -f {schema_path}"
            logger.info("Dry run enabled, command is: %s", command)
            return
        run_command(
            [
                "/usr/local/bin/eksctl",
                "create",
                "iamidentitymapping",
                "-f",
                schema_path,
            ]
        )

    def create_admin_user_schema(self, user):
        """"""
        user_arn = f"arn:aws:iam::{self.account_id}:user/{user}"
        schema = {
            "apiVersion": "eksctl.io/v1alpha5",
            "kind": "ClusterConfig",
            "metadata": {"name": self.cluster_name, "region": self.region},
            "iamIdentityMappings": [
                {
                    "arn": user_arn,
                    "username": user,
                    "groups": ["system:masters"],
                    "noDuplicateARNs": True,
                }
            ],
        }
        return schema

    def create_admin_users(self, admins):
        """
        Place set IAM account admin access to the EKS cluster for specified admin team members.
        """
        for user in admins:
            self.create_admin_user(user)

    def create_cluster(self, version):
        """
        Validate all cluster prereqs and create cluster.
        """
        self.vpc.verify_private_elb_tags()
        self.vpc.verify_public_elb_tags()
        schema_path = f"config/{self.account}/{self.region}/{self.cluster_name}/cluster-{self.cluster}-{version.replace('.', '-')}.yaml"

        if not os.path.isdir(f"config/{self.account}/{self.region}/{self.cluster_name}"):
            os.makedirs(f"config/{self.account}/{self.region}/{self.cluster_name}")
        if not os.path.exists(schema_path):
            with open(schema_path, "w") as f:
                YAML().dump(self.create_cluster_schema(version), f)
                logger.info("Saved cluster schema file to %s", schema_path)

        if self.dry_run:
            command = f"eksctl create cluster -f {schema_path}"
            logger.info("Dry run enabled, command is: %s", command)
            return
        if self.check_cluster_exists() is True:
            logger.error("Cluster %s already exists.", self.cluster_name)
            sys.exit(1)
        self.vpc.create_cluster_tags(self.cluster)
        run_command(["/usr/local/bin/eksctl", "create", "cluster", "-f", schema_path])
        self.create_admin_users(self.cluster_admins)
        self.update_control_plane_sg()
        # self.delete_cluster_public_endpoint()

    def create_cluster_schema(self, version): #TODO: maybe break this apart so starting a cluster is sequenced with nodegroups before addons that need them
        """
        Create the EKS cluster schema document.
        """
        schema = {     #TODO: add config options for addon configuration and service accounts, prob need to convert to dictionary
            "apiVersion": "eksctl.io/v1alpha5",
            "kind": "ClusterConfig",
            "metadata": {"name": self.cluster_name, "region": self.region, "version": version},
            "vpc": {
                "id": self.vpc.data.id,
                "subnets": {
                    "public": self.vpc.public_subnets_by_az,
                    "private": self.vpc.private_subnets_by_az,
                },
                "clusterEndpoints": {"privateAccess": True, "publicAccess": True},
            },
            "iam": {
                "withOIDC": True,
                "serviceAccounts": [
                    {
                        "metadata": {"name": "alb-ctrlr", "namespace": "kube-system"},
                        "wellKnownPolicies": {"awsLoadBalancerController": True},
                    },
                    {
                        "metadata": {
                            "name": "autoscaler",
                            "namespace": "cluster-autoscaler",
                            "labels": {"aws-usage": "cluster-ops"},
                        },
                        "wellKnownPolicies": {"autoScaler": True},
                    },
                ],
            },
            "addons": [
                {
                    "name": "aws-ebs-csi-driver",
                    "wellKnownPolicies": {
                        "ebsCSIController": True,
                    },
                }
            ],
            "cloudWatch": {
                "clusterLogging": {
                    "enableTypes": [
                        "api",
                        "audit",
                        "authenticator",
                        "controllerManager",
                        "scheduler",
                    ]
                }
            },
            "fargateProfiles": [
                {
                    "name": "fp-kube-system",
                    "selectors": [{"namespace": "kube-system"}],
                    "subnets": deepcopy(self.vpc.private_subnet_ids),
                },
                {
                    "name": "fp-cluster-autoscaler",
                    "selectors": [{"namespace": "cluster-autoscaler"}],
                    "subnets": deepcopy(self.vpc.private_subnet_ids),
                },
            ],
        }
        return schema

    def create_fargate_profile(self, name, namespace, labels=None):
        schema_path = (
            f"config/{self.account}/{self.region}/{self.cluster_name}/fargateprofile-{name}.yaml"
        )
        profile = self.create_fargate_profile_schema(namespace, labels)
        logger.info(profile)
        with open(schema_path, "w") as f:
            YAML().dump(profile, f)
        if self.dry_run:
            logger.info("Dry run enabled, schema written here: %s", schema_path)
            return
        run_command(["/usr/local/bin/eksctl", "create", "fargateprofile", "-f", schema_path])

    def create_fargate_profile_schema(self, namespace, labels=None):
        """
        Create the fargate profile schema file. Labels are optional and to be placed in fargate, all
        specified labels must be matched.
        """
        schema = {
            "apiVersion": "eksctl.io/v1alpha5",
            "kind": "ClusterConfig",
            "metadata": {"name": self.cluster_name, "region": self.region},
            "fargateProfiles": [
                {
                    "name": f"fp-{self.name}",
                    "selectors": [{"namespace": namespace}],
                    "subnets": deepcopy(self.vpc.private_subnet_ids),
                }
            ],
        }
        if labels:
            for label in labels:
                k, v = label.split("=")
                schema["fargateProfiles"][0]["selectors"].append({k: v})
        return schema

    def create_iam_service_account(self, service_account, namespace, iam_policy_arn=None):
        """
        Create the iam service account using eksctl.
        """
        if self.dry_run:
            command = f"eksctl create iamserviceaccount --cluster {self.cluster_name} --region {self.region} --namespace {namespace} --name {service_account} --attach-policy-arn {iam_policy_arn} --override-existing-serviceaccounts --approve"
            logger.info("Dry run enabled, command is: %s", command)
            return

        if iam_policy_arn is None:
            iam_policy_arn = self.create_iam_service_account_iam_policy(service_account)
        run_command(
            [
                "/usr/local/bin/eksctl",
                "create",
                "iamserviceaccount",
                "--cluster",
                self.cluster_name,
                "--region",
                self.region,
                "--namespace",
                namespace,
                "--name",
                service_account,
                "--attach-policy-arn",
                iam_policy_arn,
                "--override-existing-serviceaccounts",
                "--approve",
            ]
        )

    def create_iam_service_account_iam_policy(self, service_account):
        """
        Create the IAM policy that will be bound to the eks service account.
        """
        with open(f"iam-policies/{service_account}-iam-policy.json") as f:
            iam_policy = json.loads(f.read())
            response = objectify(
                self.iam.create_policy(
                    PolicyName=f"{self.cluster}-{self.region}-{service_account}",
                    PolicyDocument=json.dumps(iam_policy),
                )
            )
            return response.Policy.Arn

    def create_nodegroup(
        self, name, instance_type, version, desired_capacity=0, min_size=0, max_size=3
    ):
        """
        Create the specified nodegroup.
        """
        nodegroup = {
            "name": name,
            "desiredCapacity": desired_capacity,
            "instanceType": instance_type,
            "maxSize": max_size,
            "minSize": min_size,
            "version": version,
        }
        schema_path = f"config/{self.account}/{self.region}/{self.cluster_name}/nodegroup-{name}-{version.replace('.', '-')}.yaml"
        if not os.path.exists(schema_path):
            with open(schema_path, "w") as f:
                YAML().dump(self.create_nodegroup_schema(nodegroup, instance_type), f)
                logger.info("Saved nodegroup schema to %s", schema_path)
        if self.dry_run:
            logger.info("Dry run enabled, shema output here: %s", schema_path)
            return
        run_command(["/usr/local/bin/eksctl", "create", "nodegroup", "-f", schema_path])

    def create_nodegroup_schema(self, nodegroup, instance_type, labels=None):
        """
        Create nodegroup schema document.
        nodegroup = {
            'name': str,
            'instanceType': str,
            'desiredCapacity': int,
            'maxSize': int,
            'minSize': int
        }
        returns schema
        """
        schema = {
            "apiVersion": "eksctl.io/v1alpha5",
            "kind": "ClusterConfig",
            "metadata": {
                "name": self.cluster_name,
                "region": self.region,
                "version": nodegroup["version"],
            },
            "managedNodeGroups": [
                {
                    "name": f'{nodegroup["name"]}-{nodegroup["version"].replace(".", "-")}',
                    "instanceType": instance_type,
                    "desiredCapacity": nodegroup["desiredCapacity"],
                    "disablePodIMDS": True,
                    "ebsOptimized": True,
                    "labels": {
                        "nodegroup": nodegroup["name"],
                        "compute-type": "ec2",
                        "k8s-version": nodegroup["version"],
                    },
                    "maxSize": nodegroup["maxSize"],
                    "minSize": nodegroup["minSize"],
                    "privateNetworking": True,
                    "ssh": {"allow": False},
                    "volumeEncrypted": True,
                    "volumeSize": 128,
                    "volumeType": "gp3",
                }
            ],
        }
        # if self.config.nodegroups.vanta.enabled is True:
        #     schema["tags"] = self.config.nodegroups.vanta.tags
        #     schema["tags"]["VantaDescription"] = self.cluster
        #     schema["preBootstrapCommands"] = self.config.nodegroups.vanta.preBootstrapCommands
        if labels:
            labels = labels.split(",")
            parsed = {}
            for label in labels:
                k, v = label.split("=")
                parsed[k] = v
            schema["managedNodeGroups"][0]["labels"].update(parsed)
        return schema

    def delete_admin_user(self, user):
        if self.dry_run:
            command = f"eksctl delete iamidentitymapping --cluster {self.cluster_name} --region {self.region} --arn arn:aws:iam::{self.account_id}:user/{user}"
            logger.info("Dry run enabled, command is: %s", command)
            return
        exit_code = run_command(
            [
                "/usr/local/bin/eksctl",
                "delete",
                "iamidentitymapping",
                "--cluster",
                self.cluster_name,
                "--region",
                self.region,
                "--arn",
                f"arn:aws:iam::{self.account_id}:user/{user}",
            ]
        )
        if exit_code == 0:
            schema_path = (
                f"config/{self.account}/{self.region}/{self.cluster_name}/idmap-{user}.yaml"
            )
            os.unlink(schema_path)

    def delete_cluster(self):
        """
        Delete subnet tags and cluster.
        """
        schema_path = f"config/{self.account}/{self.region}/{self.cluster_name}/cluster.yaml"
        fargate_profiles = self.get_fargate_profiles()
        for p in fargate_profiles:
            self.delete_fargateprofile(p)
        if self.dry_run:
            command = f"eksctl delete cluster --name {self.cluster_name} --region {self.region}"
            logger.info("Dry run enabled, command is %s", command)
            return

        self.vpc.delete_cluster_tags(self.cluster_name)
        exit_code = run_command(
            [
                "/usr/local/bin/eksctl",
                "delete",
                "cluster",
                "--name",
                self.cluster_name,
                "--region",
                self.region,
            ]
        )
        if exit_code == 0:
            try:
                shutil.rmtree("/".join(schema_path.split("/")[:-1]))
            except FileNotFoundError:
                logger.error("Directory in config not found for the cluster %s", self.cluster_name)

    def delete_cluster_public_endpoint(self):
        """
        Remove the cluster controlplane public endpoint.
        """
        self.eks_client.update_cluster_config(
            name=self.cluster_name,
            resourcesVpcConfig={
                "endpointPublicAccess": False,
            },
        )
        logger.info("Removed cluster control plane public endpoint.")
        schema_path = (
            f"config/{self.account}/{self.region}/{self.cluster_name}/cluster-{self.cluster}.yaml"
        )
        with open(schema_path) as f:
            schema = objectify(YAML().load(f))
        schema.vpc.clusterEndpoints.publicAccess = False
        with open(schema_path, "w") as f:
            YAML().dump(schema.to_dict(), f)

    def delete_fargateprofile(self, name):
        """
        Delete the specified fargateprofile.
        """
        schema_path = (
            f"config/{self.account}/{self.region}/{self.cluster_name}/fargateprofile-{name}.yaml"
        )
        if self.dry_run:
            command = f"eksctl delete fargateprofile --name fp-{name} -f {schema_path}"
            logger.info("Dry run enabled, command is: %s", command)
            return
        exit_code = run_command(
            [
                "/usr/local/bin/eksctl",
                "delete",
                "fargateprofile",
                "--name",
                f"fp-{name}",
                "-f",
                schema_path,
            ]
        )
        if exit_code == 0:
            os.unlink(schema_path)

    def delete_iam_policy(self, name):
        """
        Delete the specified policy that was used the service account.
        """
        policy = f"{self.cluster}-{self.region}-{name}"
        policies = self.iam.list_policies(Scope="Local").get("Policies")
        try:
            arn = [p.get("Arn") for p in policies if p["PolicyName"] == policy][0]
            count = 6
            wait = 10
            attached = True
            while attached is True:
                status = self.iam.get_policy(PolicyArn=arn)
                if status["Policy"]["AttachmentCount"] == 0:
                    wait = 0
                    attached = False
                else:
                    count += 1
                    time.sleep(wait)
                    if count <= 6:
                        logger.error(
                            "Policy %s is still attached to %s entities.",
                            arn,
                            status["Policy"]["AttachmentCount"],
                        )
                        sys.exit(1)
            self.iam.delete_policy(PolicyArn=arn)
            logger.info("Deleted IAM policy for service account: %s", arn)
        except IndexError:
            logger.error("Policy %s does not exist.", policy)

    def delete_iam_service_account(self, service_account, namespace):
        """
        Create the iam service account using eksctl.
        """
        if self.dry_run:
            command = f"eksctl delete iamserviceaccount --cluster {self.cluster_name} --region {self.region} --namespace {namespace} --name {service_account}"
            logger.info("command: %s", command)
            logger.info("Dry run enabled, exiting now")
            return
        run_command(
            [
                "/usr/local/bin/eksctl",
                "delete",
                "iamserviceaccount",
                "--cluster",
                self.cluster_name,
                "--region",
                self.region,
                "--namespace",
                namespace,
                "--name",
                service_account,
            ]
        )
        self.delete_iam_policy(service_account)

    def delete_nodegroup(self, name, version, drain):
        """
        Delete the specified nodegorup.
        """
        schema_path = f"config/{self.account}/{self.region}/{self.cluster_name}/nodegroup-{name}-{version.replace('.', '-')}.yaml"
        drain_flag = f"--drain={drain}"

        if self.dry_run:
            logger.info(
                "Dry run enabled, command is: eksctl delete nodegroup -f %s --approve %s",
                schema_path,
                drain_flag,
            )
            return

        exit_code = run_command(
            [
                "/usr/local/bin/eksctl",
                "delete",
                "nodegroup",
                "-f",
                schema_path,
                "--approve",
                drain_flag,
            ]
        )
        if exit_code == 0:
            os.unlink(schema_path)

    def get_fargate_profiles(self):
        """
        Creates a dictionary containing cluster/nodegroup names as keys with k8s versions
        as values.
        """
        schema_dir = f"config/{self.account}/{self.region}/{self.cluster_name}"
        if not os.path.exists(schema_dir):
            logger.info("Path to schemas does not exist, please check your inputs")
            sys.exit(1)
        schemas = os.listdir(schema_dir)
        fargatge_profiles = []
        for s in schemas:
            schema_type = s.split("-")[0].split(".")[0]
            schema_name = s.split("-")[1].split(".")[0]
            if schema_type == "fargateprofile":
                fargatge_profiles.append(schema_name)
        return fargatge_profiles

    def get_versions(self):
        """
        Creates a dictionary containing cluster/nodegroup names as keys with k8s versions
        as values.
        """
        schema_dir = f"config/{self.account}/{self.region}/{self.cluster_name}"
        if not os.path.exists(schema_dir):
            logger.info("Path to schemas does not exist, please check your inputs")
            sys.exit(1)
        schemas = os.listdir(schema_dir)
        versions = {}
        for s in schemas:
            ver = s.split("-")[-1].split(".")[0]
            if ver.isnumeric():
                n = s.split("-")
                versions[f"{n[0]}-{n[1]}"] = ver
        return versions

    def update_control_plane_sg(self):
        """
        Apply 10/8 entry for 443 traffic to controlplane so VPN access can communicate to private
        endpoint.
        """
        cluster_info = self.eks_client.describe_cluster(name=self.cluster_name)
        response = objectify(
            self.vpc.client.describe_security_groups(
                GroupIds=cluster_info["cluster"]["resourcesVpcConfig"]["securityGroupIds"],
                Filters=[
                    {
                        "Name": "tag:Name",
                        "Values": [f"eksctl-{self.cluster_name}-cluster/ControlPlaneSecurityGroup"],
                    }
                ],
            )
        )
        controlplane_sg = response.SecurityGroups[0].GroupId
        update_response = objectify(
            self.vpc.client.authorize_security_group_ingress(
                GroupId=controlplane_sg,
                IpPermissions=[
                    {
                        "FromPort": 443,
                        "IpProtocol": "tcp",
                        "IpRanges": [
                            {
                                "CidrIp": "10.0.0.0/8",
                                "Description": "VPN connectivity to cluster control plane.",
                            },
                        ],
                        "ToPort": 443,
                    },
                ],
            )
        )
        if update_response.ResponseMetadata.HTTPStatusCode != 200:
            raise Exception(
                "Security group update failed with status code %s, Response of %s",
                update_response.ResponseMetadata.HTTPStatusCode,
                update_response.ResponseMetadata.to_dict(),
            )
        logger.info("Added 10.0.0.0/8 to the controlplane security group %s", controlplane_sg)

    def upgrade_all(self, current_version, new_version, drain):
        versions = self.get_versions()
        check_vals = list(versions.values())[0]
        res = all(val == check_vals for val in versions.values())
        if not res:
            logger.info(
                "Current cluster and nodegroup versions are not in sync, please update manually to match versions"
            )
            return
        logger.info("Upgrading cluster")
        self.upgrade_cluster(current_version, new_version)

        nodegroups = []
        for k, v in versions.items():
            if k.startswith("nodegroup"):
                nodegroups.append(k.replace("nodegroup-", ""))
        logger.info("nodegroups: %s", nodegroups)
        for name in nodegroups:
            self.upgrade_nodegroup_ami(name, current_version, new_version)
            self.upgrade_nodegroup(name, current_version, new_version, drain)

    def upgrade_cluster(self, current_version, new_version):
        if self.check_cluster_exists() is False:
            logger.error("Cluster %s does not exist. Exiting.", self.cluster_name)
            sys.exit(1)

        schema_directory = f"config/{self.account}/{self.region}/{self.cluster_name}"
        schema_path = (
            f"{schema_directory}/cluster-{self.cluster}-{current_version.replace('.', '-')}.yaml"
        )
        schema_path_new = (
            f"{schema_directory}/cluster-{self.cluster}-{new_version.replace('.', '-')}.yaml"
        )

        if not os.path.isdir(schema_directory):
            logger.error("Schema directory does not exist: %s", schema_directory)
            sys.exit(1)

        with open(schema_path_new, "w") as f:
            YAML().dump(self.create_cluster_schema(new_version), f)
            logger.info("Saved cluster schema file to %s", schema_path_new)

        if self.dry_run:
            run_command(["/usr/local/bin/eksctl", "upgrade", "cluster", "-f", schema_path_new])
            logger.info("Dry run enabled, exiting now")
            return
        exit_code = run_command(
            ["/usr/local/bin/eksctl", "upgrade", "cluster", "-f", schema_path_new, "--approve"]
        )
        if exit_code == 0:
            os.unlink(schema_path)

    def upgrade_nodegroup(self, name, current_version, new_version, drain):
        current_schema_path = f"config/{self.account}/{self.region}/{self.cluster_name}/nodegroup-{name}-{current_version.replace('.', '-')}.yaml"
        current_schema = YAML().load(open(current_schema_path, "r"))
        instance_type = current_schema["managedNodeGroups"][0]["instanceType"]
        desired = current_schema["managedNodeGroups"][0]["desiredCapacity"]
        max = current_schema["managedNodeGroups"][0]["maxSize"]
        min = current_schema["managedNodeGroups"][0]["minSize"]
        self.create_nodegroup(name, instance_type, new_version, desired, min, max)
        self.delete_nodegroup(name, current_version, drain)

    def upgrade_nodegroup_ami(self, name, current_version, new_version):
        if self.dry_run:
            command = (
                f"eksctl upgrade nodegroup --name={name}-{current_version.replace('.', '-')} --cluster={self.cluster_name} --kubernetes-version={new_version} --region={self.region}",
            )
            logger.info("Command to be executed:")
            logger.info(str(command))
            logger.info("Dry run enabled, exiting now")
            return
        run_command(
            [
                "eksctl",
                "upgrade",
                "nodegroup",
                f"--name={name}-{current_version.replace('.', '-')}",
                f"--cluster={self.cluster_name}",
                f"--kubernetes-version={new_version}",
                f"--region={self.region}",
            ]
        )


class Vpc(object):
    def __init__(self, args):
        """
        Init the class and populate the vpc info based on the Name tag to include subnet
        identification.
        """
        if not args.vpc:
            vpc_name = f"{args.organization}-{args.account}-{args.region}"
        else:
            vpc_name = args.vpc
        logger.info(f"vpc name is: {vpc_name}")
        self.region = args.region
        self.session = boto3.Session(region_name=args.region)
        self.ec2 = self.session.resource("ec2")
        self.client = self.session.client("ec2")
        self.data = self.ec2.Vpc(self._get_vpc(vpc_name))
        self.subnets = []
        self.private_subnets_by_az = {}
        self.private_subnet_ids = []
        self.public_subnets_by_az = {}
        self.public_subnet_ids = []
        for subnet in self.data.subnets.all():  #TODO: make an input to match public/private subnet tags
            self.subnets.append(subnet.id)
            if subnet.map_public_ip_on_launch:
                for tag in subnet.tags:
                    if tag == {"Key": "Type", "Value": "public"}:
                        self.public_subnets_by_az[subnet.availability_zone] = {"id": subnet.id}
                        self.public_subnet_ids.append(subnet.id)
            else:
                for tag in subnet.tags:
                    if tag == {"Key": "Type", "Value": "private"}:
                        self.private_subnets_by_az[subnet.availability_zone] = {"id": subnet.id}
                        self.private_subnet_ids.append(subnet.id)
        logger.info(f"Public subnets: {self.public_subnet_ids}")
        logger.info(f"Private subnets: {self.private_subnet_ids}")
        self.private_subnets = dict(sorted(self.private_subnets_by_az.items(), key=lambda x: x[0]))
        self.public_subnets = dict(sorted(self.public_subnets_by_az.items(), key=lambda x: x[0]))

    def _get_vpc(self, name):
        """
        Return the id of the vpc by reference on the Name tag.
        """
        filters = [{"Name": "tag:Name", "Values": [name]}]
        vpc = self.ec2.Vpc(self.client.describe_vpcs(Filters=filters).get("Vpcs")[0])
        return vpc.id.get("VpcId")

    def create_cluster_tags(self, cluster):
        """
        Tag the subnets with the cluster name for k8s.
        """
        self.client.create_tags(
            Resources=self.subnets,
            Tags=[{"Key": f"kubernetes.io/cluster/{cluster}", "Value": "shared"}],
        )
        logger.info("Created subnet tags with kubernetes.io/cluster/%s = shared", cluster)

    def delete_cluster_tags(self, cluster):
        """
        Delete the tag from the subnets for the cluster.
        """
        self.client.delete_tags(
            Resources=self.subnets,
            Tags=[{"Key": f"kubernetes.io/cluster/{cluster}", "Value": "shared"}],
        )
        logger.info("Deleted subnet tags with kubernetes.io/cluster/%s = shared", cluster)

    def verify_private_elb_tags(self):
        """
        Ensure that the elb subnet tags exist, if not create.
        """
        needs_tag = []
        for subnet in self.private_subnet_ids:
            sub = self.ec2.Subnet(subnet)
            tagged = False
            for tag in sub.tags:
                if tag["Key"] == "kubernetes.io/role/internal-elb":
                    tagged = True
            if not tagged:
                needs_tag.append(subnet)
        if needs_tag:
            self.client.create_tags(
                Resources=needs_tag, Tags=[{"Key": "kubernetes.io/role/internal-elb", "Value": "1"}]
            )
            logger.info("Applied private subnet internal-elb role tags.")
        else:
            logger.info("Private subnet internal-elb role tags already exist.")

    def verify_public_elb_tags(self):
        """
        Verify that the public non VR (virtual router) subnets have the elb subnet tags, if not
        create.
        """
        needs_tag = []
        for subnet in self.public_subnet_ids:
            sub = self.ec2.Subnet(subnet)
            tagged = False
            for tag in sub.tags:
                if tag["Key"] == "kubernetes.io/role/elb":
                    tagged = True
            if not tagged:
                needs_tag.append(subnet)
        if needs_tag:
            self.client.create_tags(
                Resources=needs_tag, Tags=[{"Key": "kubernetes.io/role/elb", "Value": "1"}]
            )
            logger.info("Applied public subnet elb role tags.")
        else:
            logger.info("Public subnet elb role tags already exist.")
