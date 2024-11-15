import base64
import datetime
import json
import logging
import os
import shutil
import sys
import tempfile
import time
import urllib.parse

import time
import kubernetes.client
from kubernetes.client.rest import ApiException

import botocore
from botocore.signers import RequestSigner
from copy import deepcopy
from dateutil.tz import tzlocal
from pprint import pformat
from kubernetes import client as k8sclient, config as k8sconfig

import boto3
import yaml

from botocore.auth import SigV4Auth
from botocore.awsrequest import AWSRequest
from botocore.credentials import Credentials
from botocore.signers import RequestSigner

from .utils import run_command

logger = logging.getLogger(__name__)  # TODO: add more logging


class Eks(object):
    def __init__(self, repo, config=None):
        """
        Init the object.
        """
        self.environment = repo.environment
        self.cluster_name = repo.cluster_name
        self.region = repo.region
        self.dry_run = repo.dry_run

        self.eks = boto3.client("eks", region_name=self.region)
        _session = boto3.Session()
        self.eks_client = _session.client("eks", region_name=self.region)
        self.cfn = boto3.client("cloudformation", region_name=self.region)

        self.sts = boto3.client("sts")
        self.sts_client = _session.client("sts")
        self.iam = boto3.client("iam")
        self.environment_id = self.sts.get_caller_identity().get("Account")

        if config:
            with open(config, "r") as f:
                self.config = yaml.safe_load(f)

    def check_cluster_exists(self):
        """
        Check is cluster stack already exists.
        """
        stacks_details = self.cfn.list_stacks()["StackSummaries"]
        stack_name = f"eksctl-{self.cluster_name}-cluster"
        stacks = [(s["StackName"], s["StackStatus"]) for s in stacks_details]
        exists = False
        for stack, status in stacks:
            if stack == stack_name:
                if status != "DELETE_COMPLETE":
                    exists = True
                    break
        return exists

    def create_admin_user(self, user):
        schema_path = f"state/{self.environment}/{self.region}/{self.cluster_name}/idmap-{user}.yaml"
        if not os.path.exists(schema_path):
            with open(schema_path, "w") as f:
                yaml.dump(self.create_admin_user_schema(user), f)
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

    def create_admin_user_id_maps(self, config):

        response = self.eks.describe_cluster(self.cluster_name)
        config.cluster_info = response["cluster"]
        k8s = k8sclient.CoreV1Api()
        config_map = k8s.read_namespaced_config_map("aws-auth", "kube-system")
        aws_auth_data = config_map.data["mapRoles"]
        new_role_mapping = f"""
        - userearn: arn:aws:iam::290730444397:user/admin
          username: admin
          groups:
            - system:masters
        """
        updated_aws_auth_data = aws_auth_data + new_role_mapping
        config_map.data["mapRoles"] = updated_aws_auth_data
        k8s.patch_namespaced_config_map("aws-auth", "kube-system", config_map)

    def create_admin_user_schema(self, user):
        """"""
        user_arn = f"arn:aws:iam::{self.environment_id}:user/{user}"
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

    def create_cluster(self, config):
        """
        Validate all cluster prereqs and create cluster.
        """
        urllib3_logger = logging.getLogger("urllib3")
        previous_level = urllib3_logger.level
        urllib3_logger.setLevel(logging.DEBUG)
        self.cluster_info = self.eks.create_cluster(**config)
        waiter = self.eks.get_waiter("cluster_active")
        logger.info("Waiting for EKS cluster to become active...")
        try:
            waiter.wait(
                name=self.cluster_name,
                WaiterConfig={
                    "Delay": 30,  # seconds between each pole
                    "MaxAttempts": 40,  # max attempts (20 mins)
                },
            )
            logger.info("Cluster is now active!")
            logger.debug(f"cluster create return {pformat(self.cluster_info)}")
            urllib3_logger.setLevel(previous_level)
        except Exception as e:
            logger.error(f"Error waiting for the cluster to become active: {e}")
            urllib3_logger.setLevel(previous_level)
            raise
        finally:
            urllib3_logger.setLevel(previous_level)
            return self.cluster_info

        # self.create_admin_users(config.cluster_admins)
        # self.update_control_plane_sg(vpc)
        # self.delete_cluster_public_endpoint()

    def create_fargate_profile(self, name, namespace, labels=None):
        schema_path = f"state/{self.environment}/{self.region}/{self.cluster_name}/fargateprofile-{name}.yaml"
        try:
            profile = self.create_fargate_profile_schema(namespace, labels)
        except BaseException as err:
            logger.error(err)
        logger.info(profile)
        with open(schema_path, "w") as f:
            yaml.dump(profile, f)
        if self.dry_run:
            logger.info("Dry run enabled, schema written here: %s", schema_path)
            return
        run_command(
            ["/usr/local/bin/eksctl", "create", "fargateprofile", "-f", schema_path]
        )

    def create_fargate_profile_schema(self, name, namespace, labels=None):
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
                    "name": f"fp-{name}",
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

    def create_iam_service_account(
        self, service_account, namespace, iam_policy_arn=None
    ):
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
            response = self.iam.create_policy(
                PolicyName=f"{self.cluster}-{self.region}-{service_account}",
                PolicyDocument=json.dumps(iam_policy),
            )
            return response["Policy"]["Arn"]

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
        schema_path = f"state/{self.environment}/{self.region}/{self.cluster_name}/nodegroup-{name}-{version.replace('.', '-')}.yaml"
        if not os.path.exists(schema_path):
            with open(schema_path, "w") as f:
                yaml.dump(self.create_nodegroup_schema(nodegroup, instance_type), f)
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
            command = f"eksctl delete iamidentitymapping --cluster {self.cluster_name} --region {self.region} --arn arn:aws:iam::{self.environment_id}:user/{user}"
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
                f"arn:aws:iam::{self.environment_id}:user/{user}",
            ]
        )
        if exit_code == 0:
            schema_path = f"state/{self.environment}/{self.region}/{self.cluster_name}/idmap-{user}.yaml"
            os.unlink(schema_path)

    def delete_cluster(self, repo):
        """
        Delete subnet tags and cluster.
        """
        # TODO: include deletion of subnet tags
        try:
            response = self.eks.delete_cluster(name=repo.cluster_name)
            logger.info(f"Cluster deletion initiated: {response}")

            waiter_delay = 20  # seconds
            max_attempts = 30  # maximum attempts to wait
            for attempt in range(max_attempts):
                try:
                    self.eks.describe_cluster(name=repo.cluster_name)
                    logger.info(
                        f"Waiting for cluster {repo.cluster_name} to be deleted..."
                    )
                    time.sleep(waiter_delay)
                except self.eks.exceptions.ResourceNotFoundException:
                    print(f"Cluster {repo.cluster_name} successfully deleted.")
                    return
                except botocore.exceptions.ClientError as err:
                    print(f"Unexpected error while waiting: {err}")
                    raise

            logger.info(
                f"Cluster {repo.cluster_name} deletion timed out after {max_attempts * waiter_delay} seconds."
            )
        except self.eks.exceptions.ResourceNotFoundException:
            logger.error(f"Cluster {repo.cluster_name} not found.")
        except self.eks.exceptions.ClientError as err:
            logger.error(f"An error occurred: {err}")

        # schema_path = (
        #     f"state/{self.environment}/{self.region}/{self.cluster_name}/cluster.yaml"
        # )
        # fargate_profiles = self.get_fargate_profiles()
        # for p in fargate_profiles:
        #     self.delete_fargateprofile(p)
        # if self.dry_run:
        #     command = f"eksctl delete cluster --name {self.cluster_name} --region {self.region}"
        #     logger.info("Dry run enabled, command is %s", command)
        #     return

        # self.vpc.delete_cluster_tags(self.cluster_name)
        # exit_code = run_command(
        #     [
        #         "/usr/local/bin/eksctl",
        #         "delete",
        #         "cluster",
        #         "--name",
        #         self.cluster_name,
        #         "--region",
        #         self.region,
        #     ]
        # )
        # if exit_code == 0:
        #     try:
        #         shutil.rmtree("/".join(schema_path.split("/")[:-1]))
        #     except FileNotFoundError:
        #         logger.error(
        #             "Directory in config not found for the cluster %s",
        #             self.cluster_name,
        #         )

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
        schema_path = f"state/{self.environment}/{self.region}/{self.cluster_name}/cluster-{self.cluster}.yaml"
        with open(schema_path) as f:
            schema = yaml.safe_load(f)
        schema["vpc"]["clusterEndpoints"]["publicAccess"] = False
        with open(schema_path, "w") as f:
            yaml.dump(schema.to_dict(), f)

    def delete_fargateprofile(self, name):
        """
        Delete the specified fargateprofile.
        """
        schema_path = f"state/{self.environment}/{self.region}/{self.cluster_name}/fargateprofile-{name}.yaml"
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
        schema_path = f"state/{self.environment}/{self.region}/{self.cluster_name}/nodegroup-{name}-{version.replace('.', '-')}.yaml"
        if drain:
            drain_flag = f"--drain=true"
        else:
            drain_flag = ""

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

    def get_cluster_info(self):
        self.cluster_info = self.eks.describe_cluster(name=self.cluster_name)
        logger.debug(f"cluster info:\n{pformat(self.cluster_info)}")
        return self.cluster_info

    def get_fargate_profiles(self):
        """
        Creates a dictionary containing cluster/nodegroup names as keys with k8s versions
        as values.
        """
        schema_dir = f"state/{self.environment}/{self.region}/{self.cluster_name}"
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
        schema_dir = f"state/{self.environment}/{self.region}/{self.cluster_name}"
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

    def get_bearer_token(self):
        """
        Generate a Bearer token for Kubernetes API authentication using AWS STS.
        """
        # This code was taken from here:
        # https://github.com/aws/aws-cli/blob/master/awscli/customizations/eks/get_token.py
        # if any issues happen with this method check for changes here ^^^
        try:
            url_timeout = 60  # Presigned URL timeout in seconds
            token_prefix = "k8s-aws-v1."
            k8s_aws_id_header = "x-k8s-aws-id"

            # register event handlers
            self.sts_client.meta.events.register(
                "provide-client-params.sts.GetCallerIdentity",
                lambda params, context, **kwargs: context.update(
                    {k8s_aws_id_header: params.pop(k8s_aws_id_header)}
                ),
            )
            self.sts_client.meta.events.register(
                "before-sign.sts.GetCallerIdentity",
                lambda request, **kwargs: request.headers.add_header(
                    k8s_aws_id_header, request.context[k8s_aws_id_header]
                ),
            )

            # generate presigned URL
            presigned_url = self.sts_client.generate_presigned_url(
                "get_caller_identity",
                Params={k8s_aws_id_header: self.cluster_name},
                ExpiresIn=url_timeout,
                HttpMethod="GET",
            )
            logger.debug(f"Generated signed URL: {presigned_url}")

            # encode URL to k8s bearer token
            token = token_prefix + base64.urlsafe_b64encode(
                presigned_url.encode("utf-8")
            ).decode("utf-8").rstrip("=")

            logger.debug(f"Generated Bearer token: {token}")
            return token

        except Exception as e:
            logger.error(f"Failed to generate Bearer token: {e}")
            raise

    def update_control_plane_sg(self, vpc):
        """
        Apply 10/8 entry for 443 traffic to controlplane so VPN access can communicate to private
        endpoint.
        """
        cluster_info = self.get_cluster_info()
        response = vpc.client.describe_security_groups(
            GroupIds=cluster_info["cluster"]["resourcesVpcConfig"]["securityGroupIds"],
            Filters=[
                {
                    "Name": "tag:Name",
                    "Values": [
                        f"{self.cluster_name}-cluster/ControlPlaneSecurityGroup"
                    ],
                }
            ],
        )
        controlplane_sg = response["SecurityGroups"][0]["GroupId"]
        update_response = self.vpc.client.authorize_security_group_ingress(
            GroupId=controlplane_sg,
            IpPermissions=[
                {
                    "FromPort": 443,
                    "IpProtocol": "tcp",
                    "IpRanges": [
                        {
                            "CidrIp": vpc.cidr_block,
                            "Description": "VPN connectivity to cluster control plane.",
                        },
                    ],
                    "ToPort": 443,
                },
            ],
        )
        if update_response["ResponseMetadata"]["HTTPStatusCode"] != 200:
            raise Exception(
                "Security group update failed with status code %s, Response of %s",
                update_response["ResponseMetadata"]["HTTPStatusCode"],
                update_response["ResponseMetadata"].to_dict(),
            )
        logger.info(
            f"Added {vpc.cidr_block} to the controlplane security group {controlplane_sg}"
        )

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

        schema_directory = f"state/{self.environment}/{self.region}/{self.cluster_name}"
        schema_path = f"{schema_directory}/cluster-{self.cluster}-{current_version.replace('.', '-')}.yaml"
        schema_path_new = f"{schema_directory}/cluster-{self.cluster}-{new_version.replace('.', '-')}.yaml"

        if not os.path.isdir(schema_directory):
            logger.error("Schema directory does not exist: %s", schema_directory)
            sys.exit(1)

        with open(schema_path_new, "w") as f:
            yaml.dump(self.create_cluster_schema(new_version), f)
            logger.info("Saved cluster schema file to %s", schema_path_new)

        if self.dry_run:
            run_command(
                ["/usr/local/bin/eksctl", "upgrade", "cluster", "-f", schema_path_new]
            )
            logger.info("Dry run enabled, exiting now")
            return
        exit_code = run_command(
            [
                "/usr/local/bin/eksctl",
                "upgrade",
                "cluster",
                "-f",
                schema_path_new,
                "--approve",
            ]
        )
        if exit_code == 0:
            os.unlink(schema_path)

    def upgrade_nodegroup(self, name, current_version, new_version, drain):
        current_schema_path = f"state/{self.environment}/{self.region}/{self.cluster_name}/nodegroup-{name}-{current_version.replace('.', '-')}.yaml"
        current_schema = yaml.safe_load(open(current_schema_path, "r"))
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


class IAM(object):
    def __init__(self, repo, config=None):
        """
        Init the object.
        """
        self.repo = repo
        self.iam = boto3.client("iam")

    def create_cluster_service_role(self):
        try:
            eks_trust_policy = {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": {"Service": "eks.amazonaws.com"},
                        "Action": "sts:AssumeRole",
                    }
                ],
            }
            role_name = f"{self.repo.cluster_name}-cluster-service-role"
            managed_policies = [
                "arn:aws:iam::aws:policy/AmazonEKSClusterPolicy",
                "arn:aws:iam::aws:policy/AmazonEKSVPCResourceController",
            ]
            response = self.iam.create_role(
                RoleName=role_name,
                AssumeRolePolicyDocument=json.dumps(eks_trust_policy),
                Description="EKS Cluster Service Role",
            )
            for policy_arn in managed_policies:
                self.iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)

            return response["Role"]["Arn"]
        except self.iam.exceptions.EntityAlreadyExistsException:
            print(f"Role '{role_name}' already exists.")
            existing_role = self.iam.get_role(RoleName=role_name)
            return existing_role["Role"]["Arn"]
        except Exception as e:
            print(f"Error creating role: {e}")


class k8s(object):
    def __init__(self, repo, eks=None):

        api_endpoint = repo.cluster_info["cluster"]["endpoint"]
        ca_data = repo.cluster_info["cluster"]["certificateAuthority"]["data"]
        ca_cert = base64.b64decode(ca_data)
        # token = eks.eks.get_token(clusterName=repo.cluster_name)['token']

        with tempfile.NamedTemporaryFile(delete=False) as ca_cert_file:
            ca_cert_file.write(ca_cert)
            ca_cert_path = ca_cert_file.name

        token = eks.get_bearer_token()

        kclient_config = k8sclient.Configuration()
        kclient_config.api_key_prefix["authorization"] = "Bearer"
        kclient_config.api_key["authorization"] = token
        logger.debug(f"bearer token: {kclient_config.api_key}")
        kclient_config.host = api_endpoint
        logger.debug(f"api endpoint: {kclient_config.host}")
        kclient_config.ssl_ca_cert = ca_cert_path
        logger.debug(f"ca cert path: {kclient_config.ssl_ca_cert}")
        logger.debug(f"cert: \n {ca_cert}")

        kclient_config.verify_ssl = True

        client_config = k8sclient.Configuration.set_default(kclient_config)
        logger.debug(f"client config: {client_config}")

        self.kclient = k8sclient.CoreV1Api()

        # List all ConfigMaps in kube-system
        configmaps = self.kclient.list_namespaced_config_map(namespace="kube-system")

        for cm in configmaps.items:
            print(f"ConfigMap: {cm.metadata.name}")
            if "user" in cm.metadata.name.lower() or "map" in cm.metadata.name.lower():
                print(f"Data: {cm.data}")

        aws_auth_cm = self.kclient.read_namespaced_config_map(
            name="aws-auth", namespace="kube-system"
        )
        logger.info(f"aws-auth ConfigMap Data: {aws_auth_cm.data}")

        # namespaces = self.kclient.list_namespace()
        # for ns in namespaces.items:
        #     print(f"Namespace: {ns.metadata.name}")

        # pods = self.kclient.list_namespaced_pod(namespace='kube-system')
        # for pod in pods.items:
        #     print(f"Pod Name: {pod.metadata.name}")



class Vpc(object):
    def __init__(self, args):
        """
        Init the class and populate the vpc info based on the Name tag to include subnet
        identification.
        """
        logger.info(f"vpc name is: {args.vpc_name}")
        self.region = args.region
        self.session = boto3.Session(region_name=args.region)
        self.ec2 = self.session.resource("ec2")
        self.client = self.session.client("ec2")
        self.data = self.ec2.Vpc(self._get_vpc(args.vpc_name))
        self.subnets = []
        self.private_subnets_by_az = {}
        self.private_subnet_ids = []
        self.public_subnets_by_az = {}
        self.public_subnet_ids = []
        for (
            subnet
        ) in (
            self.data.subnets.all()
        ):  # TODO: make an input to match public/private subnet tags
            self.subnets.append(subnet.id)
            if subnet.map_public_ip_on_launch:
                for tag in subnet.tags:
                    if tag == {"Key": "Type", "Value": "public"}:
                        self.public_subnets_by_az[subnet.availability_zone] = {
                            "id": subnet.id
                        }
                        self.public_subnet_ids.append(subnet.id)
            else:
                for tag in subnet.tags:
                    if tag == {"Key": "Type", "Value": "private"}:
                        self.private_subnets_by_az[subnet.availability_zone] = {
                            "id": subnet.id
                        }
                        self.private_subnet_ids.append(subnet.id)
        logger.info(f"Public subnets: {self.public_subnet_ids}")
        logger.info(f"Private subnets: {self.private_subnet_ids}")
        self.private_subnets = dict(
            sorted(self.private_subnets_by_az.items(), key=lambda x: x[0])
        )
        self.public_subnets = dict(
            sorted(self.public_subnets_by_az.items(), key=lambda x: x[0])
        )
        logger.info(f"public subnets by az: {self.public_subnets_by_az}")
        logger.info(f"private subnets by az: {self.private_subnets_by_az}")

    def _get_vpc(self, name):
        """
        Return the id of the vpc by reference on the Name tag.
        """
        filters = [{"Name": "tag:Name", "Values": [name]}]
        try:
            vpc = self.ec2.Vpc(
                self.client.describe_vpcs(Filters=filters).get("Vpcs")[0]
            )
            logger.debug(f"vpc info = {pformat(vpc)}")
            self.vpc_id = vpc.id.get("VpcId")
            self.cidr_block = vpc.id.get("CidrBlock")
            return self.vpc_id
        except IndexError as err:
            logger.error(f"VPC: {name} does not exist, {err}")
            sys.exit(1)

    def create_cluster_tags(self, cluster):
        """
        Tag the subnets with the cluster name for k8s.
        """
        self.client.create_tags(
            Resources=self.subnets,
            Tags=[{"Key": f"kubernetes.io/cluster/{cluster}", "Value": "shared"}],
        )
        logger.info(
            "Created subnet tags with kubernetes.io/cluster/%s = shared", cluster
        )

    def delete_cluster_tags(self, cluster):
        """
        Delete the tag from the subnets for the cluster.
        """
        self.client.delete_tags(
            Resources=self.subnets,
            Tags=[{"Key": f"kubernetes.io/cluster/{cluster}", "Value": "shared"}],
        )
        logger.info(
            "Deleted subnet tags with kubernetes.io/cluster/%s = shared", cluster
        )

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
                Resources=needs_tag,
                Tags=[{"Key": "kubernetes.io/role/internal-elb", "Value": "1"}],
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
                Resources=needs_tag,
                Tags=[{"Key": "kubernetes.io/role/elb", "Value": "1"}],
            )
            logger.info("Applied public subnet elb role tags.")
        else:
            logger.info("Public subnet elb role tags already exist.")
