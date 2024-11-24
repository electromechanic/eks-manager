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
from botocore.exceptions import ClientError


logger = logging.getLogger(__name__)  # TODO: add more logging


class Eks(object):
    def __init__(self, repo):
        """
        Init the object.
        """
        self.repo = repo
        self.dry_run = repo.dry_run

        self.eks = boto3.client("eks", region_name=self.repo.region)
        _session = boto3.Session()
        self.eks_client = _session.client("eks", region_name=self.repo.region)
        self.cfn = boto3.client("cloudformation", region_name=self.repo.region)

        self.sts = boto3.client("sts")
        self.sts_client = _session.client("sts")
        self.iam = boto3.client("iam")
        self.environment_id = self.sts.get_caller_identity().get("Account")

    def check_cluster_exists(self):
        """
        Check is cluster stack already exists.
        """
        stacks_details = self.cfn.list_stacks()["StackSummaries"]
        stack_name = f"eksctl-{self.repo.cluster_name}-cluster"
        stacks = [(s["StackName"], s["StackStatus"]) for s in stacks_details]
        exists = False
        for stack, status in stacks:
            if stack == stack_name:
                if status != "DELETE_COMPLETE":
                    exists = True
                    break
        return exists

    def create_cluster(self, config):
        """
        Validate all cluster prerequisites, create the cluster, and wait for it to become active.
        """
        try:
            logger.info("Creating EKS cluster...")
            self.cluster_info = self.eks.create_cluster(**config)
            cluster_name = config["name"]

            logger.info(f"Waiting for EKS cluster '{cluster_name}' to become active...")

            # Custom waiter logic
            waiter_delay = 30  # seconds
            max_attempts = 40  # 20 minutes total wait time
            start_time = time.time()  # Track start time

            for attempt in range(max_attempts):
                try:
                    response = self.eks.describe_cluster(name=cluster_name)
                    status = response["cluster"]["status"]

                    if status == "ACTIVE":
                        elapsed_seconds = int(time.time() - start_time)
                        logger.info(
                            f"Cluster '{cluster_name}' is now active! Total time: {elapsed_seconds} seconds."
                        )
                        break
                    else:
                        elapsed_seconds = int(time.time() - start_time)
                        logger.info(
                            f"Cluster '{cluster_name}' is in status '{status}'... Elapsed time: {elapsed_seconds} seconds."
                        )
                        time.sleep(waiter_delay)
                except ClientError as err:
                    logger.error(
                        f"Unexpected error while waiting for cluster to become active: {err}"
                    )
                    raise

            else:
                elapsed_seconds = int(time.time() - start_time)
                logger.error(
                    f"Timed out waiting for cluster '{cluster_name}' to become active after {elapsed_seconds} seconds."
                )
                raise TimeoutError(f"Cluster '{cluster_name}' activation timed out.")

            logger.debug(f"Cluster create return: {pformat(self.cluster_info)}")

        except Exception as err:
            logger.error(f"Error during cluster creation or activation: {err}")
            raise

        return self.cluster_info

        # self.update_control_plane_sg(vpc)
        # self.delete_cluster_public_endpoint()

    def create_fargate_profile(self, config):
        """
        Create a Fargate profile for the EKS cluster and wait for it to become active.
        """
        logger.info("Creating Fargate profile...")
        try:
            # Initiate Fargate profile creation
            self.fargate_profile_info = self.eks.create_fargate_profile(**config)
            fargate_profile_name = config["fargateProfileName"]
            cluster_name = config["clusterName"]

            logger.info(
                f"Waiting for Fargate profile '{fargate_profile_name}' to become active..."
            )

            # Custom waiter logic
            waiter_delay = 30  # seconds
            max_attempts = 40  # 20 minutes total wait time
            start_time = time.time()  # Track start time

            for attempts in range(max_attempts):
                try:
                    response = self.eks.describe_fargate_profile(
                        clusterName=cluster_name,
                        fargateProfileName=fargate_profile_name,
                    )
                    status = response["fargateProfile"]["status"]

                    if status == "ACTIVE":
                        elapsed_seconds = int(time.time() - start_time)
                        logger.info(
                            f"Fargate profile '{fargate_profile_name}' is now active! Total time: {elapsed_seconds} seconds."
                        )
                        break
                    else:
                        elapsed_seconds = int(time.time() - start_time)
                        logger.info(
                            f"Fargate profile '{fargate_profile_name}' is in status '{status}'... Elapsed time: {elapsed_seconds} seconds."
                        )
                        time.sleep(waiter_delay)
                except self.eks.exceptions.ResourceNotFoundException:
                    logger.error(f"Fargate profile '{fargate_profile_name}' not found.")
                    raise
                except ClientError as err:
                    logger.error(f"Unexpected error during wait: {err}")
                    raise
            else:
                elapsed_seconds = int(time.time() - start_time)
                logger.error(
                    f"Timed out waiting for Fargate profile '{fargate_profile_name}' to become active after {elapsed_seconds} seconds."
                )
                raise TimeoutError(
                    f"Fargate profile '{fargate_profile_name}' activation timed out."
                )

            logger.debug(
                f"Fargate profile create return: {pformat(self.fargate_profile_info)}"
            )

        except Exception as err:
            logger.error(
                f"Error waiting for the Fargate profile to become active: {err}"
            )
            raise

        return self.fargate_profile_info

    def create_nodegroup(self, config):
        """
        Create a Nodegroup for the EKS cluster and wait for it to become active.

        :param config: Dictionary containing nodegroup configuration.
        """
        logger.info("Creating Nodegroup...")
        try:
            self.nodegroup_info = self.eks.create_nodegroup(**config)
            nodegroup_name = config["nodegroupName"]
            cluster_name = config["clusterName"]

            logger.info(f"Waiting for Nodegroup '{nodegroup_name}' to become active...")

            # Custom waiter logic
            waiter_delay = 30  # seconds
            max_attempts = 40  # 20 minutes total wait time
            start_time = time.time()  # Track start time

            for attempt in range(max_attempts):
                try:
                    response = self.eks.describe_nodegroup(
                        clusterName=cluster_name, nodegroupName=nodegroup_name
                    )
                    status = response["nodegroup"]["status"]

                    if status == "ACTIVE":
                        elapsed_seconds = int(time.time() - start_time)
                        logger.info(
                            f"Nodegroup '{nodegroup_name}' is now active! Total time: {elapsed_seconds} seconds."
                        )
                        break
                    else:
                        elapsed_seconds = int(time.time() - start_time)
                        logger.info(
                            f"Nodegroup '{nodegroup_name}' is in status '{status}'... Elapsed time: {elapsed_seconds} seconds."
                        )
                        time.sleep(waiter_delay)
                except self.eks.exceptions.ResourceNotFoundException:
                    logger.error(f"Nodegroup '{nodegroup_name}' not found.")
                    raise
                except ClientError as err:
                    logger.error(f"Unexpected error during wait: {err}")
                    raise
            else:
                elapsed_seconds = int(time.time() - start_time)
                logger.error(
                    f"Timed out waiting for Nodegroup '{nodegroup_name}' to become active after {elapsed_seconds} seconds."
                )
                raise TimeoutError(
                    f"Nodegroup '{nodegroup_name}' activation timed out."
                )

            logger.debug(f"Nodegroup create return: {pformat(self.nodegroup_info)}")

        except Exception as err:
            logger.error(f"Error waiting for the Nodegroup to become active: {err}")
            raise

        return self.nodegroup_info

    def delete_cluster(self, repo):
        """
        Delete subnet tags and cluster.
        """
        # TODO: include deletion of subnet tags
        try:
            response = self.eks.delete_cluster(name=repo.cluster_name)
            logger.info(f"Cluster deletion initiated: {response['cluster']['name']}")

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

    def delete_cluster_public_endpoint(self):
        """
        Remove the cluster controlplane public endpoint.
        """
        self.eks_client.update_cluster_config(
            name=self.repo.cluster_name,
            resourcesVpcConfig={
                "endpointPublicAccess": False,
            },
        )
        logger.info("Removed cluster control plane public endpoint.")
        schema_path = f"state/{self.environment}/{self.repo.region}/{self.repo.cluster_name}/cluster-{self.cluster}.yaml"
        with open(schema_path) as f:
            schema = yaml.safe_load(f)
        schema["vpc"]["clusterEndpoints"]["publicAccess"] = False
        with open(schema_path, "w") as f:
            yaml.dump(schema.to_dict(), f)

    def delete_fargateprofile(self, name):
        """
        Delete the specified fargateprofile.
        """
        try:
            logger.info(
                f"Deleting Fargate profile '{name}' from cluster '{self.repo.cluster_name}'..."
            )
            response = self.eks.delete_fargate_profile(
                clusterName=self.repo.cluster_name, fargateProfileName=name
            )
            logger.info(f"Delete initiated for Fargate profile '{name}'.")
            waiter_delay = 10  # seconds
            max_attempts = 30  # 5 minutes total wait time
            start_time = time.time()  # Track start time
            for attempt in range(max_attempts):
                try:
                    self.eks.describe_fargate_profile(
                        clusterName=self.repo.cluster_name, fargateProfileName=name
                    )
                    elapsed_seconds = int(time.time() - start_time)
                    logger.info(
                        f"Waiting for Fargate profile '{name}' to be deleted... Elapsed time: {elapsed_seconds} seconds."
                    )
                    time.sleep(waiter_delay)
                except self.eks.exceptions.ResourceNotFoundException:
                    elapsed_seconds = int(time.time() - start_time)
                    logger.info(
                        f"Fargate profile '{name}' successfully deleted. Total time: {elapsed_seconds} seconds."
                    )
                    return
                except ClientError as err:
                    logger.error(f"Unexpected error during deletion wait: {err}")
                    raise

            elapsed_seconds = int(time.time() - start_time)
            logger.error(
                f"Timed out waiting for Fargate profile '{name}' to be deleted after {elapsed_seconds} seconds."
            )
            raise TimeoutError(
                f"Fargate profile '{name}' deletion timed out after {elapsed_seconds} seconds."
            )

        except ClientError as err:
            logger.error(f"Failed to delete Fargate profile '{name}': {err}")
            raise

    def delete_nodegroup(self, name, drain):
        """
        Delete the specified Nodegroup and wait until it is fully deleted.

        :param name: Name of the Nodegroup to delete.
        """
        cluster_name = self.repo.cluster_name

        logger.info(f"Deleting Nodegroup '{name}' from cluster '{cluster_name}'...")
        try:
            # Initiate Nodegroup deletion
            response = self.eks.delete_nodegroup(
                clusterName=cluster_name, nodegroupName=name
            )
            logger.info(f"Delete initiated for Nodegroup '{name}'.")

            # Custom waiter logic
            waiter_delay = 30  # seconds
            max_attempts = 40  # 20 minutes total wait time
            start_time = time.time()  # Track start time

            for attempt in range(max_attempts):
                try:
                    self.eks.describe_nodegroup(
                        clusterName=cluster_name, nodegroupName=name
                    )
                    elapsed_seconds = int(time.time() - start_time)
                    logger.info(
                        f"Waiting for Nodegroup '{name}' to be deleted... Elapsed time: {elapsed_seconds} seconds."
                    )
                    time.sleep(waiter_delay)
                except self.eks.exceptions.ResourceNotFoundException:
                    elapsed_seconds = int(time.time() - start_time)
                    logger.info(
                        f"Nodegroup '{name}' successfully deleted. Total time: {elapsed_seconds} seconds."
                    )
                    return
                except ClientError as err:
                    logger.error(
                        f"Unexpected error while waiting for Nodegroup deletion: {err}"
                    )
                    raise

            elapsed_seconds = int(time.time() - start_time)
            logger.error(
                f"Timed out waiting for Nodegroup '{name}' to be deleted after {elapsed_seconds} seconds."
            )
            raise TimeoutError(
                f"Nodegroup '{name}' deletion timed out after {elapsed_seconds} seconds."
            )

        except ClientError as err:
            logger.error(f"Failed to delete Nodegroup '{name}': {err}")
            raise

    def get_cluster_info(self):
        self.cluster_info = self.eks.describe_cluster(name=self.repo.cluster_name)
        logger.debug(f"cluster info:\n{pformat(self.cluster_info)}")
        return self.cluster_info

    def get_fargate_profiles(self):
        """
        Creates a dictionary containing cluster/nodegroup names as keys with k8s versions
        as values.
        """
        schema_dir = (
            f"state/{self.repo.environment}/{self.repo.region}/{self.repo.cluster_name}"
        )
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
        schema_dir = (
            f"state/{self.repo.environment}/{self.repo.region}/{self.repo.cluster_name}"
        )
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
                Params={k8s_aws_id_header: self.repo.cluster_name},
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
                        f"{self.repo.cluster_name}-cluster/ControlPlaneSecurityGroup"
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

    def upgrade_cluster(self, new_version):

        try:
            response = self.eks.update_cluster_version(
                name=self.repo.cluster_name, version=new_version
            )
            logger.info(f"Cluster version update initiated: {new_version}")

            start_time = time.time()
            waiter_delay = 30  # seconds
            max_attempts = 40  # 20 minutes max wait time
            ## When this is first initiated the cluster status shows ACTIVE for the first ~60 seconds
            ## causing the loop to exit before the operation is complete or before the status shows
            ## UPDATING. Waiting 90 seconds as a safety
            time.sleep(90)
            for attempt in range(max_attempts):
                try:
                    response = self.eks.describe_cluster(name=self.repo.cluster_name)
                    cluster_status = response["cluster"]["status"]
                    logger.debug(pformat(response["cluster"]))

                    if cluster_status == "ACTIVE":
                        elapsed_seconds = int(time.time() - start_time)
                        logger.info(
                            f"Cluster {self.repo.cluster_name} successfully updated to version {new_version}. "
                            f"Total time: {elapsed_seconds} seconds."
                        )
                        return response
                    else:
                        elapsed_seconds = int(time.time() - start_time)
                        logger.info(
                            f"Waiting for cluster {self.repo.cluster_name} update to complete... "
                            f"Elapsed time: {elapsed_seconds} seconds. Status: {cluster_status}"
                        )
                        time.sleep(waiter_delay)

                except self.eks.exceptions.ResourceNotFoundException:
                    logger.error(f"Cluster {self.repo.cluster_name} not found.")
                    raise
                except KeyError:
                    logger.info(
                        f"Waiting for update details to propagate... "
                        f"Elapsed time: {int(time.time() - start_time)} seconds."
                    )
                    time.sleep(waiter_delay)
                except ClientError as err:
                    logger.error(f"An error occurred: {err}")
                    raise

            logger.error(
                f"Cluster {self.repo.cluster_name} update timed out after {max_attempts * waiter_delay} seconds."
            )
        except ClientError as err:
            logger.error(f"Failed to initiate cluster update: {err}")
            raise
        except Exception as err:
            logger.error(f"Unexpected error: {err}")
            raise

    def upgrade_nodegroup(self, name, current_version, new_version, drain):
        current_schema = yaml.safe_load(open(current_schema_path, "r"))
        instance_type = current_schema["managedNodeGroups"][0]["instanceType"]
        desired = current_schema["managedNodeGroups"][0]["desiredCapacity"]
        max = current_schema["managedNodeGroups"][0]["maxSize"]
        min = current_schema["managedNodeGroups"][0]["minSize"]
        self.create_nodegroup(name, instance_type, new_version, desired, min, max)
        self.delete_nodegroup(name, current_version, drain)

    def upgrade_nodegroup_ami(self, name, version, release_version=None):
        """
        Upgrade the specified Nodegroup to a new Kubernetes version and wait for the upgrade to complete.

        :param name: Name of the Nodegroup to upgrade.
        :param version: Kubernetes version to upgrade the Nodegroup to.
        :param release_version: Optional AMI release version for the upgrade.
        """
        cluster_name = self.repo.cluster_name

        logger.info(
            f"Upgrading Nodegroup '{name}' in cluster '{cluster_name}' to version '{version}'..."
        )
        try:
            # Initiate Nodegroup upgrade
            upgrade_params = {
                "clusterName": cluster_name,
                "nodegroupName": name,
                "version": version,
            }
            if release_version:
                upgrade_params["releaseVersion"] = release_version

            response = self.eks.update_nodegroup_version(**upgrade_params)
            logger.info(
                f"Upgrade initiated for Nodegroup '{name}' to version '{version}'."
            )

            # Custom waiter logic
            waiter_delay = 30  # seconds
            max_attempts = 40  # 20 minutes total wait time
            start_time = time.time()  # Track start time

            for attempt in range(max_attempts):
                try:
                    response = self.eks.describe_nodegroup(
                        clusterName=cluster_name, nodegroupName=name
                    )
                    status = response["nodegroup"]["status"]

                    if status == "ACTIVE":
                        elapsed_seconds = int(time.time() - start_time)
                        logger.info(
                            f"Nodegroup '{name}' successfully upgraded to version '{version}'. Total time: {elapsed_seconds} seconds."
                        )
                        return response
                    elif status == "UPDATING":
                        elapsed_seconds = int(time.time() - start_time)
                        logger.info(
                            f"Nodegroup '{name}' is upgrading... Elapsed time: {elapsed_seconds} seconds."
                        )
                        time.sleep(waiter_delay)
                    else:
                        logger.warning(
                            f"Unexpected status '{status}' for Nodegroup '{name}'. Continuing to monitor..."
                        )
                        time.sleep(waiter_delay)
                except ClientError as err:
                    logger.error(
                        f"Unexpected error while monitoring Nodegroup upgrade: {err}"
                    )
                    raise

            elapsed_seconds = int(time.time() - start_time)
            logger.error(
                f"Timed out waiting for Nodegroup '{name}' to complete the upgrade after {elapsed_seconds} seconds."
            )
            raise TimeoutError(
                f"Nodegroup '{name}' upgrade timed out after {elapsed_seconds} seconds."
            )

        except ClientError as err:
            logger.error(f"Failed to upgrade Nodegroup '{name}': {err}")
            raise


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
            logger.info(f"created role: {response['Role']['Arn']}")
            return response["Role"]["Arn"], response["Role"]
        except self.iam.exceptions.EntityAlreadyExistsException:
            logger.info(f"Role '{role_name}' already exists.")
            existing_role = self.iam.get_role(RoleName=role_name)
            return existing_role["Role"]["Arn"]
        except Exception as err:
            logger.error(f"Error creating role: {err}")

    def create_fargate_pod_execution_role(self):
        try:
            fargate_trust_policy = {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": {"Service": "eks-fargate-pods.amazonaws.com"},
                        "Action": "sts:AssumeRole",
                    }
                ],
            }

            role_name = f"{self.repo.cluster_name}-fargate-pod-execution-role"
            managed_policies = [
                "arn:aws:iam::aws:policy/AmazonEKSFargatePodExecutionRolePolicy",
            ]

            response = self.iam.create_role(
                RoleName=role_name,
                AssumeRolePolicyDocument=json.dumps(fargate_trust_policy),
                Description="EKS Fargate Pod Execution Role",
            )

            for policy_arn in managed_policies:
                self.iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)

            logger.info(
                f"Fargate Pod Execution Role '{role_name}' created successfully."
            )
            return response["Role"]["Arn"], response["Role"]

        except self.iam.exceptions.EntityAlreadyExistsException:
            logger.info(f"Role '{role_name}' already exists.")
            existing_role = self.iam.get_role(RoleName=role_name)
            return existing_role["Role"]["Arn"], existing_role["Role"]

        except Exception as err:
            logger.error(f"Error creating Fargate Pod Execution Role: {err}")
            raise

    def create_node_role(self):
        """
        Create an IAM role for EKS Nodegroup and attach required policies.
        """
        try:
            node_trust_policy = {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": {"Service": "ec2.amazonaws.com"},
                        "Action": "sts:AssumeRole",
                    }
                ],
            }
            role_name = f"{self.repo.cluster_name}-node-role"
            managed_policies = [
                "arn:aws:iam::aws:policy/AmazonEKSWorkerNodePolicy",
                "arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryPullOnly",
                "arn:aws:iam::aws:policy/AmazonEKS_CNI_Policy",
                # TODO: add custom policy for IPV6 deployments
                # https://docs.aws.amazon.com/eks/latest/userguide/create-node-role.html
            ]
            response = self.iam.create_role(
                RoleName=role_name,
                AssumeRolePolicyDocument=json.dumps(node_trust_policy),
                Description="EKS Node Role",
            )
            for policy_arn in managed_policies:
                self.iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)

            logger.info(f"Node role '{role_name}' created successfully.")
            return response["Role"]["Arn"], response["Role"]
        except self.iam.exceptions.EntityAlreadyExistsException:
            logger.info(f"Role '{role_name}' already exists.")
            existing_role = self.iam.get_role(RoleName=role_name)
            return existing_role["Role"]["Arn"]
        except Exception as err:
            logger.error(f"Error creating node role: {err}")
            raise


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
