#! /usr/bin/env python3
import click
import functools
import logging
import json
import os
import sys

import manager.aws
from manager.utils import SpaceSeparatedList, Repo

logging.basicConfig(
    level=logging.INFO,
    format=("%(asctime)s [%(levelname)s] %(message)s"),
    datefmt="%Y-%m-%d %H:%M:%S",
)

logger = logging.getLogger(__name__)
SPACE_SEPARATED_LIST = SpaceSeparatedList()

# Reusable decorator for shared options
def common_options(func):
    @click.option(
        "--cluster-name",
        "-c",
        envvar="EKS_CLUSTER_NAME",
        default="test",
        help="EKS Cluster name",
    )
    @click.option(
        "--environment",
        "-e",
        envvar="EKS_ENVIRONMENT",
        default="dev",
        help="Environment",
    )
    @click.option(
        "--region", "-r", envvar="EKS_REGION", default="us-east-1", help="AWS Region"
    )
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        return func(*args, **kwargs)

    return wrapper


def common_nodegroup_options(func):
    @click.option(
        "-n",
        "--name",
        envvar="EKS_NODEGROUP_NAME",
        default="test",
        help="Nodegroup name",
    )
    @click.option(
        "-k",
        "--kubernetes-version",
        envvar="EKS_KUBERNETES_VERSION",
        default="1.30",
        help="EKS Version",
    )
    @functools.wraps(func)  # Keeps the original function signature and docs
    def wrapper(*args, **kwargs):
        return func(*args, **kwargs)

    return wrapper


def common_iamserviceaccount_options(func):
    @click.option(
        "-n",
        "--name",
        envvar="EKS_IAMSERVICEACCOUNT_NAME",
        help="IAM service account name",
    )
    @click.option(
        "-N",
        "--namespace",
        required=True,
        envvar="EKS_IAMSERVICEACCOUNT_NAMESPACE",
        help="Namespace for the IAM service account",
    )
    @functools.wraps(func)  # Keeps the original function signature and docs
    def wrapper(*args, **kwargs):
        return func(*args, **kwargs)

    return wrapper


import logging
from functools import wraps

# Initialize the logger
logger = logging.getLogger(__name__)


def log_debug_parameters(func):
    """Decorator to log function parameters, including contents of repo object."""

    @wraps(func)
    def wrapper(*args, **kwargs):
        # Log positional arguments
        if args:
            logger.debug(f"Positional args: {', '.join(map(str, args))}")
        # Log keyword arguments
        if kwargs:
            details = ", ".join([f"{key}: {value}" for key, value in kwargs.items()])
            logger.debug(f"Keyword args: {details}")
        # Check for `repo` in args and log its attributes
        for arg in args:
            if hasattr(arg, "__dict__"):  # Check if it has attributes
                repo_attrs = vars(arg)  # Or arg.__dict__
                repo_details = ", ".join(
                    [f"{key}: {value}" for key, value in repo_attrs.items()]
                )
                logger.debug(f"Repo object contents: {repo_details}")
        # Execute the original function
        return func(*args, **kwargs)

    return wrapper


@click.group()
@click.option("--debug", is_flag=True, help="Enable debug mode")
@click.option("--dry-run", is_flag=True, help="Enable dry-run mode")
@click.pass_context
def cli(ctx, dry_run, debug):
    """CLI main group for managing EKS clusters."""
    if debug:
        logger.setLevel(logging.DEBUG)
        logger.debug("Debug mode is enabled")
    # Initialize the Repo object and pass it into the context
    ctx.obj = Repo(dry_run, debug)


@cli.group()
@common_options
@click.pass_obj
@log_debug_parameters
def cluster(repo, cluster_name, environment, region):
    """Manage cluster actions like create, delete, or upgrade."""
    repo.cluster_name = cluster_name
    repo.environment = environment
    repo.region = region


@cluster.command()
@click.option(
    "-C",
    "--cluster-admins",
    envvar="EKS_CLUSTER_CLUSTER_ADMINS",
    type=SPACE_SEPARATED_LIST,
    default=[],
    help="Space seperated list of IAM user names in the target account to give admin access.",
)
@click.option(
    "-k",
    "--kubernetes-version",
    envvar="EKS_CLUSTER_VERSION",
    default="repo",
    help="EKS Version",
)
@click.option("-v", "--vpc-name", envvar="EKS_VPC_NAME", required=True, help="VPC name")
@click.pass_obj
@log_debug_parameters
def create(repo, cluster_admins, kubernetes_version, vpc_name):
    """Create a new cluster"""
    kubernetes_version_choice = click.Choice(repo.eks_versions)
    if kubernetes_version not in repo.eks_versions:
        logger.info(f"Invalid Kubernetes version: {kubernetes_version}.")
        logger.info(f"Supported versions: {', '.join(repo.eks_versions)}")
        return
    repo.vpc_name = vpc_name
    vpc = manager.aws.Vpc(repo)
    eks_manager = manager.aws.Eks(repo, vpc=vpc)
    eks_manager.create_cluster(kubernetes_version, cluster_admins)


@cluster.command()
@click.option("-v", "--vpc-name", envvar="EKS_VPC_NAME", required=True, help="VPC name")
@click.pass_obj
@log_debug_parameters
def delete(repo, vpc_name):
    """Delete eks cluster"""
    repo.vpc_name = vpc_name
    vpc = manager.aws.Vpc(repo)
    eks_manager = manager.aws.Eks(repo, vpc=vpc)
    eks_manager.delete_cluster()


@cluster.command()
@click.option(
    "-k",
    "--kubernetes-version",
    envvar="EKS_KUBERNETES_VERSION",
    default="1.30",
    help="EKS Version",
)
@click.option(
    "-u",
    "--upgrade-version",
    envvar="EKS_KUBERNETES_UPGRADE_VERSION",
    default="1.30",
    help="EKS Upgrade Version",
)
@click.option("-v", "--vpc-name", envvar="EKS_VPC_NAME", required=True, help="VPC name")
@click.pass_obj
@log_debug_parameters
def upgrade(repo, kubernetes_version, upgrade_version, vpc_name):
    """Upgrade eks cluster"""
    repo.vpc_name = vpc_name
    vpc = manager.aws.Vpc(repo)
    eks_manager = manager.aws.Eks(repo, vpc=vpc)
    eks_manager.upgrade_cluster(kubernetes_version, upgrade_version)


@cli.group()
@common_options
@click.pass_obj
@log_debug_parameters
def fargateprofile(repo, cluster_name, environment, region):
    """Manage fargate profiles/nodegroups, like create, delete."""
    repo.cluster_name = cluster_name
    repo.environment = environment
    repo.region = region


@fargateprofile.command()
@click.option(
    "-n",
    "--name",
    required=True,
    envvar="EKS_FARGATEPROFILE_NAME",
    help="Name for the fargate profile/nodegroup",
)
@click.option(
    "-N",
    "--namespace",
    required=True,
    envvar="EKS_FARGATEPROFILE_NAMESPACE",
    help="Namespace for the fargate profile/nodegroup",
)
@click.option(
    "-l",
    "--labels",
    envvar="EKS_FARGATEPROFILE_LABELS",
    help="Labels for the fargate profile/nodegroup",
)
@click.option("-v", "--vpc-name", envvar="EKS_VPC_NAME", required=True, help="VPC name")
@click.pass_obj
@log_debug_parameters
def create(repo, name, namespace, labels, vpc_name):
    """Create Fargate Profile/Nodegroup"""
    repo.vpc_name = vpc_name
    vpc = manager.aws.Vpc(repo)
    eks_manager = manager.aws.Eks(repo, vpc=vpc)
    eks_manager.create_fargate_profile(name, namespace, labels=labels)


@fargateprofile.command()
@click.option(
    "-n",
    "--name",
    required=True,
    envvar="EKS_FARGATEPROFILE_NAME",
    help="Name for the fargate profile/nodegroup",
)
@click.pass_obj
@log_debug_parameters
def delete(repo, name):
    """Delete Fargate Profile/Nodegroup"""
    eks_manager = manager.aws.Eks(repo)
    eks_manager.delete_fargateprofile(name)


@cli.group()
@common_options
@click.pass_obj
@log_debug_parameters
def nodegroup(repo, cluster_name, environment, region):
    """Manage nodegroups, like create, delete, upgrade."""
    repo.cluster_name = cluster_name
    repo.environment = environment
    repo.region = region


@nodegroup.command()
@common_nodegroup_options
@click.option(
    "-i",
    "--instance-class",
    envvar="EKS_NODEGROUP_INSTANCE_CLASS",
    default="t4g.medium",
    help="Instance class",
)
@click.option(
    "-d",
    "--desired-capacity",
    envvar="EKS_NODEGROUP_DESIRED_CAPACITY",
    default=0,
    help="Desired Capacity",
)
@click.option(
    "-M",
    "--max-nodes",
    envvar="EKS_NODEGROUP_MAXIMUM_NODES",
    default=0,
    help="Maximum nodes",
)
@click.option(
    "-m",
    "--min-nodes",
    envvar="EKS_NODEGROUP_MINIMUM_NODES",
    default=0,
    help="Minimum nodes",
)
@click.pass_obj
@log_debug_parameters
def create(
    repo,
    name,
    instance_class,
    desired_capacity,
    max_nodes,
    min_nodes,
    kubernetes_version,
):
    """Create Nodegroup"""
    eks_manager = manager.aws.Eks(repo)
    eks_manager.create_nodegroup(
        name,
        instance_class,
        kubernetes_version,
        desired_capacity,
        min_nodes,
        max_nodes,
    )


@nodegroup.command()
@common_nodegroup_options
@click.option(
    "-D",
    "--drain",
    is_flag=True,
    envvar="EKS_NODEGROUP_DRAIN",
    help="Flag to drain nodegroup during upgrade",
)
@click.pass_obj
@log_debug_parameters
def delete(repo, name, kubernetes_version, drain):
    """Delete Nodegroup"""
    eks_manager = manager.aws.Eks(repo)
    eks_manager.delete_nodegroup(name, kubernetes_version, drain)


@nodegroup.command()
@common_nodegroup_options
@click.option(
    "-u",
    "--upgrade-version",
    envvar="EKS_KUBERNETES_UPGRADE_VERSION",
    default="1.30",
    help="EKS Upgrade Version",
)
@click.option(
    "-D",
    "--drain",
    is_flag=True,
    envvar="EKS_NODEGROUP_DRAIN",
    help="Flag to drain nodegroup during upgrade",
)
@click.pass_obj
@log_debug_parameters
def upgrade(repo, name, kubernetes_version, upgrade_version, drain):
    """Upgrade Nodegroup"""
    eks_manager = manager.aws.Eks(repo)
    eks_manager.upgrade_nodegroup(name, kubernetes_version, upgrade_version, drain)


@nodegroup.command()
@common_nodegroup_options
@click.option(
    "-u",
    "--upgrade-version",
    envvar="EKS_KUBERNETES_UPGRADE_VERSION",
    default="1.30",
    help="EKS Upgrade Version",
)
@click.pass_obj
@log_debug_parameters
def upgrade_ami(repo, name, kubernetes_version, upgrade_version):
    """Upgrade Nodegroup AMI"""
    eks_manager = manager.aws.Eks(repo)
    eks_manager.upgrade_nodegroup_ami(name, kubernetes_version, upgrade_version)


@cli.group()
@common_options
@click.pass_obj
@log_debug_parameters
def iamserviceaccount(repo, cluster_name, environment, region):
    """Manage IAM service accounts, like create, delete."""
    repo.cluster_name = cluster_name
    repo.environment = environment
    repo.region = region


@iamserviceaccount.command()
@common_iamserviceaccount_options
@click.option(
    "-P",
    "--iam-policy-arn",
    envvar="EKS_IAMSERVICEACCOUNT_POLICYARN",
    help="IAM service account policy ARN",
)
@click.pass_obj
@log_debug_parameters
def create(repo, name, namespace, iam_policy_arn):
    """Create IAM service account"""
    eks_manager = manager.aws.Eks(repo)
    eks_manager.create_iam_service_account(
        name, namespace, iam_policy_arn=iam_policy_arn
    )


@iamserviceaccount.command()
@common_iamserviceaccount_options
@click.pass_obj
@log_debug_parameters
def delete(repo, name, namespace):
    """Create IAM service account"""
    eks_manager = manager.aws.Eks(repo)
    eks_manager.delete_iam_service_account(name, namespace)


@cli.group()
@common_options
@click.pass_obj
@log_debug_parameters
def adminusermap(repo, cluster_name, environment, region):
    """Manage IAM service accounts, like create, delete."""
    repo.cluster_name = cluster_name
    repo.environment = environment
    repo.region = region


@adminusermap.command()
@click.option("-n", "--name", envvar="EKS_ADMINUSERMAP_NAME", help="IAM user name")
@click.pass_obj
@log_debug_parameters
def create(repo, name):
    """Create IAM service account"""
    eks_manager = manager.aws.Eks(repo)
    eks_manager.create_admin_user(name)


@adminusermap.command()
@click.option("-n", "--name", envvar="EKS_ADMINUSERMAP_NAME", help="IAM user name")
@click.pass_obj
@log_debug_parameters
def delete(repo, name):
    """Create IAM service account"""
    eks_manager = manager.aws.Eks(repo)
    eks_manager.delete_admin_user(name)


@cli.command()
@common_options
@click.option(
    "-k",
    "--kubernetes-version",
    envvar="EKS_KUBERNETES_VERSION",
    default="1.30",
    help="EKS Version",
)
@click.option(
    "-u",
    "--upgrade-version",
    envvar="EKS_KUBERNETES_UPGRADE_VERSION",
    default="1.30",
    help="EKS Upgrade Version",
)
@click.option("-v", "--vpc-name", envvar="EKS_VPC_NAME", required=True, help="VPC name")
@click.option(
    "-D",
    "--drain",
    is_flag=True,
    envvar="EKS_NODEGROUP_DRAIN",
    help="Flag to drain nodegroup during upgrade",
)
@click.pass_obj
@log_debug_parameters
def upgrade_all(
    repo,
    cluster_name,
    environment,
    region,
    kubernetes_version,
    upgrade_version,
    vpc_name,
    drain,
):
    """Create IAM admin user mapping"""
    repo.cluster_name = cluster_name
    repo.environment = environment
    repo.region = region
    repo.vpc_name = vpc_name
    vpc = manager.aws.Vpc(repo)
    eks_manager = manager.aws.Eks(repo, vpc=vpc)
    eks_manager.upgrade_all(kubernetes_version, upgrade_version, drain)
