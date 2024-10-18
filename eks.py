#! /usr/bin/env python3
import click
import functools
import logging
from copy import deepcopy
from pprint import pformat
import sys

from manager.aws import Vpc, Eks, k8s
from manager.utils import (
    SpaceSeparatedList,
    KeyValueType,
    Repo,
    ConfigProcessor,
    log_debug_parameters,
    set_args_in_repo,
)

logging.basicConfig(
    level=logging.INFO,
    format=("%(asctime)s [%(name)s] [%(levelname)s] %(message)s"),
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger(__name__)

SPACE_SEPARATED_LIST = SpaceSeparatedList()
KEY_VALUE_TYPE = KeyValueType()

# Reusable decorators for shared options
def common_options(func):
    @click.option(
        "--cluster-name",
        "-c",
        envvar="EKS_CLUSTER_NAME",
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


@click.group()
@click.option("--debug", is_flag=True, help="Enable debug mode")
@click.option("--dry-run", is_flag=True, help="Enable dry-run mode")
@click.option(
    "--organization",
    "-O",
    "org",
    envvar="EKS_ORGNIZATION",
    default="default",
    help="Organization name",
)
@click.option(
    "-o",
    "--output-format",
    "format",
    default="yaml",
    type=click.Choice(["yaml", "json"], case_sensitive=False),
    help="Output format: yaml or json",
)
@click.pass_context
def cli(ctx, dry_run, debug, format, org):
    """CLI main group for managing EKS clusters."""
    if debug:
        logging.getLogger().setLevel(logging.DEBUG)
        logging.getLogger("botocore").setLevel(logging.INFO)
        logging.getLogger("boto3").setLevel(logging.INFO)
        logger.debug("Debug mode is enabled")
    # Initialize the Repo object and pass it into the context
    ctx.obj = Repo(dry_run, debug, format)
    args = locals()
    for key, value in args.items():
        if key != "ctx":
            logger.debug(f"setting repo: {key} = {value}")
            setattr(ctx.obj, key, value)


@cli.group()
@common_options
@click.pass_obj
@log_debug_parameters
def cluster(repo, cluster_name, environment, region):
    """Manage cluster actions like create, delete, or upgrade."""
    set_args_in_repo(repo, locals())


@cluster.command()
@click.option(
    "-b",
    "--bootstrap-admin-perms",
    envvar="EKS_CLUSTER_BOOTSTRAP_ADMIN",
    default=True,
    help="Specifies whether or not the cluster creator IAM principal is set as a cluster admin access",
)
@click.option(
    "-C",
    "--cluster-admins",
    envvar="EKS_CLUSTER_CLUSTER_ADMINS",
    type=SPACE_SEPARATED_LIST,
    default="",
    help="Space seperated list of IAM user names in the target account to give admin access.",
)
@click.option(
    "-c",
    "--kubernetes-cidr-block",
    envvar="EKS_CLUSTER_KUBERNETES_CIDR_BLOCK",
    default=None,
    help="CIDR block for kubernetes cluster addresses.",
)
@click.option(
    "-i",
    "--ip-family",
    envvar="EKS_CLUSTER_IP_FAMILY",
    type=click.Choice(["ipv4", "ipv6"], case_sensitive=False),
    default="ipv4",
    help="Enable public or private access to EKS api endpoints",
)
@click.option(
    "-V",
    "--kubernetes-version",
    "version",
    envvar="EKS_CLUSTER_VERSION",
    help="EKS Version",
)
@click.option(
    "-K",
    "--kms_encryption_key",
    envvar="EKS_CLUSTER_KMS_ENCRYPTION_KEY",
    default=None,
    help="KMS encryption key for secrets encryption, can be arn or alias",
)
@click.option(
    "-l",
    "--logging-types",
    envvar="EKS_CLUSTER_LOGGING_TYPES",
    type=SPACE_SEPARATED_LIST,
    default="",
    help="""Space seperated list of k8s logging types: 
            api audit authenticator controllerManager scheduler""",
)
@click.option(
    "-P",
    "--public-access-cidrs",
    envvar="EKS_CLUSTER_PUBLIC_ACCESS_CIDRS",
    type=SPACE_SEPARATED_LIST,
    default="",
    help="Space seperated list of CIDR blocks for EKS api endpoint access.",
)
@click.option(
    "-p",
    "--public-private-access",
    envvar="EKS_CLUSTER_PUBLIC_PRIVATE_ACCESS",
    type=click.Choice(["public", "private", "both"], case_sensitive=False),
    default="both",
    help="Enable public or private access to EKS api endpoints",
)
@click.option(
    "-r",
    "--role-arn",
    envvar="EKS_CLUSTER_ROLE_ARN",
    default="arn:aws:iam::290730444397:role/aws-service-role/eks.amazonaws.com/AWSServiceRoleForAmazonEKS",
    help="KMS encryption key for secrets encryption, can be arn or alias",
)
@click.option(
    "-S",
    "--security-group-ids",
    envvar="EKS_CLUSTER_SECURITY_GROUPS",
    type=SPACE_SEPARATED_LIST,
    default="",
    help="Space seperated list of security group ids for EKS resources.",
)
@click.option(
    "-s",
    "--support-type",
    envvar="EKS_CLUSTER_SECURITY_GROUPS",
    type=click.Choice(["EXTENDED", "STANDARD"], case_sensitive=False),
    default="STANDARD",
    help="EKS support type.",
)
@click.option(
    "-t",
    "--tags",
    envvar="EKS_CLUSTER_TAGS",
    type=KEY_VALUE_TYPE,
    default={},
    help="""Space seperated list of key/value pairs for EKS cluster.
            example: key1=value1 key2=value2""",
)
@click.option("-v", "--vpc-name", envvar="EKS_VPC_NAME", required=True, help="VPC name")
@click.pass_obj
@log_debug_parameters
def create(
    repo,
    bootstrap_admin_perms,
    cluster_admins,
    ip_family,
    kms_encryption_key,
    kubernetes_cidr_block,
    version,
    logging_types,
    public_access_cidrs,
    public_private_access,
    role_arn,
    security_group_ids,
    support_type,
    tags,
    vpc_name,
):
    """Create a new cluster"""
    logger.debug(f"starting cluster create command")
    if version not in repo.eks_versions:
        logger.info(f"Invalid Kubernetes version: {version}.")
        logger.info(f"Supported versions: {', '.join(repo.eks_versions)}")
        return

    set_args_in_repo(repo, locals())

    vpc = Vpc(repo)
    logger.debug("Vpc instance is: %s", type(vpc))

    repo.version = version
    repo.private_subnets = deepcopy(vpc.private_subnet_ids)
    repo.public_subnets = deepcopy(vpc.public_subnet_ids)

    if kms_encryption_key:
        repo.encrypted_resources = ["secrets"]
    else:
        repo.encrypted_resources = []

    if logging_types:
        repo.logging_enabled = True
    else:
        repo.logging_enabled = False

    endpoint_access = {
        "public": (True, False),
        "private": (False, True),
        "both": (True, True),
    }
    repo.public_access, repo.private_access = endpoint_access.get(
        public_private_access.lower(), (False, False)
    )
    config = ConfigProcessor(repo)
    config.cluster(repo)
    logger.debug(f"config object is a {type(config.cluster_config)}")
    logger.debug(f"{config.cluster_config}")
    repo.state_path = (
        f"{repo.org}/{repo.environment}/{repo.region}/{repo.cluster_name}/"
    )
    repo.cluster_filename = (
        f"cluster-{repo.cluster_name}-{repo.version.replace('.', '-')}.{repo.format}"
    )
    logger.debug(f"state path: {repo.state_path}")
    if repo.dry_run:
        config.write_state(repo, config)
    else:
        vpc.verify_private_elb_tags()
        vpc.verify_public_elb_tags()
        eks = Eks(repo)
        if eks.check_cluster_exists() is True:
            logger.error("Cluster %s already exists.", config.name)
            sys.exit(1)
        vpc.create_cluster_tags(repo.cluster_name)
        logger.debug(f"config is:\n{config}")
        eks.create_cluster(config)
        logger.debug(f"eks.cluster_info: {eks.cluster_info}")
        config.write_state(repo, eks.cluster_info)


@cluster.command()
@click.option("-v", "--vpc-name", envvar="EKS_VPC_NAME", required=True, help="VPC name")
@click.pass_obj
@log_debug_parameters
def delete(repo, vpc_name):
    """Delete eks cluster"""
    repo.vpc_name = vpc_name
    vpc = Vpc(repo)
    eks_manager = Eks(repo)
    eks_manager.delete_cluster()


@cluster.command()
@click.option(
    "-V",
    "--kubernetes-version",
    "version",
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
    vpc = Vpc(repo)
    eks_manager = Eks(repo, vpc=vpc)
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
    vpc = Vpc(repo)
    eks_manager = Eks(repo, vpc=vpc)
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
    eks_manager = Eks(repo)
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
    eks_manager = Eks(repo)
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
    eks_manager = Eks(repo)
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
    eks_manager = Eks(repo)
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
    eks_manager = Eks(repo)
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
    eks_manager = Eks(repo)
    eks_manager.create_iam_service_account(
        name, namespace, iam_policy_arn=iam_policy_arn
    )


@iamserviceaccount.command()
@common_iamserviceaccount_options
@click.pass_obj
@log_debug_parameters
def delete(repo, name, namespace):
    """Create IAM service account"""
    eks_manager = Eks(repo)
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
    eks_manager = Eks(repo)
    repo.cluster_info = eks_manager.get_cluster_info()
    eks_manager.create_admin_user(name)


@adminusermap.command()
@click.option("-n", "--name", envvar="EKS_ADMINUSERMAP_NAME", help="IAM user name")
@click.pass_obj
@log_debug_parameters
def delete(repo, name):
    """Create IAM service account"""
    eks_manager = Eks(repo)
    eks_manager.delete_admin_user(name)


@cli.command()
@common_options
@click.option(
    "-V",
    "--kubernetes-version",
    "version",
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
    version,
    upgrade_version,
    vpc_name,
    drain,
):
    """Upgrade version for all resources"""
    repo.cluster_name = cluster_name
    repo.environment = environment
    repo.region = region
    repo.vpc_name = vpc_name
    repo.version = version
    vpc = Vpc(repo)
    eks_manager = Eks(repo, vpc=vpc)
    eks_manager.upgrade_all(version, upgrade_version, drain)
