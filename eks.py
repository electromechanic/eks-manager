#! /usr/bin/env python3
import click
import copy
import functools
import logging
from copy import deepcopy
from pprint import pformat
import sys
import time

from manager.aws import Vpc, Eks, k8s, IAM
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
# fmt: off
def common_options(func):
    @click.option("--cluster-name",
        "-c",
        envvar="EKS_CLUSTER_NAME",
        help="EKS Cluster name",
    )
    @click.option("--environment",
        "-e",
        envvar="EKS_ENVIRONMENT",
        default="dev",
        help="Environment",
    )
    @click.option("--region",
        "-r",
        envvar="EKS_REGION",
        default="us-east-1",
        help="AWS Region",
    )
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        return func(*args, **kwargs)

    return wrapper


def common_drain_option(func):
    @click.option("--drain",
        "-D",
        is_flag=True,
        envvar="EKS_NODEGROUP_DRAIN",
        help="Flag to drain nodegroup during upgrade",
    )
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        return func(*args, **kwargs)

    return wrapper


def common_iamserviceaccount_options(func):
    @click.option("--name",
        "-n",
        envvar="EKS_IAMSERVICEACCOUNT_NAME",
        help="IAM service account name",
    )
    @click.option("--namespace",
        "-N",
        required=True,
        envvar="EKS_IAMSERVICEACCOUNT_NAMESPACE",
        help="Namespace for the IAM service account",
    )
    @functools.wraps(func)  # Keeps the original function signature and docs
    def wrapper(*args, **kwargs):
        return func(*args, **kwargs)

    return wrapper


def common_nodegroup_options(func):
    @click.option("--name",
        "-n",
        envvar="EKS_NODEGROUP_NAME",
        default="test",
        help="Nodegroup name",
    )
    @click.option("--kubernetes-version",
        "-k",
        "version",
        envvar="EKS_KUBERNETES_VERSION",
        default="1.30",
        help="EKS Version",
    )
    @functools.wraps(func)  # Keeps the original function signature and docs
    def wrapper(*args, **kwargs):
        return func(*args, **kwargs)

    return wrapper


def common_upgrade_options(func):
    # @click.option("--kubernetes-version",
    #     "-V",
    #     envvar="EKS_KUBERNETES_VERSION",
    #     default="1.30",
    #     required=True,
    #     help="Kubernetes version for the cluster or nodegroup",
    # )
    @click.option("--upgrade-version",
        "-u",
        envvar="EKS_KUBERNETES_UPGRADE_VERSION",
        default=None,
        required=False,
        help="Optional Kubernetes version to upgrade to",
    )
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        return func(*args, **kwargs)

    return wrapper


def common_vpc_option(func):
    @click.option("--vpc-name",
        "-v",
        envvar="EKS_VPC_NAME",
        required=True,
        help="VPC name",
    )
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        return func(*args, **kwargs)

    return wrapper
# fmt: on


@click.group()
# fmt: off
@click.option("--debug",
    is_flag=True,
    help="Enable debug mode",
)
@click.option("--dry-run",
    is_flag=True,
    help="Enable dry-run mode",
)
@click.option("--organization",
    "-O",
    "org",
    envvar="EKS_ORGNIZATION",
    default="default",
    help="Organization name",
)
@click.option("--output-format",
    "-o",
    "format",
    default="yaml",
    type=click.Choice(["yaml", "json"], case_sensitive=False),
    help="Output format: yaml or json",
)
@click.option("--state",
              "-s",
              default = "local",
              type=click.Choice(["local", "mongo", "s3"], case_sensitive=False),
              help="State location, can be local, mongo, or s3"
              )
# fmt: on
@click.pass_context
def cli(ctx, dry_run, debug, format, state, org):
    """CLI main group for managing EKS clusters."""
    if debug:
        logging.getLogger().setLevel(logging.DEBUG)
        logging.getLogger("botocore").setLevel(logging.INFO)
        logging.getLogger("boto3").setLevel(logging.INFO)
        logger.debug("Debug mode is enabled")
    # Initialize the Repo object and pass it into the context
    ctx.obj = Repo(dry_run, debug)
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
    repo.state_path = f"{repo.org}/{repo.environment}/{repo.region}/{repo.cluster_name}"
    repo.filename = f"cluster-{repo.cluster_name}.{repo.format}"


@cluster.command()
# fmt: off
@click.option("--bootstrap-admin-perms",
    "-b",
    envvar="EKS_CLUSTER_BOOTSTRAP_ADMIN",
    default=True,
    help="Specifies whether or not the cluster creator IAM principal is set as a cluster admin access",
)
@click.option("--cluster-admins",
    "-C",
    envvar="EKS_CLUSTER_CLUSTER_ADMINS",
    type=SPACE_SEPARATED_LIST,
    default="",
    help="Space separated list of IAM user names in the target account to give admin access.",
)
@click.option("--ip-family",
    "-i",
    envvar="EKS_CLUSTER_IP_FAMILY",
    type=click.Choice(["ipv4", "ipv6"], case_sensitive=False),
    default="ipv4",
    help="Enable public or private access to EKS api endpoints",
)
@click.option("--kubernetes-cidr-block",
    "-c",
    envvar="EKS_CLUSTER_KUBERNETES_CIDR_BLOCK",
    default=None,
    help="CIDR block for kubernetes cluster addresses.",
)
@click.option("--kubernetes-version",
    "-V",
    "version",
    envvar="EKS_CLUSTER_VERSION",
    help="EKS Version",
)
@click.option("--kms-encryption-key",
    "-K",
    envvar="EKS_CLUSTER_KMS_ENCRYPTION_KEY",
    default=None,
    help="KMS encryption key for secrets encryption, can be arn or alias",
)
@click.option("--logging-types",
    "-l",
    envvar="EKS_CLUSTER_LOGGING_TYPES",
    type=SPACE_SEPARATED_LIST,
    default="",
    help="""Space separated list of k8s logging types: 
            api audit authenticator controllerManager scheduler""",
)
@click.option("--public-access-cidrs",
    "-P",
    envvar="EKS_CLUSTER_PUBLIC_ACCESS_CIDRS",
    type=SPACE_SEPARATED_LIST,
    default="",
    help="Space separated list of CIDR blocks for EKS api endpoint access.",
)
@click.option("--public-private-access",
    "-p",
    envvar="EKS_CLUSTER_PUBLIC_PRIVATE_ACCESS",
    type=click.Choice(["public", "private", "both"], case_sensitive=False),
    default="both",
    help="Enable public or private access to EKS api endpoints",
)
@click.option("--role-arn",
    "-r",
    envvar="EKS_CLUSTER_ROLE_ARN",
    default=None,
    help="KMS encryption key for secrets encryption, can be arn or alias",
)
@click.option("--security-group-ids",
    "-S",
    envvar="EKS_CLUSTER_SECURITY_GROUPS",
    type=SPACE_SEPARATED_LIST,
    default="",
    help="Space separated list of security group ids for EKS resources.",
)
@click.option("--support-type",
    "-s",
    envvar="EKS_CLUSTER_SECURITY_GROUPS",
    type=click.Choice(["EXTENDED", "STANDARD"], case_sensitive=False),
    default="STANDARD",
    help="EKS support type.",
)
@click.option("--tags",
    "-t",
    envvar="EKS_CLUSTER_TAGS",
    type=KEY_VALUE_TYPE,
    default={},
    help="""Space separated list of key/value pairs for EKS cluster.
            example: key1=value1 key2=value2""",
)
# fmt: on
@common_vpc_option
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
    config = ConfigProcessor(repo)
    if not role_arn:
        iam = IAM(repo)
        repo.role_arn = iam.create_cluster_service_role()
        # if repo.dry_run:
        #     config.write_state(repo.role_config)
        # else:
        #     config.write_state(repo.role_config)
        # # TODO: figure out how to make a state object for this role

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

    cluster_config = config.cluster(repo)
    logger.debug(f"config object is a {type(config.cluster_config)}")
    logger.debug(f"{config.cluster_config}")

    logger.debug(f"state path: {repo.state_path}")
    if repo.dry_run:
        config.write_state(repo, cluster_config)
    else:
        vpc.verify_private_elb_tags()
        vpc.verify_public_elb_tags()
        eks = Eks(repo)
        if eks.check_cluster_exists() is True:  # TODO: check if exists and in state
            logger.error("Cluster %s already exists.", config.name)
            sys.exit(0)
        vpc.create_cluster_tags(repo.cluster_name)
        logger.debug(f"config is:\n{cluster_config}")
        # repo.cluster_info = eks.create_cluster(cluster_config)
        repo.cluster_info = eks.get_cluster_info()
        repo.cluster_state = copy.deepcopy(repo.cluster_info)
        repo.cluster_state["cluster"]["resourcesVpcConfig"]["subnetIds"] = {
            "private": repo.private_subnets,
            "public": repo.public_subnets,
        }
        logger.debug(f"eks.cluster_info: {repo.cluster_info}")
        config.write_state(repo.cluster_state)


@cluster.command()
@click.pass_obj
@log_debug_parameters
def delete(repo):
    """Delete eks cluster"""
    config = ConfigProcessor(repo)
    cluster_state, state_path = config.fetch_state("cluster", repo.cluster_name)
    logger.debug(pformat(cluster_state))
    eks_manager = Eks(repo)
    eks_manager.delete_cluster(repo)
    config.delete_state(state_path)


@cluster.command()
@common_upgrade_options
@click.pass_obj
@log_debug_parameters
def upgrade(repo, upgrade_version):
    """Upgrade eks cluster"""
    eks = Eks(repo)
    cluster_info = eks.upgrade_cluster(upgrade_version)
    # cluster_info = eks.get_cluster_info()
    config = ConfigProcessor(repo)
    cluster_state, state_path = config.fetch_state("cluster", repo.cluster_name)
    subnets = cluster_state["cluster"]["resourcesVpcConfig"]["subnetIds"]
    new_cluster_state = copy.deepcopy(cluster_info)
    new_cluster_state["cluster"]["resourcesVpcConfig"]["subnetIds"] = subnets
    config.write_state(new_cluster_state)


@cli.group()
@common_options
@click.pass_obj
@log_debug_parameters
def fargateprofile(repo, cluster_name, environment, region):
    """Manage fargate profiles/nodegroups, like create, delete."""
    repo.cluster_name = cluster_name
    repo.environment = environment
    repo.region = region
    repo.state_path = f"{repo.org}/{repo.environment}/{repo.region}/{repo.cluster_name}"


@fargateprofile.command()
# fmt: off
@click.option("--labels", #TODO: work out out how to do labels
    "-l",
    envvar="EKS_FARGATEPROFILE_LABELS",
    type=KEY_VALUE_TYPE,
    help="""Space separated list of key/value pairs for fargate profile labels.
            example: key1=value1 key2=value2""",)
@click.option("--name",
    "-n",
    required=True,
    envvar="EKS_FARGATEPROFILE_NAME",
    help="Name for the fargate profile/nodegroup",)
@click.option("--namespace",
    "-N",
    required=True,
    envvar="EKS_FARGATEPROFILE_NAMESPACE",
    help="Namespace for the fargate profile/nodegroup",)
@click.option("--tags",
    "-t",
    envvar="EKS_FARGATEPROFILE_TAGS",
    type=KEY_VALUE_TYPE,
    default={},
    help="""Space separated list of key/value pairs for fargate profile tags.
            example: key1=value1 key2=value2""",)
# fmt: on
@click.pass_obj
@log_debug_parameters
def create(repo, name, namespace, labels, tags):
    """Create Fargate Profile/Nodegroup"""
    set_args_in_repo(repo, locals())
    repo.filename = f"fargateprofile-{repo.name}.{repo.format}"
    config = ConfigProcessor(repo)
    cluster_state, state_path = config.fetch_state("cluster", repo.cluster_name)
    repo.subnets = cluster_state["cluster"]["resourcesVpcConfig"]["subnetIds"][
        "private"
    ]
    repo.eks_arn = cluster_state["cluster"]["arn"]
    iam = IAM(repo)
    repo.role_arn, repo.role_config = iam.create_fargate_pod_execution_role()
    time.sleep(7)
    profile_config = config.fargateprofile()
    logger.debug(f"profle_config: {profile_config}")
    eks = Eks(repo)
    eks.create_fargate_profile(profile_config)
    config.write_state(profile_config)


@fargateprofile.command()
# fmt: off
@click.option("--name",
    "-n",
    required=True,
    envvar="EKS_FARGATEPROFILE_NAME",
    help="Name for the fargate profile/nodegroup",)
# fmt: on
@click.pass_obj
@log_debug_parameters
def delete(repo, name):
    """Delete Fargate Profile/Nodegroup"""
    eks = Eks(repo)
    config = ConfigProcessor(repo)
    eks.delete_fargateprofile(name)
    fargateprofile_state, state_path = config.fetch_state("fargateprofile", name)
    config.delete_state(state_path)


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
@click.option("--min-size", default=1, type=int, help="Minimum size of the nodegroup.")
@click.option("--max-size", default=3, type=int, help="Maximum size of the nodegroup.")
@click.option(
    "--desired-size", default=1, type=int, help="Desired size of the nodegroup."
)
@click.option("--disk-size", default=20, type=int, help="Disk size in GB.")
@click.option(
    "--subnets",
    "-s",
    required=True,
    type=click.Choice(["public", "private"], case_sensitive=False),
    default="private",
    help="deploy to public or private subnets",
)
@click.option(
    "--instance-types",
    type=SPACE_SEPARATED_LIST,
    default="t4g.medium",
    help="Instance types for the nodegroup.",
)
@click.option("--ami-type", default="AL2_x86_64", help="AMI type for the nodegroup.")
@click.option("--ssh-key", help="EC2 SSH key for remote access.")
@click.option(
    "--source-security-groups",
    type=SPACE_SEPARATED_LIST,
    help="Source security groups for remote access.",
)
@click.option("--node-role-arn", help="IAM role for the nodegroup.")
@click.option("--tags", type=KEY_VALUE_TYPE, default={}, help="Tags for the nodegroup.")
@click.option("--labels", type=KEY_VALUE_TYPE, help="Labels for the nodegroup.")
@click.option(
    "--taints", type=KEY_VALUE_TYPE, help="Taints for the nodegroup (key=value:effect)."
)
# @click.option("--launch-template-name", help="Launch template name for the nodegroup.")
# @click.option("--launch-template-version", help="Launch template version for the nodegroup.")
@click.option(
    "--capacity-type",
    default="ON_DEMAND",
    type=click.Choice(["ON_DEMAND", "SPOT"], case_sensitive=False),
    help="Capacity type for the nodegroup.",
)
@click.option("--release-version", help="AMI release version for the nodegroup.")
@click.pass_obj
def create(
    repo,
    name,
    min_size,
    max_size,
    desired_size,
    disk_size,
    subnets,
    instance_types,
    ami_type,
    ssh_key,
    source_security_groups,
    node_role_arn,
    tags,
    labels,
    taints,
    # launch_template_name,
    # launch_template_version,
    capacity_type,
    version,
    release_version,
):
    """Create a new EKS nodegroup."""
    set_args_in_repo(repo, locals())
    repo.state_path = f"{repo.org}/{repo.environment}/{repo.region}/{repo.cluster_name}"
    repo.filename = f"nodegroup-{repo.name}.{repo.format}"
    config = ConfigProcessor(repo)
    if not repo.node_role_arn:
        iam = IAM(repo)
        repo.node_role_arn = iam.create_node_role()
    cluster_state, state_path = config.fetch_state("cluster", repo.cluster_name)
    repo.subnets.lower()
    if subnets == "private":
        repo.subnets = cluster_state["cluster"]["resourcesVpcConfig"]["subnetIds"][
            "private"
        ]
    if subnets == "public":
        repo.subnets = cluster_state["cluster"]["resourcesVpcConfig"]["subnetIds"][
            "public"
        ]

    nodegroup_config = config.nodegroup()

    # Create the nodegroup
    eks = Eks(repo)
    eks.create_nodegroup(nodegroup_config)

    # Save the nodegroup state
    config.write_state(nodegroup_config)


@nodegroup.command()
@common_nodegroup_options
@common_drain_option
@click.pass_obj
@log_debug_parameters
def delete(repo, name, version, drain):
    """Delete Nodegroup"""
    eks = Eks(repo)
    config = ConfigProcessor(repo)
    eks.delete_nodegroup(name, version, drain)
    nodegroup_state, state_path = config.fetch_state("nodegroup", name)
    config.delete_state(state_path)


@nodegroup.command()
@common_drain_option
# fmt: off
@click.option("--name",
    "-n",
    required=True,
    envvar="EKS_NODEGROUP_NAME",
    help="Name of the nodegroup",
)
# fmt: on
@common_upgrade_options
@click.pass_obj
@log_debug_parameters
def upgrade(repo, name, kubernetes_version, upgrade_version, drain):
    """Upgrade Nodegroup"""
    eks_manager = Eks(repo)
    eks_manager.upgrade_nodegroup(name, kubernetes_version, upgrade_version, drain)


@nodegroup.command()
# fmt: off
@click.option("--name",
    "-n",
    required=True,
    envvar="EKS_NODEGROUP_NAME",
    help="Name of the nodegroup",
)
# fmt: on
@common_upgrade_options
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
# fmt: off
@click.option("--iam-policy-arn",
    "-P",
    envvar="EKS_IAMSERVICEACCOUNT_POLICYARN",
    help="IAM service account policy ARN",
)
# fmt: on
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
    """Delete IAM service account"""
    eks_manager = Eks(repo)
    eks_manager.delete_iam_service_account(name, namespace)


@cli.group()
@common_options
@click.pass_obj
@log_debug_parameters
def admin_identitymap(repo, cluster_name, environment, region):
    """Manage IAM service accounts, like create, delete."""
    repo.cluster_name = cluster_name
    repo.environment = environment
    repo.region = region


@admin_identitymap.command()
# fmt: off
@click.option("--iam-user-arn",
    "-a",
    envvar="EKS_IAMUSERMAP_ARN_NAME",
    help="IAM user name",
)
@click.option("--name",
    "-n",
    envvar="EKS_ADMINUSERMAP_NAME",
    help="IAM user name",
)
# fmt: on
@click.pass_obj
@log_debug_parameters
def map_user(repo, name, iam_user_arn):
    """Create IAM service account"""
    eks_manager = Eks(repo)
    repo.cluster_info = eks_manager.get_cluster_info()
    k8s_manager = k8s(repo, eks_manager)
    # eks_manager.create_admin_user_id_maps(repo)


@admin_identitymap.command()
# fmt: off
@click.option("--name",
    "-n",
    envvar="EKS_ADMINUSERMAP_NAME",
    help="IAM user name",
)
# fmt: on
@click.pass_obj
@log_debug_parameters
def delete_user(repo, name):
    """Create IAM service account"""
    eks_manager = Eks(repo)
    eks_manager.delete_admin_usermap(name)


@cli.command()
@common_options
@common_drain_option
@common_upgrade_options
@common_vpc_option
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
