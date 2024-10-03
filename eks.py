#! /usr/bin/env python3
import click
import functools
import logging
import json
import os
import sys

import manager.aws
from manager.utils import run_command

logging.basicConfig(
    level=logging.INFO,
    format=("%(asctime)s [%(levelname)s] %(message)s"),
    datefmt="%Y-%m-%d %H:%M:%S",
)

logger = logging.getLogger(__name__)

# TODO: need a yes parameter for deletion actions
# TODO: all options should have env vars for configuration
# TODO: set up prompts for missing options
# TODO: config option should be file path type


class Repo(object):
    def __init__(
        self,
        dry_run=False,
        debug=False,
    ):
        self.dry_run = dry_run
        self.debug = debug
        self.eks_versions = self._get_eks_versions()
        self.home = os.path.abspath(".")

        logger.debug(f"Repo object created with dry_run={dry_run}, debug={debug}")

    def _get_eks_versions(self):
        """Get supported versions of eks based on eksctl version."""
        returncode, stdout, stderr = run_command(
            [
                "/usr/local/bin/eksctl",
                "version",
                "-o",
                "json",
            ]
        )

        # Check if the command failed
        if returncode != 0:
            logger.error(
                f"Failed to get EKS versions. Return code: {returncode}, stderr: {stderr}"
            )
            return []

        try:
            stdout_dict = json.loads(stdout)
            versions = stdout_dict.get("EKSServerSupportedVersions", [])
            logger.info(f"Supported EKS versions: {versions}")
            return versions
        except json.JSONDecodeError as err:
            logger.error(f"Failed to parse JSON from eksctl output: {err}")
            return []


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
def cluster(repo, cluster_name, environment, region):
    """Manage cluster actions like create, delete, or upgrade."""
    repo.cluster_name = cluster_name
    repo.environment = environment
    repo.region = region


@cluster.command()
@click.option(
    "-C",
    "--cluster-admins",
    envvar="CLUSTER-ADMINS",
    default=[],
    help="Space seperated list of IAM user names in the target account to give admin access.",
)
@click.option(
    "-k",
    "--kubernetes-version",
    envvar="EKS_KUBERNETES_VERSION",
    default="1.30",
    help="EKS Version",
)
@click.option("-v", "--vpc-name", envvar="EKS_VPC_NAME", required=True, help="VPC name")
@click.pass_obj
def create(repo, cluster_admins, kubernetes_version, vpc_name):
    """Create a new cluster"""
    kubernetes_version_choice = click.Choice(repo.eks_versions)
    if kubernetes_version not in repo.eks_versions:
        click.echo(f"Invalid Kubernetes version: {kubernetes_version}.")
        click.echo(f"Supported versions: {', '.join(repo.eks_versions)}")
        return
    click.echo("create a cluster")
    click.echo(f"Name: {repo.cluster_name}")
    click.echo(f"Environment: {repo.environment}")
    click.echo(f"Region: {repo.region}")
    click.echo(f"VPC: {vpc_name}")
    click.echo(f"EKS Version: {kubernetes_version}")
    repo.vpc_name = vpc_name
    vpc = manager.aws.Vpc(repo)
    eks_manager = manager.aws.Eks(repo, vpc=vpc)
    eks_manager.create_cluster(kubernetes_version, cluster_admins)


@cluster.command()
@click.pass_obj
def delete(repo):
    """Delete eks cluster"""
    click.echo("delete a cluster")
    click.echo(f"Name: {repo.cluster_name}")
    click.echo(f"Environment: {repo.environment}")
    click.echo(f"Region: {repo.region}")
    eks_manager = manager.aws.Eks(repo)
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
@click.pass_obj
def upgrade(repo, kubernetes_version, upgrade_version):
    """Upgrade eks cluster"""
    click.echo("upgrade a cluster")
    click.echo(f"Name: {repo.cluster_name}")
    click.echo(f"Environment: {repo.environment}")
    click.echo(f"Region: {repo.region}")
    click.echo(f"Current Version: {kubernetes_version}")
    click.echo(f"Upgrade Version: {upgrade_version}")
    eks_manager = manager.aws.Eks(repo)
    eks_manager.upgrade_cluster(kubernetes_version, upgrade_version)


@cli.group()
@common_options
@click.pass_obj
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
def create(repo, name, namespace, labels, vpc_name):
    """Create Fargate Profile/Nodegroup"""
    click.echo("create a fargate profile")
    click.echo(f"Cluster: {repo.cluster_name}")
    click.echo(f"Environment: {repo.environment}")
    click.echo(f"Region: {repo.region}")
    click.echo(f"Name: {name}")
    click.echo(f"Namespace: {namespace}")
    click.echo(f"Labels: {labels}")
    repo.vpc_name = vpc_name
    vpc = manager.aws.Vpc(repo)
    eks_manager = manager.aws.Eks(repo, vpc=vpc)
    eks_manager.create_fargate_profile(name, namespace, labels)


@fargateprofile.command()
@click.option(
    "-n",
    "--name",
    required=True,
    envvar="EKS_FARGATEPROFILE_NAME",
    help="Name for the fargate profile/nodegroup",
)
@click.pass_obj
def delete(repo, name):
    """Delete Fargate Profile/Nodegroup"""
    click.echo("delete a fargate profile")
    click.echo(f"Cluster: {repo.cluster_name}")
    click.echo(f"Environment: {repo.environment}")
    click.echo(f"Region: {repo.region}")
    eks_manager = manager.aws.Eks(repo)
    eks_manager.delete_fargateprofile(name)


@cli.group()
@common_options
@click.pass_obj
def nodegroup(repo, cluster_name, environment, region):
    """Manage nodegroups, like create, delete, upgrade."""
    repo.cluster_name = cluster_name
    repo.environment = environment
    repo.region = region


@nodegroup.command()
@click.option(
    "-n", "--name", envvar="EKS_NODEGROUP_NAME", default="test", help="Nodegroup name"
)
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
@click.option(
    "-k",
    "--kubernetes-version",
    envvar="EKS_KUBERNETES_VERSION",
    default="1.30",
    help="EKS Version",
)
@click.pass_obj
def create(
    repo,
    name,
    instance_class,
    desired_capacity,
    max_nodes,
    min_nodes,
    kubernetes_version
):
    """Create Nodegroup"""
    click.echo("create a nodegroup")
    click.echo(f"Cluster: {repo.cluster_name}")
    click.echo(f"Environment: {repo.environment}")
    click.echo(f"Region: {repo.region}")
    click.echo(f"Name: {name}")
    click.echo(f"Instance class: {instance_class}")
    click.echo(f"Desired Capacity: {desired_capacity}")
    click.echo(f"Maximum nodes: {max_nodes}")
    click.echo(f"Minimum nodes: {min_nodes}")
    click.echo(f"Kubernetes version: {kubernetes_version}")
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
@click.option(
    "-n", "--name", envvar="EKS_NODEGROUP_NAME", default="test", help="Nodegroup name"
)
@click.option(
    "-k",
    "--kubernetes-version",
    envvar="EKS_KUBERNETES_VERSION",
    default="1.30",
    help="EKS Version",
)
@click.option(
    "-D",
    "--drain",
    is_flag=True,
    envvar="EKS_NODEGROUP_DRAIN",
    help="Flag to drain nodegroup during upgrade",
)
@click.pass_obj
def delete(repo, name, kubernetes_version, drain):
    """Delete Nodegroup"""
    click.echo("create a fargate profile")
    click.echo(f"Cluster: {repo.cluster_name}")
    click.echo(f"Environment: {repo.environment}")
    click.echo(f"Region: {repo.region}")
    click.echo(f"Name: {name}")
    click.echo(f"Kubernetes version: {kubernetes_version}")
    click.echo(f"Drain: {drain}")
    eks_manager = manager.aws.Eks(repo)
    eks_manager.delete_nodegroup(name, kubernetes_version, drain)


@nodegroup.command()
@click.option(
    "-n", "--name", envvar="EKS_NODEGROUP_NAME", default="test", help="Nodegroup name"
)
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
@click.option(
    "-D",
    "--drain",
    is_flag=True,
    envvar="EKS_NODEGROUP_DRAIN",
    help="Flag to drain nodegroup during upgrade",
)
@click.pass_obj
def upgrade(repo, name, kubernetes_version, upgrade_version, drain):
    """Upgrade Nodegroup"""
    click.echo("create a fargate profile")
    click.echo(f"Cluster: {repo.cluster_name}")
    click.echo(f"Environment: {repo.environment}")
    click.echo(f"Region: {repo.region}")
    click.echo(f"Name: {name}")
    click.echo(f"Kubernetes version: {kubernetes_version}")
    click.echo(f"Kubernetes upgrade version: {upgrade_version}")
    click.echo(f"Drain: {drain}")
    eks_manager = manager.aws.Eks(repo)
    eks_manager.upgrade_nodegroup(name, kubernetes_version, upgrade_version, drain)


@nodegroup.command()
@click.option(
    "-n", "--name", envvar="EKS_NODEGROUP_NAME", default="test", help="Nodegroup name"
)
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
@click.pass_obj
def upgrade_ami(repo, name, kubernetes_version, upgrade_version):
    """Upgrade Nodegroup AMI"""
    click.echo("create a fargate profile")
    click.echo(f"Cluster: {repo.cluster_name}")
    click.echo(f"Environment: {repo.environment}")
    click.echo(f"Region: {repo.region}")
    click.echo(f"Name: {name}")
    click.echo(f"Kubernetes version: {kubernetes_version}")
    click.echo(f"Kubernetes upgrade version: {upgrade_version}")
    eks_manager = manager.aws.Eks(repo)
    eks_manager.upgrade_nodegroup_ami(name, kubernetes_version, upgrade_version)