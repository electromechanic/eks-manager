#! /usr/bin/env python3
import click
import logging
import json
import os
import sys

# import manager.aws

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
        cluster_name=None,
        environment=None,
        region=None,
        vpc=None,
        dry_run=False,
        debug=False,
    ):
        self.cluster = cluster_name
        self.environment = environment
        self.region = region
        self.vpc = vpc
        self.dry_run = dry_run
        self.debug = debug
        self.eks_versions = self._get_eks_versions()
        self.home = os.path.abspath(".")

        logger.debug(
            f"Repo object created with cluster_name={cluster_name}, environment={environment}, region={region}, vpc={vpc}, dry_run={dry_run}, debug={debug}"
        )

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
        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse JSON from eksctl output: {e}")
            return []


@click.group()
@click.option(
    "--cluster", "-c", envvar="EKS_CLUSTER", default="test", help="EKS Cluster name"
)
@click.option(
    "--environment", "-e", envvar="EKS_ENVIRONMENT", default="dev", help="Environment"
)
@click.option(
    "--region", "-r", envvar="EKS_REGION", default="us-east-1", help="AWS Region"
)
@click.option("--vpc", "-v", envvar="EKS_VPC", default="dev", help="VPC")
@click.option("--debug", is_flag=True, help="Enable debug mode")
@click.option("--dry-run", is_flag=True, help="Enable dry-run mode")
@click.pass_context
def cli(ctx, cluster, environment, region, vpc, dry_run, debug):
    """CLI main group for managing EKS clusters."""
    if debug:
        logger.setLevel(logging.DEBUG)
        logger.debug("Debug mode is enabled")

    # Initialize the Repo object and pass it into the context
    ctx.obj = Repo(cluster, environment, region, vpc, dry_run, debug)


@cli.command()
@click.argument("action")
@click.pass_obj
def cluster(repo, action):
    """Manage cluster actions like create, delete, or upgrade."""

    if action == "create":
        logger.debug(f"Creating cluster: {repo.cluster}")
        logger.info(f"Repo object: {repo}")
    elif action == "delete":
        logger.debug(f"Deleting cluster: {repo.cluster}")
    elif action == "upgrade":
        logger.debug(f"Upgrading cluster: {repo.cluster}")
    else:
        logger.error("Invalid action specified")
