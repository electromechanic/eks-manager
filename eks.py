#! /usr/bin/env python3

import argparse
import logging
import os
import sys

import manager.aws
import manager.utils

logging.basicConfig(
    level=logging.INFO,
    format=("%(asctime)s [%(levelname)s] %(message)s"),
    datefmt="%Y-%m-%d %H:%M:%S",
)

logger = logging.getLogger(__name__)


def arguments():
    """
    Init argparer and parse arguments.
    """
    parser = argparse.ArgumentParser(
        description="Manage full lifecycle of eksctl managed clusters running in existing VPC."
    )
    parser.add_argument(
        "-a",
        "--action",
        action="store",
        choices=["create", "delete", "upgrade", "upgrade-all"],
        dest="action",
        default=os.getenv("ACTION"),
        type=str,
    )
    parser.add_argument(
        "-A",
        "--account",
        action="store",
        choices=["dev", "staging", "prod"],
        dest="account",
        default=os.getenv("ACCOUNT"),
        type=str,
    )
    parser.add_argument(
        "--config-file",
        action="store",
        dest="config",
        default="config.yaml",
        type=str,
        help="The config file to load.",
    )

    parser.add_argument(
        "-c",
        "--cluster",
        action="store",
        dest="cluster",
        default=os.getenv("CLUSTER", "eng-svcs"),
        type=str,
        help="Name of the EKS cluster.",
    )
    parser.add_argument(
        "-C",
        "--cluster-admins",
        action="store",
        dest="cluster_admins",
        nargs="*",
        default=os.getenv("CLUSTER-ADMINS", ["rdickinson"]),
        type=str,
        help="Space seperated list of IAM user names in the target account to give admin access.",
    )
    parser.add_argument(
        "-D",
        "--drain",
        action="store",
        dest="drain",
        default=os.getenv("DRAIN", "true"),
        type=str,
        help="Name of the forces nodegroup drain behavior .",
    )
    parser.add_argument(
        "-d",
        "--desired-capacity",
        action="store",
        dest="desired",
        default=os.getenv("DESIREDCAPACITY", 3),
        type=int,
        help="The number of instances to run in the ASG for the nodegroup.",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        dest="dry_run",
        help="Dry run option",
    )
    parser.add_argument(
        "-i",
        "--instance-type",
        action="store",
        dest="instance",
        default=os.getenv("INSTANCETYPE", "m6a.xlarge"),
        type=str,
        help="The type of instance to use for the nodegroup.",
    )
    parser.add_argument(
        "-k",
        "--kube",
        action="store",
        dest="kube",
        type=str,
        choices=["1.23", "1.24", "1.25", "1.26"],
        default="1.24",
        help="The major/minor version of Kubernetes to install.",
    )
    parser.add_argument(
        "-l",
        "--labels",
        action="store",
        dest="labels",
        nargs="*",
        type=str,
        default=os.getenv("LABELS"),
        help="""Labels to be applied for fargate profile targetting. Comma delimited string.
            foo=bar,buz=baz""",
    )
    parser.add_argument(
        "-M",
        "--max-size",
        action="store",
        dest="max",
        default=os.getenv("MAXSIZE", 3),
        type=int,
        help="The maximum number of instances to run in the ASG for the nodegroup.",
    )
    parser.add_argument(
        "-m",
        "--min-size",
        action="store",
        dest="min",
        default=os.getenv("MINSIZE", 3),
        type=int,
        help="The minimum number of instances to run in the ASG for the nodegroup.",
    )
    parser.add_argument(
        "-n",
        "--name",
        action="store",
        dest="name",
        default=os.getenv("NAME"),
        type=str,
        help="""The name of the resource to work on. This is for nodegroups,
            iamserviceaccounts, fargateProfiles, and IAM identity mappings.""",
    )
    parser.add_argument(
        "-N",
        "--namespace",
        action="store",
        dest="namespace",
        default=os.getenv("NAMESPACE"),
        type=str,
        help="""The name of the resource to work on. This is for none iamserviceaccounts and
            fargateProfiles.""",
    )
    parser.add_argument(
        "--new-version",
        action="store",
        dest="new_version",
        help="New K8s version to upgrade to",
    )
    parser.add_argument(
        "-o",
        "--organization",
        action="store",
        dest="organization",
        default=os.getenv("ORGANIZATION", "lab"),
        help="organization name for object naming",
    )
    parser.add_argument(
        "--policy-arn",
        action="store",
        dest="policy_arn",
        default=None,
        help="AWS iam policy ARN",
    )
    parser.add_argument(
        "-r",
        "--region",
        action="store",
        dest="region",
        default=os.getenv("REGION"),
        type=str,
        help="Region to use for the EKS cluster.",
    )
    parser.add_argument(
        "-t",
        "--type",
        action="store",
        dest="type",
        choices=[
            "cluster",
            "nodegroup",
            "nodegroupami",
            "iamserviceaccount",
            "fargateprofile",
            "adminusermap",
        ],
        default=os.getenv("TYPE"),
        type=str,
        help="The type of resource to act upon..",
    )
    parser.add_argument(
        "-v",
        "--vpc",
        action="store",
        dest="vpc",
        default=None,
        type=str,
        help="Name of the vpc to use for the EKS cluster.",
    )
    args = parser.parse_args()
    if None in [args.organization, args.account, args.region, args.cluster]:
        parser.print_help()
        sys.exit(1)
    return args


class Manager(object):
    def __init__(self, args):
        """
        Manager object to interface with all components.
        """
        self.vpc = manager.aws.Vpc(args)
        self.eks = manager.aws.Eks(args, self.vpc, args.config)


def main():
    args = arguments()
    eks_manager = Manager(args)
    if args.action == "create":
        if args.type == "cluster":
            eks_manager.eks.create_cluster(args.kube)
        if args.type == "fargateprofile":
            eks_manager.eks.create_fargate_profile(args.name, args.namespace, args.labels)
        if args.type == "iamserviceaccount":
            eks_manager.eks.create_iam_service_account(
                args.name, args.namespace, iam_policy_arn=args.policy_arn
            )
        if args.type == "nodegroup":
            eks_manager.eks.create_nodegroup(
                args.name, args.instance, args.kube, args.desired, args.min, args.max
            )
        if args.type == "adminusermap":
            eks_manager.eks.create_admin_user(args.name)

    if args.action == "delete":
        if args.type == "cluster":
            eks_manager.eks.delete_cluster()
        if args.type == "fargateprofile":
            eks_manager.eks.delete_fargateprofile(args.name)
        if args.type == "iamserviceaccount":
            eks_manager.eks.delete_iam_service_account(args.name, args.namespace)
        if args.type == "nodegroup":
            eks_manager.eks.delete_nodegroup(args.name, args.kube, args.drain)
        if args.type == "adminusermap":
            eks_manager.eks.delete_admin_user(args.name)

    if args.action == "upgrade":
        if args.type == "cluster":
            eks_manager.eks.upgrade_cluster(args.kube, args.new_version)
        if args.type == "nodegroup":
            eks_manager.eks.upgrade_nodegroup(args.name, args.kube, args.new_version, args.drain)
        if args.type == "nodegroupami":
            eks_manager.eks.upgrade_nodegroup_ami(args.name, args.kube, args.new_version)
    if args.action == "upgrade-all":
        eks_manager.eks.upgrade_all(args.kube, args.new_version, args.drain)


if __name__ == "__main__":
    main()
