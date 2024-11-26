class Render(object):
    def __init__(self, repo):
        """
        Init the object.
        """
        self.repo = repo

    def cluster_eks(self):

        cluster_config = {
            "name": self.repo.cluster_name,
            "version": self.repo.version,
            "roleArn": self.repo.role_arn,
            "resourcesVpcConfig": {
                "subnetIds": self.repo.private_subnets + self.repo.public_subnets,
                "securityGroupIds": self.repo.security_group_ids,
                "endpointPublicAccess": self.repo.public_access,
                "endpointPrivateAccess": self.repo.private_access,
            },
            "kubernetesNetworkConfig": {"ipFamily": self.repo.ip_family},
            "logging": {
                "clusterLogging": [
                    {
                        "types": self.repo.logging_types,
                        "enabled": self.repo.logging_enabled,
                    },
                ]
            },
            "tags": self.repo.tags,
            "accessConfig": {
                "bootstrapClusterCreatorAdminPermissions": True,
                "authenticationMode": "API_AND_CONFIG_MAP",
            },
            "bootstrapSelfManagedAddons": self.repo.bootstrap_admin_perms,
            "upgradePolicy": {"supportType": self.repo.support_type},
        }

        if self.repo.kubernetes_cidr_block:
            cluster_config["kubernetesNetworkConfig"][
                "serviceIpv4Cidr"
            ] = self.repo.kubernetes_cidr_block

        if self.repo.kms_encryption_key:
            cluster_config["encryptionConfig"] = [
                {
                    "resources": self.repo.encrypted_resources,
                    "provider": {"keyArn": self.repo.kms_encryption_key},
                }
            ]

        if self.repo.public_access_cidrs:
            cluster_config["resourcesVpcConfig"][
                "publicAccessCidrs"
            ] = self.repo.public_access_cidrs

        self.cluster_config = cluster_config

        return self.cluster_config

    def fargateprofile(self):
        fargate_config = {
            "fargateProfileName": self.repo.name,
            "clusterName": self.repo.cluster_name,
            "podExecutionRoleArn": self.repo.role_arn,
            "subnets": self.repo.subnets,
            "selectors": [
                {
                    "namespace": self.repo.namespace,
                },
            ],
            "tags": self.repo.tags,
        }

        if self.repo.labels:
            fargate_config["selectors"][0]["labels"] = self.repo.labels

        # if self.repo.client_request_token:
        #     fargate_config['clientRequestToken'] = self.repo.client_request_token

        return fargate_config

    def iam_user_config(self):
        iam_user_config = {"UserName": self.repo.iam_user_name}
        if self.repo.iam_path:
            iam_user_config["Path"] = self.repo.iam_path
        if self.repo.iam_permissionsboundry:
            iam_user_config["PermissionsBoundary"] = self.repo.iam_permissionsboundry
        if self.repo.tags:
            iam_user_config["Tags"] = self.repo.tags

    def nodegroup(self):
        nodegroup_config = {
            "clusterName": self.repo.cluster_name,
            "nodegroupName": self.repo.name,
            "scalingConfig": {
                "minSize": self.repo.min_size,
                "maxSize": self.repo.max_size,
                "desiredSize": self.repo.desired_size,
            },
            "diskSize": self.repo.disk_size,
            "subnets": self.repo.subnets,
            "instanceTypes": self.repo.instance_types,
            "nodeRole": self.repo.node_role_arn,
            "capacityType": self.repo.capacity_type,
            "tags": self.repo.tags,
        }

        if self.repo.ami_type:
            nodegroup_config["amiType"] = self.repo.ami_type

        if self.repo.labels:
            nodegroup_config["labels"] = self.repo.labels

        if self.repo.taints:
            nodegroup_config["taints"] = self.repo.taints

        # if self.repo.launch_template:
        #     nodegroup_config['launchTemplate'] = self.repo.launch_template
        # if self.repo.client_request_token:
        #     nodegroup_config['clientRequestToken'] = self.repo.client_request_token

        if self.repo.ssh_key and self.repo.source_security_groups:
            nodegroup_config["remoteAccess"] = {
                "ec2SshKey": self.repo.ssh_key,
                "sourceSecurityGroups": self.repo.source_security_groups,
            }
        elif self.repo.ssh_key or self.repo.source_security_groups:
            logger.warning(
                "Incomplete remote access configuration: both 'ssh_key' and 'source_security_groups' must be provided to enable remote access."
            )

        if self.repo.release_version:
            nodegroup_config["releaseVersion"] = self.repo.release_version

        return nodegroup_config
