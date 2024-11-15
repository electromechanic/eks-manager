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
                "subnetIds": self.repo.all_subnets,
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

    def iam_user_config(self):
        iam_user_config = {"UserName": self.repo.iam_user_name}
        if self.repo.iam_path:
            iam_user_config["Path"] = self.repo.iam_path
        if self.repo.iam_permissionsboundry:
            iam_user_config["PermissionsBoundary"] = self.repo.iam_permissionsboundry
        if self.repo.tags:
            iam_user_config["Tags"] = self.repo.tags
