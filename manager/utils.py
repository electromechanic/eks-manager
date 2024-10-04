import io
import logging
import json
import os
import random
import string
import subprocess
import yaml

import click

logger = logging.getLogger(__name__)


class SpaceSeparatedList(click.ParamType):
    """Custom type that converts a space-separated string into a list."""

    name = "space-separated-list"

    def convert(self, value, param, ctx):
        try:
            return value.split()
        except AttributeError:
            self.fail(f"{value} is not a valid space-separated string", param, ctx)


# Register the custom type


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
            logger.debug(f"Supported EKS versions: {versions}")
            return versions
        except json.JSONDecodeError as err:
            logger.error(f"Failed to parse JSON from eksctl output: {err}")
            return []


def gen_password(length, numbers=True, special_characters=True):
    """
    Generate a random password with optional character sets.
    """
    characters = string.ascii_letters
    if numbers:
        characters = "{0}{1}".format(characters, string.digits)
    if special_characters:
        characters = "{0}{1}".format(characters, string.punctuation)
    password = ""
    if special_characters:
        for char in ["/", "@", '"', " ", "'", "%", ";", ":"]:
            characters = characters.replace(char, "")
    characters = "".join(random.sample(characters, len(characters)))
    for i in range(int(length)):
        password = "{0}{1}".format(
            password, characters[random.randrange(len(characters))]
        )
    return password.encode("utf-8")


def run_command(command, noout=None):
    """
    Exec the specified command and push its stdout to stdout in realtime.
    """
    if noout:
        process = subprocess.Popen(
            command,
            shell=False,
            cwd=os.getcwd(),
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    else:
        logger.info("Running command '%s'", " ".join(command))
        process = subprocess.Popen(
            command,
            shell=False,
            cwd=os.getcwd(),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        stdout, stderr = process.communicate()
        logger.debug("Command output: %s", stdout)
        if stderr:
            logger.error("Command error: %s", stderr)
    return process.returncode, stdout, stderr


def stringify_yaml(yaml_data):
    """
    Dump the yaml to a string for use with | in the final yaml file.
    """
    f = io.StringIO()
    yaml.dump(yaml_data, f, default_flow_style=False)
    f.seek(0)
    return f.read()
