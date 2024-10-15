import io
import logging
import json
import os
import random
import string
import subprocess
import yaml

import click

from functools import wraps
from pprint import pformat

from .template import Render

logger = logging.getLogger(__name__)

class ConfigProcessor(object):
    def __init__(self, repo):
        """
        Init the object.
        """
        self.repo = repo
        self.template = Render(repo)

    def cluster(self, config):
        """detect config format and pass to corresponding method"""
        if isinstance(config, Repo):
            self._cluster_cli(config)
            return
        try:
            json.loads(config)
            return "JSON string"
        except (json.JSONDecodeError, TypeError):
            pass  # Not a valid JSON string

        try:
            yaml.safe_load(config)
            return "YAML string"
        except (yaml.YAMLError, TypeError, AttributeError):
            pass

        raise ValueError("Config is not a Repo object, valid JSON, or valid YAML.")
        
    def _cluster_cli(self, repo):
        """Build cluster config from CLI repo values"""
        self.repo.all_subnets = repo.private_subnets + repo.public_subnets
        cluster_config = self.template.cluster_config()
        self.cluster_config = cluster_config
        self.cluster_config_json = json.dumps(cluster_config, indent=4)
        self.cluster_config_yaml = yaml.dump(cluster_config, default_flow_style=False)
    
    def write_state(self, repo, config):
        if repo.state == 'local':
            self._write_local_state(repo, config)
            return
        if repo.state == 's3':
            logger.info('write to s3')
            return
        if repo.state == 'mongo':
            logger.info('write to mongo')
            return

    
    def _write_local_state(self, repo, config):
        if repo.dry_run:
            state_prefix = 'dry-run'
        else:
            state_prefix = 'state'
        path = f"{state_prefix}/{repo.state_path}"
        if not os.path.isdir(path):
            os.makedirs(path)
        # if not os.path.exists(f"{path}/"):
        with open(f"{path}/{repo.cluster_filename}", "w") as f:
            if repo.format == 'json':
                f.write(config.cluster_config_json)
            elif repo.format == 'yaml':
                f.write(config.cluster_config_yaml)
            logger.info(f"Saved cluster sate file to { f'{path}/{repo.cluster_filename}'}")

class KeyValueType(click.ParamType):
    name = "key-value pair"

    def convert(self, value, param, ctx):
        if value is None or value == {}:
            return {}
        try:
            key_value_pairs = value.split()
            result = {}
            for pair in key_value_pairs:
                key, val = pair.split("=")
                result[key] = val
            return result
        except ValueError:
            self.fail(f"{value} is not a valid key=value pair", param, ctx)


class SpaceSeparatedList(click.ParamType):
    """Custom type that converts a space-separated string into a list."""

    name = "space-separated-list"

    def convert(self, value, param, ctx):
        if value is None or value == "":
            return []
        try:
            return value.split()
        except AttributeError:
            self.fail(f"{value} is not a valid space-separated string", param, ctx)


class Repo(object):
    def __init__(
        self,
        format,
        dry_run=False,
        debug=False,
    ):
        self.dry_run = dry_run
        self.debug = debug
        self.eks_versions = self._get_eks_versions()
        self.format = format
        self.home = os.path.abspath(".")

        self.environment = ""
        self.region = ""
        self.cluster_name = ""
        self.version = ""
        self.state_path = f"{self.environment}/{self.region}/{self.cluster_name}/"

        self.state = 'local'

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

def set_args_in_repo(repo, args):
    for key, value in args.items():
        if key != "repo":  # Skip repo
            if isinstance(value, (str, int, float, bool, list, dict, type(None))):
                logger.debug(f"setting repo: {key} = {value}")
                setattr(repo, key, value)
            else:
                logger.warn(f"Skipping unsupported type for {key}: {type(value)}")

def stringify_yaml(yaml_data):
    """
    Dump the yaml to a string for use with | in the final yaml file.
    """
    f = io.StringIO()
    yaml.dump(yaml_data, f, default_flow_style=False)
    f.seek(0)
    return f.read()
