import inspect
import io
import logging
import json
import os
import random
import string
import subprocess
import yaml

import click

from datetime import datetime, timezone
from dateutil.tz import tzlocal
from functools import wraps
from pprint import pformat

from .template import Render

logger = logging.getLogger(__name__)


class Repo(object):
    def __init__(
        self,
        format,
        dry_run=False,
        debug=False,
    ):
        self.dry_run = dry_run
        self.debug = debug
        self.format = format
        self.home = os.path.abspath(".")

        logger.debug(f"Repo object created with dry_run={dry_run}, debug={debug}")



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


class ConfigProcessor(object):
    def __init__(self, repo):
        """
        Init the object.
        """
        self.template = Render(repo)
        self.repo = repo

    class DateTimeEncoder(json.JSONEncoder):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            # Register the YAML representer for datetime objects during initialization
            yaml.add_representer(datetime, self.encode_for_yaml)

        @staticmethod
        def encode_for_json(obj):
            """Convert datetime objects to ISO 8601 strings for JSON."""
            if isinstance(obj, datetime):
                return obj.astimezone(timezone.utc).isoformat()
            return obj

        @staticmethod
        def encode_for_yaml(dumper, data):
            """Convert datetime objects to ISO 8601 strings for YAML."""
            return dumper.represent_str(data.astimezone(timezone.utc).isoformat())

        def default(self, obj):
            """Overriding default method to use JSON datetime handling."""
            return self.encode_for_json(obj)

    def _detect_type(self, config):
        if isinstance(config, Repo):
            logger.debug(f"config is a class")
            return "repo"
        try:
            json.loads(config)
            return "json"
        except (json.JSONDecodeError, TypeError):
            pass  # Not a valid JSON string

        try:
            yaml.safe_load(config)
            return "yaml"
        except (yaml.YAMLError, TypeError, AttributeError):
            pass

    def cluster(self, config):
        """detect config format and pass to corresponding method"""

        config_type = self._detect_type(config)
        logger.debug(f"config_type is {config_type}")
        if config_type == "repo":
            self.cluster_config = self._cluster_cli()
            return self.cluster_config
        if config_type == "json":
            pass
        if config_type == "yaml":
            pass

        raise ValueError(
            f"Config is a {type(config)} not a Repo object, valid JSON, or valid YAML."
        )

    def _cluster_cli(self):
        """Build cluster config from CLI repo values"""
        cluster_config = self.template.cluster_eks()
        logger.debug(f"cluster_config is {type(cluster_config)}")
        return cluster_config

    def fargateprofile(self):
        self.fargateprofile_config = self.template.fargateprofile()
        return self.fargateprofile_config

    def nodegroup(self):
        nodegroup_config = self.template.nodegroup()
        return nodegroup_config

    def construct_state(self, config):
        """Add state metadata to config"""
        logger.debug(f"construct state input: {config}")
        if "ResponseMetadata" in config:
            response_metadata = config.pop("ResponseMetadata")
        metadata = {
            "timestamp": datetime.now(
                timezone.utc
            ).isoformat(),  # Current GMT time as ISO string
            "organization": self.repo.org,
            "environment": self.repo.environment,
            "region": self.repo.region,
            "cloud_provider": "AWS",
            "version": 1,
        }

        config["metadata"] = metadata
        logger.debug(f"construct state metadata+config: {pformat(config)}")

        return config

    def iam_user(self, name):
        self.iam_user_config = self.template.iam_user_config(name)
        self.iam_user_config_json = json.dumps(self.iam_user_config, indent=4)
        self.iam_user_config_yaml = yaml.dump(
            self.iam_user_config, default_flow_style=False
        )

    def delete_state(self, state_path):
        if self.repo.state == "local":
            os.unlink(state_path)
            return
        if repo.state == "s3":
            logger.info("write to s3")
            return
        if repo.state == "mongo":
            logger.info("write to mongo")
            return

    def fetch_state(self, obj_type, name):

        if self.repo.state == "local":
            state, file_path = self._read_local_state(obj_type, name)
            return state, file_path
        if self.repo.state == "s3":
            logger.info("read from s3")
            return
        if self.repo.state == "mongo":
            logger.info("read from mongo")
            return

    def _read_local_state(self, obj_type, name):
        file_path = f"{self.repo.home}/state/{self.repo.state_path}/{obj_type}-{name}.{self.repo.format}"
        try:
            with open(file_path, "r") as state_file:
                state = yaml.safe_load(state_file)
                return state, file_path
        except Exception as err:
            logger.error(f"error loading state: {err}")
            return None

    def write_state(self, config):

        if self.repo.state == "local":
            config = self.construct_state(config)
            self._write_local_state(self.repo, config)
            return
        if self.repo.state.state == "s3":
            logger.info("write to s3")
            return
        if self.repo.state.state == "mongo":
            logger.info("write to mongo")
            return

    def _write_local_state(self, repo, config):
        if repo.dry_run:
            state_prefix = "dry-run"
        else:
            state_prefix = "state"
        path = f"{state_prefix}/{repo.state_path}"

        self.cluster_state_json = json.dumps(config, indent=4, cls=self.DateTimeEncoder)
        self.cluster_state_yaml = yaml.dump(config, default_flow_style=False)
        if not os.path.isdir(path):
            os.makedirs(path)
        # if not os.path.exists(f"{path}/"):
        with open(f"{path}/{repo.filename}", "w") as f:
            if repo.format == "json":
                f.write(self.cluster_state_json)
            elif repo.format == "yaml":
                f.write(self.cluster_state_yaml)
            logger.info(f"Saved cluster sate file to { f'{path}/{repo.filename}'}")


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
