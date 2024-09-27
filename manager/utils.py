import io
import logging
import os
import random
import string
import subprocess
import yaml

logger = logging.getLogger(__name__)


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
        logger.info("Command output: %s", stdout)
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
