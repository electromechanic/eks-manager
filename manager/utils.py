import io
import logging
import os
import random
import string
import subprocess

from dotted_dict import DottedDict
from ruamel.yaml import YAML

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
        password = "{0}{1}".format(password, characters[random.randrange(len(characters))])
    return password.encode("utf-8")


def objectify(data):
    """
    Take json/dict and convert dot notation python object representation.
    """
    return DottedDict(data)


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
        process = subprocess.Popen(command, shell=False, cwd=os.getcwd())
        process.communicate()

    return process.returncode

def stringify_yaml(yaml):
    """
    Dump the yaml to a string for use with | in the final yaml file.
    """
    f = io.StringIO()
    YAML().dump(yaml, f)
    f.seek(0)
    return f.read()
