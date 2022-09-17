from teamscard import create_card
from colorama import Fore, Back
import shutil
import yara
import os


def load_yara_rules(directory) -> dict:
    """ Loads YARA rules from directory and creates/return dictionary. """
    yara_rules_dict = {}
    yar_directory = directory

    for (dirpath, dirname, filenames) in os.walk(yar_directory):
        if filenames:
            for filename in filenames:
                with open(directory + dir_separator + filename, 'r') as yars:
                    yara_rules_dict[filename] = yars.read()

    return yara_rules_dict

def check_yara_rules(cwd: str, dir_sep: str, rules_dir: str, webhook='') -> int:
    """ Loads YARA dictionary. Check for matches and calls functions for sending alert to Teams and copy matches to potentially_malicious folder. """
    global current_working_directory
    global dir_separator
    global WEBHOOK_URL
    current_working_directory = cwd
    dir_separator = dir_sep
    WEBHOOK_URL = webhook

    yara_rules = load_yara_rules(rules_dir)
    print("\n\nLoaded YARA rules:")
    for y, r in yara_rules.items():
        print(y)
    print()
    yara_rules_compiled = yara.compile(sources=yara_rules)
    triggered_YARA = 0

    for (dirpath, dirname, filenames) in os.walk(current_working_directory + dir_separator + 'npm_packages'):
        if filenames:
            for filename in filenames:
                try:
                    print(Back.BLUE + "[!] Analyzing " + dirpath + filename + " with YARA!")
                    yara_matches = yara_rules_compiled.match(dirpath + dir_separator + filename)
                    package_name = dirpath.split(dir_separator)[7]
                    new_folder = current_working_directory + dir_separator + 'potentially_malicious' + dir_separator + package_name + dir_separator
                    new_dir = current_working_directory + dir_separator + 'potentially_malicious' + dir_separator + package_name + dir_separator + filename
                    if yara_matches:
                        print(Back.RED + "[!!] YARA MATCH FOR " + filename)
                        create_card(package_name, filename, yara_matches, WEBHOOK_URL)
                        positive_alert_copy_file(new_dir, dirpath + dir_separator + filename, new_folder)
                        triggered_YARA += 1
                except yara.Error:
                    print("[!] Permissions error! Not even bothering.")
                    # os.chmod(dirpath + dir_separator + filename, stat.S_IRWXU)
                    # if yara_matches:
                    #    positive_alert(new_dir, package_name)

    return triggered_YARA

def positive_alert_copy_file(dir, name, folder):
    """ Moves provided file to a separate folder. """
    try:
        shutil.copy(name, dir)

    except FileNotFoundError:

        os.mkdir(folder)
        shutil.copy(name, dir)