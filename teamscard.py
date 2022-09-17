import pymsteams

def create_card(package_name, filename, yara_matches, webhook=''):   
    """ Sends an alert to the provided webhook. """
    WEBHOOK_URL = webhook
    if WEBHOOK_URL:
        my_teams_message = pymsteams.connectorcard(WEBHOOK_URL)
        my_teams_message.title(f"Potential Malicious Package: {package_name}")
        my_teams_message.text(f"The {filename} file in the {package_name} package triggered {yara_matches} yara rules.")
        my_teams_message.send()
    else:
        pass