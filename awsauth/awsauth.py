#!/usr/bin/env python
import argparse
import hashlib
import json
import os
import re
import time
from configparser import RawConfigParser
from urllib.parse import quote_plus, unquote
import requests
from boto.iam import IAMConnection
from boto.sts import STSConnection
from colorama import Fore, Back, Style
from requests.packages.urllib3 import disable_warnings

# Awsauth Amazon Account Access

version = '1.0.0'

# CLI parser
parser = argparse.ArgumentParser(description='Awsauth: AWS Account Access')
parser.add_argument('--version', action='version', version='%(prog)s ' + version)
parser.add_argument('--project', '-p', required=True, action='store', default=False)
parser.add_argument('--env', '-e', required=True, action='store', default=False, help='-e dev,pre,pro ...')
parser.add_argument('--role', '-r', required=True, action='store',
                    help='Set role to use. Example: admin, developer ...', default=False)
parser.add_argument('--region', required=False, action='store', help='Set region for EC2. Default=eu-west-1',
                    default=False)
parser.add_argument('--nomfa', required=False, action='store_true', help='Disables Multi-Factor Authentication',
                    default=False)
parser.add_argument('--refresh', required=False, action='store_true', help='Refresh token even if there is a valid one',
                    default=False)
parser.add_argument('--verbose', '-v', action='store_true', help='prints verbosely', default=False)

args = parser.parse_args()


def verbose(msg):
    if args.verbose:
        print(Fore.BLUE + ''.join(map(str, msg)))
        print(Fore.RESET + Back.RESET + Style.RESET_ALL)


def colormsg(msg, mode):
    print()
    if mode == 'ok':
        print(Fore.GREEN + '[ OK ] ' + ''.join(map(str, msg)))
        print(Fore.RESET + Back.RESET + Style.RESET_ALL)
    if mode == 'error':
        print(Fore.RED + '[ ERROR ] ' + ''.join(map(str, msg)))
        print(Fore.RESET + Back.RESET + Style.RESET_ALL)
    if mode == 'normal':
        print(Fore.WHITE + ''.join(map(str, msg)))
        print(Fore.RESET + Back.RESET + Style.RESET_ALL)


def sha256(m):
    m = m.encode('utf-8')
    return hashlib.sha256(m).hexdigest()


def config_line(header, name, detail, data):
    return header + ", " + name + ", " + detail + ", " + data


def config_line_policy(header, name, detail, data):
    verbose("===== " + header + ":  " + name + ":  " + detail + "=====")
    verbose(data)
    verbose("=========================================================")
    return config_line(header, name, detail, sha256(data))


def output_lines(lines):
    lines.sort()
    for line in lines:
        print(line)


def save_credentials(access_key, session_key, session_token, role_session_name, project_name, environment_name,
                     role_name, region, local_file_path="~/.awsauth"):
    """
    Persists temporal credentials in a local file
    :param access_key: Access Key Id
    :param session_key: Secret Key
    :param session_token: Temporal token
    :param role_session_name: Session role name
    :param project_name: Project
    :param environment_name: Environment (dev, pro, pre...)
    :param role_name: Role name
    :param region: Default region
    """
    if os.path.isfile(os.path.expanduser(local_file_path)):

        with open(os.path.expanduser(local_file_path), 'r') as json_file:
            json_file.seek(0)
            root_json_data = json.load(json_file)
            json_file.close()

        with open(os.path.expanduser(local_file_path), 'w+') as json_file:
            if project_name not in root_json_data:
                root_json_data[project_name] = {}
            if environment_name not in root_json_data[project_name]:
                root_json_data[project_name][environment_name] = {}
            if role_name not in root_json_data[project_name][environment_name]:
                root_json_data[project_name][environment_name][role_name] = {}

            root_json_data[project_name][environment_name][role_name]["awsauth_last_timestamp"] = str(int(time.time()))
            root_json_data[project_name][environment_name][role_name]["access_key"] = access_key
            root_json_data[project_name][environment_name][role_name]["role_session_name"] = role_session_name
            root_json_data[project_name][environment_name][role_name]["session_key"] = session_key
            root_json_data[project_name][environment_name][role_name]["session_token"] = session_token
            root_json_data[project_name][environment_name][role_name]["region"] = region
            json.dump(root_json_data, json_file)
    else:
        with open(os.path.expanduser(local_file_path), 'w+') as json_file:
            data = {
                project_name: {
                    environment_name: {
                        role_name: {
                            "awsauth_last_timestamp": str(int(time.time())),
                            "access_key": access_key,
                            "role_session_name": role_session_name,
                            "session_key": session_key,
                            "session_token": session_token,
                            "region": region
                        }
                    }
                }
            }
            json.dump(data, json_file)


def get_sts_token(sts_connection, role_arn, mfa_serial_number, role_session_name, project_name, environment_name,
                  role_name, token_expiration):
    try:

        if not args.nomfa:
            mfa_token = input("Enter the MFA code: ")
            assumed_role_object = sts_connection.assume_role(
                role_arn=role_arn,
                role_session_name=role_session_name,
                duration_seconds=token_expiration,
                mfa_serial_number=mfa_serial_number,
                mfa_token=mfa_token
            )

        else:
            mfa_token = None
            assumed_role_object = sts_connection.assume_role(
                role_arn=role_arn,
                role_session_name=role_session_name,
                duration_seconds=token_expiration,
            )

    except Exception as e:
        colormsg("There was an error assuming role", "error")
        verbose(e)
        exit(1)

    colormsg("Assumed the role successfully", "ok")

    # Format resulting temporary credentials into a JSON block using
    # known field names.

    access_key = assumed_role_object.credentials.access_key
    session_key = assumed_role_object.credentials.secret_key
    session_token = assumed_role_object.credentials.session_token

    login_to_fedaccount(access_key, session_key, session_token, role_session_name)

    save_credentials(access_key, session_key, session_token, role_session_name, project_name, environment_name,
                     role_name, region)

    # and save them on the CLI config file .aws/credentials

    save_cli_credentials(access_key, session_key, session_token, '-'.join([project_name, environment_name, role_name]),
                         region)

    return {'access_key': access_key, 'session_key': session_key, 'session_token': session_token,
            'role_session_name': role_session_name}


def get_session_token(sts_connection, role_arn, mfa_serial_number, role_session_name, project_name, environment_name,
                      role_name, token_expiration, session_token_expiration):
    try:

        if not args.nomfa:
            mfa_token = input("Enter the MFA code: ")
            sts_session = sts_connection.get_session_token(
                duration=session_token_expiration,
                mfa_serial_number=mfa_serial_number,
                mfa_token=mfa_token
            )

            session_sts_connection = STSConnection(aws_access_key_id=sts_session.access_key,
                                                   aws_secret_access_key=sts_session.secret_key,
                                                   security_token=sts_session.session_token)

            assumed_role_object = session_sts_connection.assume_role(
                role_arn=role_arn,
                role_session_name=role_session_name,
                duration_seconds=token_expiration,
            )
        else:
            colormsg("When using get_session you must use MFA", "error")
            exit(1)

    except Exception as e:
        colormsg("There was an error assuming role", "error")
        verbose(e)
        exit(1)

    colormsg("Assumed the role successfully", "ok")

    access_key = sts_session.access_key
    session_key = sts_session.secret_key
    session_token = sts_session.session_token
    expiration = sts_session.expiration

    login_to_fedaccount(access_key, session_key, session_token, role_session_name)

    credential_profile = 'default'

    save_credentials(access_key, session_key, session_token, role_session_name, 'corp', 'session', credential_profile,
                     region)

    save_cli_credentials(access_key, session_key, session_token, '-'.join(['corp', 'session', credential_profile]),
                         region)

    return {'access_key': access_key, 'session_key': session_key, 'session_token': session_token,
            'role_session_name': role_session_name}


def save_cli_credentials(access_key, session_key, session_token, section_name, region):
    import configparser
    import os

    config: RawConfigParser = configparser.RawConfigParser()
    home = os.path.expanduser("~")
    basedir = os.path.dirname(home + '/.aws/credentials')
    if not os.path.exists(basedir):
        os.makedirs(basedir)
    if not os.path.isfile(home + '/.aws/credentials'):
        verbose("There is no ~/.aws/credentials (probably using an EC2 instance profile. Creating credentials file...")
        open(home + '/.aws/credentials', 'a').close()
    config.read(os.path.expanduser('~/.aws/credentials'))

    if not config.has_section(section_name):
        config.add_section(section_name)

    config.set(section_name, 'aws_access_key_id', access_key)
    config.set(section_name, 'aws_secret_access_key', session_key)
    config.set(section_name, 'aws_session_token', session_token)
    config.set(section_name, 'aws_security_token', session_token)
    config.set(section_name, 'region', region)

    with open(os.path.expanduser('~/.aws/credentials'), 'w') as configfile:
        config.write(configfile)


def login_to_fedaccount(access_key, session_key, session_token, role_session_name):
    json_temp_credentials = '{'
    json_temp_credentials += '"sessionId":"' + access_key + '",'
    json_temp_credentials += '"sessionKey":"' + session_key + '",'
    json_temp_credentials += '"sessionToken":"' + session_token + '"'
    json_temp_credentials += '}'

    # Make a request to the AWS federation endpoint to get a sign-in
    # token, passing parameters in the query string. The call requires an
    # Action parameter ('getSigninToken') and a Session parameter (the
    # JSON string that contains the temporary credentials that have
    # been URL-encoded).
    request_parameters = "?Action=getSigninToken"
    request_parameters += "&Session="
    request_parameters += quote_plus(json_temp_credentials)
    request_url = "https://signin.aws.amazon.com/federation"
    request_url += request_parameters
    r = requests.get(request_url)

    # Get the return value from the federation endpoint--a
    # JSON document that has a single element named 'SigninToken'.
    sign_in_token = json.loads(r.text)["SigninToken"]

    # Create the URL that will let users sign in to the console using
    # the sign-in token. This URL must be used within 15 minutes of when the
    # sign-in token was issued.
    request_parameters = "?Action=login"
    request_parameters += "&Issuer=" + role_session_name
    request_parameters += "&Destination="
    request_parameters += quote_plus("https://console.aws.amazon.com/")
    request_parameters += "&SigninToken=" + sign_in_token
    request_url = "https://signin.aws.amazon.com/federation"
    request_url += request_parameters


# END FUNCTIONS SECTION
class Awsauth:
    disable_warnings()

    def token(self):
        global region
        global role
        global access_key
        global session_key
        global session_token

        # Welcome
        if args.verbose:
            print()
            print("Awsauth Amazon Account Access " + version)
            print()

        else:
            print()
            print("Awsauth Amazon Account Access " + version)
            print()

        # Set values from parser
        if args.role:
            role = args.role
        else:
            role = 'developer'

        if args.region:
            region = args.region
        else:
            region = 'eu-west-1'

        if args.project:
            project = args.project
            project = project.lower()
            verbose("Project: " + project)

        if args.env:
            env = args.env
            env = env.lower()
            verbose("Environment: " + env)

        token_expiration = 3600

        iam_connection = IAMConnection()

        # role_session_name=iam_connection.get_user()['get_user_response']['get_user_result']['user']['user_name']
        try:
            role_session_name = iam_connection.get_user().get_user_response.get_user_result.user.user_name
        except Exception as e:
            colormsg("There was an error retrieving your session_name. Check your credentials", "error")
            verbose(e)
            exit(1)

        # account_id=iam_connection.get_user()['get_user_response']['get_user_result']['user']['arn'].split(':')[4]
        try:
            account_id = iam_connection.get_user().get_user_response.get_user_result.user.arn.split(':')[4]
        except Exception as e:
            colormsg("There was an error retrieving your account id. Check your credentials", "error")
            verbose(e)
            exit(1)

        # Regexp for groups and policies. Set the policy name used by your organization

        if args.project and args.env:
            group_name = 'corp-' + project + '-master-' + role
            policy_name = 'Delegated_Roles'
            role_filter = env + '-' + project + '-delegated-' + role

        # Step 1: Prompt user for target account ID and name of role to assume

        # IAM groups
        verbose("Getting IAM group info:")
        delegated_policy = []
        group_policy = []
        delegated_arn = []

        try:
            policy = iam_connection.get_group_policy(group_name, policy_name)
        except Exception as e:
            colormsg(
                "There was an error retrieving your group policy. Check your credentials, group_name and policy_name",
                "error")
            verbose(e)
            exit(1)

        policy = policy.get_group_policy_response.get_group_policy_result.policy_document
        policy = unquote(policy)
        group_policy.append(config_line_policy("iam:grouppolicy", group_name, policy_name, policy))

        output_lines(group_policy)

        # Format policy and search by role_filter

        policy = re.split('"', policy)

        for i in policy:
            result_filter = re.search(role_filter, i)
            if result_filter:
                delegated_arn.append(i)

        if len(delegated_arn) == 0:
            if args.role and args.project:
                colormsg("Sorry, you are not authorized to use the role " + role + " for project " + project, "error")
                exit(1)
            else:
                colormsg("Sorry, you are not authorized to use the role " + role_filter, "error")
                exit(1)

        elif len(delegated_arn) == 1:
            account_id_from_user = delegated_arn[0].split(':')[4]
            role_name_from_user = delegated_arn[0].split('/')[1]

        else:
            colormsg("There are two or more policies matching your input", "error")
            exit(1)

        colormsg("You are authenticated as " + role_session_name, "ok")

        # MFA
        if not args.nomfa:
            mfa_devices_r = iam_connection.get_all_mfa_devices(role_session_name)
            if mfa_devices_r.list_mfa_devices_response.list_mfa_devices_result.mfa_devices:
                mfa_serial_number = mfa_devices_r.list_mfa_devices_response.list_mfa_devices_result.mfa_devices[
                    0].serial_number
            else:
                colormsg("You don't have MFA devices associated with our user", "error")
                exit(1)
        else:
            mfa_serial_number = "arn:aws:iam::" + account_id + ":mfa/" + role_session_name

        # Create an ARN out of the information provided by the user.
        role_arn = "arn:aws:iam::" + account_id_from_user + ":role/"
        role_arn += role_name_from_user

        # Connect to AWS STS and then call AssumeRole. This returns temporary security credentials.
        sts_connection = STSConnection()

        # Assume the role
        if not args.nomfa:
            verbose("Assuming role " + role_arn + " using MFA device " + mfa_serial_number + "...")
            if args.project:
                colormsg(
                    "Assuming role " + role + " from project " + project + " using MFA device from user " + role_session_name + "...",
                    "normal")
            elif args.iam_delegated_role:
                colormsg("Assuming role " + role + " using MFA device from user " + role_session_name + "...", "normal")
        else:
            verbose("Assuming role " + role_arn + "...")
            if args.project:
                colormsg(
                    "Assuming role " + role + " from project " + project + " from user " + role_session_name + "...",
                    "normal")
            elif args.iam_delegated_role:
                colormsg("Assuming role " + role + " from user " + role_session_name + "...", "normal")

        if os.path.isfile(os.path.expanduser('~/.awsauth')):

            with open(os.path.expanduser('~/.awsauth')) as json_file:
                root_json_data = json.load(json_file)
                json_file.close()

                if project in root_json_data and env in root_json_data[project] and role in root_json_data[project][
                    env]:
                    json_data = root_json_data[project][env][role]
                    awsauth_last_timestamp = json_data["awsauth_last_timestamp"]

                    # check if the token has expired
                    if int(time.time()) - int(awsauth_last_timestamp) > token_expiration or args.refresh:

                        verbose("token has expired")
                        sts_token = get_sts_token(sts_connection, role_arn, mfa_serial_number, role_session_name,
                                                  project, env, role, token_expiration)

                    else:
                        verbose("token has not expired, trying to login...")
                    login_to_fedaccount(json_data["access_key"], json_data["session_key"], json_data["session_token"],
                                        json_data["role_session_name"])
                    sts_token = {'access_key': json_data["access_key"], 'session_key': json_data["session_key"],
                                 'session_token': json_data["session_token"],
                                 'role_session_name': json_data["role_session_name"]}

                else:
                    sts_token = get_sts_token(sts_connection, role_arn, mfa_serial_number, role_session_name, project,
                                              env, role, token_expiration)
        else:
            verbose("role is " + role)
            sts_token = get_sts_token(sts_connection, role_arn, mfa_serial_number, role_session_name, project, env,
                                      role, token_expiration)
        return sts_token

    # Runs all the functions
    def __init__(self):
        global access_key
        global session_key
        global session_token
        token = self.token()
        access_key = token['access_key']
        session_key = token['session_key']
        session_token = token['session_token']
        exit(0)


# This idiom means the below code only runs when executed from command line

if __name__ == '__main__':
    a = Awsauth()
