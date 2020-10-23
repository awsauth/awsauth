# Awsauth Amazon Account Access

## Introduction

Awsauth is a CLI tool to create temporary credentials to log into a AWS delegated account. For this you must have a central account where you add all your users (corporate account) with the only permission to assume roles cross-accounts, then the user must be added to the group that you want to let access the delegated account.

Based on [How to Enable Cross-Account Access to the AWS Management Console](https://blogs.aws.amazon.com/security/post/Tx70F69I9G8TYG/How-to-enable-cross-account-access-to-the-AWS-Management-Console)

![Squema for auth](static/delegated.png "squema for auth")

## Dependencies

Before creating the awsauth python egg and installing it, you need to install the AWS CLI, you need to make sure you have python2.x installed on your system

```
$ python --version
Python 3.4.3
$ python2.7 --version
Python 2.7.10
$ python2 --version
Python 2.7.10
```

It's possible that you already have installed python, just make sure which is your primary python environment, as awsauth **IS ONLY** compatible with python 2.x, 

You need to install setuptools package, so the bootstraping can create the CLI command. Please [go here](https://pypi.python.org/pypi/setuptools) and follow the installation instructions for your system.


Then you need to install the AWS Command Line Interface

```
$ sudo pip install awscli
```

and the requests library version 2.9.1

```
$ sudo pip install requests==2.9.1
```

## Installation

simply generate the egg and install it with the setup.py program, to do this be sure you have **python 2.X** installed (python3 is unsupported), so you might need to use **python, python2, or python2.6, o python2.7** depending on your python install, in the following example I used **python2**.

```
$ sudo python2 setup.py install
running install
running bdist_egg
running egg_info
writing requirements to awsauth.egg-info/requires.txt
writing awsauth.egg-info/PKG-INFO
writing top-level names to awsauth.egg-info/top_level.txt
....
Using /usr/lib/python2.7/site-packages/colorama-0.3.3-py2.7.egg
Finished processing dependencies for awsauth==1.0.0
```

### Boto Version

If you have an old versión of boto or the CLI installed on your system, you need to make sure its the cli 1.7.34 at least since AWS changed how the CLI and boto look for the credentials in your system, you can read more about this [here](http://blogs.aws.amazon.com/security/post/Tx3D6U6WSFGOK2H/A-New-and-Standardized-Way-to-Manage-Credentials-in-the-AWS-SDKs).

## Setup Corp credentials

An easy way to setup your credentials for the main (corp) account, is to install boto and set them on the **default** profile with the following command

```
$ aws configure
AWS Access Key ID [None]: XXXXXXXXXXXXXXX
AWS Secret Access Key [None]: XXXXXXXXXXXXXXXXXXX
Default region name [None]: eu-west-1
Default output format [None]: json
```

while doing so you will require to **PAIR** a MFA device such as your mobile device with Google Authenticator, and that's it!

### Groups in the master account

```
corp-<project>-master-<role_name>
```

where role name should be *admin*, *developer*, *devops*, *user*, *audit* or *jenkins*. It has only a policy named *Delegated_Roles*

### Naming in the delegated account

```
 <environment>-<project>-delegated-<role_name>
```

Please note that this role must be created as type "Role for Cross-Account Access" with subtype "Provide access between AWS accounts you own"


## Running the CLI

you can simply type the awsauth command anywhere in your system console, you must provide always the project name (-p), the environment (-e) and the role (-r). If you want that Awnbis opens a web tab in your browser with the console of that particular account just add -b and either chrome/google-chrome/firefox/chromium depending on your favorite browser installation, i.e

```
awsauth -p <project_name> -e <environment> -r <role>

Awsauth Amazon Account Access 1.0.0

iam:grouppolicy, corp-datalab-master-admin, Delegated_Roles, 3c78b4798a75ad40f75405356a139a7.....

[ OK ] You are authenticated as luis.gonzalez


Assuming role admin from project project_name using MFA device from user test.user...

role is admin
Enter the MFA code: 123456

[ OK ] Assumed the role successfully

```


## Generating AccessKeys/SecretKeys

Everytime you run awsauth and succesfully generate a new session token, the role PROJECT-ENV-ROLE on your boto credentials (~/.aws/credentials) will be updated/created... i.e.

```
$ awsauth -p project -e dev -r admin

....

$ cat ~/.aws/credentials
[default]
aws_access_key_id = XXXXXXX
aws_secret_access_key = XXXXXXX

[project-dev-admin]
aws_access_key_id = XXXXXXX
aws_secret_access_key = XXXXXXX
aws_session_token = XXXXXXX
```

This means you can use the AWS CLI with the profile flag like this

```
$ aws s3 ls --profile project-dev-admin
```
and you will be running this command against the delegated account.

Another way is to export the role to the AWS_PROFILE and/or AWS_DEFAULT_PROFILE env variables, so its used by the CLI and sdks on your computer. 

Note that in AWS credentials chain system environment variables takes precedence over .aws/credentials file, so you need to use another tty or unset environment variables in order to use awsauth again.

```
$ export AWS_PROFILE=project-dev-admin; export AWS_DEFAULT_PROFILE=project-dev-admin
```

If you are doing tests or development in local, use the awsauth profile in your configuration with the AWS SDK credentials provider class, for instance in java __AWSIAMProfileCredentialsProvider__ will use the credentials stored in the profile name you specify.
