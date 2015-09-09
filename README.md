**brkt-cli** is a command-line interface to the Bracket service.  It
produces an encrypted version of an Amazon Machine Image, which can then be
launched in EC2.

## Requirements

**brkt-cli** requires Python 2.7.9+ with a corresponding openssl
version of 1.0.1+

## Installation

Use **pip** to install **brkt-cli** directly from the GitHub repo:

```
$ pip install git+ssh://git@github.int.brkt.net/brkt/brkt-cli.git
Collecting git+ssh://git@github.int.brkt.net/brkt/brkt-cli.git
  Cloning ssh://git@github.int.brkt.net/brkt/brkt-cli.git to /var/folders/tz/k2yndc9j5bj5dgzngb1g67rc0000gn/T/pip-tekQzC-build
Collecting boto>=2.38.0 (from brkt-cli==0.9a1)
  Using cached boto-2.38.0-py2.py3-none-any.whl
Collecting requests>=2.7.0 (from brkt-cli==0.9a1)
  Downloading requests-2.7.0-py2.py3-none-any.whl (470kB)
    100% |################################| 471kB 10.9MB/s
Installing collected packages: brkt-cli, requests, boto
  Running setup.py install for brkt-cli
    Installing brkt script to /usr/local/bin


Successfully installed boto-2.38.0 brkt-cli-0.9a1 requests-2.7.0
```

## Configuration

Before running the **brkt** command, make sure that you've set the AWS
environment variables:

```
$ export AWS_SECRET_ACCESS_KEY=<access key>
$ export AWS_ACCESS_KEY_ID=<key id>
```

You'll also need to make sure that your AWS account has the required
permissions, such as running an instance, describing an image, and
creating snapshots.  See *iam.json* in the repo root for the complete
list of required permissions.

## Encrypting an AMI

Run **brkt encrypt-ami** to create a new encrypted AMI based on an existing
image:

```
~/brkt-cli$ ./brkt encrypt-ami --key my-aws-key --region us-east-1 ami-76e27e1e
15:28:37 Starting encryptor session 0ba2065fbeec48e08002c6db1ca5ba46
15:28:38 Launching instance i-703f4c99 to snapshot root disk for ami-76e27e1e
...
15:57:11 Created encrypted AMI ami-07c2a262 based on ami-76e27e1e
15:57:11 Terminating encryptor instance i-753e4d9c
15:57:12 Deleting snapshot copy of original root volume snap-847da3e1
15:57:12 Done.
ami-07c2a262
```

When the process completes, the new AMI id is written to stdout.  All log
messages are written to stderr.

## Uninstall

Use **pip** to uninstall **brkt-cli**:
```
$ pip uninstall brkt-cli
```
