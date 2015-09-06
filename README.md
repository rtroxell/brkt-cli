The **brkt** utility is a command-line interface to the Bracket service.

## Installation

**brkt-cli** will eventually be published to PyPi.  In the interim, you'll
need to clone the Git repo and optionally use the *setup.py* script to install
the command and related code.

The **brkt-cli** tool requires Python 2.7.9+ with a corresponding openssl
version of 1.0.1+

### Clone the repo

You'll need to clone the **brkt-cli** repo in order to run the **brkt**
command.  Note that you'll also need to install
[boto](https://github.com/boto/boto).

```shell
~$ git clone git@github.int.brkt.net:brkt/brkt-cli.git
Cloning into 'brkt-cli'...
remote: Counting objects: 41, done.
remote: Compressing objects: 100% (21/21), done.
remote: Total 41 (delta 8), reused 0 (delta 0), pack-reused 20
Receiving objects: 100% (41/41), 27.10 KiB | 0 bytes/s, done.
Resolving deltas: 100% (12/12), done.
Checking connectivity... done.

~$ cd brkt-cli

~/brkt-cli (master)$ ./brkt encrypt-ami -h
usage: brkt encrypt-ami [-h] [--encryptor-ami ID] --key NAME [--validate-ami]
                        [--no-validate-ami] --region NAME
                        AMI_ID

positional arguments:
  AMI_ID              The AMI that will be encrypted

optional arguments:
  -h, --help          show this help message and exit
  --encryptor-ami ID  Bracket Encryptor AMI
  --key NAME          EC2 SSH Key Pair name
  --validate-ami      Validate AMI properties (default)
  --no-validate-ami   Don't validate AMI properties
  --region NAME       AWS region (e.g. us-west-2)
```

### Virtualenv install

The **brkt-cli** installer uses *setup.py* uses Python *setuptools*,
which unfortunately does not provide an uninstall option.  You can use
[virtualenv](https://virtualenv.pypa.io/en/latest/) to install the command
in its own Python environment:

```shell
~/venv$ virtualenv brkt-cli
New python executable in brkt-cli/bin/python2.7
Also creating executable in brkt-cli/bin/python
Installing setuptools, pip...done.

~/venv$ source ~/venv/brkt-cli/bin/activate

(brkt-cli)~/venv$ cd ~/brkt-cli

(brkt-cli)~/brkt-cli (master)$ pip install -r requirements.txt
Collecting boto==2.38.0 (from -r requirements.txt (line 1))
  Using cached boto-2.38.0-py2.py3-none-any.whl
  Requirement already satisfied (use --upgrade to upgrade): wsgiref==0.1.2 in /usr/local/Cellar/python/2.7.10_2/Frameworks/Python.framework/Versions/2.7/lib/python2.7 (from -r ../requirements.txt (line 2))
  Collecting requests==2.7.0 (from -r ../requirements.txt (line 3))
    Using cached requests-2.7.0-py2.py3-none-any.whl
    Installing collected packages: boto, requests
    Successfully installed boto-2.38.0 requests-2.7.0

(brkt-cli)~/brkt-cli (master)$ python setup.py install
running install
...
Finished processing dependencies for brkt-cli==0.9a1
(brkt-cli)~/brkt-cli (master)$ which brkt
/Users/boris/venv/brkt-cli/bin/brkt
```
