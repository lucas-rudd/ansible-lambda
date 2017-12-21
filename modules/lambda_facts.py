#!/usr/bin/python
# (c) 2016, Pierre Jodouin <pjodouin@virtualcomputing.solutions>
#
# Ansible is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# Ansible is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Ansible.  If not, see <http://www.gnu.org/licenses/>.

import datetime
import sys

# TODO: used temporarily for backward compatibility with older versions of ansible but should be removed once included in the distro.
try:
    import boto
except ImportError:
    pass
try:
    import boto3
    from botocore.exceptions import ClientError

    HAS_BOTO3 = True
except ImportError:
    HAS_BOTO3 = False

DOCUMENTATION = '''
---
module: lambda_opinions
short_description: Gathers AWS Lambda function details as Ansible facts 
description:
  - Gathers various details related to Lambda functions, including aliases, versions and event source mappings.
    Use module M(lambda) to manage the lambda function itself, M(lambda_alias) to manage function aliases and
    M(lambda_event) to manage lambda event source mappings.
version_added: "2.2"
options:
  query:
    description:
      - Specifies the resource type for which to gather facts.  Leave blank to retrieve all facts.
    required: true
    choices: [ "aliases", "all", "config", "mappings", "policy", "versions" ]
    default: "all"
  function_name:
    description:
      - The name of the lambda function for which facts are requested.
    required: false
    default: null
    aliases: [ "function", "name"]
  event_source_arn:
    description:
      - For query type 'mappings', this is the Amazon Resource Name (ARN) of the Amazon Kinesis or DynamoDB stream.
    default: null
    required: false
author: Pierre Jodouin (@pjodouin)
requirements:
    - boto3
extends_documentation_fragment:
    - aws
'''

EXAMPLES = '''
---
# Simple example of listing all info for a function
- name: List all for a specific function
  lambda_opinions:
    query: all
    function_name: myFunction
  register: my_function_details
# List all versions of a function
- name: List function versions
  lambda_opinions:
    query: versions
    function_name: myFunction
  register: my_function_versions
# List all lambda function versions
- name: List all function
  lambda_opinions:
    query: all
    max_items: 20
- name: show Lambda facts
  debug: var=lambda_opinions
'''

RETURN = '''
---
lambda_opinions:
    description: lambda facts
    returned: success
    type: dict
lambda_opinions.aliases:
    description: lambda function aliases
    returned: success
    type: list
lambda_opinions.function:
    description: lambda function configuration, when function_name is specified
    returned: success
    type: dict
lambda_opinions.function_list:
    description: list of lambda functions, when function_name is not specified
    returned: success
    type: list
lambda_opinions.mappings:
    description: lambda event source mappings
    returned: success
    type: list
lambda_opinions.policy:
    description: policy document attached to lambda function
    returned: success
    type: dict
lambda_opinions.versions:
    description: list of all version configurations for a specified function
    returned: success
    type: list
'''


def fix_return(node):
    """
    fixup returned dictionary
    :param node:
    :return:
    """

    if isinstance(node, datetime.datetime):
        node_value = str(node)

    elif isinstance(node, list):
        node_value = [fix_return(item) for item in node]

    elif isinstance(node, dict):
        node_value = dict([(item, fix_return(node[item])) for item in node.keys()])

    else:
        node_value = node

    return node_value


def paginate(client, function_name):
    full_list = list()
    try:
        paginator = client.get_paginator(function_name)
        page_iterator = paginator.paginate()
        for page in page_iterator:
            full_list.extend(page['Functions'])
        return full_list
    except ClientError as e:
        if e.response['Error']['Code'] == 'ResourceNotFoundException':
            return []
        else:
            module.fail_json(msg='Unable to get function list, error: {0}'.format(e))


def alias_details(client, module):
    """
    Returns list of aliases for a specified function.
    :param client: AWS API client reference (boto3)
    :param module: Ansible module reference
    :return dict:
    """

    lambda_opinions = dict()

    function_name = module.params.get('function_name')
    no_paginate = module.params.get('no_paginate')
    if function_name:
        params = dict()
        if module.params.get('max_items'):
            params['MaxItems'] = module.params.get('max_items')

        if module.params.get('next_marker'):
            params['Marker'] = module.params.get('next_marker')
        try:
            list_aliases = client.list_aliases(FunctionName=function_name, **params)
            lambda_opinions.update(aliases=list_aliases['Aliases'], next_marker=list_aliases['NextMarker'])
        except ClientError as e:
            if e.response['Error']['Code'] == 'ResourceNotFoundException':
                lambda_opinions.update(aliases=[])
            else:
                module.fail_json(msg='Unable to get {0} aliases, error: {1}'.format(function_name, e))
    else:
        module.fail_json(msg='Parameter function_name required for query=aliases.')

    return lambda_opinions


def all_details(client, module):
    """
    Returns all lambda related facts.
    :param client: AWS API client reference (boto3)
    :param module: Ansible module reference
    :return dict:
    """

    lambda_opinions = dict()

    function_name = module.params.get('function_name')
    if function_name:
        lambda_opinions.update(config_details(client, module))
        lambda_opinions.update(alias_details(client, module))
        lambda_opinions.update(policy_details(client, module))
        lambda_opinions.update(version_details(client, module))
        lambda_opinions.update(mapping_details(client, module))
    else:
        lambda_opinions.update(config_details(client, module))

    return lambda_opinions


def config_details(client, module):
    """
    Returns configuration details for one or all lambda functions.
    :param client: AWS API client reference (boto3)
    :param module: Ansible module reference
    :return dict:
    """

    lambda_opinions = dict()

    function_name = module.params.get('function_name')
    no_paginate = module.params.get('no_paginate')
    if function_name:
        try:
            lambda_opinions.update(function=client.get_function_configuration(FunctionName=function_name))
        except ClientError as e:
            if e.response['Error']['Code'] == 'ResourceNotFoundException':
                lambda_opinions.update(function={})
            else:
                module.fail_json(msg='Unable to get {0} configuration, error: {1}'.format(function_name, e))

    elif no_paginate:
        lambda_opinions.update(function_list=paginate(client, 'list_functions'))

    else:
        params = dict()
        if module.params.get('max_items'):
            params['MaxItems'] = module.params.get('max_items')

        if module.params.get('next_marker'):
            params['Marker'] = module.params.get('next_marker')

        try:
            list_functions = client.list_functions(**params)
            lambda_opinions.update(function_list=list_functions['Functions'], next_marker=list_functions['NextMarker'])
        except ClientError as e:
            if e.response['Error']['Code'] == 'ResourceNotFoundException':
                lambda_opinions.update(function_list=[])
            else:
                module.fail_json(msg='Unable to get function list, error: {0}'.format(e))

    return lambda_opinions


def mapping_details(client, module):
    """
    Returns all lambda event source mappings.
    :param client: AWS API client reference (boto3)
    :param module: Ansible module reference
    :return dict:
    """

    lambda_opinions = dict()
    params = dict()

    if module.params.get('function_name'):
        params['FunctionName'] = module.params.get('function_name')

    if module.params.get('event_source_arn'):
        params['EventSourceArn'] = module.params.get('event_source_arn')

    if module.params.get('max_items'):
        params['MaxItems'] = module.params.get('max_items')

    if module.params.get('next_marker'):
        params['Marker'] = module.params.get('next_marker')

    try:
        list_event_source_mappings = client.list_event_source_mappings(**params)
        lambda_opinions.update(mappings=list_event_source_mappings['EventSourceMappings'])
    except ClientError as e:
        if e.response['Error']['Code'] == 'ResourceNotFoundException':
            lambda_opinions.update(mappings=[])
        else:
            module.fail_json(msg='Unable to get source event mappings, error: {0}'.format(e))

    return lambda_opinions


def policy_details(client, module):
    """
    Returns policy attached to a lambda function.
    :param client: AWS API client reference (boto3)
    :param module: Ansible module reference
    :return dict:
    """

    if module.params.get('max_items') or module.params.get('next_marker'):
        module.fail_json(msg='Cannot specify max_items nor next_marker for query=policy.')

    lambda_opinions = dict()

    function_name = module.params.get('function_name')
    if function_name:
        try:
            # get_policy returns a JSON string so must convert to dict before reassigning to its key
            lambda_opinions.update(policy=json.loads(client.get_policy(FunctionName=function_name)['Policy']))
        except ClientError as e:
            if e.response['Error']['Code'] == 'ResourceNotFoundException':
                lambda_opinions.update(policy={})
            else:
                module.fail_json(msg='Unable to get {0} policy, error: {1}'.format(function_name, e))
    else:
        module.fail_json(msg='Parameter function_name required for query=policy.')

    return lambda_opinions


def version_details(client, module):
    """
    Returns all lambda function versions.
    :param client: AWS API client reference (boto3)
    :param module: Ansible module reference
    :return dict:
    """

    lambda_opinions = dict()

    function_name = module.params.get('function_name')
    if function_name:
        params = dict()
        if module.params.get('max_items'):
            params['MaxItems'] = module.params.get('max_items')

        if module.params.get('next_marker'):
            params['Marker'] = module.params.get('next_marker')

        try:
            list_versions_by_function = client.list_versions_by_function(FunctionName=function_name, **params)
            lambda_opinions.update(versions=list_versions_by_function['Versions'],
                                   next_marker=list_versions_by_function['NextMarker'])
        except ClientError as e:
            if e.response['Error']['Code'] == 'ResourceNotFoundException':
                lambda_opinions.update(versions=[])
            else:
                module.fail_json(msg='Unable to get {0} versions, error: {1}'.format(function_name, e))
    else:
        module.fail_json(msg='Parameter function_name required for query=versions.')

    return lambda_opinions


def main():
    """
    Main entry point.
    :return dict: ansible facts
    """
    argument_spec = ec2_argument_spec()
    argument_spec.update(
        dict(
            function_name=dict(required=False, default=None, aliases=['function', 'name']),
            query=dict(required=False, choices=['aliases', 'all', 'config', 'mappings', 'policy', 'versions'],
                       default='all'),
            event_source_arn=dict(required=False, default=None),
            max_items=dict(type='int', required=False, default=100),
            next_marker=dict(type='string', required=False, default=None),
            no_paginate=dict(type='bool', required=False, default=False)
        )
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        mutually_exclusive=[],
        required_together=[]
    )

    # validate dependencies
    if not HAS_BOTO3:
        module.fail_json(msg='boto3 is required for this module.')

    # validate function_name if present
    function_name = module.params['function_name']
    if function_name:
        if not re.search("^[\w\-:]+$", function_name):
            module.fail_json(
                msg='Function name {0} is invalid. Names must contain only alphanumeric characters and hyphens.'.format(
                    function_name)
            )
        if ':' in function_name:
            if len(function_name) > 140:
                module.fail_json(msg='Function ARN "{0}" exceeds 140 character limit'.format(function_name))
        else:
            if len(function_name) > 64:
                module.fail_json(msg='Function name "{0}" exceeds 64 character limit'.format(function_name))

    try:
        region, endpoint, aws_connect_kwargs = get_aws_connection_info(module, boto3=True)
        aws_connect_kwargs.update(dict(region=region,
                                       endpoint=endpoint,
                                       conn_type='client',
                                       resource='lambda'
                                       ))
        client = boto3_conn(module, **aws_connect_kwargs)
    except ClientError as e:
        module.fail_json(msg="Can't authorize connection - {0}".format(e))

    this_module = sys.modules[__name__]

    invocations = dict(
        aliases='alias_details',
        all='all_details',
        config='config_details',
        mappings='mapping_details',
        policy='policy_details',
        versions='version_details',
    )

    this_module_function = getattr(this_module, invocations[module.params['query']])
    all_facts = fix_return(this_module_function(client, module))

    results = dict(ansible_facts=dict(lambda_opinions=all_facts), changed=False)

    if module.check_mode:
        results.update(dict(msg='Check mode set but ignored for fact gathering only.'))

    module.exit_json(**results)


# ansible import module(s) kept at ~eof as recommended
from ansible.module_utils.basic import *
from ansible.module_utils.ec2 import *

if __name__ == '__main__':
    main()
