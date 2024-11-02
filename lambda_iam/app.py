import boto3  
import json  
import re

# Create an IAM client using Boto3
iam = boto3.client('iam')

# Define a regex pattern to validate IAM ARNs
arn_regex = r"^arn:aws:iam::\d{12}:(user|role|group)/[a-zA-Z0-9+=,.@_\-/]+$"

# Function to validate the format of IAM ARNs
def is_valid_iam_arn(arn):
    return re.match(arn_regex, arn) is not None  # Return True if ARN matches the regex pattern

# Function to retrieve attached policies for users, groups, or roles
def list_attached_policies(entity_type, entity_name):
    list_aux = []  # Initialize a list to hold inline policies
    # Check the type of IAM entity (user, group, or role)
    if entity_type == 'user':
        # Retrieve inline policies for the user
        for name in iam.list_user_policies(UserName=entity_name)['PolicyNames']:
            list_aux.append(iam.get_user_policy(UserName=entity_name, PolicyName=name))  # Get inline policy
        # Retrieve attached policies for the user and combine with inline policies
        attached_policies = iam.list_attached_user_policies(UserName=entity_name)['AttachedPolicies'] + list_aux
    elif entity_type == 'group':
        # Retrieve inline policies for the group
        for name in iam.list_group_policies(GroupName=entity_name)['PolicyNames']:
            list_aux.append(iam.get_group_policy(GroupName=entity_name, PolicyName=name))  # Get inline policy
        # Retrieve attached policies for the group and combine with inline policies
        attached_policies = iam.list_attached_group_policies(GroupName=entity_name)['AttachedPolicies'] + list_aux
    elif entity_type == 'role':
        # Retrieve inline policies for the role
        for name in iam.list_role_policies(RoleName=entity_name)['PolicyNames']:
            list_aux.append(iam.get_role_policy(RoleName=entity_name, PolicyName=name))  # Get inline policy
        # Retrieve attached policies for the role and combine with inline policies
        attached_policies = iam.list_attached_role_policies(RoleName=entity_name)['AttachedPolicies'] + list_aux
    else:
        return []  # Return an empty list if the entity type is unrecognized
    return attached_policies  # Return the list of attached policies

# Lambda handler function to identify unused ARNs in IAM policies
def lambda_handler(event, context):
    # Collect all IAM users, roles, and groups
    users = iam.list_users()['Users']
    roles = iam.list_roles()['Roles']
    groups = iam.list_groups()['Groups']
    
    # Collect ARNs for all IAM entities into a set
    arns = set([user['Arn'] for user in users] + 
               [role['Arn'] for role in roles] + 
               [group['Arn'] for group in groups])
    
    # Initialize a list to collect all policies attached to IAM entities
    all_attached_policies = []
    for user in users:
        all_attached_policies.extend(list_attached_policies('user', user['UserName']))  # Add user policies
    for group in groups:
        all_attached_policies.extend(list_attached_policies('group', group['GroupName']))  # Add group policies
    for role in roles:
        all_attached_policies.extend(list_attached_policies('role', role['RoleName']))  # Add role policies

    # Extract referenced ARNs from attached policy documents
    mentioned_arn_attached_policies = []
    for policy_document in all_attached_policies:
        # Check if the policy document is embedded in the document
        if 'PolicyDocument' in policy_document:
            policy_doc = policy_document['PolicyDocument']
        else:
            # Fetch the policy and its latest version if not embedded
            policy = iam.get_policy(PolicyArn=policy_document['PolicyArn'])['Policy']
            policy_doc = iam.get_policy_version(
                PolicyArn=policy['Arn'], 
                VersionId=policy['DefaultVersionId']
            )['PolicyVersion']['Document']
        
        statements = policy_doc['Statement']  # Extract statements from the policy document
        if not isinstance(statements, list):  # Ensure statements is a list
            statements = [statements]
        
        for statement in statements:
            if 'Resource' in statement:  # Check if the statement contains resources
                resources = statement['Resource']
                if not isinstance(resources, list):  # Ensure resources is a list
                    resources = [resources]
                for resource in resources:
                    if is_valid_iam_arn(resource):  # Validate the resource ARN
                        mentioned_arn_attached_policies.append(resource)  # Add valid ARNs to the list
    
    # Combine all ARNs (from entities and mentioned in policies) into a single list
    arns.update(mentioned_arn_attached_policies)
    
    # Identify policies that contain unused ARNs
    names_policies = []
    policies = iam.list_policies(Scope='Local')['Policies']  # Get user-created policies
    for policy in policies:
        not_existing_arn = []  # List to hold ARNs not found in the account
        # Retrieve the latest version of the policy document
        policy_document = iam.get_policy_version(
            PolicyArn=policy['Arn'], 
            VersionId=policy['DefaultVersionId']
        )['PolicyVersion']['Document']
        
        statements = policy_document['Statement']
        if not isinstance(statements, list):  # Ensure statements is a list
            statements = [statements]
        
        for statement in statements:
            if 'Resource' in statement:  # Check if the statement contains resources
                resources = statement['Resource']
                if not isinstance(resources, list):  # Ensure resources is a list
                    resources = [resources]
                for resource in resources:
                    # Check if the resource is a valid ARN and not in the existing ARNs
                    if is_valid_iam_arn(resource) and resource not in arns:
                        not_existing_arn.append(resource)  # Add unused ARN to the list
        
        if not_existing_arn:  # If there are unused ARNs, add to the output list
            names_policies.append({'arn_policy': policy['Arn'], 'arn_unused': not_existing_arn})
    


    #ARN mentioned on all the policies - ARN exist on the account- ARN roles can be assumed by the account
    # Return a list of policies with unused ARNs
    return {
        'statusCode': 200,
        'body': {
            'managed_name_policy': names_policies  # Return the list of policies with their unused ARNs
        }
    }
    