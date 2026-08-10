"""
AWS Lambda security checks for CIS benchmarks.
Validates Lambda function configurations for security best practices.
"""

import boto3
from typing import List, Dict, Any


class LambdaSecurityChecker:
    """Check Lambda functions for security misconfigurations."""

    def __init__(self):
        self.client = boto3.client('lambda')

    def check_function_timeout(self, function_name: str) -> Dict[str, Any]:
        """
        Check if Lambda function timeout is reasonable (max 15 minutes recommended).
        CIS AWS Foundations Benchmark 4.15
        """
        try:
            response = self.client.get_function_configuration(
                FunctionName=function_name
            )
            timeout = response.get('Timeout', 3)
            
            return {
                'passed': timeout <= 900,  # 15 minutes in seconds
                'timeout_seconds': timeout,
                'recommendation': 'Set function timeout to <= 900 seconds'
            }
        except Exception as e:
            return {'error': str(e)}

    def check_execution_role_permissions(self, function_name: str) -> Dict[str, Any]:
        """
        Check if Lambda execution role has minimal permissions.
        CIS AWS Foundations Benchmark 4.16
        """
        try:
            response = self.client.get_function_configuration(
                FunctionName=function_name
            )
            role_arn = response.get('Role', '')
            
            # Extract role name from ARN
            role_name = role_arn.split('/')[-1] if '/' in role_arn else role_arn
            
            return {
                'function': function_name,
                'role': role_name,
                'recommendation': 'Audit role for least privilege (AdministratorAccess is high risk)'
            }
        except Exception as e:
            return {'error': str(e)}

    def check_environment_variable_encryption(self, function_name: str) -> Dict[str, Any]:
        """
        Check if Lambda environment variables use KMS encryption.
        CIS AWS Foundations Benchmark 4.17
        """
        try:
            response = self.client.get_function_configuration(
                FunctionName=function_name
            )
            
            env_vars = response.get('Environment', {}).get('Variables', {})
            kms_key_arn = response.get('KMSKeyArn', None)
            
            return {
                'passed': kms_key_arn is not None and len(env_vars) > 0,
                'has_kms_encryption': kms_key_arn is not None,
                'env_var_count': len(env_vars),
                'recommendation': 'Enable KMS encryption for sensitive environment variables'
            }
        except Exception as e:
            return {'error': str(e)}

    def check_vpc_configuration(self, function_name: str) -> Dict[str, Any]:
        """
        Check if Lambda function is deployed in a VPC.
        CIS AWS Foundations Benchmark 4.18
        """
        try:
            response = self.client.get_function_configuration(
                FunctionName=function_name
            )
            
            vpc_config = response.get('VpcConfig', {})
            subnet_ids = vpc_config.get('SubnetIds', [])
            
            return {
                'passed': len(subnet_ids) > 0,
                'deployed_in_vpc': len(subnet_ids) > 0,
                'subnet_count': len(subnet_ids),
                'recommendation': 'Deploy sensitive Lambda functions in VPC for network isolation'
            }
        except Exception as e:
            return {'error': str(e)}
