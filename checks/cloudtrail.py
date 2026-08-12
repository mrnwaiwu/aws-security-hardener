"""
CloudTrail Security Checks
Validates CloudTrail configuration and logging compliance.
"""

def check_cloudtrail_enabled(client):
    """Check if CloudTrail is enabled for all regions."""
    try:
        response = client.describe_trails(includeShadowTrails=True)
        if not response['trailList']:
            return {'status': 'FAIL', 'message': 'No CloudTrail trails configured'}
        
        # Check if multi-region trails are enabled
        multi_region_trails = [t for t in response['trailList'] if t.get('IsMultiRegionTrail')]
        if not multi_region_trails:
            return {'status': 'FAIL', 'message': 'No multi-region CloudTrail trails found'}
        
        return {'status': 'PASS', 'message': f'CloudTrail enabled with {len(multi_region_trails)} multi-region trail(s)'}
    except Exception as e:
        return {'status': 'ERROR', 'message': str(e)}

def check_cloudtrail_s3_encryption(client):
    """Check if CloudTrail logs are encrypted in S3."""
    try:
        response = client.describe_trails(includeShadowTrails=True)
        for trail in response['trailList']:
            if not trail.get('KMSKeyId'):
                return {'status': 'FAIL', 'message': f'Trail {trail["Name"]} is not using KMS encryption'}
        
        return {'status': 'PASS', 'message': 'All CloudTrail logs are encrypted with KMS'}
    except Exception as e:
        return {'status': 'ERROR', 'message': str(e)}

def check_cloudtrail_log_validation(client):
    """Check if CloudTrail log file validation is enabled."""
    try:
        response = client.describe_trails(includeShadowTrails=True)
        invalid_trails = [t for t in response['trailList'] if not t.get('LogFileValidationEnabled')]
        
        if invalid_trails:
            return {'status': 'FAIL', 'message': f'{len(invalid_trails)} trail(s) without log file validation'}
        
        return {'status': 'PASS', 'message': 'Log file validation enabled on all trails'}
    except Exception as e:
        return {'status': 'ERROR', 'message': str(e)}
