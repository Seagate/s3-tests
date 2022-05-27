import json

from botocore.exceptions import ClientError
from nose.plugins.attrib import attr
from nose.tools import eq_ as eq

from s3tests.functional.utils import assert_raises
from s3tests_boto3.functional.test_s3 import _multipart_upload
from . import (
    get_tenant_iam_client,
    get_client,
    get_tenant_user_id,
    get_new_bucket,
)
from .utils import _get_status, _get_status_and_error_code


@attr(resource='user-policy')
@attr(method='put')
@attr(operation='Verify Put User Policy')
@attr(assertion='succeeds')
@attr('user-policy')
def test_put_user_policy():
    client = get_tenant_iam_client()

    policy_document = json.dumps(
        {"Version": "2012-10-17",
         "Statement": {
             "Effect": "Allow",
             "Action": "*",
             "Resource": "*"}}
    )
    client.put_user_policy(PolicyDocument=policy_document, PolicyName='AllAccessPolicy',
                           UserName=get_tenant_user_id())
    client.delete_user_policy(PolicyName='AllAccessPolicy', UserName=get_tenant_user_id())


@attr(resource='user-policy')
@attr(method='put')
@attr(operation='Verify Put User Policy with invalid user')
@attr(assertion='succeeds')
@attr('user-policy')
def test_put_user_policy_invalid_user():
    client = get_tenant_iam_client()

    policy_document = json.dumps(
        {"Version": "2012-10-17",
         "Statement": {
             "Effect": "Allow",
             "Action": "*",
             "Resource": "*"}}
    )
    e = assert_raises(ClientError, client.put_user_policy, PolicyDocument=policy_document,
                      PolicyName='AllAccessPolicy', UserName="some-non-existing-user-id")
    status = _get_status(e.response)
    eq(status, 404)


@attr(resource='user-policy')
@attr(method='put')
@attr(operation='Verify Put User Policy using parameter value outside limit')
@attr(assertion='succeeds')
@attr('user-policy')
def test_put_user_policy_parameter_limit():
    client = get_tenant_iam_client()

    policy_document = json.dumps(
        {"Version": "2012-10-17",
         "Statement": [{
             "Effect": "Allow",
             "Action": "*",
             "Resource": "*"}] * 1000
         }
    )
    e = assert_raises(ClientError, client.put_user_policy, PolicyDocument=policy_document,
                      PolicyName='AllAccessPolicy' * 10, UserName=get_tenant_user_id())
    status = _get_status(e.response)
    eq(status, 400)


@attr(resource='user-policy')
@attr(method='put')
@attr(operation='Verify Put User Policy using invalid policy document elements')
@attr(assertion='succeeds')
@attr('user-policy')
def test_put_user_policy_invalid_element():
    client = get_tenant_iam_client()

    # With Version other than 2012-10-17
    policy_document = json.dumps(
        {"Version": "2010-10-17",
         "Statement": [{
             "Effect": "Allow",
             "Action": "*",
             "Resource": "*"}]
         }
    )
    e = assert_raises(ClientError, client.put_user_policy, PolicyDocument=policy_document,
                      PolicyName='AllAccessPolicy', UserName=get_tenant_user_id())
    status = _get_status(e.response)
    eq(status, 400)

    # With no Statement
    policy_document = json.dumps(
        {
            "Version": "2012-10-17"
        }
    )
    e = assert_raises(ClientError, client.put_user_policy, PolicyDocument=policy_document,
                      PolicyName='AllAccessPolicy', UserName=get_tenant_user_id())
    status = _get_status(e.response)
    eq(status, 400)

    # with same Sid for 2 statements
    policy_document = json.dumps(
        {"Version": "2012-10-17",
         "Statement": [
             {"Sid": "98AB54CF",
              "Effect": "Allow",
              "Action": "*",
              "Resource": "*"},
             {"Sid": "98AB54CF",
              "Effect": "Allow",
              "Action": "*",
              "Resource": "*"}]
         }
    )
    e = assert_raises(ClientError, client.put_user_policy, PolicyDocument=policy_document,
                      PolicyName='AllAccessPolicy', UserName=get_tenant_user_id())
    status = _get_status(e.response)
    eq(status, 400)

    # with Principal
    policy_document = json.dumps(
        {"Version": "2012-10-17",
         "Statement": [{
             "Effect": "Allow",
             "Action": "*",
             "Resource": "*",
             "Principal": "arn:aws:iam:::username"}]
         }
    )
    e = assert_raises(ClientError, client.put_user_policy, PolicyDocument=policy_document,
                      PolicyName='AllAccessPolicy', UserName=get_tenant_user_id())
    status = _get_status(e.response)
    eq(status, 400)


@attr(resource='user-policy')
@attr(method='put')
@attr(operation='Verify Put a policy that already exists')
@attr(assertion='succeeds')
@attr('user-policy')
def test_put_existing_user_policy():
    client = get_tenant_iam_client()

    policy_document = json.dumps(
        {"Version": "2012-10-17",
         "Statement": {
             "Effect": "Allow",
             "Action": "*",
             "Resource": "*"}
         }
    )
    client.put_user_policy(PolicyDocument=policy_document, PolicyName='AllAccessPolicy',
                           UserName=get_tenant_user_id())
    client.put_user_policy(PolicyDocument=policy_document, PolicyName='AllAccessPolicy',
                           UserName=get_tenant_user_id())
    client.delete_user_policy(PolicyName='AllAccessPolicy', UserName=get_tenant_user_id())


@attr(resource='user-policy')
@attr(method='put')
@attr(operation='Verify List User policies')
@attr(assertion='succeeds')
@attr('user-policy')
def test_list_user_policy():
    client = get_tenant_iam_client()

    policy_document = json.dumps(
        {"Version": "2012-10-17",
         "Statement": {
             "Effect": "Allow",
             "Action": "*",
             "Resource": "*"}
         }
    )
    client.put_user_policy(PolicyDocument=policy_document, PolicyName='AllAccessPolicy',
                           UserName=get_tenant_user_id())
    response = client.list_user_policies(UserName=get_tenant_user_id())
    eq("AllAccessPolicy" in response["PolicyNames"], True)
    client.delete_user_policy(PolicyName='AllAccessPolicy', UserName=get_tenant_user_id())


@attr(resource='user-policy')
@attr(method='put')
@attr(operation='Verify List User policies with invalid user')
@attr(assertion='succeeds')
@attr('user-policy')
def test_list_user_policy_invalid_user():
    client = get_tenant_iam_client()
    e = assert_raises(ClientError, client.list_user_policies, UserName="some-non-existing-user-id")
    status = _get_status(e.response)
    eq(status, 404)


@attr(resource='user-policy')
@attr(method='get')
@attr(operation='Verify Get User policy')
@attr(assertion='succeeds')
@attr('user-policy')
def test_get_user_policy():
    client = get_tenant_iam_client()

    policy_document = json.dumps(
        {"Version": "2012-10-17",
         "Statement": {
             "Effect": "Allow",
             "Action": "*",
             "Resource": "*"}}
    )
    client.put_user_policy(PolicyDocument=policy_document, PolicyName='AllAccessPolicy',
                           UserName=get_tenant_user_id())
    client.get_user_policy(PolicyName='AllAccessPolicy', UserName=get_tenant_user_id())
    client.delete_user_policy(PolicyName='AllAccessPolicy', UserName=get_tenant_user_id())


@attr(resource='user-policy')
@attr(method='get')
@attr(operation='Verify Get User Policy with invalid user')
@attr(assertion='succeeds')
@attr('user-policy')
def test_get_user_policy_invalid_user():
    client = get_tenant_iam_client()

    policy_document = json.dumps(
        {"Version": "2012-10-17",
         "Statement": {
             "Effect": "Allow",
             "Action": "*",
             "Resource": "*"}}
    )
    client.put_user_policy(PolicyDocument=policy_document, PolicyName='AllAccessPolicy',
                           UserName=get_tenant_user_id())
    e = assert_raises(ClientError, client.get_user_policy, PolicyName='AllAccessPolicy',
                      UserName="some-non-existing-user-id")
    status = _get_status(e.response)
    eq(status, 404)
    client.delete_user_policy(PolicyName='AllAccessPolicy', UserName=get_tenant_user_id())


@attr(resource='user-policy')
@attr(method='get')
@attr(operation='Verify Get User Policy with invalid policy name')
@attr(assertion='succeeds')
@attr('user-policy')
def test_get_user_policy_invalid_policy_name():
    client = get_tenant_iam_client()

    policy_document = json.dumps(
        {"Version": "2012-10-17",
         "Statement": {
             "Effect": "Allow",
             "Action": "*",
             "Resource": "*"}}
    )
    client.put_user_policy(PolicyDocument=policy_document, PolicyName='AllAccessPolicy',
                           UserName=get_tenant_user_id())
    e = assert_raises(ClientError, client.get_user_policy, PolicyName='non-existing-policy-name',
                      UserName=get_tenant_user_id())
    status = _get_status(e.response)
    eq(status, 404)
    client.delete_user_policy(PolicyName='AllAccessPolicy', UserName=get_tenant_user_id())


@attr(resource='user-policy')
@attr(method='get')
@attr(operation='Verify Get Deleted User Policy')
@attr(assertion='succeeds')
@attr('user-policy')
def test_get_deleted_user_policy():
    client = get_tenant_iam_client()

    policy_document = json.dumps(
        {"Version": "2012-10-17",
         "Statement": {
             "Effect": "Allow",
             "Action": "*",
             "Resource": "*"}}
    )
    client.put_user_policy(PolicyDocument=policy_document, PolicyName='AllAccessPolicy',
                           UserName=get_tenant_user_id())
    client.delete_user_policy(PolicyName='AllAccessPolicy', UserName=get_tenant_user_id())
    e = assert_raises(ClientError, client.get_user_policy, PolicyName='AllAccessPolicy',
                      UserName=get_tenant_user_id())
    status = _get_status(e.response)
    eq(status, 404)


@attr(resource='user-policy')
@attr(method='get')
@attr(operation='Verify Get a policy from multiple policies for a user')
@attr(assertion='succeeds')
@attr('user-policy')
def test_get_user_policy_from_multiple_policies():
    client = get_tenant_iam_client()

    policy_document_allow = json.dumps(
        {"Version": "2012-10-17",
         "Statement": {
             "Effect": "Allow",
             "Action": "*",
             "Resource": "*"}}
    )

    client.put_user_policy(PolicyDocument=policy_document_allow, PolicyName='AllowAccessPolicy1',
                           UserName=get_tenant_user_id())
    client.put_user_policy(PolicyDocument=policy_document_allow, PolicyName='AllowAccessPolicy2',
                           UserName=get_tenant_user_id())
    client.get_user_policy(PolicyName='AllowAccessPolicy2', UserName=get_tenant_user_id())
    client.delete_user_policy(PolicyName='AllowAccessPolicy1', UserName=get_tenant_user_id())
    client.delete_user_policy(PolicyName='AllowAccessPolicy2', UserName=get_tenant_user_id())


@attr(resource='user-policy')
@attr(method='delete')
@attr(operation='Verify Delete User Policy')
@attr(assertion='succeeds')
@attr('user-policy')
def test_delete_user_policy():
    client = get_tenant_iam_client()

    policy_document_allow = json.dumps(
        {"Version": "2012-10-17",
         "Statement": {
             "Effect": "Allow",
             "Action": "*",
             "Resource": "*"}}
    )

    client.put_user_policy(PolicyDocument=policy_document_allow, PolicyName='AllowAccessPolicy',
                           UserName=get_tenant_user_id())
    client.delete_user_policy(PolicyName='AllowAccessPolicy', UserName=get_tenant_user_id())


@attr(resource='user-policy')
@attr(method='delete')
@attr(operation='Verify Delete User Policy with invalid user')
@attr(assertion='succeeds')
@attr('user-policy')
def test_delete_user_policy_invalid_user():
    client = get_tenant_iam_client()

    policy_document_allow = json.dumps(
        {"Version": "2012-10-17",
         "Statement": {
             "Effect": "Allow",
             "Action": "*",
             "Resource": "*"}}
    )

    client.put_user_policy(PolicyDocument=policy_document_allow, PolicyName='AllowAccessPolicy',
                           UserName=get_tenant_user_id())
    e = assert_raises(ClientError, client.delete_user_policy, PolicyName='AllAccessPolicy',
                      UserName="some-non-existing-user-id")
    status = _get_status(e.response)
    eq(status, 404)
    client.delete_user_policy(PolicyName='AllowAccessPolicy', UserName=get_tenant_user_id())


@attr(resource='user-policy')
@attr(method='delete')
@attr(operation='Verify Delete User Policy with invalid policy name')
@attr(assertion='succeeds')
@attr('user-policy')
def test_delete_user_policy_invalid_policy_name():
    client = get_tenant_iam_client()

    policy_document_allow = json.dumps(
        {"Version": "2012-10-17",
         "Statement": {
             "Effect": "Allow",
             "Action": "*",
             "Resource": "*"}}
    )

    client.put_user_policy(PolicyDocument=policy_document_allow, PolicyName='AllowAccessPolicy',
                           UserName=get_tenant_user_id())
    e = assert_raises(ClientError, client.delete_user_policy, PolicyName='non-existing-policy-name',
                      UserName=get_tenant_user_id())
    status = _get_status(e.response)
    eq(status, 404)
    client.delete_user_policy(PolicyName='AllowAccessPolicy', UserName=get_tenant_user_id())


@attr(resource='user-policy')
@attr(method='delete')
@attr(operation='Verify Delete multiple User policies for a user')
@attr(assertion='succeeds')
@attr('user-policy')
def test_delete_user_policy_from_multiple_policies():
    client = get_tenant_iam_client()

    policy_document_allow = json.dumps(
        {"Version": "2012-10-17",
         "Statement": {
             "Effect": "Allow",
             "Action": "*",
             "Resource": "*"}}
    )

    client.put_user_policy(PolicyDocument=policy_document_allow, PolicyName='AllowAccessPolicy1',
                           UserName=get_tenant_user_id())
    client.put_user_policy(PolicyDocument=policy_document_allow, PolicyName='AllowAccessPolicy2',
                           UserName=get_tenant_user_id())
    client.put_user_policy(PolicyDocument=policy_document_allow, PolicyName='AllowAccessPolicy3',
                           UserName=get_tenant_user_id())
    client.delete_user_policy(PolicyName='AllowAccessPolicy1', UserName=get_tenant_user_id())
    client.delete_user_policy(PolicyName='AllowAccessPolicy2', UserName=get_tenant_user_id())
    client.get_user_policy(PolicyName='AllowAccessPolicy3', UserName=get_tenant_user_id())
    client.delete_user_policy(PolicyName='AllowAccessPolicy3', UserName=get_tenant_user_id())


@attr(resource='user-policy')
@attr(method='s3 Actions')
@attr(operation='Verify Allow Bucket Actions in user Policy')
@attr(assertion='succeeds')
@attr('user-policy')
def test_allow_bucket_actions_in_user_policy():
    client = get_tenant_iam_client()
    bucket = get_new_bucket()
    bucket_listed = False

    policy_document_allow = json.dumps(
        {"Version": "2012-10-17",
         "Statement": {
             "Effect": "Allow",
             "Action": ["s3:ListAllMyBuckets", "s3:DeleteBucket"],
             "Resource": "arn:aws:s3:::*"}}
    )
    client.put_user_policy(PolicyDocument=policy_document_allow, PolicyName='AllowAccessPolicy',
                           UserName=get_tenant_user_id())
    s3_client = get_client()
    response = s3_client.list_buckets()
    for index in range(len(response['Buckets'])):
        if bucket == response['Buckets'][index]['Name']:
            bucket_listed = True
            break
    if not bucket_listed:
        raise AssertionError("bucket is not listed")

    s3_client.delete_bucket(Bucket=bucket)
    response = s3_client.list_buckets()
    bucket_listed = False
    for index in range(len(response['Buckets'])):
        if bucket == response['Buckets'][index]['Name']:
            bucket_listed = True
            break
    if bucket_listed:
        raise AssertionError("deleted bucket is getting listed")
    client.delete_user_policy(PolicyName='AllowAccessPolicy', UserName=get_tenant_user_id())


@attr(resource='user-policy')
@attr(method='s3 Actions')
@attr(operation='Verify Deny Bucket Actions in user Policy')
@attr(assertion='succeeds')
@attr('user-policy')
def test_deny_bucket_actions_in_user_policy():
    client = get_tenant_iam_client()
    bucket = get_new_bucket()
    policy_document_deny = json.dumps(
        {"Version": "2012-10-17",
         "Statement": {
             "Effect": "Deny",
             "Action": ["s3:ListAllMyBuckets", "s3:DeleteBucket"],
             "Resource": "arn:aws:s3:::*"}}
    )

    client.put_user_policy(PolicyDocument=policy_document_deny, PolicyName='DenyAccessPolicy',
                           UserName=get_tenant_user_id())
    s3_client = get_client()

    e = assert_raises(ClientError, s3_client.list_buckets, Bucket=bucket)
    status, error_code = _get_status_and_error_code(e.response)
    eq(status, 403)
    eq(error_code, 'AccessDenied')
    e = assert_raises(ClientError, s3_client.delete_bucket, Bucket=bucket)
    status, error_code = _get_status_and_error_code(e.response)
    eq(status, 403)
    eq(error_code, 'AccessDenied')
    client.delete_user_policy(PolicyName='DenyAccessPolicy', UserName=get_tenant_user_id())
    s3_client.delete_bucket(Bucket=bucket)


@attr(resource='user-policy')
@attr(method='s3 Actions')
@attr(operation='Verify Allow Object Actions in user Policy')
@attr(assertion='succeeds')
@attr('user-policy')
def test_allow_object_actions_in_user_policy():
    client = get_tenant_iam_client()
    bucket = get_new_bucket()

    policy_document_allow = json.dumps(
        {"Version": "2012-10-17",
         "Statement": {
             "Effect": "Allow",
             "Action": ["s3:PutObject", "s3:GetObject", "s3:DeleteObject"],
             "Resource": f"arn:aws:s3:::{bucket}/*"}}
    )
    client.put_user_policy(PolicyDocument=policy_document_allow, PolicyName='AllowAccessPolicy',
                           UserName=get_tenant_user_id())

    s3_client = get_client()
    s3_client.put_object(Bucket=bucket, Key='foo', Body='bar')
    response = s3_client.get_object(Bucket=bucket, Key='foo')
    body = response['Body'].read()
    if type(body) is bytes:
        body = body.decode()
    eq(body, "bar")
    s3_client.delete_object(Bucket=bucket, Key='foo')
    e = assert_raises(ClientError, s3_client.get_object, Bucket=bucket, Key='foo')
    status, error_code = _get_status_and_error_code(e.response)
    eq(status, 404)
    eq(error_code, 'NoSuchKey')
    s3_client.delete_bucket(Bucket=bucket)
    client.delete_user_policy(PolicyName='AllowAccessPolicy', UserName=get_tenant_user_id())


@attr(resource='user-policy')
@attr(method='s3 Actions')
@attr(operation='Verify Deny Object Actions in user Policy')
@attr(assertion='succeeds')
@attr('user-policy')
def test_deny_object_actions_in_user_policy():
    client = get_tenant_iam_client()
    bucket = get_new_bucket()

    policy_document_deny = json.dumps(
        {"Version": "2012-10-17",
         "Statement": {
             "Effect": "Deny",
             "Action": ["s3:PutObject", "s3:GetObject", "s3:DeleteObject"],
             "Resource": f"arn:aws:s3:::{bucket}/*"}}
    )
    client.put_user_policy(PolicyDocument=policy_document_deny, PolicyName='DenyAccessPolicy',
                           UserName=get_tenant_user_id())

    s3_client = get_client()
    e = assert_raises(ClientError, s3_client.put_object, Bucket=bucket, Key='foo')
    status, error_code = _get_status_and_error_code(e.response)
    eq(status, 403)
    eq(error_code, 'AccessDenied')
    e = assert_raises(ClientError, s3_client.get_object, Bucket=bucket, Key='foo')
    status, error_code = _get_status_and_error_code(e.response)
    eq(status, 403)
    eq(error_code, 'AccessDenied')
    e = assert_raises(ClientError, s3_client.delete_object, Bucket=bucket, Key='foo')
    status, error_code = _get_status_and_error_code(e.response)
    eq(status, 403)
    eq(error_code, 'AccessDenied')
    s3_client.delete_bucket(Bucket=bucket)
    client.delete_user_policy(PolicyName='DenyAccessPolicy', UserName=get_tenant_user_id())


@attr(resource='user-policy')
@attr(method='s3 Actions')
@attr(operation='Verify Allow Multipart Actions in user Policy')
@attr(assertion='succeeds')
@attr('user-policy')
def test_allow_multipart_actions_in_user_policy():
    client = get_tenant_iam_client()
    bucket = get_new_bucket()

    policy_document_allow = json.dumps(
        {"Version": "2012-10-17",
         "Statement": {
             "Effect": "Allow",
             "Action": ["s3:ListBucketMultipartUploads", "s3:AbortMultipartUpload"],
             "Resource": "arn:aws:s3:::*"}}
    )
    client.put_user_policy(PolicyDocument=policy_document_allow, PolicyName='AllowAccessPolicy',
                           UserName=get_tenant_user_id())
    key = "mymultipart"
    mb = 1024 * 1024
    s3_client = get_client()

    (upload_id, _, _) = _multipart_upload(bucket_name=bucket, key=key, size=5 * mb)
    s3_client.list_multipart_uploads(Bucket=bucket)
    s3_client.abort_multipart_upload(Bucket=bucket, Key=key, UploadId=upload_id)

    s3_client.delete_bucket(Bucket=bucket)
    client.delete_user_policy(PolicyName='AllowAccessPolicy', UserName=get_tenant_user_id())


@attr(resource='user-policy')
@attr(method='s3 Actions')
@attr(operation='Verify Deny Multipart Actions in user Policy')
@attr(assertion='succeeds')
@attr('user-policy')
def test_deny_multipart_actions_in_user_policy():
    client = get_tenant_iam_client()
    bucket = get_new_bucket()

    policy_document_deny = json.dumps(
        {"Version": "2012-10-17",
         "Statement": {
             "Effect": "Deny",
             "Action": ["s3:ListBucketMultipartUploads", "s3:AbortMultipartUpload"],
             "Resource": "arn:aws:s3:::*"}}
    )
    client.put_user_policy(PolicyDocument=policy_document_deny, PolicyName='DenyAccessPolicy',
                           UserName=get_tenant_user_id())
    key = "mymultipart"
    mb = 1024 * 1024
    s3_client = get_client()
    (upload_id, _, _) = _multipart_upload(bucket_name=bucket, key=key, size=5 * mb)

    e = assert_raises(ClientError, s3_client.list_multipart_uploads, Bucket=bucket)
    status, error_code = _get_status_and_error_code(e.response)
    eq(status, 403)
    eq(error_code, 'AccessDenied')

    e = assert_raises(ClientError, s3_client.abort_multipart_upload, Bucket=bucket,
                      Key=key, UploadId=upload_id)
    status, error_code = _get_status_and_error_code(e.response)
    eq(status, 403)
    eq(error_code, 'AccessDenied')

    s3_client.delete_bucket(Bucket=bucket)
    client.delete_user_policy(PolicyName='DenyAccessPolicy', UserName=get_tenant_user_id())


@attr(resource='user-policy')
@attr(method='s3 Actions')
@attr(operation='Verify Allow Tagging Actions in user Policy')
@attr(assertion='succeeds')
@attr('user-policy')
def test_allow_tagging_actions_in_user_policy():
    client = get_tenant_iam_client()
    bucket = get_new_bucket()

    policy_document_allow = json.dumps(
        {"Version": "2012-10-17",
         "Statement": {
             "Effect": "Allow",
             "Action": ["s3:PutBucketTagging", "s3:GetBucketTagging",
                        "s3:PutObjectTagging", "s3:GetObjectTagging"],
             "Resource": f"arn:aws:s3:::*"}}
    )
    client.put_user_policy(PolicyDocument=policy_document_allow, PolicyName='AllowAccessPolicy',
                           UserName=get_tenant_user_id())
    tags = {'TagSet': [{'Key': 'Hello', 'Value': 'World'}, ]}

    s3_client = get_client()
    s3_client.put_bucket_tagging(Bucket=bucket, Tagging=tags)
    response = s3_client.get_bucket_tagging(Bucket=bucket)
    eq(response['TagSet'][0]['Key'], 'Hello')
    eq(response['TagSet'][0]['Value'], 'World')

    obj_key = 'obj'
    s3_client.put_object(Bucket=bucket, Key=obj_key, Body='obj_body')
    s3_client.put_object_tagging(Bucket=bucket, Key=obj_key, Tagging=tags)
    response = s3_client.get_object_tagging(Bucket=bucket, Key=obj_key)
    eq(response['TagSet'], tags['TagSet'])

    s3_client.delete_object(Bucket=bucket, Key=obj_key)
    s3_client.delete_bucket(Bucket=bucket)
    client.delete_user_policy(PolicyName='AllowAccessPolicy', UserName=get_tenant_user_id())


@attr(resource='user-policy')
@attr(method='s3 Actions')
@attr(operation='Verify Deny Tagging Actions in user Policy')
@attr(assertion='succeeds')
@attr('user-policy')
def test_deny_tagging_actions_in_user_policy():
    client = get_tenant_iam_client()
    bucket = get_new_bucket()

    policy_document_deny = json.dumps(
        {"Version": "2012-10-17",
         "Statement": {
             "Effect": "Deny",
             "Action": ["s3:PutBucketTagging", "s3:GetBucketTagging",
                        "s3:PutObjectTagging", "s3:DeleteObjectTagging"],
             "Resource": "arn:aws:s3:::*"}}
    )
    client.put_user_policy(PolicyDocument=policy_document_deny, PolicyName='DenyAccessPolicy',
                           UserName=get_tenant_user_id())
    tags = {'TagSet': [{'Key': 'Hello', 'Value': 'World'}, ]}

    s3_client = get_client()
    e = assert_raises(ClientError, s3_client.put_bucket_tagging, Bucket=bucket, Tagging=tags)
    status, error_code = _get_status_and_error_code(e.response)
    eq(status, 403)
    eq(error_code, 'AccessDenied')
    e = assert_raises(ClientError, s3_client.get_bucket_tagging, Bucket=bucket)
    status, error_code = _get_status_and_error_code(e.response)
    eq(status, 403)
    eq(error_code, 'AccessDenied')

    obj_key = 'obj'
    s3_client.put_object(Bucket=bucket, Key=obj_key, Body='obj_body')

    e = assert_raises(ClientError, s3_client.put_object_tagging, Bucket=bucket, Key=obj_key,
                      Tagging=tags)
    status, error_code = _get_status_and_error_code(e.response)
    eq(status, 403)
    eq(error_code, 'AccessDenied')
    e = assert_raises(ClientError, s3_client.delete_object_tagging, Bucket=bucket, Key=obj_key)
    status, error_code = _get_status_and_error_code(e.response)
    eq(status, 403)
    eq(error_code, 'AccessDenied')

    s3_client.delete_object(Bucket=bucket, Key=obj_key)
    s3_client.delete_bucket(Bucket=bucket)
    client.delete_user_policy(PolicyName='DenyAccessPolicy', UserName=get_tenant_user_id())


@attr(resource='user-policy')
@attr(method='put')
@attr(operation='Verify conflicting user policy statements')
@attr(assertion='succeeds')
@attr('user-policy')
def test_verify_conflicting_user_policy_statements():
    s3client = get_client()
    bucket = get_new_bucket()
    policy_document = json.dumps(
        {"Version": "2012-10-17",
         "Statement": [
             {"Sid": "98AB54CG",
              "Effect": "Allow",
              "Action": "s3:ListBucket",
              "Resource": f"arn:aws:s3:::{bucket}"},
             {"Sid": "98AB54CA",
              "Effect": "Deny",
              "Action": "s3:ListBucket",
              "Resource": f"arn:aws:s3:::{bucket}"}
         ]}
    )
    client = get_tenant_iam_client()
    client.put_user_policy(PolicyDocument=policy_document, PolicyName='DenyAccessPolicy',
                           UserName=get_tenant_user_id())
    e = assert_raises(ClientError, s3client.list_objects, Bucket=bucket)
    status, error_code = _get_status_and_error_code(e.response)
    eq(status, 403)
    eq(error_code, 'AccessDenied')
    client.delete_user_policy(PolicyName='DenyAccessPolicy', UserName=get_tenant_user_id())


@attr(resource='user-policy')
@attr(method='put')
@attr(operation='Verify conflicting user policies')
@attr(assertion='succeeds')
@attr('user-policy')
def test_verify_conflicting_user_policies():
    s3client = get_client()
    bucket = get_new_bucket()
    policy_allow = json.dumps(
        {"Version": "2012-10-17",
         "Statement": {"Sid": "98AB54CG",
                       "Effect": "Allow",
                       "Action": "s3:ListBucket",
                       "Resource": f"arn:aws:s3:::{bucket}"}}
    )
    policy_deny = json.dumps(
        {"Version": "2012-10-17",
         "Statement": {"Sid": "98AB54CGZ",
                       "Effect": "Deny",
                       "Action": "s3:ListBucket",
                       "Resource": f"arn:aws:s3:::{bucket}"}}
    )
    client = get_tenant_iam_client()
    client.put_user_policy(PolicyDocument=policy_allow, PolicyName='AllowAccessPolicy',
                           UserName=get_tenant_user_id())
    client.put_user_policy(PolicyDocument=policy_deny, PolicyName='DenyAccessPolicy',
                           UserName=get_tenant_user_id())
    e = assert_raises(ClientError, s3client.list_objects, Bucket=bucket)
    status, error_code = _get_status_and_error_code(e.response)
    eq(status, 403)
    eq(error_code, 'AccessDenied')
    client.delete_user_policy(PolicyName='AllowAccessPolicy', UserName=get_tenant_user_id())
    client.delete_user_policy(PolicyName='DenyAccessPolicy', UserName=get_tenant_user_id())


@attr(resource='user-policy')
@attr(operation='Verify Allow Actions for IAM user policies')
@attr(assertion='succeeds')
@attr('user-policy')
def test_verify_allow_iam_actions():
    policy1 = json.dumps(
        {"Version": "2012-10-17",
         "Statement": {"Sid": "98AB54CGA",
                       "Effect": "Allow",
                       "Action": ["iam:PutUserPolicy", "iam:GetUserPolicy",
                                  "iam:ListUserPolicies", "iam:DeleteUserPolicy"],
                       "Resource": f"arn:aws:iam:::user/{get_tenant_user_id()}"}}
    )
    client1 = get_tenant_iam_client()

    client1.put_user_policy(PolicyDocument=policy1, PolicyName='AllowAccessPolicy',
                            UserName=get_tenant_user_id())
    client1.get_user_policy(PolicyName='AllowAccessPolicy', UserName=get_tenant_user_id())
    client1.list_user_policies(UserName=get_tenant_user_id())
    client1.delete_user_policy(PolicyName='AllowAccessPolicy', UserName=get_tenant_user_id())
