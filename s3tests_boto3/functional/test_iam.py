import json
from nose.tools import eq_ as eq

from botocore.exceptions import ClientError
from nose.plugins.attrib import attr

from s3tests.functional.utils import assert_raises
from . import (
    get_tenant_iam_client,
    get_client,
    get_tenant_user_id,
    get_new_bucket,
    get_new_bucket_resource,
    )
from .utils import _get_status
from .utils import _get_status_and_error_code


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
            "Version": "2012-10-17",
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
        else:
            continue
    if not bucket_listed:
        raise AssertionError("bucket is not listed")

    s3_client.delete_bucket(Bucket=bucket)
    response = s3_client.list_buckets()
    bucket_listed = False
    for index in range(len(response['Buckets'])):
        if bucket == response['Buckets'][index]['Name']:
            bucket_listed = True
            break
        else:
            continue
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
    policy_document_allow = json.dumps(
        {"Version": "2012-10-17",
         "Statement": {
             "Effect": "Deny",
             "Action": ["s3:ListAllMyBuckets", "s3:DeleteBucket"],
             "Resource": "arn:aws:s3:::*"}}
    )

    client.put_user_policy(PolicyDocument=policy_document_allow, PolicyName='DenyAccessPolicy',
                           UserName=get_tenant_user_id())
    s3_client = get_client()

    e = assert_raises(ClientError, s3_client.list_buckets, Bucket=bucket)
    status = _get_status(e.response)
    eq(status, 403)
    e = assert_raises(ClientError, s3_client.delete_bucket, Bucket=bucket)
    status = _get_status(e.response)
    eq(status, 403)
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
        print("decode")
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

    policy_document_allow = json.dumps(
        {"Version": "2012-10-17",
         "Statement": {
             "Effect": "Deny",
             "Action": ["s3:PutObject", "s3:GetObject", "s3:DeleteObject"],
             "Resource": f"arn:aws:s3:::{bucket}/*"}}
    )
    client.put_user_policy(PolicyDocument=policy_document_allow, PolicyName='AllowAccessPolicy',
                           UserName=get_tenant_user_id())

    s3_client = get_client()
    e = assert_raises(ClientError, s3_client.put_object, Bucket=bucket, Key='foo')
    status = _get_status(e.response)
    eq(status, 403)
    e = assert_raises(ClientError, s3_client.get_object, Bucket=bucket, Key='foo')
    status = _get_status(e.response)
    eq(status, 403)
    e = assert_raises(ClientError, s3_client.delete_object, Bucket=bucket, Key='foo')
    status = _get_status(e.response)
    eq(status, 403)

    s3_client.delete_bucket(Bucket=bucket)
    client.delete_user_policy(PolicyName='AllowAccessPolicy', UserName=get_tenant_user_id())
