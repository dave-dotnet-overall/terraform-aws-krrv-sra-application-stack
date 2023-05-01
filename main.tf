# --------------------------------------------------------------------------------------------------
# ACCOUNT STACKSET FOR APP ACCOUNTS
# --------------------------------------------------------------------------------------------------
terraform {
  # This module is now only being tested with Terraform 1.1.x. However, to make upgrading easier, we are setting 1.0.0 as the minimum version.
  required_version = ">= 1.4.4"
  
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 4.61.0"
      configuration_aliases = [
        aws.af_south_1,
        aws.ap_east_1,
        aws.ap_northeast_1,
        aws.ap_northeast_2,
        aws.ap_northeast_3,
        aws.ap_south_1,
        aws.ap_southeast_1,
        aws.ap_southeast_2,
        aws.ap_southeast_3,
        aws.ca_central_1,
        aws.cn_north_1,
        aws.cn_northwest_1,
        aws.eu_central_1,
        aws.eu_north_1,
        aws.eu_south_1,
        aws.eu_west_1,
        aws.eu_west_2,
        aws.eu_west_3,
        aws.me_south_1,
        aws.sa_east_1,
        aws.us_east_1,
        aws.us_east_2,
        aws.us_west_1,
        aws.us_west_2,
      ]
    }
  }
}

data "aws_caller_identity" "current" {
  provider = aws.me_south_1
}

# ----------------------------------------------------------------------------------------------------
# CONFIGURE LOCAL CLOUDTRAIL
# ----------------------------------------------------------------------------------------------------
module "cloudtrail" {
  source = "../krrv-sra-cloudtrail"

  # kms_key_deletion_window_in_days                 = 15
  # sns_delivery_topic                              = null

  # ----------------------------------------------------------------------------------------------------
  # REQUIRED VARIABLES
  # ----------------------------------------------------------------------------------------------------

  # If true, an IAM Policy that grants access to CloudTrail will be honored. If
  # false, only the ARNs listed in var.kms_key_user_iam_arns will have access to
  # CloudTrail and any IAM Policy grants will be ignored. (true or false)
  allow_cloudtrail_access_with_iam = var.allow_cloudtrail_access_with_iam

  # The name of the S3 Bucket where CloudTrail logs will be stored.
  s3_bucket_name = var.cloudtrail_s3_bucket_name

  # ----------------------------------------------------------------------------------------------------
  # OPTIONAL VARIABLES
  # ----------------------------------------------------------------------------------------------------

  # The S3 bucket where access logs for this bucket should be stored. Only used if
  # access_logging_enabled is true.
  access_logging_bucket = null

  # access_logging_enabled is true.

  # A prefix (i.e., folder path) to use for all access logs stored in
  # access_logging_bucket. Only used if access_logging_enabled is true.
  access_logging_prefix = null

  # Additional IAM policies to apply to the Cloudtrail S3 bucket. You can use this
  # to grant read/write access beyond what is provided to Cloudtrail. This should be
  # a map, where each key is a unique statement ID (SID), and each value is an
  # object that contains the parameters defined in the comment below.
  additional_bucket_policy_statements = null

  # Map of advanced event selector name to list of field selectors to apply for that
  # event selector. Advanced event selectors allow for more fine grained data
  # logging of events.

  # Note that you can not configure basic data logging
  # (var.data_logging_enabled) if advanced event logging is enabled.

  # Refer to the
  # AWS docs on data event selection for more details on the difference between
  # basic data logging and advanced data logging.

  advanced_event_selectors = {}

  # Whether or not to allow kms:DescribeKey to external AWS accounts with write
  # access to the bucket. This is useful during deployment so that you don't have to
  # pass around the KMS key ARN.
  allow_kms_describe_key_to_external_aws_accounts = var.cloudtrail_allow_kms_describe_key_to_external_aws_accounts

  # Optional whether or not to use Amazon S3 Bucket Keys for SSE-KMS.
  bucket_key_enabled = var.cloudtrail_s3_bucket_key_enabled

  # If defined, uses this value as the name of the CloudTrail IAM role. If not
  # defined, and cloudwatch_logs_group_name is defined, uses that name for the role.
  # If cloudwatch_logs_group_name is not defined, this resource is not created.
  # cloudtrail_iam_role_name = null not set so the logs group name is used

  # The ARN of the policy that is used to set the permissions boundary for the IAM
  # role.
  cloudtrail_iam_role_permissions_boundary = var.cloudtrail_iam_role_permissions_boundary

  # The name to assign to the CloudTrail 'trail' that will be used to track all API
  # calls in your AWS account.
  cloudtrail_trail_name = "full-account"

  # If defined, creates a CloudWatch Logs group with the specified name and
  # configures the trail to publish logs to the group. If undefined, cloudwatch logs
  # group is not created.
  cloudwatch_logs_group_name = var.cloudtrail_cloudwatch_logs_group_name

  # Set to false to have this module skip creating resources. This weird parameter
  # exists solely because Terraform does not support conditional modules. Therefore,
  # this is a hack to allow you to conditionally decide if the resources in this
  # module should be created or not.
  # create_resources = true

  # If true, logging of data events will be enabled.
  data_logging_enabled = var.cloudtrail_data_logging_enabled

  # Specify if you want your event selector to include management events for your
  # trail.
  data_logging_include_management_events = var.cloudtrail_data_logging_include_management_events

  # Specify if you want your trail to log read-only events, write-only events, or
  # all. Possible values are: ReadOnly, WriteOnly, All.
  data_logging_read_write_type = var.cloudtrail_data_logging_read_write_type

  # Data resources for which to log data events. This should be a map, where each
  # key is a data resource type, and each value is a list of data resource values.
  # Possible values for data resource types are: AWS::S3::Object,
  # AWS::Lambda::Function and AWS::DynamoDB::Table. See the 'data_resource' block
  # within the 'event_selector' block of the 'aws_cloudtrail' resource for context:
  # https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/clou
  # trail#data_resource.
  data_logging_resources = var.cloudtrail_data_logging_resources

  # Create a dependency between the resources in this module to the interpolated
  # values in this list (and thus the source resources). In other words, the
  # resources in this module will now depend on the resources backing the values in
  # this list such that those resources need to be created before the resources in
  # this module, and the resources in this module need to be destroyed before the
  # resources in the list.
  # dependencies = []

  # Enables logging for the trail. Setting this to false will pause logging. (true
  # or false)
  enable_cloudtrail = var.enable_cloudtrail

  # Whether or not to enable automatic annual rotation of the KMS key. Defaults to
  # true.
  enable_key_rotation = true

  # Enables S3 server access logging which sends detailed records for the requests
  # that are made to the bucket. Defaults to false.
  enable_s3_server_access_logging = false

  # A list of external AWS accounts that should be given write access for CloudTrail
  # logs to this S3 bucket. This is useful when aggregating CloudTrail logs for
  # multiple AWS accounts in one common S3 bucket.
  external_aws_account_ids_with_write_access = var.cloudtrail_external_aws_account_ids_with_write_access

  # If set to true, when you run 'terraform destroy', delete all objects from the
  # bucket so that the bucket can be destroyed without error. Warning: these objects
  # are not recoverable so only use this if you're absolutely sure you want to
  # permanently delete everything!
  force_destroy = var.cloudtrail_force_destroy

  # Type of insights to log on a trail. Valid values are: ApiCallRateInsight and
  # ApiErrorRateInsight.
  insight_selector = []

  # Specifies whether CloudTrail will log only API calls in the current region or in
  # all regions. (true or false)
  is_multi_region_trail = true

  # Specifies whether the trail is an AWS Organizations trail. Organization trails
  # log events for the root account and all member accounts. Can only be created in
  # the organization root account. (true or false)
  is_organization_trail = false

  # All CloudTrail Logs will be encrypted with a KMS Key (a Customer Master Key)
  # that governs access to write API calls older than 7 days and all read API calls.
  # The IAM Users specified in this list will have rights to change who can access
  # this extended log data. This is optional if allow_cloudtrail_access_with_iam is
  # true, otherwise it is required.
  kms_key_administrator_iam_arns = var.cloudtrail_kms_key_administrator_iam_arns

  # If set to true, that means the KMS key you're using already exists, and does not
  # need to be created.
  kms_key_already_exists = false

  # If you wish to specify a custom KMS key, then specify the key arn using this
  # variable. This is especially useful when using CloudTrail with multiple AWS
  # accounts, so the logs are all encrypted using the same key.
  kms_key_arn = var.cloudtrail_kms_key_arn

  # If the kms_key_arn provided is an alias or alias ARN, then this must be set to
  # true so that the module will exchange the alias for a CMK ARN. Setting this to
  # true and using aliases requires
  # var.allow_kms_describe_key_to_external_aws_accounts to also be true for
  # multi-account scenarios.
  kms_key_arn_is_alias = var.cloudtrail_kms_key_arn_is_alias

  # The number of days to keep this KMS Key (a Customer Master Key) around after it
  # has been marked for deletion.
  kms_key_deletion_window_in_days = 15

  # Additional service principals beyond CloudTrail that should have access to the
  # KMS key used to encrypt the logs. This is useful for granting access to the logs
  # for the purposes of constructing metric filters.
  kms_key_service_principals = var.cloudtrail_kms_key_service_principals

  # All CloudTrail Logs will be encrypted with a KMS Key (a Customer Master Key)
  # that governs access to write API calls older than 7 days and all read API calls.
  # The IAM Users specified in this list will have read-only access to this extended
  # log data.
  kms_key_user_iam_arns = var.cloudtrail_kms_key_user_iam_arns

  # After this number of days, log files should be transitioned from S3 to Glacier.
  # Enter 0 to never archive log data.
  num_days_after_which_archive_log_data = var.cloudtrail_num_days_after_which_archive_log_data

  # After this number of days, log files should be deleted from S3. If null, never
  # delete.
  num_days_after_which_delete_log_data = var.cloudtrail_num_days_after_which_delete_log_data

  # After this number of days, logs stored in CloudWatch will be deleted. Possible
  # values are: 1, 3, 5, 7, 14, 30, 60, 90, 120, 150, 180, 365, 400, 545, 731, 1827,
  # 3653, and 0 (default). When set to 0, logs will be retained indefinitely.
  num_days_to_retain_cloudwatch_logs = var.cloudtrail_num_days_to_retain_cloudwatch_logs

  # The ID of the organization. Required only if an organization wide CloudTrail is
  # being setup. In such a case, this ensures that the entire organization is
  # whitelisted in the CloudTrail bucket write policy.
  organization_id = null

  # Set to true to enable replication for this bucket. You can set the role to use
  # for replication using the replication_role parameter and the rules for
  # replication using the replication_rules parameter.
  # replication_enabled = false

  # The ARN of the IAM role for Amazon S3 to assume when replicating objects. Only
  # used if replication_enabled is set to true.
  # replication_role = null

  # The rules for managing replication. Only used if replication_enabled is set to
  # true. This should be a map, where the key is a unique ID for each replication
  # rule and the value is an object of the form explained in a comment above.
  # replication_rules = {}

  # If set to true, that means the S3 bucket you're using already exists, and does
  # not need to be created. This is especially useful when using CloudTrail with
  # multiple AWS accounts, with a common S3 bucket shared by all of them.
  s3_bucket_already_exists = var.cloudtrail_s3_bucket_already_exists

  # Enable MFA delete for either 'Change the versioning state of your bucket' or
  # 'Permanently delete an object version'. This setting only applies to the bucket
  # used to storage Cloudtrail data. This cannot be used to toggle this setting but
  # is available to allow managed buckets to reflect the state in AWS. For
  # instructions on how to enable MFA Delete, check out the README from the
  # private-s3-bucket module. CIS v1.4 requires this variable to be true. If you do
  # not wish to be CIS-compliant, you can set it to false.
  s3_mfa_delete = var.cloudtrail_s3_mfa_delete

  # SNS topic for S3 log delivery notifications.
  sns_delivery_topic = null

  # A map of tags to apply to the S3 Bucket, CloudTrail KMS Key, and CloudTrail
  # itself. The key is the tag name and the value is the tag value.
  tags = merge(var.cloudtrail_tags, local.tags)

  # When true, all IAM policies will be managed as dedicated policies rather than
  # inline policies attached to the IAM roles. Dedicated managed policies are
  # friendlier to automated policy checkers, which may scan a single resource for
  # findings. As such, it is important to avoid inline policies when targeting
  # compliance with various security standards.
  use_managed_iam_policies = var.use_managed_iam_policies
}
#custom_cloudtrail_trail_name

# ----------------------------------------------------------------------------------------------------
# CREATE ROLES THAT CAN BE ASSUMED IN THIS ACCOUNT
# ----------------------------------------------------------------------------------------------------
module "cross_account_iam_roles" {
  count =var.enable_iam_cross_account_roles?1:0
  source = "../krrv-sra-iam-roles"

  # ----------------------------------------------------------------------------------------------------
  # REQUIRED VARIABLES
  # ----------------------------------------------------------------------------------------------------

  # The ID of the AWS Account.
  aws_account_id = var.aws_account_id

  # Should we require that all IAM Users use Multi-Factor Authentication for both
  # AWS API calls and the AWS Web Console? (true or false)
  should_require_mfa = var.should_require_mfa

  # ----------------------------------------------------------------------------------------------------
  # OPTIONAL VARIABLES
  # ----------------------------------------------------------------------------------------------------

  # A list of IAM ARNs from other AWS accounts that will be allowed full (read and
  # write) access to the billing info for this account.
  allow_billing_access_from_other_account_arns = var.allow_billing_access_from_other_account_arns

  # The ARN of the policy that is used to set the permissions boundary for the IAM
  # role.
  allow_billing_access_iam_role_permissions_boundary = var.allow_billing_access_iam_role_permissions_boundary

  # A list of IAM ARNs from other AWS accounts that will be allowed full (read and
  # write) access to the services in this account specified in
  # var.dev_permitted_services.
  allow_dev_access_from_other_account_arns = var.allow_dev_access_from_other_account_arns

  # The ARN of the policy that is used to set the permissions boundary for the IAM
  # role.
  allow_dev_access_iam_role_permissions_boundary = var.allow_dev_access_iam_role_permissions_boundary

  # A list of IAM ARNs from other AWS accounts that will be allowed full (read and
  # write) access to this account.
  allow_full_access_from_other_account_arns = var.allow_full_access_from_other_account_arns

  # The ARN of the policy that is used to set the permissions boundary for the IAM
  # role.
  allow_full_access_iam_role_permissions_boundary = var.allow_full_access_iam_role_permissions_boundary

  # A list of IAM ARNs from other AWS accounts that will be allowed IAM admin access
  # to this account.
  allow_iam_admin_access_from_other_account_arns = []

  # A list of IAM ARNs from other AWS accounts that will be allowed read access to
  # the logs in CloudTrail, AWS Config, and CloudWatch for this account. If
  # var.cloudtrail_kms_key_arn is set, will also grant decrypt permissions for the
  # KMS CMK.
  allow_logs_access_from_other_account_arns = var.allow_logs_access_from_other_account_arns

  # A list of IAM ARNs from other AWS accounts that will be allowed read-only access
  # to this account.
  allow_read_only_access_from_other_account_arns = var.allow_read_only_access_from_other_account_arns

  # The ARN of the policy that is used to set the permissions boundary for the IAM
  # role.
  allow_read_only_access_iam_role_permissions_boundary = var.allow_read_only_access_iam_role_permissions_boundary

  # A list of IAM ARNs from other AWS accounts that will be allowed access to AWS
  # support for this account.
  allow_support_access_from_other_account_arns = var.allow_support_access_from_other_account_arns

  # The ARN of the policy that is used to set the permissions boundary for the IAM
  # role.
  allow_support_access_iam_role_permissions_boundary = var.allow_support_access_iam_role_permissions_boundary

  # What to name the billing access IAM role
  billing_access_role_name = "allow-billing-only-access-from-other-accounts"

  # The ARN of a KMS CMK used to encrypt CloudTrail logs. If set, the logs IAM role
  # will include permissions to decrypt using this CMK.
  cloudtrail_kms_key_arn = var.cloudtrail_kms_key_arn

  # Set to false to have this module create no resources. This weird parameter
  # exists solely because Terraform does not support conditional modules. Therefore,
  # this is a hack to allow you to conditionally decide if the resources should be
  # created or not.
  # create_resources = true

  # What to name the dev access IAM role
  dev_access_role_name = "allow-dev-access-from-other-accounts"

  # A list of AWS services for which the developers from the accounts in
  # var.allow_dev_access_from_other_account_arns will receive full permissions. See
  # https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_actions-reso
  # rces-contextkeys.html to find the service name. For example, to grant developers
  # access only to EC2 and Amazon Machine Learning, use the value
  # ["ec2","machinelearning"]. Do NOT add iam to the list of services, or that will
  # grant Developers de facto admin access.
  dev_permitted_services = var.dev_permitted_services

  # What to name the full access IAM role
  full_access_role_name = "allow-full-access-from-other-accounts"

  # What to name the IAM admin access IAM role
  iam_admin_access_role_name = "allow-iam-admin-access-from-other-accounts"

  # Include this value as a prefix in the name of every IAM role created by this
  # module. This is useful to prepend, for example, '<account-name>-' to every IAM
  # role name: e.g., allow-full-access-from-other-accounts becomes
  # stage-allow-full-access-from-other-accounts.
  iam_role_name_prefix = var.name_prefix

  # What to name the logs access IAM role
  logs_access_role_name = "allow-logs-access-from-other-accounts"

  # The maximum allowable session duration, in seconds, for the credentials you get
  # when assuming the IAM roles created by this module. This variable applies to all
  # IAM roles created by this module that are intended for people to use, such as
  # allow-read-only-access-from-other-accounts. For IAM roles that are intended for
  # machine users, such as allow-auto-deploy-from-other-accounts, see
  # var.max_session_duration_machine_users.
  max_session_duration_human_users = var.max_session_duration_human_users

  # What to name the read-only access IAM role
  read_only_access_role_name = "allow-read-only-access-from-other-accounts"

  # What to name the support access IAM role
  support_access_role_name = "allow-support-access-from-other-accounts"

  # A map of tags to apply to the IAM roles.
  tags = merge(var.iam_role_tags, local.tags)

  # When true, all IAM policies will be managed as dedicated policies rather than
  # inline policies attached to the IAM roles. Dedicated managed policies are
  # friendlier to automated policy checkers, which may scan a single resource for
  # findings. As such, it is important to avoid inline policies when targeting
  # compliance with various security standards.
  use_managed_iam_policies = var.use_managed_iam_policies
}

# ----------------------------------------------------------------------------------------------------
# CREATE LOCAL IAM GROUPS
# ----------------------------------------------------------------------------------------------------
module "iam_groups" {
  source = "../krrv-sra-iam-groups"

  # ----------------------------------------------------------------------------------------------------
  # REQUIRED VARIABLES
  # ----------------------------------------------------------------------------------------------------

  # The ID of the AWS Account.
  aws_account_id = var.aws_account_id

  # Should we require that all IAM Users use Multi-Factor Authentication for both
  # AWS API calls and the AWS Web Console? (true or false)
  should_require_mfa = var.should_require_mfa

  # ----------------------------------------------------------------------------------------------------
  # OPTIONAL VARIABLES
  # ----------------------------------------------------------------------------------------------------

  # The ARN of a KMS CMK used to encrypt CloudTrail logs. If set, the logs group
  # will include permissions to decrypt using this CMK.
  cloudtrail_kms_key_arn = var.cloudtrail_kms_key_arn

  # The name of the IAM group that will grant access to all external AWS accounts in
  # var.iam_groups_for_cross_account_access.
  # cross_account_access_all_group_name = "access-all-external-accounts"

  # A list of AWS services for which the developers IAM Group will receive full
  # permissions. See https://goo.gl/ZyoHlz to find the IAM Service name. For
  # example, to grant developers access only to EC2 and Amazon Machine Learning, use
  # the value ["ec2","machinelearning"]. Do NOT add iam to the list of services, or
  # that will grant Developers de facto admin access. If you need to grant iam
  # privileges, just grant the user Full Access.
  iam_group_developers_permitted_services = var.dev_permitted_services

  # The prefix of the S3 Bucket Name to which an individual IAM User will have full
  # access. For example, if the prefix is acme.user-, then IAM User john.doe will
  # have access to S3 Bucket acme.user-john.doe.
  # iam_group_developers_s3_bucket_prefix = "your-org-name.user-"

  # The name to be used for the IAM Group that grants read/write access to all
  # billing features in AWS.
  iam_group_name_billing = "billing"

  # The name to be used for the IAM Group that grants IAM Users a reasonable set of
  # permissions for developers.
  iam_group_name_developers = "developers"

  # The name to be used for the IAM Group that grants full access to all AWS
  # resources.
  iam_group_name_full_access = "full-access"

  # The name to be used for the IAM Group that grants IAM administrative access.
  # Effectively grants administrator access.
  iam_group_name_iam_admin = "iam-admin"

  # The name to be used for the IAM Group that grants IAM Users the permissions to
  # manage their own IAM User account.
  iam_group_name_iam_user_self_mgmt = "iam-user-self-mgmt"

  # The name to be used for the IAM Group that grants read access to CloudTrail, AWS
  # Config, and CloudWatch in AWS.
  iam_group_name_logs = "logs"

  # The name to be used for the IAM Group that grants read-only access to all AWS
  # resources.
  iam_group_name_read_only = "read-only"

  # The name of the IAM Group that allows access to AWS Support.
  iam_group_name_support = "support"

  # The name to be used for the IAM Group that grants IAM Users the permissions to
  # use existing IAM Roles when launching AWS Resources. This does NOT grant the
  # permission to create new IAM Roles.
  # iam_group_name_use_existing_iam_roles = "use-existing-iam-roles"

  # This variable is used to create groups that allow IAM users to assume roles in
  # your other AWS accounts. It should be a list of objects, where each object has
  # the fields 'group_name', which will be used as the name of the IAM group, and
  # 'iam_role_arns', which is a list of ARNs of IAM Roles that you can assume when
  # part of that group. For each entry in the list of objects, we will create an IAM
  # group that allows users to assume the given IAM role(s) in the other AWS
  # account. This allows you to define all your IAM users in one account (e.g. the
  # users account) and to grant them access to certain IAM roles in other accounts
  # (e.g. the stage, prod, audit accounts).
  iam_groups_for_cross_account_access = []

  # The name to be used for the IAM Policy that grants IAM administrative access.
  iam_policy_iam_admin = "iam-admin"

  # The name to be used for the IAM Policy that grants IAM Users the permissions to
  # manage their own IAM User account.
  iam_policy_iam_user_self_mgmt = "iam-user-self-mgmt"

  # Should we create the IAM Group for billing? Allows read-write access to billing
  # features only. (true or false)
  should_create_iam_group_billing = true

  # Should we create the IAM Group for access to all external AWS accounts? 
  # should_create_iam_group_cross_account_access_all = true

  # Should we create the IAM Group for developers? The permissions of that group are
  # specified via var.iam_group_developers_permitted_services. (true or false)
  should_create_iam_group_developers = true

  # Should we create the IAM Group for full access? Allows full access to all AWS
  # resources. (true or false)
  should_create_iam_group_full_access = true

  # Should we create the IAM Group for IAM administrator access? Allows users to
  # manage all IAM entities, effectively granting administrator access. (true or
  # false)
  should_create_iam_group_iam_admin = false

  # Should we create the IAM Group for logs? Allows read access to CloudTrail, AWS
  # Config, and CloudWatch. If var.cloudtrail_kms_key_arn is set, will also give
  # decrypt access to a KMS CMK. (true or false)
  should_create_iam_group_logs = true

  # Should we create the IAM Group for read-only? Allows read-only access to all AWS
  # resources. (true or false)
  should_create_iam_group_read_only = true

  # Should we create the IAM Group for support users? Allows users to access AWS
  # support.
  should_create_iam_group_support = false

  # Should we create the IAM Group for use-existing-iam-roles? Allow launching AWS
  # resources with existing IAM Roles, but no ability to create new IAM Roles. (true
  # or false)
  # should_create_iam_group_use_existing_iam_roles = false

  # Should we create the IAM Group for user self-management? Allows users to manage
  # their own IAM user accounts, but not other IAM users. (true or false)
  should_create_iam_group_user_self_mgmt = true

}

# ----------------------------------------------------------------------------------------------------
# CREATE LOCAL IAM USERS
# ----------------------------------------------------------------------------------------------------

# ----------------------------------------------------------------------------------------------------
# DEFINE USER PASSWORD POLICY
# ----------------------------------------------------------------------------------------------------
module "iam_user_password_policy" {
  count = var.enable_iam_user_password_policy?1:0
  source = "../krrv-sra-iam-password-policy"

  # ----------------------------------------------------------------------------------------------------
  # OPTIONAL VARIABLES
  # ----------------------------------------------------------------------------------------------------

  # Whether to allow users to change their own password (true or false).
  allow_users_to_change_password = var.iam_password_policy_allow_users_to_change_password

  # Whether users are prevented from setting a new password after their password has
  # expired (i.e. require administrator reset) (true or false).
  hard_expiry = var.iam_password_policy_hard_expiry

  # The number of days that an user password is valid. Enter 0 for no expiration.
  max_password_age = var.iam_password_policy_max_password_age

  # Minimum length to require for user passwords.
  minimum_password_length = var.iam_password_policy_minimum_password_length

  # The number of previous passwords that users are prevented from reusing.
  password_reuse_prevention = var.iam_password_policy_password_reuse_prevention

  # Whether to require lowercase characters for user passwords (true or false).
  require_lowercase_characters = var.iam_password_policy_require_lowercase_characters

  # Whether to require numbers for user passwords (true or false).
  require_numbers = var.iam_password_policy_require_numbers

  # Whether to require symbols for user passwords (true or false).
  require_symbols = var.iam_password_policy_require_symbols

  # Whether to require uppercase characters for user passwords (true or false).
  require_uppercase_characters = var.iam_password_policy_require_uppercase_characters
}

# ----------------------------------------------------------------------------------------------------
# MULTI-REGION EBS ENCRYPTION
# ----------------------------------------------------------------------------------------------------
module "multiregion_ebs_encryption" {
  source = "../krrv-sra-ebs-encryption-multi-region"

  # You MUST create a provider block for EVERY AWS region (see providers.tf) and pass all those providers in here via
  # this providers map. However, you should use var.opt_in_regions to tell Terraform to only use and authenticate to
  # regions that are enabled in your AWS account.
  providers = {
    aws.af_south_1     = aws.af_south_1
    aws.ap_east_1      = aws.ap_east_1
    aws.ap_northeast_1 = aws.ap_northeast_1
    aws.ap_northeast_2 = aws.ap_northeast_2
    aws.ap_northeast_3 = aws.ap_northeast_3
    aws.ap_south_1     = aws.ap_south_1
    aws.ap_southeast_1 = aws.ap_southeast_1
    aws.ap_southeast_2 = aws.ap_southeast_2
    aws.ap_southeast_3 = aws.ap_southeast_3
    aws.ca_central_1   = aws.ca_central_1
    aws.cn_north_1     = aws.cn_north_1
    aws.cn_northwest_1 = aws.cn_northwest_1
    aws.eu_central_1   = aws.eu_central_1
    aws.eu_north_1     = aws.eu_north_1
    aws.eu_south_1     = aws.eu_south_1
    aws.eu_west_1      = aws.eu_west_1
    aws.eu_west_2      = aws.eu_west_2
    aws.eu_west_3      = aws.eu_west_3
    aws.sa_east_1      = aws.sa_east_1
    aws.us_east_1      = aws.us_east_1
    aws.us_east_2      = aws.us_east_2
    aws.us_west_1      = aws.us_west_1
    aws.us_west_2      = aws.us_west_2
  }

  # ----------------------------------------------------------------------------------------------------
  # REQUIRED VARIABLES
  # ----------------------------------------------------------------------------------------------------

  # The AWS Account ID the template should be operated on. This avoids
  # misconfiguration errors caused by environment variables.
  aws_account_id = var.aws_account_id

  # ----------------------------------------------------------------------------------------------------
  # OPTIONAL VARIABLES
  # ----------------------------------------------------------------------------------------------------

  # The list of region in to which all new EBS volumes will have encryption enabled 
  opt_in_regions = var.ebs_opt_in_regions

  # If set to true, all new EBS volumes will have encryption enabled by default
  enable_encryption = var.ebs_enable_encryption

  # Optional map of region names to KMS keys to use for EBS volume encryption when
  # var.use_existing_kms_keys is enabled.
  kms_key_arns = var.ebs_kms_key_arns

  # Whether or not to use the existing keys specified in var.kms_key_arns. If false
  # (the default), will use the default aws/ebs key. We need this weird parameter
  # because `count` must be a known value at plan time, so we cannot calculate
  # whether or not to use the key dynamically.
  use_existing_kms_keys = var.ebs_use_existing_kms_keys
}

# ----------------------------------------------------------------------------------------------------
# CONFIGURE IM ACCESS ANALYZER
# ----------------------------------------------------------------------------------------------------
module "multiregion_iam_access_analyzer" {
  count = var.enable_iam_access_analyzer ? 1: 0
  source = "../krrv-sra-iam-accessanalyzer-multi-region"

  # You MUST create a provider block for EVERY AWS region (see providers.tf) and pass all those providers in here via
  # this providers map. However, you should use var.opt_in_regions to tell Terraform to only use and authenticate to
  # regions that are enabled in your AWS account.
  providers = {
    aws = aws
    aws.af_south_1     = aws.af_south_1
    aws.ap_east_1      = aws.ap_east_1
    aws.ap_northeast_1 = aws.ap_northeast_1
    aws.ap_northeast_2 = aws.ap_northeast_2
    aws.ap_northeast_3 = aws.ap_northeast_3
    aws.ap_south_1     = aws.ap_south_1
    aws.ap_southeast_1 = aws.ap_southeast_1
    aws.ap_southeast_2 = aws.ap_southeast_2
    aws.ap_southeast_3 = aws.ap_southeast_3
    aws.ca_central_1   = aws.ca_central_1
    aws.cn_north_1     = aws.cn_north_1
    aws.cn_northwest_1 = aws.cn_northwest_1
    aws.eu_central_1   = aws.eu_central_1
    aws.eu_north_1     = aws.eu_north_1
    aws.eu_south_1     = aws.eu_south_1
    aws.eu_west_1      = aws.eu_west_1
    aws.eu_west_2      = aws.eu_west_2
    aws.eu_west_3      = aws.eu_west_3
    aws.sa_east_1      = aws.sa_east_1
    aws.us_east_1      = aws.us_east_1
    aws.us_east_2      = aws.us_east_2
    aws.us_west_1      = aws.us_west_1
    aws.us_west_2      = aws.us_west_2
  }

  # ----------------------------------------------------------------------------------------------------
  # REQUIRED VARIABLES
  # ----------------------------------------------------------------------------------------------------

  # The list of region in to which all new EBS volumes will have encryption enabled 
  opt_in_regions = var.iam_access_analyzer_opt_in_regions

  # The AWS Account ID the template should be operated on. This avoids
  # misconfiguration errors caused by environment variables.
  aws_account_id = var.aws_account_id

  # ----------------------------------------------------------------------------------------------------
  # OPTIONAL VARIABLES
  # ----------------------------------------------------------------------------------------------------

  # A feature flag to enable or disable this module.
  # create_resources = true

  # The name of the IAM Access Analyzer module
  iam_access_analyzer_name = var.iam_access_analyzer_name

  # If set to ACCOUNT, the analyzer will only be scanning the current AWS account
  # it's in. If set to ORGANIZATION - will scan the organization AWS account and the
  # child accounts.
  iam_access_analyzer_type = var.iam_access_analyzer_type

}

# ------------------------------------------------------------------------------------------------------
# MULTI-REGION KMS-MASTER-KEY - NOT IMPLEMENTED YET
# ------------------------------------------------------------------------------------------------------
# module "multiregion_kms_master_key" {
#   source = ""

#   # ----------------------------------------------------------------------------------------------------
#   # REQUIRED VARIABLES
#   # ----------------------------------------------------------------------------------------------------

#   # The AWS Account ID the template should be operated on. This avoids
#   # misconfiguration errors caused by environment variables.
#   aws_account_id = var.aws_account_id

#   # You can use this variable to create account-level KMS Customer Master Keys
#   # (CMKs) for encrypting and decrypting data. This variable should be a map where
#   # the keys are the names of the CMK and the values are an object that defines the
#   # configuration for that CMK. See the comment below for the configuration options
#   # you can set for each key.
#   customer_master_keys = var.kms_customer_master_keys

#   # ----------------------------------------------------------------------------------------------------
#   # OPTIONAL VARIABLES
#   # ----------------------------------------------------------------------------------------------------

#   # The default value to use for spec (specifies whether the key contains a
#   # symmetric key or an asymmetric key pair and the encryption algorithms or signing
#   # algorithms that the key supports). Applies to all keys, unless overridden in the
#   # customer_master_keys map. Valid values: SYMMETRIC_DEFAULT, RSA_2048, RSA_3072,
#   # RSA_4096, ECC_NIST_P256, ECC_NIST_P384, ECC_NIST_P521, or ECC_SECG_P256K1.
#   default_customer_master_key_spec = null

#   # The default value to use for deletion_window_in_days (the number of days to keep
#   # this KMS Master Key around after it has been marked for deletion). Applies to
#   # all keys, unless overridden on a specific key in the customer_master_keys map.
#   default_deletion_window_in_days = 30

#   # The default value to use for enable_key_rotation (whether or not to enable
#   # automatic annual rotation of the KMS key). Applies to all keys, unless
#   # overridden in the customer_master_keys map.
#   default_enable_key_rotation = true

#   # A map of tags to apply to all KMS Keys to be created. In this map variable, the
#   # key is the tag name and the value is the tag value.
#   global_tags = var.kms_cmk_global_tag

# }

# ------------------------------------------------------------------------------------------------------
# MULTI-REGION KMS-GRANT - NOT IMPLEMENTED YET
# ------------------------------------------------------------------------------------------------------
# module "kms_grant_multi_region" {
#   source = ""

#   # ----------------------------------------------------------------------------------------------------
#   # REQUIRED VARIABLES
#   # ----------------------------------------------------------------------------------------------------

#   # The AWS Account ID the template should be operated on. This avoids
#   # misconfiguration errors caused by environment variables.
#   aws_account_id = var.aws_account_id

#   # The map of names of KMS grants to the region where the key resides in. There
#   # should be a one to one mapping between entries in this map and the entries of
#   # the kms_grants map. This is used to workaround a terraform limitation where the
#   # for_each value can not depend on resources.
#   kms_grant_regions = var.kms_grant_region

#   # Create the specified KMS grants to allow entities to use the KMS key without
#   # modifying the KMS policy or IAM. This is necessary to allow AWS services (e.g.
#   # ASG) to use CMKs encrypt and decrypt resources. The input is a map of grant name
#   # to grant properties. The name must be unique per account.
#   kms_grants = var.kms_grants

#   # ----------------------------------------------------------------------------------------------------
#   # OPTIONAL VARIABLES
#   # ----------------------------------------------------------------------------------------------------

# }

