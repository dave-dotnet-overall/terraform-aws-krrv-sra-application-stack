# --------------------------------------------------------------------------------------------------
# Outputs
# --------------------------------------------------------------------------------------------------
output "allow_billing_access_from_other_accounts_iam_role_arn" {
  description = ""
  value       = ""
}

output "allow_billing_access_from_other_accounts_iam_role_id" {
  description = ""
  value       = ""
}

output "allow_billing_access_sign_in_url" {
  description = ""
  value       = ""
}

output "allow_dev_access_from_other_accounts_iam_role_arn" {
  description = ""
  value       = ""
}

output "allow_dev_access_from_other_accounts_iam_role_id" {
  description = ""
  value       = ""
}

output "allow_dev_access_sign_in_url" {
  description = ""
  value       = ""
}

output "allow_full_access_from_other_accounts_iam_role_arn" {
  description = ""
  value       = ""
}

output "allow_full_access_from_other_accounts_iam_role_id" {
  description = ""
  value       = ""
}

output "allow_full_access_sign_in_url" {
  description = ""
  value       = ""
}

output "allow_iam_admin_access_from_other_accounts_iam_role_arn" {
  description = ""
  value       = ""
}

output "allow_iam_admin_access_from_other_accounts_iam_role_id" {
  description = ""
  value       = ""
}

output "allow_iam_admin_access_sign_in_url" {
  description = ""
  value       = ""
}

output "allow_logs_access_from_other_accounts_iam_role_arn" {
  description = ""
  value       = ""
}

output "allow_logs_access_from_other_accounts_iam_role_id" {
  description = ""
  value       = ""
}

output "allow_logs_access_sign_in_url" {
  description = ""
  value       = ""
}

output "allow_read_only_access_from_other_accounts_iam_role_arn" {
  description = ""
  value       = ""
}

output "allow_read_only_access_from_other_accounts_iam_role_id" {
  description = ""
  value       = ""
}

output "allow_read_only_access_sign_in_url" {
  description = ""
  value       = ""
}

output "allow_support_access_from_other_accounts_iam_role_arn" {
  description = ""
  value       = ""
}

output "allow_support_access_from_other_accounts_iam_role_id" {
  description = ""
  value       = ""
}

output "allow_support_access_sign_in_url" {
  description = ""
  value       = ""
}

output "aws_ebs_encryption_by_default_enabled" {
  description = "A map from region to a boolean indicating whether or not EBS encryption is enabled by default for each region."
  value       = ""
}

output "aws_ebs_encryption_default_kms_key" {
  description = "A map from region to the ARN of the KMS key used for default EBS encryption for each region."
  value       = ""
}

output "cloudtrail_cloudwatch_group_arn" {
  description = "The ARN of the cloudwatch log group."
  value       = ""
}

output "cloudtrail_cloudwatch_group_name" {
  description = "The name of the cloudwatch log group."
  value       = ""
}

output "cloudtrail_iam_role_arn" {
  description = "The ARN of the IAM role used by the cloudwatch log group."
  value       = ""
}

output "cloudtrail_iam_role_name" {
  description = "The name of the IAM role used by the cloudwatch log group."
  value       = ""
}

output "cloudtrail_kms_key_alias_name" {
  description = "The alias of the KMS key used by the S3 bucket to encrypt cloudtrail logs."
  value       = ""
}

output "cloudtrail_kms_key_arn" {
  description = "The ARN of the KMS key used by the S3 bucket to encrypt cloudtrail logs."
  value       = ""
}

output "cloudtrail_s3_access_logging_bucket_name" {
  description = "The name of the S3 bucket where server access logs are delivered."
  value       = ""
}

output "cloudtrail_s3_bucket_name" {
  description = "The name of the S3 bucket where cloudtrail logs are delivered."
  value       = ""
}

output "cloudtrail_trail_arn" {
  description = "The ARN of the cloudtrail trail."
  value       = ""
}

output "invalid_cmk_inputs" {
  description = "Map of CMKs from the input customer_master_keys that had an invalid region, and thus were not created. The structure of the map is the same as the input. This will only include KMS key inputs that were not created because the region attribute was invalid (either not a valid region identifier, the region is not enabled on the account, or the region is not included in the opt_in_regions input)."
  value       = ""
}

output "kms_key_aliases" {
  description = "A map from region to aliases of the KMS CMKs that were created. The value will also be a map mapping the keys from the customer_master_keys input variable to the corresponding alias."
  value       = ""
}

output "kms_key_arns" {
  description = "A map from region to ARNs of the KMS CMKs that were created. The value will also be a map mapping the keys from the kms_customer_master_keys input variable to the corresponding ARN."
  value       = ""
}

output "kms_key_ids" {
  description = "A map from region to IDs of the KMS CMKs that were created. The value will also be a map mapping the keys from the kms_customer_master_keys input variable to the corresponding ID."
  value       = ""
}

output "service_linked_role_arns" {
  description = "A map of ARNs of the service linked roles created from service_linked_roles."
  value       = ""
}
