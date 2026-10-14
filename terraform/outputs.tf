output "log_bucket" {
  value = aws_s3_bucket.logs.id
}

output "findings_table" {
  value = aws_dynamodb_table.findings.name
}
