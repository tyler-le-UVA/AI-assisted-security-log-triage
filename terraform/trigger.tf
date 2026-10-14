resource "aws_lambda_permission" "allow_s3" {
  statement_id   = "AllowS3Invoke"
  action         = "lambda:InvokeFunction"
  function_name  = aws_lambda_function.parser.function_name
  principal      = "s3.amazonaws.com"
  source_arn     = aws_s3_bucket.logs.arn
  source_account = local.account_id
}

resource "aws_s3_bucket_notification" "logs" {
  bucket = aws_s3_bucket.logs.id

  lambda_function {
    lambda_function_arn = aws_lambda_function.parser.arn
    events              = ["s3:ObjectCreated:*"]
    filter_prefix       = "AWSLogs/${local.account_id}/CloudTrail/"
    filter_suffix       = ".json.gz"
  }

  depends_on = [aws_lambda_permission.allow_s3]
}
