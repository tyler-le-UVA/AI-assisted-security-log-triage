data "archive_file" "parser" {
  type        = "zip"
  output_path = "${path.module}/parser.zip"

  source {
    content  = file("${path.module}/../lambda/parser.py")
    filename = "lambda_function.py"
  }
}

resource "aws_cloudwatch_log_group" "parser" {
  name              = "/aws/lambda/${var.name_prefix}-parser"
  retention_in_days = var.function_log_retention_days
}

resource "aws_lambda_function" "parser" {
  function_name    = "${var.name_prefix}-parser"
  role             = aws_iam_role.parser.arn
  runtime          = "python3.12"
  handler          = "lambda_function.lambda_handler"
  filename         = data.archive_file.parser.output_path
  source_code_hash = data.archive_file.parser.output_base64sha256
  memory_size      = var.lambda_memory_mb
  timeout          = var.lambda_timeout_s

  environment {
    variables = {
      TABLE_NAME = aws_dynamodb_table.findings.name
      MODEL_ID   = var.model_id
    }
  }

  # Code is deployed by GitHub Actions; Terraform manages everything else.
  lifecycle {
    ignore_changes = [filename, source_code_hash]
  }

  depends_on = [
    aws_cloudwatch_log_group.parser,
    aws_iam_role_policy.parser,
  ]
}
