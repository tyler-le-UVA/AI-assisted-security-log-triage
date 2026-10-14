data "aws_iam_policy_document" "lambda_assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "parser" {
  name               = "${var.name_prefix}-parser-role"
  assume_role_policy = data.aws_iam_policy_document.lambda_assume.json
}

data "aws_iam_policy_document" "parser" {
  statement {
    sid       = "ReadCloudTrailLogs"
    actions   = ["s3:GetObject"]
    resources = ["${aws_s3_bucket.logs.arn}/*"]
  }

  statement {
    sid       = "WriteFindings"
    actions   = ["dynamodb:PutItem", "dynamodb:UpdateItem"]
    resources = [aws_dynamodb_table.findings.arn]
  }

  statement {
    sid     = "InvokeNovaModels"
    actions = ["bedrock:InvokeModel"]
    resources = [
      "arn:aws:bedrock:*::foundation-model/amazon.nova-*",
      "arn:aws:bedrock:${var.region}:${local.account_id}:inference-profile/*amazon.nova-*",
    ]
  }

  statement {
    sid       = "WriteOwnLogs"
    actions   = ["logs:CreateLogStream", "logs:PutLogEvents"]
    resources = ["${aws_cloudwatch_log_group.parser.arn}:*"]
  }
}

resource "aws_iam_role_policy" "parser" {
  name   = "${var.name_prefix}-parser"
  role   = aws_iam_role.parser.id
  policy = data.aws_iam_policy_document.parser.json
}
