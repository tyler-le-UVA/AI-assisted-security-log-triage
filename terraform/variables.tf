variable "region" {
  type    = string
  default = "us-east-1"
}

variable "name_prefix" {
  type    = string
  default = "triage-tf"
}

variable "log_retention_days" {
  type    = number
  default = 90
}

variable "model_id" {
  type    = string
  default = "us.amazon.nova-2-lite-v1:0"
}

variable "lambda_memory_mb" {
  type    = number
  default = 256
}

variable "lambda_timeout_s" {
  type    = number
  default = 60
}

variable "function_log_retention_days" {
  type    = number
  default = 30
}
