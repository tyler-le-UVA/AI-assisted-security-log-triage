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
