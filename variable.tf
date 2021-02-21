provider "aws" {
  region  = "ap-south-1"
}

data "aws_vpc" "selected" {
  default = true
}

data "aws_availability_zones" "available" {
  state = "available"
}

data "aws_subnet_ids" "example" {
  vpc_id = data.aws_vpc.selected.id
}
variable "INSTANCE_USERNAME" {}
variable "INSTANCE_PASSWORD" {}
