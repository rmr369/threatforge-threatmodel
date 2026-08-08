resource "aws_s3_bucket" "assets" {
  bucket = "shop-public-assets"
  acl    = "public-read"
}

resource "aws_db_instance" "shop" {
  identifier          = "shop-prod"
  engine              = "postgres"
  publicly_accessible = true
  storage_encrypted   = false
  skip_final_snapshot = true
  password            = "Pr0dDbPassw0rd!"
}

resource "aws_security_group" "web" {
  name = "web-sg"
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_instance" "worker" {
  ami           = "ami-0123456789"
  instance_type = "t3.medium"
  metadata_options {
    http_tokens = "optional"
  }
}

resource "aws_iam_policy" "broad" {
  name   = "broad-policy"
  policy = "{\"Statement\":[{\"Effect\":\"Allow\",\"Action\":\"*\",\"Resource\":\"*\"}]}"
}
