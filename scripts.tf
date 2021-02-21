resource "tls_private_key" "webserver_key" {
    algorithm   =   "RSA"
    rsa_bits    =   4096
}
resource "local_file" "private_key" {
    content         =   tls_private_key.webserver_key.private_key_pem
    filename        =   "webserver.pem"
    file_permission =   0400
}

provider "aws" {
    profile = "ALIC"
    region  = "ap-southeast-1"
}


data "aws_vpc" "selected" {
    default = true
}

locals {
    vpc_id    = data.aws_vpc.selected.id
}

resource "aws_key_pair" "webserver_key" {
    key_name   = "webserver"
    public_key = tls_private_key.webserver_key.public_key_openssh
}

resource "aws_security_group" "webserver_sg" {
    name        = "webserver"
    description = "https, ssh, icmp"
    vpc_id      = local.vpc_id

    ingress {
        description = "http"
        from_port   = 80
        to_port     = 80
        protocol    = "tcp"
        cidr_blocks = ["0.0.0.0/0"]
    }
    
    ingress {
        description = "ssh"
        from_port   = 22
        to_port     = 22
        protocol    = "tcp"
        cidr_blocks = ["0.0.0.0/0"]
    }

    ingress {
        description = "ping-icmp"
        from_port   = -1
        to_port     = -1
        protocol    = "icmp"
        cidr_blocks = ["0.0.0.0/0"]
    }

    egress {
        from_port   = 0
        to_port     = 0
        protocol    = "-1"
        cidr_blocks = ["0.0.0.0/0"]
    }

    tags = {
        Name = "webserver"
    }
}

resource "aws_instance" "LinuxServer" {
    ami                     = "ami-01aab85a5e4a5a0fe"
    instance_type           = "t2.micro"
    key_name                = aws_key_pair.webserver_key.key_name
    vpc_security_group_ids  = [aws_security_group.webserver_sg.id]
     availability_zone       = "ap-southeast-1a"
    root_block_device {
        volume_type     = "gp2"
        volume_size     = 12
        delete_on_termination   = true
    }

    tags = {
        Name = "LinuxServer"
    }

    connection {
        type    = "ssh"
        user    = "ec2-user"
        host    = aws_instance.LinuxServer.public_ip
        port    = 22
        private_key = tls_private_key.webserver_key.private_key_pem
    }

    provisioner "remote-exec" {
        inline = [
        "sudo yum install httpd -y",
        "sudo systemctl start httpd",
        "sudo systemctl enable httpd",
        "sudo yum install git -y"
        ]
    }
}

resource "aws_ebs_volume" "document_root" {
    availability_zone = aws_instance.LinuxServer.availability_zone
    size              = 1
    type = "gp2"
    tags = {
        Name = "document_root"
    }
}

resource "aws_volume_attachment" "document_root_mount" {
    device_name = "/dev/xvdb"
    volume_id   = aws_ebs_volume.document_root.id
    instance_id = aws_instance.LinuxServer.id

    connection {
        type    = "ssh"
        user    = "ec2-user"
        host    = aws_instance.LinuxServer.public_ip
        port    = 22
        private_key = tls_private_key.webserver_key.private_key_pem
    }

    provisioner "remote-exec" {
        inline  = [
            "sudo mkfs.ext4 /dev/xvdb",
            "sudo mount /dev/xvdb /var/www/html",
            "sudo git clone https://github.com/aqilshaikh/alic-linux.git /temp_repo",
            "sudo cp -rf /temp_repo/* /var/www/html",
            "sudo rm -rf /temp_repo",
            "sudo setenforce 0"
        ]
    }
    
}

data "aws_ami" "windows" {
  most_recent = true
  filter {
    name   = "description"
    values = ["Microsoft Windows Server 2012 R2 RTM 64-bit Locale English AMI provided by Amazon"]
  }

  filter {
    name   = "root-device-type"
    values = ["ebs"]
      
  }

  owners = ["801119661308"] # Canonical
}

resource "aws_instance" "WindowsServer" {
  ami = "${data.aws_ami.windows.id}"
  instance_type = "t2.micro"
  key_name                = aws_key_pair.webserver_key.key_name
  vpc_security_group_ids = [aws_security_group.webserver_sg.id]
  availability_zone       = "ap-southeast-1b"
  tags = {
    Name =  "WindowsServer"
  }
  user_data = <<EOF
  <powershell>
    net user ${var.INSTANCE_USERNAME} ${var.INSTANCE_PASSWORD} /add
    net localgroup administrators ${var.INSTANCE_USERNAME} /add
    winrm quickconfig -q
    winrm set winrm/config/winrs '@{MaxMemoryPerShellMB="300"}'
    winrm set winrm/config '@{MaxTimeoutms="1800000"}'
    winrm set winrm/config/service '@{AllowUnencrypted="true"}'
    winrm set winrm/config/service/auth '@{Basic="true"}'
    netsh advfirewall firewall add rule name="WinRM 5985" protocol=TCP dir=in localport=5985 action=allow
    netsh advfirewall firewall add rule name="WinRM 5986" protocol=TCP dir=in localport=5986 action=allow
    net stop winrm
    sc.exe config winrm start=auto
    net start winrm
    mkdir C:\Project
    Start-Process powershell -Verb runAs  
    Install-WindowsFeature -Name Web-Server -IncludeAllSubFeature -IncludeManagementTools    
    Import-Module WebAdministration
    Get-WebSite -Name "Default Web Site" | Remove-WebSite -Confirm:$false -Verbose
    New-Website -Name Aqil -ApplicationPool DefaultAppPool -IPAddress * -PhysicalPath C:\Project -Port 80
    iisreset
  </powershell>
  EOF
  
  provisioner "file" {
    source = "./index.html"
    destination = "C:/Project/index.html"
    }
    
    
  connection {
    type = "winrm"
    host = "localhost"
    user = "${var.INSTANCE_USERNAME}"
    password = "${var.INSTANCE_PASSWORD}"
    }
}

  

resource "aws_lb_target_group" "test" {
  depends_on = [
    aws_instance.LinuxServer,
    aws_instance.WindowsServer
  ]
  name        = "webserver-tg"
  port        = 80
  protocol    = "HTTP"
  vpc_id      = data.aws_vpc.selected.id
  target_type = "instance"
}

resource "aws_lb_target_group_attachment" "Linux" {
  depends_on = [
    aws_lb_target_group.test
  ]
  target_group_arn = aws_lb_target_group.test.arn
  target_id        = aws_instance.LinuxServer.id
  port             = 80
}

resource "aws_lb_target_group_attachment" "Windows" {
  depends_on = [
    aws_lb_target_group.test
  ]
  target_group_arn = aws_lb_target_group.test.arn
  target_id        = aws_instance.WindowsServer.id
  port             = 80
}

resource "aws_lb" "test" {
  depends_on = [
    aws_lb_target_group.test
  ]
  name               = "webserver-lb"
  internal           = false
  load_balancer_type = "application"
  security_groups    = [aws_security_group.webserver_sg.id]
 }

resource "aws_lb_listener" "front_end" {
  depends_on = [
    aws_lb.test
  ]
  load_balancer_arn = aws_lb.test.arn
  port              = "80"
  protocol          = "HTTP"

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.test.arn
  }
}
resource "aws_s3_bucket" "image-bucket" {
    bucket  = "webserver-images-test"
    acl     = "public-read"
    provisioner "local-exec" {
        command     = "git clone https://github.com/ALIC-images/webserver-image webserver-image"
    }

    provisioner "local-exec" {
        when        =   destroy
        command     =   "echo Y | rmdir /s webserver-image"
    }
}

resource "aws_s3_bucket_object" "image-upload" {
    bucket  = aws_s3_bucket.image-bucket.bucket
    key     = "myphoto.jpeg"
    source  = "webserver-image/StudentPhoto.jpg"
    acl     = "public-read"


    provisioner "local-exec" {
        command     = "git clone https://github.com/devil-test/webserver-image webserver-image"
    }

    provisioner "local-exec" {
        when        =   destroy
        command     =   "echo Y | rmdir /s webserver-image"
    }
}


variable "var1" {default = "S3-"}

locals {
    s3_origin_id = "${var.var1}${aws_s3_bucket.image-bucket.bucket}"
    image_url = "${aws_cloudfront_distribution.s3_distribution.domain_name}/${aws_s3_bucket_object.image-upload.key}"
}

resource "aws_cloudfront_distribution" "s3_distribution" {
    default_cache_behavior {
        allowed_methods  = ["DELETE", "GET", "HEAD", "OPTIONS", "PATCH", "POST", "PUT"]
        cached_methods   = ["GET", "HEAD"]
        target_origin_id = local.s3_origin_id
        forwarded_values {
            query_string = false
            cookies {
                forward = "none"
            }
        }
        viewer_protocol_policy = "allow-all"
    }

    enabled             = true

    origin {
        domain_name = aws_s3_bucket.image-bucket.bucket_domain_name
        origin_id   = local.s3_origin_id
    }

    restrictions {
        geo_restriction {
        restriction_type = "none"
        }
    }

    viewer_certificate {
        cloudfront_default_certificate = true
    }

    connection {
        type    = "ssh"
        user    = "ec2-user"
        host    = aws_instance.LinuxServer.public_ip
        port    = 22
        private_key = tls_private_key.webserver_key.private_key_pem
    }

    provisioner "remote-exec" {
        inline  = [
            # "sudo su << \"EOF\" \n echo \"<img src='${self.domain_name}'>\" >> /var/www/html/test.html \n \"EOF\""
            "sudo su << EOF",
            "echo \"<img src='http://${self.domain_name}/${aws_s3_bucket_object.image-upload.key}'>\" >> /var/www/html/test.html",
            "EOF"
        ]
    }
}
