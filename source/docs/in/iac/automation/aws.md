# Set up AWS on bouncer

EC2 is the AWS service managing machines, networks, load balancers, etc.

Create an AWS account and [an IAM user](https://serverless-stack.com/chapters/create-an-iam-user.html) to create a
programmatic account for username terraform and grant it full access to all EC2 operations by 
attaching the AmazonEC2FullAccess policy. 

Download the credentials as a `.csv` file. Note the `Access key ID` and `Secret access key`.

Download the AWS command line tool and save your credentials:

```text
root@Bouncer:~/# apt install awscli
root@Bouncer:~/# aws configure
AWS Access Key ID [None]: XXXXXXXXXXXXXXXXXXX
AWS Secret Access Key [None]: XXXXXXXXXXXXXXXXXXXXXX...
Default region name [None]: eu-west-1
```

Set up a folder to host the infrastructure’s configuration:

    root@Bouncer:~/# mkdir infra && cd infra

Create two files: `provider.tf` and `main.tf`:

```text
# provider.tf
provider "aws" {
region = "eu-west-1"
version = "~> 2.28"
}
```

Check all the [prepared Ubuntu images for your region](https://cloud-images.ubuntu.com/locator/ec2/) and 
choose your aws_instance resource for Terraform to spawn a server using the `main.tf` file:

```text
# main.tf
resource "aws_instance" "basic_ec2" {
ami = "ami-0f66b05137bbada09"
instance_type = "hvm:ebs-ssd"
}
```

Save `main.tf` and initialise Terraform for it to download the AWS provider:

    root@Bounce:~/infra# terraform init



