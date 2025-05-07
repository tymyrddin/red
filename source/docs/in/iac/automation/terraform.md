# Set up terraform

Terraform is open source and [supports a number of cloud providers](https://registry.terraform.io). We can SSH into
our bouncing servers and download the tool:

```text
root@Bouncer:~/# wget\
https://releases.hashicorp.com/terraform/1.2.7/terraform_1.2.7_linux_amd64.zip
root@Bouncer:~/# unzip terraform_1.2.7_linux_amd64.zip
root@Bouncer:~/# chmod +x terraform
```

Terraform will interact with the AWS Cloud using valid credentials provided.