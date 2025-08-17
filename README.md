# 🔹 Project #1: Build & Secure Static Site with **S3 + CloudFront + WAF + HTTPS**

A production‑grade, end‑to‑end project that:

* Hosts a static website in **Amazon S3** (private bucket)
* Serves it globally through **Amazon CloudFront** with **OAC** (Origin Access Control)
* Secures it with **AWS WAFv2** managed rules + rate limiting
* Uses a custom domain + **ACM** certificate + **HTTPS** (optional Route 53)
* Includes **CI/CD (GitHub Actions)** to upload assets and invalidate CloudFront

> Target audience: Cloud/DevOps engineers. Time to complete: \~45–90 min. Terraform v1.7+, AWS provider v5+.

---

## 🧱 Architecture (High Level)

```
Users → CloudFront (Global) —(HTTPS)—> S3 (Private Bucket, OAC)
                     └─> WAFv2 WebACL (Global)
                     └─> Response Headers Policy (HSTS/CSP/etc.)
Optional: Route 53 → Custom Domain → ACM cert (us-east-1 for CloudFront)
```

---

## 📁 Repository Layout

```
secure-static-site/
├─ terraform/
│  ├─ main.tf
│  ├─ providers.tf
│  ├─ variables.tf
│  ├─ outputs.tf
│  ├─ waf.tf
│  ├─ cloudfront.tf
│  ├─ s3.tf
│  ├─ policies/
│  │  ├─ iam_ci_policy.json
│  │  └─ s3_bucket_policy.tpl.json
│  └─ versions.tf
├─ site/
│  ├─ index.html
│  ├─ assets/
│  │  └─ example.png
│  └─ 404.html
├─ .github/
│  └─ workflows/
│     └─ deploy.yml
├─ Makefile
└─ README.md  (this file)
```

---

## ✅ Prerequisites

* AWS account with permissions to create S3, CloudFront, ACM, WAF, IAM
* (Optional) A hosted zone in Route 53 for your domain
* Terraform ≥ 1.5 and AWS CLI configured locally
* A public GitHub repo if you want CI/CD

---

## ⚙️ Terraform — `versions.tf`

```hcl
terraform {
  required_version = ">= 1.5.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.50"
    }
  }
}
```

## 🌍 Providers — `providers.tf`

> CloudFront & WAF & ACM must be created/attached in **us-east-1** (global edge region)

```hcl
provider "aws" {
  region = var.aws_region          # e.g., ap-south-1
}

provider "aws" {
  alias  = "us_east_1"
  region = "us-east-1"
}
```

## 🔧 Variables — `variables.tf`

```hcl
variable "project_name" { type = string  default = "secure-static-site" }
variable "aws_region"   { type = string  default = "ap-south-1" }

# Domain is optional. If not set, CloudFront will use its default domain.
variable "domain_name"         { type = string  default = "" } # e.g., "www.example.com"
variable "hosted_zone_id"      { type = string  default = "" } # Route53 hosted zone ID (optional)

# Cache/TTL sizing
variable "default_ttl" { type = number default = 3600 }
variable "min_ttl"     { type = number default = 0 }
variable "max_ttl"     { type = number default = 86400 }
```

## 🪣 S3 (private) — `s3.tf`

```hcl
resource "aws_s3_bucket" "site" {
  bucket = "${var.project_name}-${random_id.suffix.hex}"
}

resource "random_id" "suffix" {
  byte_length = 4
}

resource "aws_s3_bucket_ownership_controls" "site" {
  bucket = aws_s3_bucket.site.id
  rule {
    object_ownership = "BucketOwnerPreferred"
  }
}

resource "aws_s3_bucket_public_access_block" "site" {
  bucket                  = aws_s3_bucket.site.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# Put a simple index and 404 page using local files (optional — or use CI/CD)
resource "aws_s3_object" "index" {
  bucket       = aws_s3_bucket.site.id
  key          = "index.html"
  source       = "${path.module}/../site/index.html"
  content_type = "text/html"
}

resource "aws_s3_object" "notfound" {
  bucket       = aws_s3_bucket.site.id
  key          = "404.html"
  source       = "${path.module}/../site/404.html"
  content_type = "text/html"
}
```

## 🌐 Certificate (us-east-1) & DNS (optional) — `main.tf`

```hcl
# Request/lookup ACM cert only if domain provided
locals {
  use_custom_domain = length(var.domain_name) > 0
}

resource "aws_acm_certificate" "cert" {
  provider          = aws.us_east_1
  count             = local.use_custom_domain ? 1 : 0
  domain_name       = var.domain_name
  validation_method = "DNS"
}

# If using Route53, create validation records
resource "aws_route53_record" "cert_validation" {
  count   = local.use_custom_domain && length(var.hosted_zone_id) > 0 ? length(aws_acm_certificate.cert[0].domain_validation_options) : 0
  zone_id = var.hosted_zone_id
  name    = aws_acm_certificate.cert[0].domain_validation_options[count.index].resource_record_name
  type    = aws_acm_certificate.cert[0].domain_validation_options[count.index].resource_record_type
  records = [aws_acm_certificate.cert[0].domain_validation_options[count.index].resource_record_value]
  ttl     = 60
}

resource "aws_acm_certificate_validation" "cert" {
  provider                = aws.us_east_1
  count                   = local.use_custom_domain && length(var.hosted_zone_id) > 0 ? 1 : 0
  certificate_arn         = aws_acm_certificate.cert[0].arn
  validation_record_fqdns = [for r in aws_route53_record.cert_validation : r.fqdn]
}
```

## ☁️ CloudFront + OAC + Security Headers — `cloudfront.tf`

```hcl
# Response headers policy to add security headers
resource "aws_cloudfront_response_headers_policy" "security" {
  name = "${var.project_name}-security-headers"

  security_headers_config {
    content_type_options { override = true }
    frame_options { frame_option = "DENY" override = true }
    referrer_policy { referrer_policy = "same-origin" override = true }
    xss_protection { protection = true mode_block = true override = true }
    strict_transport_security {
      access_control_max_age_sec = 63072000 # 2 years
      include_subdomains         = true
      preload                    = true
      override                   = true
    }

    content_security_policy {
      content_security_policy = "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; script-src 'self'; object-src 'none'; base-uri 'self';"
      override                = true
    }
  }
}

# OAC to securely access S3
resource "aws_cloudfront_origin_access_control" "oac" {
  name                              = "${var.project_name}-oac"
  description                       = "OAC for S3 origin"
  signing_behavior                   = "always"
  signing_protocol                   = "sigv4"
  origin_access_control_origin_type  = "s3"
}

# Distribution
resource "aws_cloudfront_distribution" "cdn" {
  enabled             = true
  is_ipv6_enabled     = true
  comment             = var.project_name

  origin {
    domain_name              = aws_s3_bucket.site.bucket_regional_domain_name
    origin_id                = "s3-origin"
    origin_access_control_id = aws_cloudfront_origin_access_control.oac.id
  }

  default_cache_behavior {
    allowed_methods  = ["GET", "HEAD"]
    cached_methods   = ["GET", "HEAD"]
    target_origin_id = "s3-origin"

    viewer_protocol_policy = "redirect-to-https"

    response_headers_policy_id = aws_cloudfront_response_headers_policy.security.id

    forwarded_values {
      query_string = false
      cookies { forward = "none" }
    }

    min_ttl     = var.min_ttl
    default_ttl = var.default_ttl
    max_ttl     = var.max_ttl
  }

  custom_error_response {
    error_code            = 404
    response_code         = 404
    response_page_path    = "/404.html"
    error_caching_min_ttl = 60
  }

  restrictions {
    geo_restriction { restriction_type = "none" }
  }

  viewer_certificate {
    # If custom domain provided & cert validated, use it; else use default CF cert
    acm_certificate_arn            = local.use_custom_domain && length(var.hosted_zone_id) > 0 ? aws_acm_certificate_validation.cert[0].certificate_arn : null
    cloudfront_default_certificate = !(local.use_custom_domain && length(var.hosted_zone_id) > 0)
    minimum_protocol_version       = "TLSv1.2_2021"
    ssl_support_method             = local.use_custom_domain ? "sni-only" : null
  }

  aliases = local.use_custom_domain ? [var.domain_name] : []
}

# S3 bucket policy allowing only this CloudFront distribution via OAC
# (Rendered from template after distribution exists to avoid circular deps)
data "aws_caller_identity" "current" {}

data "aws_iam_policy_document" "s3_oac" {
  statement {
    effect = "Allow"
    principals { type = "Service" identifiers = ["cloudfront.amazonaws.com"] }
    actions   = ["s3:GetObject"]
    resources = ["${aws_s3_bucket.site.arn}/*"]

    condition {
      test     = "StringEquals"
      variable = "AWS:SourceArn"
      values   = [aws_cloudfront_distribution.cdn.arn]
    }
  }
}

resource "aws_s3_bucket_policy" "site" {
  bucket = aws_s3_bucket.site.id
  policy = data.aws_iam_policy_document.s3_oac.json
}

# Optional: Route53 alias record to CloudFront
resource "aws_route53_record" "alias" {
  count   = local.use_custom_domain && length(var.hosted_zone_id) > 0 ? 1 : 0
  zone_id = var.hosted_zone_id
  name    = var.domain_name
  type    = "A"

  alias {
    name                   = aws_cloudfront_distribution.cdn.domain_name
    zone_id                = aws_cloudfront_distribution.cdn.hosted_zone_id
    evaluate_target_health = false
  }
}
```

## 🛡️ WAFv2 (Managed Rules + Rate Limit) — `waf.tf`

```hcl
resource "aws_wafv2_web_acl" "web" {
  provider = aws.us_east_1
  name     = "${var.project_name}-waf"
  scope    = "CLOUDFRONT"     # must be CLOUDFRONT for distributions
  default_action { allow {} }

  visibility_config {
    sampled_requests_enabled = true
    cloudwatch_metrics_enabled = true
    metric_name = "${var.project_name}-waf"
  }

  rule {
    name     = "AWSManagedRulesCommonRuleSet"
    priority = 1
    override_action { none {} }
    statement { managed_rule_group_statement { vendor_name = "AWS" name = "AWSManagedRulesCommonRuleSet" } }
    visibility_config { sampled_requests_enabled = true cloudwatch_metrics_enabled = true metric_name = "common" }
  }

  rule {
    name     = "AWSManagedRulesKnownBadInputsRuleSet"
    priority = 2
    override_action { none {} }
    statement { managed_rule_group_statement { vendor_name = "AWS" name = "AWSManagedRulesKnownBadInputsRuleSet" } }
    visibility_config { sampled_requests_enabled = true cloudwatch_metrics_enabled = true metric_name = "bad-inputs" }
  }

  rule {
    name     = "AWSManagedRulesAmazonIpReputationList"
    priority = 3
    override_action { none {} }
    statement { managed_rule_group_statement { vendor_name = "AWS" name = "AWSManagedRulesAmazonIpReputationList" } }
    visibility_config { sampled_requests_enabled = true cloudwatch_metrics_enabled = true metric_name = "ip-rep" }
  }

  rule {
    name     = "SQLi"
    priority = 4
    override_action { none {} }
    statement { managed_rule_group_statement { vendor_name = "AWS" name = "AWSManagedRulesSQLiRuleSet" } }
    visibility_config { sampled_requests_enabled = true cloudwatch_metrics_enabled = true metric_name = "sqli" }
  }

  rule {
    name     = "RateLimit"
    priority = 5
    action { block {} }
    statement { rate_based_statement { limit = 2000 aggregate_key_type = "IP" } }
    visibility_config { sampled_requests_enabled = true cloudwatch_metrics_enabled = true metric_name = "ratelimit" }
  }
}

# Attach the WebACL to the CloudFront distribution
resource "aws_cloudfront_distribution" "cdn_attach" {
  # This is a Terraform trick: use 'lifecycle { ignore_changes = [*] }' is discouraged.
  # Instead, set web_acl_id on the main resource via depends_on.
  # We'll set the association directly on the main distribution using its argument.
}
```

🔗 **Attach WAF on the main distribution** (update `cloudfront.tf`):

```hcl
resource "aws_cloudfront_distribution" "cdn" {
  # ...existing config...
  web_acl_id = aws_wafv2_web_acl.web.arn
}
```

---

## 📤 Outputs — `outputs.tf`

```hcl
output "bucket_name" { value = aws_s3_bucket.site.bucket }
output "cloudfront_domain" { value = aws_cloudfront_distribution.cdn.domain_name }
output "cloudfront_id"     { value = aws_cloudfront_distribution.cdn.id }
output "site_url" {
  value = length(var.domain_name) > 0 ? var.domain_name : aws_cloudfront_distribution.cdn.domain_name
}
```

---

## 🖥️ Sample Site — `site/index.html`

```html
<!doctype html>
<html>
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Secure Static Site</title>
</head>
<body>
  <main style="max-width:720px;margin:40px auto;font-family:system-ui,Segoe UI,Roboto,sans-serif;">
    <h1>✅ Deployed via S3 + CloudFront + WAF</h1>
    <p>If you can see this, your pipeline is working! ✨</p>
    <img src="assets/example.png" alt="Example" style="max-width:100%" />
  </main>
</body>
</html>
```

### `site/404.html`

```html
<!doctype html>
<html><body><h1>404 — Not found</h1></body></html>
```

---

## 🤖 CI/CD — GitHub Actions (`.github/workflows/deploy.yml`)

> Uses OIDC to assume an IAM role and deploy site changes automatically on push to `main`.

```yaml
name: Deploy Static Site

on:
  push:
    branches: ["main"]
    paths:
      - "site/**"
      - "terraform/**"

permissions:
  id-token: write
  contents: read

jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout
        uses: actions/checkout@v4

      - name: Configure AWS credentials (OIDC)
        uses: aws-actions/configure-aws-credentials@v4
        with:
          role-to-assume: ${{ secrets.DEPLOY_ROLE_ARN }}
          aws-region: ap-south-1

      - name: Sync site to S3
        run: |
          aws s3 sync site/ s3://$BUCKET_NAME/ --delete --cache-control max-age=3600
        env:
          BUCKET_NAME: ${{ secrets.S3_BUCKET_NAME }}

      - name: Create CloudFront invalidation
        run: |
          aws cloudfront create-invalidation --distribution-id $DISTRIBUTION_ID --paths "/*"
        env:
          DISTRIBUTION_ID: ${{ secrets.CF_DISTRIBUTION_ID }}
```

### Minimal IAM for CI Role — `policies/iam_ci_policy.json`

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "S3Write",
      "Effect": "Allow",
      "Action": ["s3:PutObject", "s3:DeleteObject", "s3:ListBucket"],
      "Resource": [
        "arn:aws:s3:::${bucket}",
        "arn:aws:s3:::${bucket}/*"
      ]
    },
    {
      "Sid": "InvalidateCF",
      "Effect": "Allow",
      "Action": ["cloudfront:CreateInvalidation"],
      "Resource": "arn:aws:cloudfront::${account_id}:distribution/${distribution_id}"
    }
  ]
}
```

> Replace `${bucket}`, `${account_id}`, `${distribution_id}` at attach time (or use Terraform to render/push this policy).

**GitHub OIDC Role Trust Policy (attach to the role you create):**

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {"Federated": "arn:aws:iam::<ACCOUNT_ID>:oidc-provider/token.actions.githubusercontent.com"},
      "Action": "sts:AssumeRoleWithWebIdentity",
      "Condition": {
        "StringEquals": {"token.actions.githubusercontent.com:aud": "sts.amazonaws.com"},
        "StringLike": {"token.actions.githubusercontent.com:sub": "repo:<owner>/<repo>:ref:refs/heads/main"}
      }
    }
  ]
}
```

---

## 🧪 Makefile (optional convenience)

```make
init:
	cd terraform && terraform init

plan:
	cd terraform && terraform plan -out tfplan

apply:
	cd terraform && terraform apply -auto-approve tfplan

outputs:
	cd terraform && terraform output

sync:
	aws s3 sync site/ s3://$$(cd terraform && terraform output -raw bucket_name)/ --delete --cache-control max-age=3600

invalidate:
	aws cloudfront create-invalidation --distribution-id $$(cd terraform && terraform output -raw cloudfront_id) --paths "/*"
```

---

## 🚀 Deployment Steps

1. **Clone & Configure**

```bash
git clone <your-repo> secure-static-site
cd secure-static-site/terraform
```

* Edit `variables.tf` (or create `terraform.tfvars`) to set `aws_region`.
* (Optional) Set `domain_name` and `hosted_zone_id` if you have Route 53 and want HTTPS on your own domain.

2. **Init & Apply**

```bash
terraform init
terraform plan -out tfplan
terraform apply -auto-approve tfplan
terraform output
```

* Note the `bucket_name`, `cloudfront_domain`, and `cloudfront_id` outputs.

3. **Upload Content** (if not using CI yet)

```bash
aws s3 sync ../site/ s3://<bucket_name>/ --delete --cache-control max-age=3600
aws cloudfront create-invalidation --distribution-id <cloudfront_id> --paths "/*"
```

4. **(Optional) Route 53 DNS**

* If using a custom domain, wait for ACM validation to succeed.
* Create/update the A-record that points to the CloudFront domain (Terraform already does this if `hosted_zone_id` was given).

5. **(Optional) Enable CI/CD**

* Create the IAM role with OIDC trust & attach the policy.
* Add repo secrets: `DEPLOY_ROLE_ARN`, `S3_BUCKET_NAME`, `CF_DISTRIBUTION_ID`.
* Push to `main` → pipeline runs, syncs S3, invalidates CF.

---

## 🔒 Security Checklist

* [x] S3 bucket is private; **no public access** (enforced via Public Access Block)
* [x] Access from CloudFront only via **OAC** and bucket policy **AWS\:SourceArn = distribution ARN**
* [x] CloudFront **HTTPS only**, TLS v1.2\_2021
* [x] **Response headers** add HSTS, CSP, XSS, X-Frame-Options, etc.
* [x] **WAFv2** managed rules + IP reputation + SQLi + **rate limit**
* [x] Optional **Geo** blocking (add a `geo_match_statement` rule if needed)
* [x] CloudFront & WAF created in **us-east-1** as required
* [x] Minimal IAM for CI; recommend GitHub OIDC instead of long‑lived keys

---

## 🧰 Useful Tweaks

* Add **logging**: S3 access logs & CloudFront standard logs to an S3 log bucket.
* Add **image optimization**: CloudFront functions/Lambda\@Edge.
* Add **SPA routing**: Map 403→200 to `/index.html` for React/SPA.
* Add **Geo restriction** rule in WAF for regions you want to block or allow.

---

## 🧭 Troubleshooting

* **AccessDenied from S3**: Check bucket policy includes the **exact** CloudFront distribution ARN and OAC is attached.
* **ACM validation stuck**: Ensure DNS validation records exist in the **hosted zone for the same domain**.
* **WAF not applying**: Confirm `web_acl_id` is set on the distribution and WAF scope = `CLOUDFRONT`.
* **No HTTPS on custom domain**: You must use ACM cert in **us-east-1** for CloudFront.

---

## 🗑️ Teardown

```bash
cd terraform
terraform destroy -auto-approve
```

---

## 📓 Notes

* Terraform intentionally uploads `index.html`/`404.html` once; ongoing content changes should use CI/CD or `aws s3 sync`.
* Change CSP if you need to load external fonts, analytics, etc.

---

Happy shipping! 🚀
