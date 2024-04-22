import {
  to = module.cdn.aws_cloudfront_distribution.default[0]
  id = "E27C9HGPZVK7G9" # update
}

module "cdn" {
  source                 = "git::https://github.com/cloudposse/terraform-aws-cloudfront-cdn?ref=1.1.0"
  acm_certificate_arn    = "arn:aws:acm:us-east-1:604880673236:certificate/4c3de8b3-6529-4c45-826b-1766b79e1144" # update
  aliases                = ["16.aws-waf-testing.venkatamutyala.com"] # update
  origin_domain_name     = "" # update
  dns_aliases_enabled    = false
  name                   = "glueops-cluster"
  price_class            = "PriceClass_100"
  forward_headers        = ["*"]
  forward_query_string   = true
  forward_cookies        = "all"
  default_ttl            = 0
  logging_enabled        = false
  viewer_protocol_policy = "allow-all"
  default_root_object    = null
  web_acl_id             = "arn:aws:wafv2:us-east-1:604880673236:global/webacl/rate-limit-only/ca9c9a96-1836-44da-903b-61961c724ad4" # update
}
