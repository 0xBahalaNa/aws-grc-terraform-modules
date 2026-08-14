output "compliance_attestation" {
  description = "Self-verifying evidence map from the s3-compliant-bucket module (Lab 2.4 pattern)."
  value       = module.evidence_bucket.compliance_attestation
}
