output "compliance_attestation" {
  description = "Self-verifying evidence map from the iam-hardening module (Lab 2.4 pattern)."
  value       = module.iam_baseline.compliance_attestation
}
