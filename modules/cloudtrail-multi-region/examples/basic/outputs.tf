output "compliance_attestation" {
  description = "Self-verifying evidence map from the cloudtrail-multi-region module (Lab 2.4 pattern)."
  value       = module.audit_trail.compliance_attestation
}
