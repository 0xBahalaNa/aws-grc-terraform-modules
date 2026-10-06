output "compliance_attestation" {
  description = "Self-verifying evidence map from the vpc-boundary module (Lab 2.4 pattern)."
  value       = module.enclave.compliance_attestation
}
