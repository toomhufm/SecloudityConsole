tpm2_flushcontext -t
tpm2_unseal -c seal_api.ctx -p pcr:sha256:0,1,2,3
