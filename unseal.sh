#!/bin/bash
sudo tpm2_flushcontext -t
sudo tpm2_unseal -c seal_secret.ctx -p pcr:sha256:0,1,2,3
