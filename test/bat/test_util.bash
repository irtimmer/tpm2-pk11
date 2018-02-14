create_key() {
    tpm2_createprimary -H o -g sha256 -G rsa -C po.ctx
    tpm2_create -c po.ctx -g sha256 -G rsa -u key.pub -r key.priv
    tpm2_load -c po.ctx -u key.pub -r key.priv -C obj.ctx
    tpm2_evictcontrol -A o -c obj.ctx -H 0x81010010
}

delete_key() {
    tpm2_evictcontrol -A o -H 0x81010010 -p 0x81010010
    rm key.pub
    rm key.priv
}
