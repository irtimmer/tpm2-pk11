create_key() {
    tpm2_createprimary -a o -g sha256 -G rsa -o po.ctx
    tpm2_create -C po.ctx -g sha256 -G rsa -u key.pub -r key.priv
    tpm2_load -C po.ctx -u key.pub -r key.priv -o obj.ctx
    tpm2_evictcontrol -a o -c obj.ctx -p 0x81010010
}

delete_key() {
    tpm2_evictcontrol -a o -c 0x81010010
    rm key.pub
    rm key.priv
}
