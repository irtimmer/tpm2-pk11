#!/usr/bin/env bats

load test_util

@test "Confirm SSH client functionality" {
    create_key
    run ssh-keygen -D ./libtpm2-pk11.so
    [ $status -eq 0 ]
    echo $output >> $HOME/.ssh/authorized_keys
    host_hostname=`hostname -s`
    test_hostname=`ssh -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no -I ./libtpm2-pk11.so localhost hostname -s`
    [ ${test_hostname} == ${host_hostname} ]
    delete_key
}
