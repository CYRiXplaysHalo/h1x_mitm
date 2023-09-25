define cbc_crypt
    set $encrypt = *(int*)($sp+0x4)
    set $key = *(char**)($sp+0x8)
    set $key_len = *(int*)($sp+0xc)
    set $iv = *(char**)($sp+0x10)
    set $buf = *(char**)($sp+0x14)
    set $buf_len = *(int*)($sp+0x18)

    printf "key @ %p+%d:\n", $key, $key_len
    dump binary memory key $key $key+$key_len
    !hexdump -vC key

    printf "iv @ %p+%d:\n", $iv, 8
    dump binary memory iv $iv $iv+8
    !hexdump -vC iv

    printf "input @ %p+%d:\n", $buf, $buf_len
    dump binary memory input $buf $buf+$buf_len
    !hexdump -vC input

    # run until ret
    until *$sp

    if $encrypt == 1
        printf "encrypted:\n"
    else
        printf "decrypted:\n"
    end
    dump binary memory out $buf $buf+$buf_len
    !hexdump -vC out
end
