# Dump the encrypted contents of System Link packets in real-time.
#
# Should work with all games that use the XcBlockCryptCBC function.

set $XcBlockCryptCBC = 0x80030c69

define dump_messages
    break *$XcBlockCryptCBC
    while 1
        continue
        set $buf_len = *(int*)($sp+0x8)
        set $buf_out = *(char**)($sp+0xc)
        set $buf_in = *(char**)($sp+0x10)
        set $encrypt = *(int*)($sp+0x18)
        if $encrypt == 1
            set $buf = $buf_in
            printf "encrypted:\n"
        else
            set $buf = $buf_out
            until *(int*)$sp
            printf "decrypted:\n"
        end
        dump binary memory out $buf $buf+$buf_len
        !hexdump -C out
    end
end
