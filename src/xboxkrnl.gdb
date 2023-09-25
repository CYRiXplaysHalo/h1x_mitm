set $xboxkrnl_base = 0x80010000

# addresses for xboxkrnl 4132
set $XcRC4Crypt_ofs         = 0x20be5
set $XcHMAC_ofs             = 0x20beb
set $XcModExp_ofs           = 0x20c25
set $XcDESKeyParity_ofs     = 0x20c41
set $XcKeyTable_ofs         = 0x20c47
set $XcBlockCryptCBC_ofs    = 0x20c69
set $XboxLANKey_ofs         = 0x2bf08

set $XcRC4Crypt             = $xboxkrnl_base + $XcRC4Crypt_ofs
set $XcHMAC                 = $xboxkrnl_base + $XcHMAC_ofs
set $XcModExp               = $xboxkrnl_base + $XcModExp_ofs
set $XcDESKeyParity         = $xboxkrnl_base + $XcDESKeyParity_ofs
set $XcKeyTable             = $xboxkrnl_base + $XcKeyTable_ofs
set $XcBlockCryptCBC        = $xboxkrnl_base + $XcBlockCryptCBC_ofs
set $XboxLANKey             = $xboxkrnl_base + $XboxLANKey_ofs

define xboxkrnl_set_breakpoints
    break *$XcRC4Crypt
    break *$XcHMAC
    break *$XcModExp
    break *$XcDESKeyParity
    break *$XcKeyTable
    break *$XcBlockCryptCBC
end

define xboxkrnl_print
    if $pc == $XcRC4Crypt
        echo XcRC4Crypt\n
        xc_rc4_crypt
    end
    if $pc == $XcHMAC
        echo XcHMAC\n
        xc_hmac
    end
    if $pc == $XcModExp
        echo XcModExp\n
        xc_mod_exp
    end
    if $pc == $XcDESKeyParity
        echo XcDESKeyParity\n
        xc_des_key_parity
    end
    if $pc == $XcKeyTable
        echo XcKeyTable\n
        xc_key_table
    end
    if $pc == $XcBlockCryptCBC
        echo XcBlockCryptCBC\n
        xc_block_crypt_cbc
    end
end

define xboxkrnl
    delete

    xboxkrnl_set_breakpoints

    while 1
        continue
        xboxkrnl_print
    end
end

define xc_rc4_crypt
    set $state = *(char**)($sp+0x4)
    set $len = *(int*)($sp+0x8)
    set $buf = *(char**)($sp+0xc)

    printf "input @ %p+%d\n", $buf, $len
    dump binary memory out $buf $buf+$len
    !hexdump -vC out

    until *$sp

    printf "output @ %p+%d\n", $buf, $len
    dump binary memory out $buf $buf+$len
    !hexdump -vC out
end

define xc_hmac
    set $key = *(char**)($sp+0x4)
    set $key_len = *(int*)($sp+0x8)
    set $data0 = *(char**)($sp+0xc)
    set $data0_len = *(int*)($sp+0x10)
    set $data1 = *(char**)($sp+0x14)
    set $data1_len = *(int*)($sp+0x18)
    set $output = *(char**)($sp+0x1c)

    printf "key @ %p+%d:\n", $key, $key_len
    dump binary memory out $key $key+$key_len
    !hexdump -vC out

    printf "data0 @ %p+%d:\n", $data0, $data0_len
    dump binary memory out $data0 $data0+$data0_len
    !hexdump -vC out

    if $data1_len > 0
        printf "data1 @ %p+%d:\n", $data1, $data1_len
        dump binary memory out $data1 $data1+$data1_len
        !hexdump -vC out
    end

    until *$sp

    printf "output @ %p:\n", $output
    dump binary memory out $output $output+20
    !hexdump -vC out
end

# a = b ** c (mod d)
# power = base ** exponent (mod modulo)
define xc_mod_exp
    set $power = *(char**)($sp+0x4)
    set $base = *(char**)($sp+0x8)
    set $exponent = *(char**)($sp+0xc)
    set $modulo = *(char**)($sp+0x10)
    set $word_count = *(int*)($sp+0x14)

    set $len = 4*$word_count

    printf "base @ %p+%d\n", $base, $len
    dump binary memory out $base $base+$len
    !hexdump -vC out

    printf "exponent @ %p+%d\n", $exponent, $len
    dump binary memory out $exponent $exponent+$len
    !hexdump -vC out

    printf "modulo @ %p+%d\n", $modulo, $len
    dump binary memory out $modulo $modulo+$len
    !hexdump -vC out

    until *$sp

    printf "power @ %p+%d\n", $modulo, $len
    dump binary memory out $power $power+$len
    !hexdump -vC out
end

define xc_des_key_parity
    set $key = *(char**)($sp+0x4)
    set $key_len = *(int*)($sp+0x8)

    printf "key in @ %p+%d:\n", $key, $key_len
    dump binary memory out $key $key+$key_len
    !hexdump -vC out

    until *$sp

    printf "key out:\n"
    dump binary memory out $key $key+$key_len
    !hexdump -vC out
end

define xc_key_table
    set $cipher = *(int*)($sp+0x4)
    set $key_table = *(char**)($sp+0x8)
    set $key = *(char**)($sp+0xc)

    if $cipher == 1
        set $key_len = 24
    else
        set $key_len = 8
    end

    printf "cipher: %d\n", $cipher

    printf "key @ %p+%d:\n", $key, $key_len
    dump binary memory out $key $key+$key_len
    !hexdump -vC out
end

define xc_block_crypt_cbc
    set $cipher = *(int*)($sp+0x4)
    set $buf_len = *(int*)($sp+0x8)
    set $buf_out = *(char**)($sp+0xc)
    set $buf_in = *(char**)($sp+0x10)
    set $key_table = *(char**)($sp+0x14)
    set $encrypt = *(int*)($sp+0x18)
    set $iv = *(char**)($sp+0x1c)

    printf "keytable @ %p\n", $key_table

    printf "iv @ %p+%d\n", $iv, 8
    dump binary memory out $iv $iv+8
    !hexdump -vC out

    printf "input @ %p+%d:\n", $buf_in, $buf_len
    dump binary memory out $buf_in $buf_in+$buf_len
    !hexdump -vC out

    until *$sp

    if $encrypt == 1
        printf "encrypted"
    else
        printf "decrypted"
    end
    printf " @ %p+%d:\n", $buf_out, $buf_len
    dump binary memory out $buf_out $buf_out+$buf_len
    !hexdump -vC out
end

define xbox_lan_key
    printf "xbox_lan_key @ %p+%d\n", $XboxLANKey, 16
    dump binary memory out $XboxLANKey $XboxLANKey+16
    !hexdump -vC out
end
