# addresses are for h1 pal

set $boot_rc4_key = 0x001b3b41
set $boot_rc4_crypt = 0x001b3b55

set $init_des3_hmac0 = 0x001b4582
set $init_des3_hmac1 = 0x001b459f
set $init_des3_key_parity = 0x001b45c4

set $hmac_key_addr0 = 0xd00428f0
set $hmac_key_addr1 = 0xd0042930

set $mod_exp_c_addr0 = 0xd0042900
set $mod_exp_c_addr1 = 0xd0042940

set $init_sa1 = 0x001b42a2
set $init_sa1_hmac = 0x001b42c8
set $init_sa1_rc4_crypt = 0x001b3bb6
set $init_sa1_mod_exp = 0x001b42f1

set $des1_des3_crypt = 0x001b5213

set $init_sa = 0x001b4e7e
set $init_sa_hmac = 0x001b4f53

set $init_des1 = 0x001b4035
set $init_des1_mod_exp = 0x001b405b
set $init_des1_hmac0 = 0x001b40b4
set $init_des1_hmac1 = 0x001b40d8
set $init_des1_key_parity = 0x001b40eb

set $encrypt_post_hmac = 0x1b488b

set $cbc_crypt = 0x001b3f64

define monitor
    delete

    xboxkrnl_set_breakpoints

    break *$boot_rc4_key
    break *$boot_rc4_crypt

    break *$init_des3_hmac0
    break *$init_des3_hmac1
    break *$init_des3_key_parity

    # written to from init_sa1
    watch *$hmac_key_addr0
    watch *$hmac_key_addr1

    watch *$mod_exp_c_addr0
    watch *$mod_exp_c_addr1

    break *$des1_des3_crypt

    break *$init_sa1_hmac
    break *$init_sa1_rc4_crypt
    break *$init_sa1_mod_exp

    break *$init_sa
    break *$init_sa_hmac

    break *$init_des1
    break *$init_des1_mod_exp
    break *$init_des1_hmac0
    break *$init_des1_hmac1
    break *$init_des1_key_parity

    break *$encrypt_post_hmac

    break *$cbc_crypt

    while 1
        continue

        if $pc == $boot_rc4_key
            echo boot_rc4_key\n
            xc_rc4_key
        end
        if $pc == $boot_rc4_crypt
            echo boot_rc4_crypt\n
        end
        if $pc == $init_des3_hmac0
            # constant xbox lan key as key (c5 4f 1a..)
            # 0 ++ constant xbe lan key as data0 (00 f3 ca..)
            echo init_des3_hmac0\n
        end
        if $pc == $init_des3_hmac1
            # constant xbox lan key as key (c5 4f 1a..)
            # 1 ++ constant xbe lan key as data0 (01 f3 ca..)
            echo init_des3_hmac1\n
        end
        if $pc == $init_des3_key_parity
            # hmac0_digest[16:20] ++ hmac1_digest[0:20] as input
            # output is used as key for des3 encryption/decryption
            # constant output (c2 b0 31 10 79 2a...)
            echo init_des3_key_parity\n
        end
        if $pc == $des1_des3_crypt
            echo des1_des3_crypt\n
            des1_des3_crypt
        end
        if $pc == $init_sa1_hmac
            echo init_sa1_hmac\n
        end
        if $pc == $init_sa1_rc4_crypt
            echo init_sa1_rc4_crypt\n
        end
        if $pc == $init_sa1_mod_exp
            # base is 2 (last word)
            # exponent is same as in init_des1
            # modulo is same as in init_des1
            # power is written to remote payload_handshake, used as base in their
            # init_des1_mod_exp
            echo init_sa1_mod_exp\n
        end
        if $pc == $init_sa
            echo init_sa\n
            init_sa
        end
        if $pc == $init_sa_hmac
            echo init_sa_hmac\n
            # key seems to be constant per boot
            # key same as for init_des1_hmac{0,1}
            # key located on stack, different addresses:
            #   0xd00428f0, 0xd0042930 => written from init_sa1
            # output[:12] matches 12 last bytes of packet payload, seems to be
            # signature verification
        end
        if $pc == $init_des1
            echo init_des1\n
            init_des1
        end
        if $pc == $init_des1_mod_exp
            # base is from unencrypted handshake payload
            # exponent is from rc4, differs from remote
            # modulo is from binary, loaded at 0x1b8c40
            # both clients get same power with base and exponent differing
            echo init_des1_mod_exp\n
        end
        if $pc == $init_des1_hmac0
            echo init_des1_hmac0\n
        end
        if $pc == $init_des1_hmac1
            echo init_des1_hmac1\n
            # 8 first bytes of output used for key des parity input
        end
        if $pc == $init_des1_key_parity
            echo init_des1_key_parity\n
            # 1st call output used for des1 host src, 2nd for guest
        end
        if $pc == $encrypt_post_hmac
            echo encrypt_post_hmac\n
        end
        if $pc == $cbc_crypt
            echo cbc_crypt\n
            cbc_crypt
        end

        xboxkrnl_print
    end
end

define des1_des3_crypt
    set $payload_ptr = *(char**)($sp+0x4)
    set $unknown1 = *(char**)($sp+0x8)
    set $payload = *(char**)($sp+0xc)
    set $payload_len = *(int*)($sp+0x10)

    printf "payload @ %p+%d:\n", $payload, $payload_len
    dump binary memory out $payload $payload+$payload_len
    !hexdump -vC out

    printf "mac dst @ %p+%d:\n", $payload-34, 6
    dump binary memory out $payload-34 $payload-28
    !hexdump -vC out
    printf "mac src @ %p+%d:\n", $payload-28, 6
    dump binary memory out $payload-28 $payload-22
    !hexdump -vC out

    p/x $payload_ptr
    p/x $unknown1
end

define init_sa
    set $struct = *(char**)($sp+0x4)
    set $some_ptr = *(char**)($sp+0x8)
    set $payload = *(char**)($sp+0xc)

    p/x $struct

    printf "some_ptr? @ %p+%d:\n", $some_ptr, 16
    dump binary memory out $some_ptr $some_ptr+16
    !hexdump -vC out

    printf "payload_handshake @ %p+%d:\n", $payload, 152
    dump binary memory out $payload $payload+152
    !hexdump -vC out
end

define cbc_crypt
    set $encrypt = *(int*)($sp+0x4)
    set $key = *(char**)($sp+0x8)
    set $key_len = *(int*)($sp+0xc)
    set $iv = *(char**)($sp+0x10)
    set $buf = *(char**)($sp+0x14)
    set $buf_len = *(int*)($sp+0x18)

    set $packet_base = $iv - 50
    set $mac_dst = $packet_base
    set $mac_src = $packet_base + 6

    printf "mac dst @ %p+%d:\n", $mac_dst, 6
    dump binary memory out $mac_dst $mac_dst+6
    !hexdump -vC out

    printf "mac src @ %p+%d:\n", $mac_src, 6
    dump binary memory out $mac_src $mac_src+6
    !hexdump -vC out

    set $spi = $iv - 8
    printf "spi: "
    x/wx $spi

    set $udp_len = 256 * (*(char*)($spi - 4)) + *(char*)($spi - 3)
    printf "udp len: %x\n", $udp_len
    printf "inner len: %x, msg len: %x, extra: %x\n", $udp_len - 24, $buf_len, $udp_len - 24 - $buf_len
end

define init_des1
    set $unknown0 = *(int*)($sp+0x4)
    set $unknown1 = *(char**)($sp+0x8)
    set $unknown2 = *(char**)($sp+0xc)
    set $unknown3 = *(char**)($sp+0x10)
    set $bool_true = *(int*)($sp+0x14)

    p/x $unknown0
    p/x $unknown1
    p/x $unknown2
    p/x $unknown3
    p/x $bool_true
end

define xc_rc4_key
    set $state = *(char**)($sp)
    set $key_len = *(int*)($sp+0x4)
    set $key = *(char**)($sp+0x8)

    printf "input @ %p+%d\n", $key, $key_len
    dump binary memory out $key $key+$key_len
    !hexdump -vC out

    until *$pc+5

    printf "state @ %p+%d\n", $state, 0x104
    dump binary memory out $state $state+0x104
    !hexdump -vC out
end
