# Dump any encryption/decryption keys as soon as they are used. Provide the key
# directory to decrypt.c to decrypt remaining packets in real-time.
#
# Tested to work with:
#  - Halo: Combat Evolved
#  - Halo 2

define dump_keys
    set $XcKeyTable = 0x80030c47
    !rm -rf keys && mkdir keys
    break *$XcKeyTable
    set $n = 20
    while $n > 0
        continue
        set $cipher = *(int*)($sp+0x4)
        set $key = *(char**)($sp+0xc)

        if $cipher == 1
            set $key_len = 24
        else
            set $key_len = 8
        end

        # get iv from previous stack frame (assumes calling function is
        # identical between different games)
        set $iv = *(char**)($sp+0x1b0)
        set $spi = *(int*)($iv-0x8)

        dump binary memory key $key $key+$key_len
        # mv key file to "keys/$spi"
        pipe printf "%08x", $spi | xargs -I{} mv key keys/{}

        set $n = $n - 1
    end
    quit
end
