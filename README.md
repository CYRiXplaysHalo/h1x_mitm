# h1x_mitm
Branch of Noah Hellman's MITM script for Halo 1 on Xbox. Largely using this repository to store all of my thoughts and research around this. 

# Questions, Tests, and Answers

I am slightly out of my depth here, but: 

- Does the game send a packet signifying the end of the game?
    - No, it does not. Each box determines the game is over as it knows the rules of the game and the state of the game.
- Do we know enough about how a game starts that we don't need a box (emulated or real) to host and start a game?
    - No, not yet. While all boxes exchange keys/info with the host were we to fully understand those and retrieve/set them to some known values there is still unknown game logic and a PRNG we would need to understand first before we could initialize the game state for a system link match.
        - Image for reference: https://hllmn.net/blog/2023-09-18_h1x-net/key.svg
        - We could determine/set XboxLANKey, TitleLANKey, d(constant), and the handshake paypload but we don't understand how XcRC4Crypt (the PRNG) works.
- Can we MITM the Host?
    - Not as the code is currently written. It takes the action of a guest box joining a host box to initiate the MITM attack.
    - With an emulator we can read the entire memory of an xbox, so that can be used to parse out game state in even greater detail with has already be done.
- How does the game detect desync?
    - Noah's response to that is this:
        - Perhaps they are using the hash value that is sent by the host. The host might calculate a hash of its entire game state, if the guest client then obtains a different hash for its game state compared to the one it receives by the host, it will present the desync message and try to reset. Modifying this hash value once using our MITM client causes the desync message to flash by for a second on the guest console and make the guest players immediately leave the game.
    - AFAICT, this isn't a hash but the `global_random` of the game. I do think it is fair to believe this and the `tick` values are the logic to determine desync.
        - Every tick, the host sends the `hash/global_random`, `tick_a` and `tick_b`.
        - Every tick, each guest sends the host their players' inputs with a `tick` value.
        - My theory/hope is simply if the guest's `tick` value does not match either `tick_a` or `tick_b` values last sent by the host, then the client decides it is too far out of sync and crashes the game.
              - If that's the case, then the MITM could be modified to ensure the `tick_a` and `tick_b` values sent from the host always match the most recent `tick` value sent by the guest.
                  - If that worked, then it would allow the games to significantly desync from each other or more likely allow one guest client to control the inputs of every player.
          
