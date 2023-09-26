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
