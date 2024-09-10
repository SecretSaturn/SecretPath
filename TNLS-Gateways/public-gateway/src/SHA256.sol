// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.25;

library SHA256 {

     /*//////////////////////////////////////////////////////////////
            SHA256 for zkEVMs without a SHA256 precompile
    //////////////////////////////////////////////////////////////*/

    function hashSHA256(bytes32 valueHash) private pure returns (bytes32 output) {
        // pad and format input into array of uint32 words 

        uint32 a = 0x6a09e667;
        uint32 b = 0xbb67ae85;
        uint32 c = 0x3c6ef372;
        uint32 d = 0xa54ff53a;
        uint32 e = 0x510e527f;
        uint32 f = 0x9b05688c;
        uint32 g = 0x1f83d9ab;
        uint32 h = 0x5be0cd19;

        unchecked {
            uint32[64] memory w;
            assembly {
                // this part that pads the data is from rage_pit
                let dataPtr := mload(0x40)
                mstore(dataPtr, valueHash)
                // pad message with 0b1
                mstore(add(32, dataPtr), shl(0xf8, 0x80))
                // end padding with message length
                mstore(add(56, dataPtr), shl(0xc0, 0x100))
                mstore(0x40, add(dataPtr, 64))
                //copy data into w directly
                mstore(add(w, 0x00), shr(0xe0, mload(dataPtr)))
                mstore(add(w, 0x20), shr(0xe0, mload(add(dataPtr, 0x04))))
                mstore(add(w, 0x40), shr(0xe0, mload(add(dataPtr, 0x08))))
                mstore(add(w, 0x60), shr(0xe0, mload(add(dataPtr, 0x0c))))
                mstore(add(w, 0x80), shr(0xe0, mload(add(dataPtr, 0x10))))
                mstore(add(w, 0xa0), shr(0xe0, mload(add(dataPtr, 0x14))))
                mstore(add(w, 0xc0), shr(0xe0, mload(add(dataPtr, 0x18))))
                mstore(add(w, 0xe0), shr(0xe0, mload(add(dataPtr, 0x1c))))
                mstore(add(w, 0x100), shr(0xe0, mload(add(dataPtr, 0x20))))
                mstore(add(w, 0x120), shr(0xe0, mload(add(dataPtr, 0x24))))
                mstore(add(w, 0x140), shr(0xe0, mload(add(dataPtr, 0x28))))
                mstore(add(w, 0x160), shr(0xe0, mload(add(dataPtr, 0x2c))))
                mstore(add(w, 0x180), shr(0xe0, mload(add(dataPtr, 0x30))))
                mstore(add(w, 0x1a0), shr(0xe0, mload(add(dataPtr, 0x34))))
                mstore(add(w, 0x1c0), shr(0xe0, mload(add(dataPtr, 0x38))))
                mstore(add(w, 0x1e0), shr(0xe0, mload(add(dataPtr, 0x3c))))
            }
            w[16] = w[0] + gamma0(w[1]) + w[9] + gamma1(w[14]);
            w[17] = w[1] + gamma0(w[2]) + w[10] + gamma1(w[15]);
            w[18] = w[2] + gamma0(w[3]) + w[11] + gamma1(w[16]);
            w[19] = w[3] + gamma0(w[4]) + w[12] + gamma1(w[17]);
            w[20] = w[4] + gamma0(w[5]) + w[13] + gamma1(w[18]);
            w[21] = w[5] + gamma0(w[6]) + w[14] + gamma1(w[19]);
            w[22] = w[6] + gamma0(w[7]) + w[15] + gamma1(w[20]);
            w[23] = w[7] + gamma0(w[8]) + w[16] + gamma1(w[21]);
            w[24] = w[8] + gamma0(w[9]) + w[17] + gamma1(w[22]);
            w[25] = w[9] + gamma0(w[10]) + w[18] + gamma1(w[23]);
            w[26] = w[10] + gamma0(w[11]) + w[19] + gamma1(w[24]);
            w[27] = w[11] + gamma0(w[12]) + w[20] + gamma1(w[25]);
            w[28] = w[12] + gamma0(w[13]) + w[21] + gamma1(w[26]);
            w[29] = w[13] + gamma0(w[14]) + w[22] + gamma1(w[27]);
            w[30] = w[14] + gamma0(w[15]) + w[23] + gamma1(w[28]);
            w[31] = w[15] + gamma0(w[16]) + w[24] + gamma1(w[29]);
            w[32] = w[16] + gamma0(w[17]) + w[25] + gamma1(w[30]);
            w[33] = w[17] + gamma0(w[18]) + w[26] + gamma1(w[31]);
            w[34] = w[18] + gamma0(w[19]) + w[27] + gamma1(w[32]);
            w[35] = w[19] + gamma0(w[20]) + w[28] + gamma1(w[33]);
            w[36] = w[20] + gamma0(w[21]) + w[29] + gamma1(w[34]);
            w[37] = w[21] + gamma0(w[22]) + w[30] + gamma1(w[35]);
            w[38] = w[22] + gamma0(w[23]) + w[31] + gamma1(w[36]);
            w[39] = w[23] + gamma0(w[24]) + w[32] + gamma1(w[37]);
            w[40] = w[24] + gamma0(w[25]) + w[33] + gamma1(w[38]);
            w[41] = w[25] + gamma0(w[26]) + w[34] + gamma1(w[39]);
            w[42] = w[26] + gamma0(w[27]) + w[35] + gamma1(w[40]);
            w[43] = w[27] + gamma0(w[28]) + w[36] + gamma1(w[41]);
            w[44] = w[28] + gamma0(w[29]) + w[37] + gamma1(w[42]);
            w[45] = w[29] + gamma0(w[30]) + w[38] + gamma1(w[43]);
            w[46] = w[30] + gamma0(w[31]) + w[39] + gamma1(w[44]);
            w[47] = w[31] + gamma0(w[32]) + w[40] + gamma1(w[45]);
            w[48] = w[32] + gamma0(w[33]) + w[41] + gamma1(w[46]);
            w[49] = w[33] + gamma0(w[34]) + w[42] + gamma1(w[47]);
            w[50] = w[34] + gamma0(w[35]) + w[43] + gamma1(w[48]);
            w[51] = w[35] + gamma0(w[36]) + w[44] + gamma1(w[49]);
            w[52] = w[36] + gamma0(w[37]) + w[45] + gamma1(w[50]);
            w[53] = w[37] + gamma0(w[38]) + w[46] + gamma1(w[51]);
            w[54] = w[38] + gamma0(w[39]) + w[47] + gamma1(w[52]);
            w[55] = w[39] + gamma0(w[40]) + w[48] + gamma1(w[53]);
            w[56] = w[40] + gamma0(w[41]) + w[49] + gamma1(w[54]);
            w[57] = w[41] + gamma0(w[42]) + w[50] + gamma1(w[55]);
            w[58] = w[42] + gamma0(w[43]) + w[51] + gamma1(w[56]);
            w[59] = w[43] + gamma0(w[44]) + w[52] + gamma1(w[57]);
            w[60] = w[44] + gamma0(w[45]) + w[53] + gamma1(w[58]);
            w[61] = w[45] + gamma0(w[46]) + w[54] + gamma1(w[59]);
            w[62] = w[46] + gamma0(w[47]) + w[55] + gamma1(w[60]);
            w[63] = w[47] + gamma0(w[48]) + w[56] + gamma1(w[61]);

            // Round 0
            uint32 temp1 = h + sigma1(e) + Ch(e,f,g) + 0x428a2f98 + w[0];
            uint32 temp2 = sigma0(a) + Maj(a,b,c);
            h = g; g = f; f = e; e = d + temp1; d = c; c = b; b = a; a = temp1 + temp2;

            // Round 1
            temp1 = h + sigma1(e) + Ch(e,f,g) + 0x71374491 + w[1];
            temp2 = sigma0(a) + Maj(a,b,c);
            h = g; g = f; f = e; e = d + temp1; d = c; c = b; b = a; a = temp1 + temp2;

            // Round 2
            temp1 = h + sigma1(e) + Ch(e,f,g) + 0xb5c0fbcf + w[2];
            temp2 = sigma0(a) + Maj(a,b,c);
            h = g; g = f; f = e; e = d + temp1; d = c; c = b; b = a; a = temp1 + temp2;

            // Round 3
            temp1 = h + sigma1(e) + Ch(e,f,g) + 0xe9b5dba5 + w[3];
            temp2 = sigma0(a) + Maj(a,b,c);
            h = g; g = f; f = e; e = d + temp1; d = c; c = b; b = a; a = temp1 + temp2;

            // Round 4
            temp1 = h + sigma1(e) + Ch(e,f,g) + 0x3956c25b + w[4];
            temp2 = sigma0(a) + Maj(a,b,c);
            h = g; g = f; f = e; e = d + temp1; d = c; c = b; b = a; a = temp1 + temp2;

            // Round 5
            temp1 = h + sigma1(e) + Ch(e,f,g) + 0x59f111f1 + w[5];
            temp2 = sigma0(a) + Maj(a,b,c);
            h = g; g = f; f = e; e = d + temp1; d = c; c = b; b = a; a = temp1 + temp2;

            // Round 6
            temp1 = h + sigma1(e) + Ch(e,f,g) + 0x923f82a4 + w[6];
            temp2 = sigma0(a) + Maj(a,b,c);
            h = g; g = f; f = e; e = d + temp1; d = c; c = b; b = a; a = temp1 + temp2;

            // Round 7
            temp1 = h + sigma1(e) + Ch(e,f,g) + 0xab1c5ed5 + w[7];
            temp2 = sigma0(a) + Maj(a,b,c);
            h = g; g = f; f = e; e = d + temp1; d = c; c = b; b = a; a = temp1 + temp2;

            // Round 8
            temp1 = h + sigma1(e) + Ch(e,f,g) + 0xd807aa98 + w[8];
            temp2 = sigma0(a) + Maj(a,b,c);
            h = g; g = f; f = e; e = d + temp1; d = c; c = b; b = a; a = temp1 + temp2;

            // Round 9
            temp1 = h + sigma1(e) + Ch(e,f,g) + 0x12835b01 + w[9];
            temp2 = sigma0(a) + Maj(a,b,c);
            h = g; g = f; f = e; e = d + temp1; d = c; c = b; b = a; a = temp1 + temp2;

            // Round 10
            temp1 = h + sigma1(e) + Ch(e,f,g) + 0x243185be + w[10];
            temp2 = sigma0(a) + Maj(a,b,c);
            h = g; g = f; f = e; e = d + temp1; d = c; c = b; b = a; a = temp1 + temp2;

            // Round 11
            temp1 = h + sigma1(e) + Ch(e,f,g) + 0x550c7dc3 + w[11];
            temp2 = sigma0(a) + Maj(a,b,c);
            h = g; g = f; f = e; e = d + temp1; d = c; c = b; b = a; a = temp1 + temp2;

            // Round 12
            temp1 = h + sigma1(e) + Ch(e,f,g) + 0x72be5d74 + w[12];
            temp2 = sigma0(a) + Maj(a,b,c);
            h = g; g = f; f = e; e = d + temp1; d = c; c = b; b = a; a = temp1 + temp2;

            // Round 13
            temp1 = h + sigma1(e) + Ch(e,f,g) + 0x80deb1fe + w[13];
            temp2 = sigma0(a) + Maj(a,b,c);
            h = g; g = f; f = e; e = d + temp1; d = c; c = b; b = a; a = temp1 + temp2;

            // Round 14
            temp1 = h + sigma1(e) + Ch(e,f,g) + 0x9bdc06a7 + w[14];
            temp2 = sigma0(a) + Maj(a,b,c);
            h = g; g = f; f = e; e = d + temp1; d = c; c = b; b = a; a = temp1 + temp2;

            // Round 15
            temp1 = h + sigma1(e) + Ch(e,f,g) + 0xc19bf174 + w[15];
            temp2 = sigma0(a) + Maj(a,b,c);
            h = g; g = f; f = e; e = d + temp1; d = c; c = b; b = a; a = temp1 + temp2;

            // Round 16
            temp1 = h + sigma1(e) + Ch(e,f,g) + 0xe49b69c1 + w[16];
            temp2 = sigma0(a) + Maj(a,b,c);
            h = g; g = f; f = e; e = d + temp1; d = c; c = b; b = a; a = temp1 + temp2;

            // Round 17
            temp1 = h + sigma1(e) + Ch(e,f,g) + 0xefbe4786 + w[17];
            temp2 = sigma0(a) + Maj(a,b,c);
            h = g; g = f; f = e; e = d + temp1; d = c; c = b; b = a; a = temp1 + temp2;

            // Round 18
            temp1 = h + sigma1(e) + Ch(e,f,g) + 0x0fc19dc6 + w[18];
            temp2 = sigma0(a) + Maj(a,b,c);
            h = g; g = f; f = e; e = d + temp1; d = c; c = b; b = a; a = temp1 + temp2;

            // Round 19
            temp1 = h + sigma1(e) + Ch(e,f,g) + 0x240ca1cc + w[19];
            temp2 = sigma0(a) + Maj(a,b,c);
            h = g; g = f; f = e; e = d + temp1; d = c; c = b; b = a; a = temp1 + temp2;

            // Round 20
            temp1 = h + sigma1(e) + Ch(e,f,g) + 0x2de92c6f + w[20];
            temp2 = sigma0(a) + Maj(a,b,c);
            h = g; g = f; f = e; e = d + temp1; d = c; c = b; b = a; a = temp1 + temp2;

            // Round 21
            temp1 = h + sigma1(e) + Ch(e,f,g) + 0x4a7484aa + w[21];
            temp2 = sigma0(a) + Maj(a,b,c);
            h = g; g = f; f = e; e = d + temp1; d = c; c = b; b = a; a = temp1 + temp2;

            // Round 22
            temp1 = h + sigma1(e) + Ch(e,f,g) + 0x5cb0a9dc + w[22];
            temp2 = sigma0(a) + Maj(a,b,c);
            h = g; g = f; f = e; e = d + temp1; d = c; c = b; b = a; a = temp1 + temp2;

            // Round 23
            temp1 = h + sigma1(e) + Ch(e,f,g) + 0x76f988da + w[23];
            temp2 = sigma0(a) + Maj(a,b,c);
            h = g; g = f; f = e; e = d + temp1; d = c; c = b; b = a; a = temp1 + temp2;

            // Round 24
            temp1 = h + sigma1(e) + Ch(e,f,g) + 0x983e5152 + w[24];
            temp2 = sigma0(a) + Maj(a,b,c);
            h = g; g = f; f = e; e = d + temp1; d = c; c = b; b = a; a = temp1 + temp2;

            // Round 25
            temp1 = h + sigma1(e) + Ch(e,f,g) + 0xa831c66d + w[25];
            temp2 = sigma0(a) + Maj(a,b,c);
            h = g; g = f; f = e; e = d + temp1; d = c; c = b; b = a; a = temp1 + temp2;

            // Round 26
            temp1 = h + sigma1(e) + Ch(e,f,g) + 0xb00327c8 + w[26];
            temp2 = sigma0(a) + Maj(a,b,c);
            h = g; g = f; f = e; e = d + temp1; d = c; c = b; b = a; a = temp1 + temp2;

            // Round 27
            temp1 = h + sigma1(e) + Ch(e,f,g) + 0xbf597fc7 + w[27];
            temp2 = sigma0(a) + Maj(a,b,c);
            h = g; g = f; f = e; e = d + temp1; d = c; c = b; b = a; a = temp1 + temp2;

            // Round 28
            temp1 = h + sigma1(e) + Ch(e,f,g) + 0xc6e00bf3 + w[28];
            temp2 = sigma0(a) + Maj(a,b,c);
            h = g; g = f; f = e; e = d + temp1; d = c; c = b; b = a; a = temp1 + temp2;

            // Round 29
            temp1 = h + sigma1(e) + Ch(e,f,g) + 0xd5a79147 + w[29];
            temp2 = sigma0(a) + Maj(a,b,c);
            h = g; g = f; f = e; e = d + temp1; d = c; c = b; b = a; a = temp1 + temp2;

            // Round 30
            temp1 = h + sigma1(e) + Ch(e,f,g) + 0x06ca6351 + w[30];
            temp2 = sigma0(a) + Maj(a,b,c);
            h = g; g = f; f = e; e = d + temp1; d = c; c = b; b = a; a = temp1 + temp2;

            // Round 31
            temp1 = h + sigma1(e) + Ch(e,f,g) + 0x14292967 + w[31];
            temp2 = sigma0(a) + Maj(a,b,c);
            h = g; g = f; f = e; e = d + temp1; d = c; c = b; b = a; a = temp1 + temp2;

            // Round 32
            temp1 = h + sigma1(e) + Ch(e,f,g) + 0x27b70a85 + w[32];
            temp2 = sigma0(a) + Maj(a,b,c);
            h = g; g = f; f = e; e = d + temp1; d = c; c = b; b = a; a = temp1 + temp2;

            // Round 33
            temp1 = h + sigma1(e) + Ch(e,f,g) + 0x2e1b2138 + w[33];
            temp2 = sigma0(a) + Maj(a,b,c);
            h = g; g = f; f = e; e = d + temp1; d = c; c = b; b = a; a = temp1 + temp2;

            // Round 34
            temp1 = h + sigma1(e) + Ch(e,f,g) + 0x4d2c6dfc + w[34];
            temp2 = sigma0(a) + Maj(a,b,c);
            h = g; g = f; f = e; e = d + temp1; d = c; c = b; b = a; a = temp1 + temp2;

            // Round 35
            temp1 = h + sigma1(e) + Ch(e,f,g) + 0x53380d13 + w[35];
            temp2 = sigma0(a) + Maj(a,b,c);
            h = g; g = f; f = e; e = d + temp1; d = c; c = b; b = a; a = temp1 + temp2;

            // Round 36
            temp1 = h + sigma1(e) + Ch(e,f,g) + 0x650a7354 + w[36];
            temp2 = sigma0(a) + Maj(a,b,c);
            h = g; g = f; f = e; e = d + temp1; d = c; c = b; b = a; a = temp1 + temp2;

            // Round 37
            temp1 = h + sigma1(e) + Ch(e,f,g) + 0x766a0abb + w[37];
            temp2 = sigma0(a) + Maj(a,b,c);
            h = g; g = f; f = e; e = d + temp1; d = c; c = b; b = a; a = temp1 + temp2;

            // Round 38
            temp1 = h + sigma1(e) + Ch(e,f,g) + 0x81c2c92e + w[38];
            temp2 = sigma0(a) + Maj(a,b,c);
            h = g; g = f; f = e; e = d + temp1; d = c; c = b; b = a; a = temp1 + temp2;

            // Round 39
            temp1 = h + sigma1(e) + Ch(e,f,g) + 0x92722c85 + w[39];
            temp2 = sigma0(a) + Maj(a,b,c);
            h = g; g = f; f = e; e = d + temp1; d = c; c = b; b = a; a = temp1 + temp2;

            // Round 40
            temp1 = h + sigma1(e) + Ch(e,f,g) + 0xa2bfe8a1 + w[40];
            temp2 = sigma0(a) + Maj(a,b,c);
            h = g; g = f; f = e; e = d + temp1; d = c; c = b; b = a; a = temp1 + temp2;

            // Round 41
            temp1 = h + sigma1(e) + Ch(e,f,g) + 0xa81a664b + w[41];
            temp2 = sigma0(a) + Maj(a,b,c);
            h = g; g = f; f = e; e = d + temp1; d = c; c = b; b = a; a = temp1 + temp2;

            // Round 42
            temp1 = h + sigma1(e) + Ch(e,f,g) + 0xc24b8b70 + w[42];
            temp2 = sigma0(a) + Maj(a,b,c);
            h = g; g = f; f = e; e = d + temp1; d = c; c = b; b = a; a = temp1 + temp2;

            // Round 43
            temp1 = h + sigma1(e) + Ch(e,f,g) + 0xc76c51a3 + w[43];
            temp2 = sigma0(a) + Maj(a,b,c);
            h = g; g = f; f = e; e = d + temp1; d = c; c = b; b = a; a = temp1 + temp2;

            // Round 44
            temp1 = h + sigma1(e) + Ch(e,f,g) + 0xd192e819 + w[44];
            temp2 = sigma0(a) + Maj(a,b,c);
            h = g; g = f; f = e; e = d + temp1; d = c; c = b; b = a; a = temp1 + temp2;

            // Round 45
            temp1 = h + sigma1(e) + Ch(e,f,g) + 0xd6990624 + w[45];
            temp2 = sigma0(a) + Maj(a,b,c);
            h = g; g = f; f = e; e = d + temp1; d = c; c = b; b = a; a = temp1 + temp2;

            // Round 46
            temp1 = h + sigma1(e) + Ch(e,f,g) + 0xf40e3585 + w[46];
            temp2 = sigma0(a) + Maj(a,b,c);
            h = g; g = f; f = e; e = d + temp1; d = c; c = b; b = a; a = temp1 + temp2;

            // Round 47
            temp1 = h + sigma1(e) + Ch(e,f,g) + 0x106aa070 + w[47];
            temp2 = sigma0(a) + Maj(a,b,c);
            h = g; g = f; f = e; e = d + temp1; d = c; c = b; b = a; a = temp1 + temp2;

            // Round 48
            temp1 = h + sigma1(e) + Ch(e,f,g) + 0x19a4c116 + w[48];
            temp2 = sigma0(a) + Maj(a,b,c);
            h = g; g = f; f = e; e = d + temp1; d = c; c = b; b = a; a = temp1 + temp2;

            // Round 49
            temp1 = h + sigma1(e) + Ch(e,f,g) + 0x1e376c08 + w[49];
            temp2 = sigma0(a) + Maj(a,b,c);
            h = g; g = f; f = e; e = d + temp1; d = c; c = b; b = a; a = temp1 + temp2;

            // Round 50
            temp1 = h + sigma1(e) + Ch(e,f,g) + 0x2748774c + w[50];
            temp2 = sigma0(a) + Maj(a,b,c);
            h = g; g = f; f = e; e = d + temp1; d = c; c = b; b = a; a = temp1 + temp2;

            // Round 51
            temp1 = h + sigma1(e) + Ch(e,f,g) + 0x34b0bcb5 + w[51];
            temp2 = sigma0(a) + Maj(a,b,c);
            h = g; g = f; f = e; e = d + temp1; d = c; c = b; b = a; a = temp1 + temp2;

            // Round 52
            temp1 = h + sigma1(e) + Ch(e,f,g) + 0x391c0cb3 + w[52];
            temp2 = sigma0(a) + Maj(a,b,c);
            h = g; g = f; f = e; e = d + temp1; d = c; c = b; b = a; a = temp1 + temp2;

            // Round 53
            temp1 = h + sigma1(e) + Ch(e,f,g) + 0x4ed8aa4a + w[53];
            temp2 = sigma0(a) + Maj(a,b,c);
            h = g; g = f; f = e; e = d + temp1; d = c; c = b; b = a; a = temp1 + temp2;

            // Round 54
            temp1 = h + sigma1(e) + Ch(e,f,g) + 0x5b9cca4f + w[54];
            temp2 = sigma0(a) + Maj(a,b,c);
            h = g; g = f; f = e; e = d + temp1; d = c; c = b; b = a; a = temp1 + temp2;

            // Round 55
            temp1 = h + sigma1(e) + Ch(e,f,g) + 0x682e6ff3 + w[55];
            temp2 = sigma0(a) + Maj(a,b,c);
            h = g; g = f; f = e; e = d + temp1; d = c; c = b; b = a; a = temp1 + temp2;

            // Round 56
            temp1 = h + sigma1(e) + Ch(e,f,g) + 0x748f82ee + w[56];
            temp2 = sigma0(a) + Maj(a,b,c);
            h = g; g = f; f = e; e = d + temp1; d = c; c = b; b = a; a = temp1 + temp2;

            // Round 57
            temp1 = h + sigma1(e) + Ch(e,f,g) + 0x78a5636f + w[57];
            temp2 = sigma0(a) + Maj(a,b,c);
            h = g; g = f; f = e; e = d + temp1; d = c; c = b; b = a; a = temp1 + temp2;

            // Round 58
            temp1 = h + sigma1(e) + Ch(e,f,g) + 0x84c87814 + w[58];
            temp2 = sigma0(a) + Maj(a,b,c);
            h = g; g = f; f = e; e = d + temp1; d = c; c = b; b = a; a = temp1 + temp2;

            // Round 59
            temp1 = h + sigma1(e) + Ch(e,f,g) + 0x8cc70208 + w[59];
            temp2 = sigma0(a) + Maj(a,b,c);
            h = g; g = f; f = e; e = d + temp1; d = c; c = b; b = a; a = temp1 + temp2;

            // Round 60
            temp1 = h + sigma1(e) + Ch(e,f,g) + 0x90befffa + w[60];
            temp2 = sigma0(a) + Maj(a,b,c);
            h = g; g = f; f = e; e = d + temp1; d = c; c = b; b = a; a = temp1 + temp2;

            // Round 61
            temp1 = h + sigma1(e) + Ch(e,f,g) + 0xa4506ceb + w[61];
            temp2 = sigma0(a) + Maj(a,b,c);
            h = g; g = f; f = e; e = d + temp1; d = c; c = b; b = a; a = temp1 + temp2;

            // Round 62
            temp1 = h + sigma1(e) + Ch(e,f,g) + 0xbef9a3f7 + w[62];
            temp2 = sigma0(a) + Maj(a,b,c);
            h = g; g = f; f = e; e = d + temp1; d = c; c = b; b = a; a = temp1 + temp2;

            // Round 63
            temp1 = h + sigma1(e) + Ch(e,f,g) + 0xc67178f2 + w[63];
            temp2 = sigma0(a) + Maj(a,b,c);
            h = g; g = f; f = e; e = d + temp1; d = c; c = b; b = a; a = temp1 + temp2;

            assembly {
                let ptr := mload(0x40)
                mstore(ptr, shl(0xe0, add(0x6a09e667,a)))
                mstore(add(ptr, 0x04), shl(0xe0, add(0xbb67ae85,b)))
                mstore(add(ptr, 0x08), shl(0xe0, add(0x3c6ef372,c)))
                mstore(add(ptr, 0x0c), shl(0xe0, add(0xa54ff53a,d)))
                mstore(add(ptr, 0x10), shl(0xe0, add(0x510e527f,e)))
                mstore(add(ptr, 0x14), shl(0xe0, add(0x9b05688c,f)))
                mstore(add(ptr, 0x18), shl(0xe0, add(0x1f83d9ab,g)))
                mstore(add(ptr, 0x1c), shl(0xe0, add(0x5be0cd19,h)))
                mstore(0x40, add(ptr,0x20)) //update free memory pointer
                output := mload(ptr)
            }
        }
    }    
    
    //do NOT change uint256 to uint32 here or it will break the memory layout for the shifts
    function sigma0(uint256 x) private pure returns (uint32 result) {
        assembly {result := xor(xor(or(shr(2, x),shl(30,x)),or(shr(13, x),shl(19,x))),or(shr(22, x),shl(10,x)))}
    }
    //do NOT change uint256 to uint32 here or it will break the memory layout for the shifts
    function sigma1(uint256 x) private pure returns (uint32 result) {
       assembly {result := xor(xor(or(shr(6, x),shl(26,x)),or(shr(11, x),shl(21,x))),or(shr(25, x),shl(7,x)))}
    }

    function gamma0(uint32 x) private pure returns (uint32 result) {
        assembly {result := xor(xor(or(shr(7, x), shl(25, x)), or(shr(18, x), shl(14, x))), shr(3, x))}
    }

    function gamma1(uint32 x) private pure returns (uint32 result) {
        assembly {result := xor(xor(or(shr(17, x), shl(15, x)), or(shr(19, x), shl(13, x))), shr(10, x))}
    }

   function Ch(uint32 x, uint32 y, uint32 z) private pure returns (uint32 result) {
        assembly {result := xor(z, and(x, xor(y, z)))}
    }

    function Maj(uint32 x, uint32 y, uint32 z) private pure returns (uint32 result) {
        assembly {result := or(and(or(x, y), z), and(x, y))}
    }
}
