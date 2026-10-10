package org.peergos.iroh;

import java.nio.charset.StandardCharsets;

/**
 * BLAKE3 (hash and derive_key, 32-byte output), following the reference implementation.
 */
public final class Blake3 {

    private static final int[] IV = {
            0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A, 0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19
    };
    private static final int[] MSG_PERMUTATION = {2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8};
    private static final int BLOCK_LEN = 64;
    private static final int CHUNK_LEN = 1024;
    private static final int CHUNK_START = 1;
    private static final int CHUNK_END = 2;
    private static final int PARENT = 4;
    private static final int ROOT = 8;
    private static final int DERIVE_KEY_CONTEXT = 32;
    private static final int DERIVE_KEY_MATERIAL = 64;

    private Blake3() {}

    public static byte[] hash(byte[] input) {
        return hash(IV, 0, input);
    }

    public static byte[] deriveKey(String context, byte[] keyMaterial) {
        byte[] contextKey = hash(IV, DERIVE_KEY_CONTEXT, context.getBytes(StandardCharsets.UTF_8));
        return hash(wordsFromBytes(contextKey, 0, 8), DERIVE_KEY_MATERIAL, keyMaterial);
    }

    private static byte[] hash(int[] key, int flags, byte[] input) {
        // Chaining values of completed subtrees, merged like the reference implementation's stack.
        int[][] stack = new int[54][];
        int stackLength = 0;
        long chunkCounter = 0;
        int offset = 0;
        while (input.length - offset > CHUNK_LEN) {
            int[] chunkCv = chunkOutput(key, flags, input, offset, CHUNK_LEN, chunkCounter).chainingValue();
            chunkCounter++;
            long totalChunks = chunkCounter;
            while ((totalChunks & 1) == 0) {
                chunkCv = parentOutput(stack[--stackLength], chunkCv, key, flags).chainingValue();
                totalChunks >>= 1;
            }
            stack[stackLength++] = chunkCv;
            offset += CHUNK_LEN;
        }
        Output output = chunkOutput(key, flags, input, offset, input.length - offset, chunkCounter);
        while (stackLength > 0) {
            output = parentOutput(stack[--stackLength], output.chainingValue(), key, flags);
        }
        return output.rootBytes();
    }

    private record Output(int[] inputCv, int[] blockWords, long counter, int blockLen, int flags) {
        int[] chainingValue() {
            int[] out = compress(inputCv, blockWords, counter, blockLen, flags);
            int[] cv = new int[8];
            System.arraycopy(out, 0, cv, 0, 8);
            return cv;
        }

        byte[] rootBytes() {
            int[] words = compress(inputCv, blockWords, 0, blockLen, flags | ROOT);
            byte[] out = new byte[32];
            for (int i = 0; i < 8; i++) {
                out[4 * i] = (byte) words[i];
                out[4 * i + 1] = (byte) (words[i] >>> 8);
                out[4 * i + 2] = (byte) (words[i] >>> 16);
                out[4 * i + 3] = (byte) (words[i] >>> 24);
            }
            return out;
        }
    }

    private static Output chunkOutput(int[] key, int flags, byte[] input, int offset, int length, long counter) {
        int[] cv = key.clone();
        int blocksCompressed = 0;
        int position = 0;
        while (length - position > BLOCK_LEN) {
            int blockFlags = flags | (blocksCompressed == 0? CHUNK_START: 0);
            int[] out = compress(cv, block(input, offset + position, BLOCK_LEN), counter, BLOCK_LEN, blockFlags);
            System.arraycopy(out, 0, cv, 0, 8);
            blocksCompressed++;
            position += BLOCK_LEN;
        }
        int lastLength = length - position;
        int lastFlags = flags | CHUNK_END | (blocksCompressed == 0? CHUNK_START: 0);
        return new Output(cv, block(input, offset + position, lastLength), counter, lastLength, lastFlags);
    }

    private static Output parentOutput(int[] left, int[] right, int[] key, int flags) {
        int[] words = new int[16];
        System.arraycopy(left, 0, words, 0, 8);
        System.arraycopy(right, 0, words, 8, 8);
        return new Output(key, words, 0, BLOCK_LEN, flags | PARENT);
    }

    private static int[] block(byte[] input, int offset, int length) {
        byte[] padded = new byte[BLOCK_LEN];
        System.arraycopy(input, offset, padded, 0, length);
        return wordsFromBytes(padded, 0, 16);
    }

    private static int[] wordsFromBytes(byte[] bytes, int offset, int count) {
        int[] words = new int[count];
        for (int i = 0; i < count; i++) {
            int p = offset + 4 * i;
            words[i] = (bytes[p] & 0xff) | (bytes[p + 1] & 0xff) << 8 | (bytes[p + 2] & 0xff) << 16 | (bytes[p + 3] & 0xff) << 24;
        }
        return words;
    }

    private static void g(int[] s, int a, int b, int c, int d, int mx, int my) {
        s[a] = s[a] + s[b] + mx;
        s[d] = Integer.rotateRight(s[d] ^ s[a], 16);
        s[c] = s[c] + s[d];
        s[b] = Integer.rotateRight(s[b] ^ s[c], 12);
        s[a] = s[a] + s[b] + my;
        s[d] = Integer.rotateRight(s[d] ^ s[a], 8);
        s[c] = s[c] + s[d];
        s[b] = Integer.rotateRight(s[b] ^ s[c], 7);
    }

    private static int[] compress(int[] cv, int[] blockWords, long counter, int blockLen, int flags) {
        int[] s = {
                cv[0], cv[1], cv[2], cv[3], cv[4], cv[5], cv[6], cv[7],
                IV[0], IV[1], IV[2], IV[3], (int) counter, (int) (counter >>> 32), blockLen, flags
        };
        int[] m = blockWords.clone();
        for (int round = 0; round < 7; round++) {
            g(s, 0, 4, 8, 12, m[0], m[1]);
            g(s, 1, 5, 9, 13, m[2], m[3]);
            g(s, 2, 6, 10, 14, m[4], m[5]);
            g(s, 3, 7, 11, 15, m[6], m[7]);
            g(s, 0, 5, 10, 15, m[8], m[9]);
            g(s, 1, 6, 11, 12, m[10], m[11]);
            g(s, 2, 7, 8, 13, m[12], m[13]);
            g(s, 3, 4, 9, 14, m[14], m[15]);
            if (round < 6) {
                int[] permuted = new int[16];
                for (int i = 0; i < 16; i++) {
                    permuted[i] = m[MSG_PERMUTATION[i]];
                }
                m = permuted;
            }
        }
        for (int i = 0; i < 8; i++) {
            s[i] ^= s[i + 8];
            s[i + 8] ^= cv[i];
        }
        return s;
    }
}
