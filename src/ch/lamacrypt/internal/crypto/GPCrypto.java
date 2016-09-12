/* 
 * Copyright (c) 2016, LamaCrypt
 * All rights reserved.
 *
 * The LamaCrypt client software and its source code are available
 * under the LamaCrypt Software License: 
 * https://www.lamacrypt.ch/lcsl.php
 */
package ch.lamacrypt.internal.crypto;

import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.Charset;
import java.security.SecureRandom;
import java.util.Arrays;
import javax.crypto.SecretKey;
import javax.xml.bind.DatatypeConverter;

/**
 * General purpose cryptographic class
 * <p>
 * Methods which are used for cryptographic yet general purpose are defined
 * here, so that the *Cipher class files only contains
 * encryption/decryption-related code.
 *
 * @author LamaGuy
 */
public abstract class GPCrypto {

    private static final SecureRandom rand = new SecureRandom();

    public static final int SANITIZATION_COUNT = 10000;

    /**
     * Generates a random array of bytes
     *
     * @param size width of the byte array
     *
     * @return a random array of bytes, of length size
     */
    public static byte[] randomGen(int size) {
        byte[] randBytes = new byte[size];
        rand.nextBytes(randBytes);
        return randBytes;
    }

    /**
     * Fills a byte array 10'000 times with random values to prevent future
     * retrieval of its original state
     *
     * @param array byte array to sanitize
     */
    public static void sanitize(byte[] array) {
        for (int i = 0; i < SANITIZATION_COUNT; i++) {
            rand.nextBytes(array);
        }
    }

    /**
     * Overwrites multiple byte arrays 10'000 times
     *
     * @param arrays arrays to overwrite
     */
    public static void eraseByteArrays(byte[]  
        ... arrays) {
        for (byte[] array : arrays) {
            sanitize(array);
        }
    }

    /**
     * Fills a char array 10'000 times with random values to prevent future
     * retrieval of its original state
     *
     * @param arr char array to sanitize
     */
    public static void sanitize(char[] arr) {
        for (int i = 0; i < SANITIZATION_COUNT; i++) {
            Arrays.fill(arr, (char) rand.nextInt());
        }
    }

    /**
     * Overwrites many SecretKey objects 10'000 times
     *
     * @param keys SecretKey objects to overwrite
     */
    public static void eraseKeys(SecretKey... keys) {
        for (SecretKey key : keys) {
            sanitize(key.getEncoded());
        }
    }

    /**
     * Converts a char array into a byte array, using UTF-8 as the encoding
     * charset
     * <p>
     * Note: does not change the input char array by processing a clone of it
     *
     *
     * @param c char array to convert
     *
     * @return byte array representation of the char array
     */
    public static byte[] charToByte(char[] c) {
        CharBuffer charBuffer = CharBuffer.wrap(c.clone());
        ByteBuffer byteBuffer = Charset.forName("UTF-8").encode(charBuffer);
        byte[] bytes = Arrays.copyOfRange(byteBuffer.array(),
                byteBuffer.position(), byteBuffer.limit());
        sanitize(charBuffer.array());
        sanitize(byteBuffer.array());
        return bytes;
    }

    /**
     * Converts a byte array into an integer
     *
     * @param b byte array to convert
     *
     * @return integer value of the byte array
     */
    public static int byteArrayToInt(byte[] b) {
        int value = 0;
        for (int i = 0; i < 4; i++) {
            int shift = (4 - 1 - i) * 8;
            value += (b[i] & 0x000000FF) << shift;
        }
        return value;
    }

    /**
     * Converts an integer into a byte array
     *
     * @param i integer to convert
     *
     * @return byte array representation of the integer
     */
    public static byte[] intToByteArray(int i) {
        byte[] ret = new byte[4];
        ret[3] = (byte) (i & 0xFF);
        ret[2] = (byte) ((i >> 8) & 0xFF);
        ret[1] = (byte) ((i >> 16) & 0xFF);
        ret[0] = (byte) ((i >> 24) & 0xFF);
        return ret;
    }

    /**
     * Checks whether the specified string is a string representation of an
     * hexadecimal value
     *
     * @param hex hexadecimal string
     *
     * @return
     */
    public static boolean checkHex(String hex) {
        boolean res = true;

        try {
            DatatypeConverter.parseHexBinary(hex);
        } catch (IllegalArgumentException ex) {
            res = false;
        }

        return res;
    }

    /**
     * Checks whether the specified string is a representation of a 256-bit
     * secret key
     *
     * @param key string representation of a 256-bit secret key
     *
     * @return true the string represents a 32 byte hex value
     */
    public static boolean checkKey(String key) {
        return checkHex(key) && key.length() == 64;
    }

    /**
     * Checks whether the specified string is a representation of a 16 byte uuid
     *
     * @param uuid string representation of a 16 byte uuid
     *
     * @return true the string represents a 16 byte hex value
     */
    public static boolean checkUUID(String uuid) {
        return checkHex(uuid) && uuid.length() == 32;
    }
}
