package cz.edris.crypto.paillier;

import java.math.BigInteger;

public interface Encryptor {

    /**
     * Encrypt arbitrary big number
     * @param n number to encrypt
     * @return numberic cipher instance
     */
    CipherNumber encrypt(BigInteger n);

    /**
     * Encrypt primitive long
     * @param n primitive long to encrypt
     * @return numeric cipher instance
     */
    CipherNumber encrypt(long n);

    /**
     * Encrypt string message
     * @param text message
     * @return textual cipher instance
     */
    CipherString encrypt(String text);

    /**
     * Encrypt series of bytes
     * @param bytes array of bytes value
     * @return array of bytes cipher instance
     */
    CipherBytes encrypt(byte[] bytes);

    /**
     * Compute sum of two plain big numbers
     * @param n
     * @param m
     * @return
     */
    CipherNumber sum(BigInteger n, BigInteger m);

    CipherNumber sum(BigInteger ...numbers);

    CipherNumber sum(long n, long m);

    CipherNumber sum(long ...numbers);

    CipherNumber sum(CipherNumber c, BigInteger p);

    CipherNumber sum(CipherNumber c1, CipherNumber c2);

    CipherNumber product(BigInteger n, BigInteger m);

    CipherNumber product(BigInteger ...numbers);

    CipherNumber product(long n, long m);

    CipherNumber product(long ...numbers);

    CipherNumber product(CipherNumber c, BigInteger p);

    CipherNumber product(CipherNumber c, long n);
}
