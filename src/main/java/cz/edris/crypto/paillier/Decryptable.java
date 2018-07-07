package cz.edris.crypto.paillier;

import java.math.BigInteger;

/**
 * This interface is a rich marker interface for all encapsulating cipher classes
 *
 * @param <T>
 */
public interface Decryptable<T> {
    /**
     * Typed decrypt operation
     *
     * @param privateKey private key for decryption
     * @return decrypted value
     */
    T decrypt(PrivateKey privateKey);

    /**
     * Cipher text accessor
     *
     * @return cipher number
     */
    BigInteger get();
}
