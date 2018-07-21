package cz.edris.crypto.paillier;

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
}
