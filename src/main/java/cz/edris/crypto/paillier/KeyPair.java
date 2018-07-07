package cz.edris.crypto.paillier;

import java.math.BigInteger;
import java.security.SecureRandom;

import static cz.edris.crypto.paillier.MathSupport.*;

public final class KeyPair {
    private final PrivateKey privateKey;
    private final PublicKey publicKey;

    KeyPair(PrivateKey privateKey, PublicKey publicKey) {
        this.privateKey = privateKey;
        this.publicKey = publicKey;
    }

    public PrivateKey getPrivateKey() {
        return privateKey;
    }

    public PublicKey getPublicKey() {
        return publicKey;
    }

    @Override
    public String toString() {
        return "KeyPair{" +
                "privateKey=" + privateKey +
                ",publicKey=" + publicKey +
                '}';
    }

    /**
     * Generate private and public keys based on given arguments
     *
     * @param bits a key size in bits
     * @param certainty certainty
     * @param isSimpleVariant if simplification should be used
     * @throws IllegalArgumentException if bits is not an even number
     * @return key pair generated for given parameters
     */
    public static KeyPair generate(int bits, int certainty, boolean isSimpleVariant) {
        if ((bits & 1) == 1) {
            throw new IllegalArgumentException("Number of bits has to be even number");
        }

        BigInteger g, lambda, mu, p, q, n;

        do {
            p = new BigInteger(bits / 2, certainty, new SecureRandom());
            q = new BigInteger(bits / 2, certainty, new SecureRandom());
            n = p.multiply(q);
        } while (q.compareTo(p) == 0 || n.bitLength() != bits);

        if (isSimpleVariant) {
            g = n.add(BigInteger.ONE);
            lambda = p.subtract(BigInteger.ONE).multiply(q.subtract(BigInteger.ONE));
            mu = lambda.modInverse(n);
        } else {
            g = yield(n);
            lambda = lcm(p.subtract(BigInteger.ONE), q.subtract(BigInteger.ONE));
            mu = L(g.modPow(lambda, n.pow(2)), n).modInverse(n);
        }

        PublicKey publicKey = new PublicKey(n, g);
        return new KeyPair(
                new PrivateKey(lambda, mu, p, q, publicKey),
                publicKey);
    }
}
