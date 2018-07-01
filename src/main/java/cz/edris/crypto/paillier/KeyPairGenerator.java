package cz.edris.crypto.paillier;

import java.math.BigInteger;
import java.security.SecureRandom;

public final class KeyPairGenerator {

    private KeyPairGenerator() {
    }

    /**
     *
     * @param bits a key size in bits
     * @param certainty certainty
     * @param isSimpleVariant
     * @throws IllegalArgumentException if bits is not an even number
     * @return a key pair generated with given parameters
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
            g = Math.yield(n);
            lambda = Math.lcm(p.subtract(BigInteger.ONE), q.subtract(BigInteger.ONE));
            mu = Math.L(g.modPow(lambda, n.pow(2)), n).modInverse(n);
        }

        PublicKey publicKey = new PublicKey(n, g);
        return new KeyPair(
                new PrivateKey(lambda, mu, p, q, publicKey),
                publicKey);
    }

    public static KeyPair generate() {
        return generate(2048, 64, false);
    }
}
