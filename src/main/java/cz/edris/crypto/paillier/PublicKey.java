package cz.edris.crypto.paillier;

import java.math.BigInteger;
import java.util.Objects;

public final class PublicKey {
    public final BigInteger n;
    public final BigInteger g;
    public final transient BigInteger nsquare;

    public PublicKey(BigInteger n, BigInteger g) {
        this.n = n;
        this.g = g;
        this.nsquare = n.pow(2);
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        PublicKey publicKey = (PublicKey) o;
        return Objects.equals(n, publicKey.n) && Objects.equals(g, publicKey.g);
    }

    @Override
    public int hashCode() {
        return Objects.hash(n, g);
    }

    @Override
    public String toString() {
        return "PublicKey{" +
                "n=" + n +
                ",g=" + g +
                '}';
    }

    public BigInteger encrypt(BigInteger m) {
        BigInteger r;
        do {
            r = Math.rand2toN(n);
        } while (r.compareTo(BigInteger.ONE) <= 0);
        return g.modPow(m, nsquare).multiply(r.modPow(n, nsquare)).mod(nsquare);
    }

    BigInteger add(BigInteger c1, BigInteger c2) {
        return c1.multiply(c2).mod(nsquare);
    }

    BigInteger multiply(BigInteger c, BigInteger k) {
        return c.modPow(k, nsquare);
    }
}
