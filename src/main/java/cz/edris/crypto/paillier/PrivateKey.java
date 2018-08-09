package cz.edris.crypto.paillier;

import org.jetbrains.annotations.NotNull;

import java.math.BigInteger;
import java.util.Objects;

import static cz.edris.crypto.paillier.MathSupport.L;

public final class PrivateKey {
    public final BigInteger lambda;
    public final BigInteger mu;
    public final BigInteger p;
    public final BigInteger q;
    public final PublicKey publicKey;

    public PrivateKey(@NotNull BigInteger lambda,
                      @NotNull BigInteger mu,
                      @NotNull BigInteger p,
                      @NotNull BigInteger q,
                      @NotNull PublicKey publicKey) {
        this.lambda = lambda;
        this.mu = mu;
        this.p = p;
        this.q = q;
        this.publicKey = publicKey;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        PrivateKey that = (PrivateKey) o;
        return Objects.equals(lambda, that.lambda) &&
                Objects.equals(mu, that.mu) &&
                Objects.equals(p, that.p) &&
                Objects.equals(q, that.q) &&
                Objects.equals(publicKey, that.publicKey);
    }

    @Override
    public int hashCode() {
        return Objects.hash(lambda, mu, p, q, publicKey);
    }

    @Override
    public String toString() {
        return "PrivateKey{" +
                "lambda=" + lambda +
                ",mu=" + mu +
                ",p=" + p +
                ",q=" + q +
                ",publicKey=" + publicKey +
                '}';
    }

    @NotNull
    public BigInteger decrypt(@NotNull BigInteger cipher) {
        return L(cipher.modPow(lambda, publicKey.nsquare), publicKey.n)
                .multiply(mu)
                .mod(publicKey.n);
    }
}
