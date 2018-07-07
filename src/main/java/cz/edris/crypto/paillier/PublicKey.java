package cz.edris.crypto.paillier;

import org.jetbrains.annotations.NotNull;

import java.math.BigInteger;
import java.util.Objects;

import static cz.edris.crypto.paillier.MathSupport.rand2toN;

public final class PublicKey {
    public final BigInteger n;
    public final BigInteger g;
    public final transient BigInteger nsquare;

    public PublicKey(@NotNull BigInteger n, @NotNull BigInteger g) {
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

    @NotNull BigInteger encrypt(@NotNull BigInteger plain) {
        return g.modPow(plain, nsquare)
                .multiply(rand2toN(n).modPow(n, nsquare))
                .mod(nsquare);
    }

    @NotNull public CipherBytes encryptBytes(@NotNull byte[] bytes) {
        if (bytes.length == 0) {
            throw new IllegalArgumentException("Given byte array cannot be empty");
        }
        return new CipherBytes(encrypt(new BigInteger(bytes)));
    }

    @NotNull public CipherNumber encryptNumber(@NotNull BigInteger plain) {
        return new CipherNumber(this, encrypt(plain));
    }

    @NotNull public CipherNumber encryptNumber(long plain) {
        return encryptNumber(BigInteger.valueOf(plain));
    }

    @NotNull public CipherString encryptString(@NotNull String plain) {
        if (plain.isEmpty()) {
            throw new IllegalArgumentException("Given string cannot be empty");
        }
        return new CipherString(encrypt(new BigInteger(plain.getBytes())));
    }

    @NotNull BigInteger add(@NotNull BigInteger cipher1, @NotNull BigInteger cipher2) {
        return cipher1.multiply(cipher2).mod(nsquare);
    }

    @NotNull BigInteger multiply(@NotNull BigInteger c, @NotNull BigInteger k) {
        return c.modPow(k, nsquare);
    }
}
