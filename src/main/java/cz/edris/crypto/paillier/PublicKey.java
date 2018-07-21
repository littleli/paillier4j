package cz.edris.crypto.paillier;

import org.jetbrains.annotations.NotNull;

import java.io.UnsupportedEncodingException;
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

    public CipherString encryptString(@NotNull String plain) {
        if (plain == null || plain.isEmpty()) {
            throw new IllegalArgumentException("Given string cannot be empty");
        }
        try {
            byte[] bytes = plain.getBytes("UTF-8");
            return new CipherString(encrypt(new BigInteger(bytes)));
        } catch (UnsupportedEncodingException e) {
            throw new RuntimeException(e);
        }
    }

    BigInteger encrypt(@NotNull BigInteger plain) {
        return g.modPow(plain, nsquare)
                .multiply(rand2toN(n).modPow(n, nsquare))
                .mod(nsquare);
    }

    BigInteger add(@NotNull BigInteger cipher1, @NotNull BigInteger cipher2) {
        return cipher1.multiply(cipher2).mod(nsquare);
    }

    BigInteger multiply(@NotNull BigInteger cipher, @NotNull BigInteger k) {
        return cipher.modPow(k, nsquare);
    }
}
