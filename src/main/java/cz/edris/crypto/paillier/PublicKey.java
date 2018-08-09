package cz.edris.crypto.paillier;

import org.jetbrains.annotations.NotNull;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
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

    public CipherNumber encryptNumberUnsafe(@NotNull BigInteger plain) {
        return new CipherNumber(this, encrypt(plain));
    }

    public CipherNumber encryptNumberUnsafe(long plain) {
        return new CipherNumber(this, encrypt(BigInteger.valueOf(plain)));
    }

    public CipherNumber encryptNumber(@NotNull BigInteger plain) {
        if (plain.compareTo(BigInteger.ZERO) < 0) {
            throw new IllegalArgumentException("Given number is negative");
        }
        return encryptNumberUnsafe(plain);
    }

    public CipherNumber encryptNumber(long plain) {
        return encryptNumber(BigInteger.valueOf(plain));
    }

    public CipherString encryptString(@NotNull String plain) {
        if (plain == null || plain.isEmpty()) {
            throw new IllegalArgumentException("Given string cannot be empty");
        }
        byte[] bytes = plain.getBytes(StandardCharsets.UTF_8);
        return new CipherString(encrypt(new BigInteger(bytes)));
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
        if (k.compareTo(BigInteger.ZERO) < 1) {
            throw new IllegalArgumentException("Only positive multiplier is possible");
        }
        return cipher.modPow(k, nsquare);
    }
}
