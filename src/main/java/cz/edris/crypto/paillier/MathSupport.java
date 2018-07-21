package cz.edris.crypto.paillier;

import org.jetbrains.annotations.NotNull;

import java.math.BigInteger;
import java.security.SecureRandom;

final class MathSupport {
    private MathSupport() {
    }

    static BigInteger rand2toN(BigInteger end) {
        BigInteger start = BigInteger.valueOf(2L);
        BigInteger interval = end.subtract(start);
        BigInteger noi = new BigInteger(interval.bitCount(), new SecureRandom());
        return start.add(noi);
    }

    static BigInteger yield(BigInteger n) {
        BigInteger nsqr = n.pow(2);
        BigInteger alpha = rand2toN(n);
        BigInteger beta = rand2toN(n);
        return alpha
                .multiply(n)
                .add(BigInteger.ONE)
                .multiply(beta.modPow(n, nsqr))
                .mod(nsqr);
    }

    static BigInteger L(@NotNull BigInteger a, @NotNull BigInteger n) {
        return a.subtract(BigInteger.ONE).divide(n);
    }

    static BigInteger lcm(@NotNull BigInteger a, @NotNull BigInteger b) {
        return a.multiply(b).divide(a.gcd(b));
    }
}
