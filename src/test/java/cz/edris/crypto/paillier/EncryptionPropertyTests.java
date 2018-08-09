package cz.edris.crypto.paillier;

import com.pholser.junit.quickcheck.From;
import com.pholser.junit.quickcheck.Property;
import com.pholser.junit.quickcheck.generator.InRange;
import com.pholser.junit.quickcheck.runner.JUnitQuickcheck;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;

import java.math.BigInteger;

import static org.junit.Assert.assertEquals;

@RunWith(JUnitQuickcheck.class)
public class EncryptionPropertyTests {
    static KeyPair keyPair;

    @BeforeClass
    public static void init() {
        keyPair = KeyPair.generate(1024, 64, false);
    }

    @Property
    public void numberEncryption(@InRange(minLong = 0, maxLong = 10000) long plainText) {
        CipherNumber cipherText = keyPair.getPublicKey().encryptNumber(plainText);
        assertEquals("D(E(p)) != p, where p is int and p >= 0", BigInteger.valueOf(plainText), cipherText.decrypt(keyPair.getPrivateKey()));
    }

    @Property
    public void stringEncryption(@From(LoremIpsumGenerator.class) String plainText) {
        CipherString cipherText = keyPair.getPublicKey().encryptString(plainText);
        assertEquals("D(E(p)) != p, where p is string", plainText, cipherText.decrypt(keyPair.getPrivateKey()));
    }

    @Property
    public void additionOfPositiveNumbers(@InRange(minLong = 0, maxLong = 1000) long a,
                                          @InRange(minLong = 0, maxLong = 500) long b) {
        CipherNumber cipher = keyPair.getPublicKey()
                .encryptNumber(a)
                .add(10)
                .addUnsafe(b);
        assertEquals(cipher.decrypt(keyPair.getPrivateKey()), BigInteger.valueOf(a + 10 + b));
    }

    @Property
    public void limitedSubtractionPossible(@InRange(minLong =  500, maxLong = 1000) long a,
                                           @InRange(minLong = -500, maxLong =    0) long b) {
        CipherNumber cipher = keyPair.getPublicKey()
                .encryptNumber(a)
                .addUnsafe(b);
        assertEquals(cipher.decrypt(keyPair.getPrivateKey()), BigInteger.valueOf(a + b));
    }

    @Property
    public void additionAndMultiplicationOfNumbers(@InRange(minLong =  1, maxLong =  10) long m,
                                                   @InRange(minLong = 10, maxLong = 100) long b,
                                                   @InRange(minLong = 10, maxLong = 100) long c) {
        CipherNumber n = keyPair.getPublicKey()
                .encryptNumber(7)
                .multiply(m)
                .add(b)
                .add(c);

        assertEquals(n.decrypt(keyPair.getPrivateKey()), BigInteger.valueOf(7 * m + b + c));
    }

    @Test
    public void encryptNegative() {
        CipherNumber n = keyPair.getPublicKey()
                .encryptNumberUnsafe(-100)
                .add(200);
        assertEquals(n.decrypt(keyPair.getPrivateKey()), BigInteger.valueOf(100));
    }
}
