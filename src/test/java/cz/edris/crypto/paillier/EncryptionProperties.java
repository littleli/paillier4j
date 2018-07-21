package cz.edris.crypto.paillier;

import com.pholser.junit.quickcheck.From;
import com.pholser.junit.quickcheck.Property;
import com.pholser.junit.quickcheck.generator.InRange;
import com.pholser.junit.quickcheck.runner.JUnitQuickcheck;
import org.junit.BeforeClass;
import org.junit.runner.RunWith;

import java.math.BigInteger;

import static org.junit.Assert.*;

@RunWith(JUnitQuickcheck.class)
public class EncryptionProperties {
    static KeyPair keyPair;

    @BeforeClass
    public static void init() {
        keyPair = KeyPair.generate(2048, 64, false);
    }

    @Property public void numberEncryption(@InRange(minLong = 0, maxLong = 10000) long plainText) {

        PublicKey publicKey = keyPair.getPublicKey();
        CipherNumber cipherText = publicKey.encryptNumber(plainText);

        System.out.println("Plaintext: " + plainText);

        assertEquals("D(E(p)) = p, where p >= 0", BigInteger.valueOf(plainText), cipherText.decrypt(keyPair.getPrivateKey()));
    }

    @Property public void stringEncryption(@From(LoremIpsumGenerator.class) String plainText) {
        System.out.println(plainText);

        PublicKey publicKey = keyPair.getPublicKey();
        CipherString cipherText = publicKey.encryptString(plainText);

        assertEquals("D(E(p) = p, where p is string", plainText, cipherText.decrypt(keyPair.getPrivateKey()));
    }
}
