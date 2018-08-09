package cz.edris.crypto.paillier;

import org.junit.BeforeClass;
import org.junit.Test;

import static org.junit.Assert.assertEquals;

public class KeyTest {
    static KeyPair keyPair;

    @BeforeClass
    public static void init() {
        keyPair = KeyPair.generate(1024, 64, false);
    }

    @Test
    public void equalityTest() {
        PublicKey pubk1 = keyPair.getPublicKey();
        PrivateKey privk1 = keyPair.getPrivateKey();

        PublicKey pubk2 = new PublicKey(pubk1.n, pubk1.g);
        assertEquals(pubk1, pubk2);
        assertEquals(pubk1.hashCode(), pubk2.hashCode());

        PrivateKey privk2 = new PrivateKey(privk1.lambda,
                privk1.mu,
                privk1.p,
                privk1.q,
                privk1.publicKey);
        assertEquals(privk1, privk2);
        assertEquals(privk1.hashCode(), privk2.hashCode());
    }

    @Test(expected = IllegalArgumentException.class)
    public void correctness() {
        KeyPair.generate(1023, 32, true);
    }
}
