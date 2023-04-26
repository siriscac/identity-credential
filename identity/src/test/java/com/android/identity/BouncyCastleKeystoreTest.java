package com.android.identity;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.Security;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.X509Certificate;
import java.util.List;

public class BouncyCastleKeystoreTest {

    @Before
    public void setup() {
        Security.addProvider(new BouncyCastleProvider());
    }

    @Test
    public void testEcKeyDeletion() throws IOException {
        File storageDir = Files.createTempDirectory("ic-test").toFile();
        GenericStorageEngine storage = new GenericStorageEngine(storageDir);
        BouncyCastleKeystore ks = new BouncyCastleKeystore(storage);

        // First create the key...
        List<X509Certificate> certChain = ks.ecKeyCreate("testKey",
                new BouncyCastleKeystore.CreateKeySettings.Builder().build());
        Assert.assertTrue(certChain.size() >= 1);

        // Now delete it...
        ks.ecKeyDelete("testKey");

        // Now that we know the key doesn't exist, check that ecKeySign() throws
        try {
            ks.ecKeySign("testKey", KeystoreEngine.ALGORITHM_ES256, new byte[] {1, 2});
            Assert.fail();
        } catch (IllegalArgumentException e) {
            // Expected path.
        }

        // Now delete it again, this should not fail.
        ks.ecKeyDelete("testKey");
    }

    @Test
    public void testEcKeySigning() throws IOException {
        File storageDir = Files.createTempDirectory("ic-test").toFile();
        GenericStorageEngine storage = new GenericStorageEngine(storageDir);
        BouncyCastleKeystore ks = new BouncyCastleKeystore(storage);

        List<X509Certificate> certChain = ks.ecKeyCreate("testKey",
                new BouncyCastleKeystore.CreateKeySettings.Builder().build());
        Assert.assertTrue(certChain.size() >= 1);
        byte[] dataToSign = new byte[] {4, 5, 6};
        byte[] derSignature = ks.ecKeySign("testKey", KeystoreEngine.ALGORITHM_ES256, dataToSign);

        try {
            Signature signature = Signature.getInstance("SHA256withECDSA");
            signature.initVerify(certChain.get(0).getPublicKey());
            signature.update(dataToSign);
            signature.verify(derSignature);
        } catch (NoSuchAlgorithmException
                 | SignatureException
                 | InvalidKeyException e) {
            Assert.fail();
        }
    }

    @Test
    public void testEcKeyCreationOverridesExistingAlias() throws IOException {
        File storageDir = Files.createTempDirectory("ic-test").toFile();
        GenericStorageEngine storage = new GenericStorageEngine(storageDir);
        BouncyCastleKeystore ks = new BouncyCastleKeystore(storage);

        List<X509Certificate> certChainOld = ks.ecKeyCreate("testKey",
                new BouncyCastleKeystore.CreateKeySettings.Builder().build());
        Assert.assertTrue(certChainOld.size() >= 1);

        List<X509Certificate> certChain = ks.ecKeyCreate("testKey",
                new BouncyCastleKeystore.CreateKeySettings.Builder().build());
        Assert.assertTrue(certChain.size() >= 1);
        byte[] dataToSign = new byte[] {4, 5, 6};
        byte[] derSignature = ks.ecKeySign("testKey", KeystoreEngine.ALGORITHM_ES256, dataToSign);

        // Check new key is a different cert chain.
        Assert.assertNotEquals(
                certChainOld.get(0).getPublicKey().getEncoded(),
                certChain.get(0).getPublicKey().getEncoded());

        // Check new key is used to sign.
        try {
            Signature signature = Signature.getInstance("SHA256withECDSA");
            signature.initVerify(certChain.get(0).getPublicKey());
            signature.update(dataToSign);
            signature.verify(derSignature);
        } catch (NoSuchAlgorithmException
                 | SignatureException
                 | InvalidKeyException e) {
            Assert.fail();
        }
    }

    @Test
    public void testEcKeySigningAllCurves() throws IOException {
        File storageDir = Files.createTempDirectory("ic-test").toFile();
        GenericStorageEngine storage = new GenericStorageEngine(storageDir);
        BouncyCastleKeystore ks = new BouncyCastleKeystore(storage);

        int[] knownEcCurves = new int[] {
                KeystoreEngine.EC_CURVE_P256,
                KeystoreEngine.EC_CURVE_P384,
                KeystoreEngine.EC_CURVE_P521,
                KeystoreEngine.EC_CURVE_BRAINPOOLP256R1,
                KeystoreEngine.EC_CURVE_BRAINPOOLP320R1,
                KeystoreEngine.EC_CURVE_BRAINPOOLP384R1,
                KeystoreEngine.EC_CURVE_BRAINPOOLP512R1,
                // TODO: Edwards curve keys requires work in how private key is saved/loaded
                //KeystoreEngine.EC_CURVE_ED_25519,
                //KeystoreEngine.EC_CURVE_ED_448,
        };

        for (@KeystoreEngine.EcCurve int ecCurve : knownEcCurves) {
            List<X509Certificate> certChain = ks.ecKeyCreate("testKey",
                    new BouncyCastleKeystore.CreateKeySettings.Builder()
                            .setEcCurve(ecCurve)
                            .build());

            @KeystoreEngine.Algorithm int[] signatureAlgorithms = new int[0];
            switch (ecCurve) {
                case KeystoreEngine.EC_CURVE_P256:
                case KeystoreEngine.EC_CURVE_P384:
                case KeystoreEngine.EC_CURVE_P521:
                case KeystoreEngine.EC_CURVE_BRAINPOOLP256R1:
                case KeystoreEngine.EC_CURVE_BRAINPOOLP320R1:
                case KeystoreEngine.EC_CURVE_BRAINPOOLP384R1:
                case KeystoreEngine.EC_CURVE_BRAINPOOLP512R1:
                    signatureAlgorithms = new int[] {
                            KeystoreEngine.ALGORITHM_ES256,
                            KeystoreEngine.ALGORITHM_ES384,
                            KeystoreEngine.ALGORITHM_ES512};
                    break;

                case KeystoreEngine.EC_CURVE_ED25519:
                case KeystoreEngine.EC_CURVE_ED448:
                    signatureAlgorithms = new int[] {KeystoreEngine.ALGORITHM_EDDSA};
                    break;

                default:
                    Assert.fail();
            }

            Assert.assertTrue(certChain.size() >= 1);
            for (@KeystoreEngine.Algorithm int signatureAlgorithm : signatureAlgorithms){
                byte[] dataToSign = new byte[]{4, 5, 6};
                byte[] derSignature = ks.ecKeySign("testKey", signatureAlgorithm, dataToSign);

                String signatureAlgorithmName = "";
                switch (signatureAlgorithm) {
                    case KeystoreEngine.ALGORITHM_ES256:
                        signatureAlgorithmName = "SHA256withECDSA";
                        break;
                    case KeystoreEngine.ALGORITHM_ES384:
                        signatureAlgorithmName = "SHA384withECDSA";
                        break;
                    case KeystoreEngine.ALGORITHM_ES512:
                        signatureAlgorithmName = "SHA512withECDSA";
                        break;
                    case KeystoreEngine.ALGORITHM_EDDSA:
                        if (ecCurve == KeystoreEngine.EC_CURVE_ED25519) {
                            signatureAlgorithmName = "Ed25519";
                        } else if (ecCurve == KeystoreEngine.EC_CURVE_ED448) {
                            signatureAlgorithmName = "Ed448";
                        } else {
                            Assert.fail("ALGORITHM_EDDSA can only be used with "
                                    + "EC_CURVE_ED_25519 and EC_CURVE_ED_448");
                        }
                        break;
                    default:
                        Assert.fail("Unsupported signing algorithm  with id " + signatureAlgorithm);
                }

                try {
                    Signature signature = Signature.getInstance(signatureAlgorithmName);
                    signature.initVerify(certChain.get(0).getPublicKey());
                    signature.update(dataToSign);
                    signature.verify(derSignature);
                } catch (NoSuchAlgorithmException
                         | SignatureException
                         | InvalidKeyException e) {
                    Assert.fail();
                }
            }
        }
    }
}
