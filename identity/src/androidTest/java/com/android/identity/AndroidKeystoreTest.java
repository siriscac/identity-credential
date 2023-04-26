/*
 * Copyright 2022 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.android.identity;

import android.content.Context;
import android.content.pm.PackageManager;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;

import org.junit.Assert;
import org.junit.Assume;
import org.junit.Test;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.List;

public class AndroidKeystoreTest {

    @Test
    public void testEcKeyDeletion() {
        Context context = androidx.test.InstrumentationRegistry.getTargetContext();
        AndroidKeystore ks = new AndroidKeystore(context);
        AndroidKeystore.CreateKeySettings settings =
                new AndroidKeystore.CreateKeySettings.Builder(new byte[] {1, 2, 3}).build();

        // First create the key...
        List<X509Certificate> certChain = ks.ecKeyCreate("testKey", settings);
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
    public void testEcKeySigning() {
        Context context = androidx.test.InstrumentationRegistry.getTargetContext();
        AndroidKeystore ks = new AndroidKeystore(context);

        byte[] challenge = new byte[] {1, 2, 3};
        AndroidKeystore.CreateKeySettings settings =
                new AndroidKeystore.CreateKeySettings.Builder(challenge).build();

        List<X509Certificate> certChain = ks.ecKeyCreate("testKey", settings);
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
    public void testEcKeyCreationOverridesExistingAlias() {
        Context context = androidx.test.InstrumentationRegistry.getTargetContext();
        AndroidKeystore ks = new AndroidKeystore(context);
        byte[] challenge = new byte[] {1, 2, 3};
        AndroidKeystore.CreateKeySettings settings =
                new AndroidKeystore.CreateKeySettings.Builder(challenge).build();

        List<X509Certificate> certChainOld = ks.ecKeyCreate("testKey", settings);
        Assert.assertTrue(certChainOld.size() >= 1);

        List<X509Certificate> certChain = ks.ecKeyCreate("testKey", settings);
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
    public void testAttestation() throws IOException {
        Context context = androidx.test.InstrumentationRegistry.getTargetContext();
        testAttestationHelper(context, false);
    }

    @Test
    public void testAttestationStrongBox() throws IOException {
        Context context = androidx.test.InstrumentationRegistry.getTargetContext();
        Assume.assumeTrue(context.getPackageManager().hasSystemFeature(PackageManager.FEATURE_STRONGBOX_KEYSTORE));
        testAttestationHelper(context, true);
    }

    public void testAttestationHelper(Context context, boolean useStrongBox) throws IOException {

        AndroidKeystore ks = new AndroidKeystore(context);
        byte[] challenge = new byte[] {1, 2, 3};
        AndroidKeystore.CreateKeySettings settings =
                new AndroidKeystore.CreateKeySettings.Builder(challenge)
                        .setUseStrongBox(useStrongBox)
                        .build();

        ks.ecKeyDelete("testKey");

        List<X509Certificate> certChain = ks.ecKeyCreate("testKey", settings);

        // On Android, at least three certificates are present in the chain.
        Assert.assertTrue(certChain.size() >= 3);

        // Check the attestation extension
        AndroidAttestationExtensionParser parser = new AndroidAttestationExtensionParser(certChain.get(0));
        Assert.assertArrayEquals(challenge, parser.getAttestationChallenge());
        AndroidAttestationExtensionParser.SecurityLevel securityLevel = parser.getKeymasterSecurityLevel();
        Assert.assertEquals(
                useStrongBox ? AndroidAttestationExtensionParser.SecurityLevel.STRONG_BOX
                        : AndroidAttestationExtensionParser.SecurityLevel.TRUSTED_ENVIRONMENT, securityLevel);
    }

    @Test
    public void testAttestKey() throws IOException {
        Context context = androidx.test.InstrumentationRegistry.getTargetContext();
        Assume.assumeTrue(context.getPackageManager().hasSystemFeature(PackageManager.FEATURE_KEYSTORE_APP_ATTEST_KEY));
        testAttestKeyHelper(context, false);
    }

    @Test
    public void testAttestKeyStrongBox() throws IOException {
        Context context = androidx.test.InstrumentationRegistry.getTargetContext();
        Assume.assumeTrue(context.getPackageManager().hasSystemFeature(PackageManager.FEATURE_KEYSTORE_APP_ATTEST_KEY));
        Assume.assumeTrue(context.getPackageManager().hasSystemFeature(PackageManager.FEATURE_STRONGBOX_KEYSTORE));
        testAttestKeyHelper(context, true);
    }

    public void testAttestKeyHelper(Context context, boolean useStrongBox) throws IOException {
        String attestKeyAlias = "icTestAttestKey";
        Certificate[] attestKeyCertificates;
        KeyPairGenerator kpg = null;
        try {
            kpg = KeyPairGenerator.getInstance(
                    KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore");
            KeyGenParameterSpec.Builder builder = new KeyGenParameterSpec.Builder(
                    attestKeyAlias,
                    KeyProperties.PURPOSE_ATTEST_KEY);
            builder.setAttestationChallenge(new byte[]{1, 2, 3});
            if (useStrongBox) {
                builder.setIsStrongBoxBacked(true);
            }
            kpg.initialize(builder.build());
            kpg.generateKeyPair();

            KeyStore aks = KeyStore.getInstance("AndroidKeyStore");
            aks.load(null);
            attestKeyCertificates = aks.getCertificateChain(attestKeyAlias);
        } catch (InvalidAlgorithmParameterException
                 | NoSuchAlgorithmException
                 | NoSuchProviderException
                 | KeyStoreException
                 | CertificateException e) {
            throw new IllegalStateException("Error creating attest key", e);
        }

        AndroidKeystore ks = new AndroidKeystore(context);
        byte[] challenge = new byte[] {4, 5, 6, 7};
        AndroidKeystore.CreateKeySettings settings =
                new AndroidKeystore.CreateKeySettings.Builder(challenge)
                        .setAttestKeyAlias(attestKeyAlias)
                        .setUseStrongBox(useStrongBox)
                        .build();

        ks.ecKeyDelete("testKey");

        List<X509Certificate> certChain = ks.ecKeyCreate("testKey", settings);

        // When using an attest key, only one certificate is returned ...
        Assert.assertEquals(1, certChain.size());
        // ... and this certificate is signed by the attest key. Check that.
        try {
            certChain.get(0).verify(attestKeyCertificates[0].getPublicKey());
        } catch (CertificateException
                 | InvalidKeyException
                 | NoSuchAlgorithmException
                 | NoSuchProviderException
                 | SignatureException e) {
            throw new AssertionError(e);
        }

        // Check the attestation extension
        AndroidAttestationExtensionParser parser = new AndroidAttestationExtensionParser(certChain.get(0));
        Assert.assertArrayEquals(challenge, parser.getAttestationChallenge());
        AndroidAttestationExtensionParser.SecurityLevel securityLevel = parser.getKeymasterSecurityLevel();
        Assert.assertEquals(
                useStrongBox ? AndroidAttestationExtensionParser.SecurityLevel.STRONG_BOX
                        : AndroidAttestationExtensionParser.SecurityLevel.TRUSTED_ENVIRONMENT, securityLevel);
    }

}
