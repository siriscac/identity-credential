package com.android.identity;

import android.content.Context;

import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

import java.io.File;
import java.io.IOException;
import java.security.cert.X509Certificate;
import java.util.List;

// See CredentialStoreTest in non-Android tests for main tests for CredentialStore. These
// tests are just for the Android-specific bits including attestation.
//
public class AndroidKeystoreCredentialStoreTest {

    StorageEngine mStorageEngine;

    KeystoreEngine mKeystoreEngine;

    KeystoreEngineRepository mKeystoreEngineRepository;

    @Before
    public void setup() {
        Context context = androidx.test.InstrumentationRegistry.getTargetContext();
        File storageDir = new File(context.getDataDir(), "ic-testing");
        mStorageEngine = new AndroidStorageEngine(context, storageDir);

        mKeystoreEngineRepository = new KeystoreEngineRepository();
        mKeystoreEngine = new AndroidKeystore(context);
        mKeystoreEngineRepository.addImplementation(mKeystoreEngine);
    }

    @Test
    public void testBasic() throws IOException {

        CredentialStore credentialStore = new CredentialStore(
                mStorageEngine,
                mKeystoreEngineRepository);

        byte[] credentialKeyAttestationChallenge = new byte[] {10, 11, 12};

        Credential credential = credentialStore.createCredential(
                "testCredential",
                "org.iso.18013.5.1.mDL",
                new AndroidKeystore.CreateKeySettings.Builder(credentialKeyAttestationChallenge).build());
        Assert.assertEquals("testCredential", credential.getName());
        Assert.assertEquals("org.iso.18013.5.1.mDL", credential.getDocType());
        List<X509Certificate> certChain = credential.getCredentialKeyCertificateChain();

        // Check the attestation extension
        AndroidAttestationExtensionParser parser = new AndroidAttestationExtensionParser(certChain.get(0));
        Assert.assertArrayEquals(credentialKeyAttestationChallenge, parser.getAttestationChallenge());
        AndroidAttestationExtensionParser.SecurityLevel securityLevel = parser.getKeymasterSecurityLevel();
        Assert.assertEquals(AndroidAttestationExtensionParser.SecurityLevel.TRUSTED_ENVIRONMENT, securityLevel);

        // Create pending authentication key and check its attestation
        byte[] authKeyChallenge = new byte[] {20, 21, 22};
        Credential.PendingAuthenticationKey pendingAuthenticationKey =
                credential.createAuthenticationKey(new AndroidKeystore.CreateKeySettings.Builder(authKeyChallenge)
                        .setUserAuthenticationRequired(true, 30*1000)
                        .build());
        parser = new AndroidAttestationExtensionParser(pendingAuthenticationKey.getCertificateChain().get(0));
        Assert.assertArrayEquals(authKeyChallenge,
                parser.getAttestationChallenge());
        Assert.assertEquals(AndroidAttestationExtensionParser.SecurityLevel.TRUSTED_ENVIRONMENT,
                parser.getKeymasterSecurityLevel());

        // Check we can load the credential...
        credential = credentialStore.lookupCredential("testCredential");
        Assert.assertNotNull(credential);
        Assert.assertEquals("testCredential", credential.getName());
        Assert.assertEquals("org.iso.18013.5.1.mDL", credential.getDocType());
        List<X509Certificate> certChain2 = credential.getCredentialKeyCertificateChain();
        Assert.assertEquals(certChain.size(), certChain2.size());
        for (int n = 0; n < certChain.size(); n++) {
            Assert.assertEquals(certChain.get(n), certChain2.get(n));
        }

        Assert.assertNull(credentialStore.lookupCredential("nonExistingCredential"));

        // Check creating a credential with an existing name overwrites the existing one
        credential = credentialStore.createCredential(
                "testCredential",
                "org.iso.18013.5.1.mDL.other",
                new AndroidKeystore.CreateKeySettings.Builder(credentialKeyAttestationChallenge).build());
        Assert.assertEquals("testCredential", credential.getName());
        Assert.assertEquals("org.iso.18013.5.1.mDL.other", credential.getDocType());
        // At least the leaf certificate should be different
        List<X509Certificate> certChain3 = credential.getCredentialKeyCertificateChain();
        Assert.assertNotEquals(certChain3.get(0), certChain2.get(0));

        credential = credentialStore.lookupCredential("testCredential");
        Assert.assertNotNull(credential);
        Assert.assertEquals("testCredential", credential.getName());
        Assert.assertEquals("org.iso.18013.5.1.mDL.other", credential.getDocType());

        credentialStore.deleteCredential("testCredential");
        Assert.assertNull(credentialStore.lookupCredential("testCredential"));
    }
}
