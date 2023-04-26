package com.android.identity;

import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.security.cert.X509Certificate;
import java.util.Iterator;
import java.util.List;

public class CredentialStoreTest {

    StorageEngine mStorageEngine;

    KeystoreEngine mKeystoreEngine;

    KeystoreEngineRepository mKeystoreEngineRepository;
    
    @Before
    public void setup() throws IOException {
        File storageDir = Files.createTempDirectory("ic-test").toFile();
        mStorageEngine = new GenericStorageEngine(storageDir);

        mKeystoreEngineRepository = new KeystoreEngineRepository();
        mKeystoreEngine = new BouncyCastleKeystore(mStorageEngine);
        mKeystoreEngineRepository.addImplementation(mKeystoreEngine);
    }

    @Test
    public void testListCredentials() {
        mStorageEngine.deleteAll();
        CredentialStore credentialStore = new CredentialStore(
                mStorageEngine,
                mKeystoreEngineRepository);

        Assert.assertEquals(0, credentialStore.listCredentials().size());
        for (int n = 0; n < 10; n++) {
            credentialStore.createCredential(
                    "testCred" + n,
                    "org.iso.18013.5.1.mDL",
                    new BouncyCastleKeystore.CreateKeySettings.Builder().build());
        }
        Assert.assertEquals(10, credentialStore.listCredentials().size());
        credentialStore.deleteCredential("testCred1");
        Assert.assertEquals(9, credentialStore.listCredentials().size());
        for (int n = 0; n < 10; n++) {
            if (n == 1) {
                Assert.assertFalse(credentialStore.listCredentials().contains("testCred" + n));
            } else {
                Assert.assertTrue(credentialStore.listCredentials().contains("testCred" + n));
            }
        }
    }

    @Test
    public void testCreationDeletion() {

        CredentialStore credentialStore = new CredentialStore(
                mStorageEngine,
                mKeystoreEngineRepository);

        Credential credential = credentialStore.createCredential(
                "testCredential",
                "org.iso.18013.5.1.mDL",
                new BouncyCastleKeystore.CreateKeySettings.Builder().build());
        Assert.assertEquals("testCredential", credential.getName());
        Assert.assertEquals("org.iso.18013.5.1.mDL", credential.getDocType());
        List<X509Certificate> certChain = credential.getCredentialKeyCertificateChain();
        Assert.assertTrue(certChain.size() >= 1);

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
                new BouncyCastleKeystore.CreateKeySettings.Builder().build());
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

    @Test
    public void testNameSpacedData() {
        CredentialStore credentialStore = new CredentialStore(
                mStorageEngine,
                mKeystoreEngineRepository);

        Credential credential = credentialStore.createCredential(
                "testCredential",
                "org.iso.18013.5.1.mDL",
                new BouncyCastleKeystore.CreateKeySettings.Builder().build());

        // After creation, NameSpacedData is present but empty.
        Assert.assertEquals(0, credential.getNameSpacedData().getNameSpaceNames().size());

        NameSpacedData nameSpacedData = new NameSpacedData.Builder()
                .putEntryString("ns1", "foo1", "bar1")
                .putEntryString("ns1", "foo2", "bar2")
                .putEntryString("ns1", "foo3", "bar3")
                .putEntryString("ns2", "bar1", "foo1")
                .putEntryString("ns2", "bar2", "foo2")
                .build();
        credential.setNameSpacedData(nameSpacedData);

        Credential loadedCredential = credentialStore.lookupCredential("testCredential");
        Assert.assertNotNull(loadedCredential);
        Assert.assertEquals("testCredential", loadedCredential.getName());
        //Assert.assertEquals("org.iso.18013.5.1.mDL", loadedCredential.getDocType());

        // We check that NameSpacedData is preserved across loads by simply comparing the
        // encoded data.
        Assert.assertArrayEquals(
                Util.cborEncode(credential.getNameSpacedData().toCbor()),
                Util.cborEncode(loadedCredential.getNameSpacedData().toCbor()));
    }

    @Test
    public void testAuthenticationKeyUsage() {
        CredentialStore credentialStore = new CredentialStore(
                mStorageEngine,
                mKeystoreEngineRepository);

        Credential credential = credentialStore.createCredential(
                "testCredential",
                "org.iso.18013.5.1.mDL",
                new BouncyCastleKeystore.CreateKeySettings.Builder().build());

        Timestamp timeBeforeValidity = Timestamp.ofEpochMilli(40);
        Timestamp timeValidityBegin = Timestamp.ofEpochMilli(50);
        Timestamp timeDuringValidity = Timestamp.ofEpochMilli(100);
        Timestamp timeValidityEnd = Timestamp.ofEpochMilli(150);
        Timestamp timeAfterValidity = Timestamp.ofEpochMilli(200);

        // By default, we don't have any auth keys nor any pending auth keys.
        Assert.assertEquals(0, credential.getAuthenticationKeys().size());
        Assert.assertEquals(0, credential.getPendingAuthenticationKeys().size());

        // Since none are certified or even pending yet, we can't present anything.
        Assert.assertNull(credential.findAuthenticationKey(timeDuringValidity));

        // Create ten authentication keys...
        for (int n = 0; n < 10; n++) {
            credential.createAuthenticationKey(new BouncyCastleKeystore.CreateKeySettings.Builder().build());
        }
        Assert.assertEquals(0, credential.getAuthenticationKeys().size());
        Assert.assertEquals(10, credential.getPendingAuthenticationKeys().size());

        // ... and certify all of them
        int n = 0;
        for (Credential.PendingAuthenticationKey pendingAuthenticationKey :
                credential.getPendingAuthenticationKeys()) {
            byte[] issuerProvidedAuthenticationData = {1, 2, (byte) n++};
            pendingAuthenticationKey.certify(
                    issuerProvidedAuthenticationData,
                    timeValidityBegin,
                    timeValidityEnd);
        }
        Assert.assertEquals(10, credential.getAuthenticationKeys().size());
        Assert.assertEquals(0, credential.getPendingAuthenticationKeys().size());

        // If at a time before anything is valid, should not be able to present
        Assert.assertNull(credential.findAuthenticationKey(timeBeforeValidity));

        // Ditto for right after
        Assert.assertNull(credential.findAuthenticationKey(timeAfterValidity));

        // Check we're able to present at a time when the auth keys are valid
        Credential.AuthenticationKey authKey = credential.findAuthenticationKey(timeDuringValidity);
        Assert.assertNotNull(authKey);

        Assert.assertEquals(0, authKey.getUsageCount());

        // B/c of how findAuthenticationKey() we know we get the first key. Match
        // up with expected issuer signed data as per above.
        Assert.assertEquals((byte) 0, authKey.getIssuerProvidedData()[2]);

        Assert.assertEquals(0, authKey.getUsageCount());
        authKey.increaseUsageCount();
        Assert.assertEquals(1, authKey.getUsageCount());

        // Simulate nine more presentations, all of them should now be used up
        for (n = 0; n < 9; n++) {
            authKey = credential.findAuthenticationKey(timeDuringValidity);
            Assert.assertNotNull(authKey);

            // B/c of how findAuthenticationKey() we know we get the keys after
            // the first one in order. Match up with expected issuer signed data as per above.
            Assert.assertEquals((byte) (n + 1), authKey.getIssuerProvidedData()[2]);

            authKey.increaseUsageCount();
        }

        // All ten auth keys should now have a use count of 1.
        for (Credential.AuthenticationKey authenticationKey : credential.getAuthenticationKeys()) {
            Assert.assertEquals(1, authenticationKey.getUsageCount());
        }

        // Simulate ten more presentations
        for (n = 0; n < 10; n++) {
            authKey = credential.findAuthenticationKey(timeDuringValidity);
            Assert.assertNotNull(authKey);
            authKey.increaseUsageCount();
        }

        // All ten auth keys should now have a use count of 2.
        for (Credential.AuthenticationKey authenticationKey : credential.getAuthenticationKeys()) {
            Assert.assertEquals(2, authenticationKey.getUsageCount());
        }

        // Create and certify five replacements
        for (n = 0; n < 5; n++) {
            credential.createAuthenticationKey(new BouncyCastleKeystore.CreateKeySettings.Builder().build());
        }
        Assert.assertEquals(10, credential.getAuthenticationKeys().size());
        Assert.assertEquals(5, credential.getPendingAuthenticationKeys().size());
        for (Credential.PendingAuthenticationKey pendingAuthenticationKey :
                credential.getPendingAuthenticationKeys()) {
            pendingAuthenticationKey.certify(
                    new byte[0],
                    timeValidityBegin,
                    timeValidityEnd);
        }
        Assert.assertEquals(15, credential.getAuthenticationKeys().size());
        Assert.assertEquals(0, credential.getPendingAuthenticationKeys().size());

        // Simulate ten presentations and check we get the newly created ones
        for (n = 0; n < 10; n++) {
            authKey = credential.findAuthenticationKey(timeDuringValidity);
            Assert.assertNotNull(authKey);
            Assert.assertEquals(0, authKey.getIssuerProvidedData().length);
            authKey.increaseUsageCount();
        }

        // All fifteen auth keys should now have a use count of 2.
        for (Credential.AuthenticationKey authenticationKey : credential.getAuthenticationKeys()) {
            Assert.assertEquals(2, authenticationKey.getUsageCount());
        }

        // Simulate 15 more presentations
        for (n = 0; n < 15; n++) {
            authKey = credential.findAuthenticationKey(timeDuringValidity);
            Assert.assertNotNull(authKey);
            authKey.increaseUsageCount();
        }

        // All fifteen auth keys should now have a use count of 3. This shows that
        // we're hitting the auth keys evenly (both old and new).
        for (Credential.AuthenticationKey authenticationKey : credential.getAuthenticationKeys()) {
            Assert.assertEquals(3, authenticationKey.getUsageCount());
        }
    }

    @Test
    public void testAuthenticationKeyPersistence() {
        int n;

        Timestamp timeValidityBegin = Timestamp.ofEpochMilli(50);
        Timestamp timeValidityEnd = Timestamp.ofEpochMilli(150);

        CredentialStore credentialStore = new CredentialStore(
                mStorageEngine,
                mKeystoreEngineRepository);

        Credential credential = credentialStore.createCredential(
                "testCredential",
                "org.iso.18013.5.1.mDL",
                new BouncyCastleKeystore.CreateKeySettings.Builder().build());

        Assert.assertEquals(0, credential.getAuthenticationKeys().size());
        Assert.assertEquals(0, credential.getPendingAuthenticationKeys().size());

        // Create ten pending auth keys and certify four of them
        for (n = 0; n < 4; n++) {
            credential.createAuthenticationKey(new BouncyCastleKeystore.CreateKeySettings.Builder().build());
        }
        Assert.assertEquals(0, credential.getAuthenticationKeys().size());
        Assert.assertEquals(4, credential.getPendingAuthenticationKeys().size());
        n = 0;
        for (Credential.PendingAuthenticationKey pendingAuthenticationKey :
                credential.getPendingAuthenticationKeys()) {
            // Because we check that we serialize things correctly below, make sure
            // the data and validity times vary for each key...
            Credential.AuthenticationKey authenticationKey =
                    pendingAuthenticationKey.certify(
                            new byte[] {1, 2, (byte) n},
                            Timestamp.ofEpochMilli(timeValidityBegin.toEpochMilli() + n),
                            Timestamp.ofEpochMilli(timeValidityEnd.toEpochMilli() + 2*n));
            for (int m = 0; m < n; m++) {
                authenticationKey.increaseUsageCount();
            }
            Assert.assertEquals(n, authenticationKey.getUsageCount());
        }
        Assert.assertEquals(4, credential.getAuthenticationKeys().size());
        Assert.assertEquals(0, credential.getPendingAuthenticationKeys().size());
        for (n = 0; n < 6; n++) {
            credential.createAuthenticationKey(new BouncyCastleKeystore.CreateKeySettings.Builder().build());
        }
        Assert.assertEquals(4, credential.getAuthenticationKeys().size());
        Assert.assertEquals(6, credential.getPendingAuthenticationKeys().size());

        Credential credential2 = credentialStore.lookupCredential("testCredential");
        Assert.assertNotNull(credential2);
        Assert.assertEquals(4, credential2.getAuthenticationKeys().size());
        Assert.assertEquals(6, credential2.getPendingAuthenticationKeys().size());

        // Now check that what we loaded matches what we created in-memory just above. We
        // use the fact that the order of the keys are preserved across save/load.
        Iterator<Credential.AuthenticationKey> it1 = credential.getAuthenticationKeys().iterator();
        Iterator<Credential.AuthenticationKey> it2 = credential2.getAuthenticationKeys().iterator();
        for (n = 0; n < 4; n++) {
            Credential.AuthenticationKey key1 = it1.next();
            Credential.AuthenticationKey key2 = it2.next();
            Assert.assertEquals(key1.mAlias, key2.mAlias);
            Assert.assertEquals(key1.getValidFrom(), key2.getValidFrom());
            Assert.assertEquals(key1.getValidUntil(), key2.getValidUntil());
            Assert.assertEquals(key1.getUsageCount(), key2.getUsageCount());
            Assert.assertArrayEquals(key1.getIssuerProvidedData(), key2.getIssuerProvidedData());
            Assert.assertArrayEquals(key1.getCertificateChain().toArray(),
                    key2.getCertificateChain().toArray());
        }

        Iterator<Credential.PendingAuthenticationKey> itp1 = credential.getPendingAuthenticationKeys().iterator();
        Iterator<Credential.PendingAuthenticationKey> itp2 = credential2.getPendingAuthenticationKeys().iterator();
        for (n = 0; n < 6; n++) {
            Credential.PendingAuthenticationKey key1 = itp1.next();
            Credential.PendingAuthenticationKey key2 = itp2.next();
            Assert.assertEquals(key1.mAlias, key2.mAlias);
            Assert.assertArrayEquals(key1.getCertificateChain().toArray(),
                    key2.getCertificateChain().toArray());
        }
    }

    @Test
    public void testAuthenticationKeyValidity() {
        CredentialStore credentialStore = new CredentialStore(
                mStorageEngine,
                mKeystoreEngineRepository);

        Credential credential = credentialStore.createCredential(
                "testCredential",
                "org.iso.18013.5.1.mDL",
                new BouncyCastleKeystore.CreateKeySettings.Builder().build());

        // We want to check the behavior for when the holder has a birthday and the issuer
        // carefully sends half the MSOs to be used before the birthday (with age_in_years set to
        // 17) and half the MSOs for after the birthday (with age_in_years set to 18).
        //
        // The validity periods are carefully set so the MSOs for 17 are have validUntil set to
        // to the holders birthday and the MSOs for 18 are set so validFrom starts at the birthday.
        //

        Timestamp timeValidityBegin = Timestamp.ofEpochMilli(50);
        Timestamp timeOfRequest = Timestamp.ofEpochMilli(50);
        Timestamp timeOfUseBeforeBirthday = Timestamp.ofEpochMilli(80);
        Timestamp timeOfBirthday = Timestamp.ofEpochMilli(100);
        Timestamp timeOfUseAfterBirthday = Timestamp.ofEpochMilli(120);
        Timestamp timeValidityEnd = Timestamp.ofEpochMilli(150);

        // Create and certify ten auth keys. Put age_in_years as the issuer provided data so we can
        // check it below.
        int n;
        for (n = 0; n < 10; n++) {
            credential.createAuthenticationKey(new BouncyCastleKeystore.CreateKeySettings.Builder().build());
        }
        Assert.assertEquals(10, credential.getPendingAuthenticationKeys().size());

        n = 0;
        for (Credential.PendingAuthenticationKey pendingAuthenticationKey :
                credential.getPendingAuthenticationKeys()) {
            if (n < 5) {
                pendingAuthenticationKey.certify(new byte[]{17}, timeValidityBegin, timeOfBirthday);
            } else {
                pendingAuthenticationKey.certify(new byte[]{18}, timeOfBirthday, timeValidityEnd);
            }
            n++;
        }

        // Simulate ten presentations before the birthday
        for (n = 0; n < 10; n++) {
            Credential.AuthenticationKey authenticationKey =
                    credential.findAuthenticationKey(timeOfUseBeforeBirthday);
            Assert.assertNotNull(authenticationKey);
            // Check we got a key with age 17.
            Assert.assertEquals((byte) 17, authenticationKey.getIssuerProvidedData()[0]);
            authenticationKey.increaseUsageCount();
        }

        // Simulate twenty presentations after the birthday
        for (n = 0; n < 20; n++) {
            Credential.AuthenticationKey authenticationKey =
                    credential.findAuthenticationKey(timeOfUseAfterBirthday);
            Assert.assertNotNull(authenticationKey);
            // Check we got a key with age 18.
            Assert.assertEquals((byte) 18, authenticationKey.getIssuerProvidedData()[0]);
            authenticationKey.increaseUsageCount();
        }

        // Examine the authentication keys. The first five should have use count 2, the
        // latter five use count 4.
        n = 0;
        for (Credential.AuthenticationKey authenticationKey : credential.getAuthenticationKeys()) {
            if (n++ < 5) {
                Assert.assertEquals(2, authenticationKey.getUsageCount());
            } else {
                Assert.assertEquals(4, authenticationKey.getUsageCount());
            }
        }
    }

        /*

    @Test
    public void testAuthenticationSlotsExpiringSoon() {
        CredentialStore credentialStore = new CredentialStore(
                mStorageEngine,
                mKeystoreEngineRepository);

        Credential credential = credentialStore.createCredential(
                "testCredential",
                "org.iso.18013.5.1.mDL",
                new CreateKeySettings());

        long minValidTimeMillis = 20;
        Timestamp timeValidityBegin = Timestamp.ofEpochMilli(50);
        Timestamp timeWhenNoneAreExpired = Timestamp.ofEpochMilli(100);
        Timestamp timeWhenTwoAreExpired = Timestamp.ofEpochMilli(132);
        Timestamp timeWhenNineAreExpired = Timestamp.ofEpochMilli(139);
        Timestamp timeWhenAllAreExpired = Timestamp.ofEpochMilli(140);
        Timestamp timeValidityEnd = Timestamp.ofEpochMilli(150);

        List<CredentialAuthSlot> pendingCertifications =
                credential.getAuthSlotsNeedingCertification(timeWhenNoneAreExpired, minValidTimeMillis);
        Assert.assertEquals(10, pendingCertifications.size());

        // Certify all ten and slide the validity window.
        int n = 0;
        for (CredentialAuthSlot slot : pendingCertifications) {
            credential.certifyPendingAuthSlot(
                    slot,
                    new byte[]{},
                    Timestamp.ofEpochMilli(timeValidityBegin.toEpochMilli() + n),
                    Timestamp.ofEpochMilli(timeValidityEnd.toEpochMilli() + n));
            n++;
        }

        pendingCertifications =
                credential.getAuthSlotsNeedingCertification(timeWhenNoneAreExpired, minValidTimeMillis);
        Assert.assertEquals(0, pendingCertifications.size());

        pendingCertifications =
                credential.getAuthSlotsNeedingCertification(timeWhenTwoAreExpired, minValidTimeMillis);
        Assert.assertEquals(2, pendingCertifications.size());

        pendingCertifications =
                credential.getAuthSlotsNeedingCertification(timeWhenNineAreExpired, minValidTimeMillis);
        Assert.assertEquals(9, pendingCertifications.size());

        pendingCertifications =
                credential.getAuthSlotsNeedingCertification(timeWhenAllAreExpired, minValidTimeMillis);
        Assert.assertEquals(10, pendingCertifications.size());
    }

     */

}
