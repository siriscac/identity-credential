package com.android.identity;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

import java.io.ByteArrayInputStream;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import co.nstant.in.cbor.CborBuilder;
import co.nstant.in.cbor.CborDecoder;
import co.nstant.in.cbor.CborException;
import co.nstant.in.cbor.builder.ArrayBuilder;
import co.nstant.in.cbor.builder.MapBuilder;
import co.nstant.in.cbor.model.Array;
import co.nstant.in.cbor.model.ByteString;
import co.nstant.in.cbor.model.DataItem;
import co.nstant.in.cbor.model.UnicodeString;

/**
 * TODO: writeme
 */
public class Credential {
    static String CREDENTIAL_PREFIX = "com.android.Credential_";

    static String CREDENTIAL_KEY_ALIAS_PREFIX =  "IC_CredentialKey_";

    static String AUTHENTICATION_KEY_ALIAS_PREFIX =  "IC_AuthenticationKey_";

    private final StorageEngine mStorageEngine;
    private final KeystoreEngineRepository mKeystoreEngineRepository;
    private String mName;
    private String mDocType;
    private String mCredentialKeyAlias;
    private List<X509Certificate> mCredentialKeyCertificateChain;

    private NameSpacedData mNameSpacedData = new NameSpacedData();
    private KeystoreEngine mKeystoreEngine;

    private List<PendingAuthenticationKey> mPendingAuthenticationKeys = new ArrayList<>();
    private List<AuthenticationKey> mAuthenticationKeys = new ArrayList<>();

    private long mAuthenticationKeyCounter;

    private Credential(@NonNull StorageEngine storageEngine,
                       @NonNull KeystoreEngineRepository keystoreEngineRepository) {
        mStorageEngine = storageEngine;
        mKeystoreEngineRepository = keystoreEngineRepository;
    }

    // Called by CredentialStore.createCredential().
    static Credential create(@NonNull StorageEngine storageEngine,
                             @NonNull KeystoreEngineRepository keystoreEngineRepository,
                             @NonNull String name,
                             @NonNull String docType,
                             @NonNull KeystoreEngine.CreateKeySettings credentialKeySettings) {

        Credential credential = new Credential(storageEngine, keystoreEngineRepository);
        credential.mName = name;
        credential.mDocType = docType;
        String keystoreEngineClassName = credentialKeySettings.getKeystoreEngineClass().getName();
        credential.mKeystoreEngine = keystoreEngineRepository.getImplementation(keystoreEngineClassName);
        if (credential.mKeystoreEngine == null) {
            throw new IllegalStateException("No KeystoreEngine with name " + keystoreEngineClassName);
        }
        credential.mCredentialKeyAlias = CREDENTIAL_KEY_ALIAS_PREFIX + name;

        credential.mCredentialKeyCertificateChain = credential.mKeystoreEngine.ecKeyCreate(
                credential.mCredentialKeyAlias,
                credentialKeySettings);

        credential.saveCredential();

        return credential;
    }

    private void saveCredential() {
        CborBuilder builder = new CborBuilder();
        MapBuilder<CborBuilder> map = builder.addMap();
        map.put("docType", mDocType);
        map.put("keystoreImplementationClassName", mKeystoreEngine.getClass().getName());
        map.put("credentialKeyAlias", mCredentialKeyAlias);

        ArrayBuilder<MapBuilder<CborBuilder>> credentialKeyCertChainBuilder =
                map.putArray("credentialKeyCertChain");
        for (X509Certificate certificate : mCredentialKeyCertificateChain) {
            try {
                credentialKeyCertChainBuilder.add(certificate.getEncoded());
            } catch (CertificateEncodingException e) {
                throw new IllegalStateException("Error encoding CredentialKey certificate chain", e);
            }
        }
        credentialKeyCertChainBuilder.end();

        map.put(new UnicodeString("nameSpacedData"), mNameSpacedData.toCbor());

        ArrayBuilder<MapBuilder<CborBuilder>> pendingAuthenticationKeysArrayBuilder =
                map.putArray("pendingAuthenticationKeys");
        for (PendingAuthenticationKey pendingAuthenticationKey : mPendingAuthenticationKeys) {
            pendingAuthenticationKeysArrayBuilder.add(pendingAuthenticationKey.toCbor());
        }

        ArrayBuilder<MapBuilder<CborBuilder>> authenticationKeysArrayBuilder =
                map.putArray("authenticationKeys");
        for (AuthenticationKey authenticationKey : mAuthenticationKeys) {
            authenticationKeysArrayBuilder.add(authenticationKey.toCbor());
        }

        map.put("authenticationKeyCounter", mAuthenticationKeyCounter);

        mStorageEngine.saveData(CREDENTIAL_PREFIX + mName, Util.cborEncode(builder.build().get(0)));
    }

    // Called by CredentialStore.lookupCredential().
    static Credential lookup(@NonNull StorageEngine storageEngine,
                             @NonNull KeystoreEngineRepository keystoreEngineRepository,
                             @NonNull String name) {
        Credential credential = new Credential(storageEngine, keystoreEngineRepository);
        credential.mName = name;
        if (!credential.loadCredential(keystoreEngineRepository)) {
            return null;
        }
        return credential;
    }

    private boolean loadCredential(@NonNull KeystoreEngineRepository keystoreEngineRepository) {
        byte[] data = mStorageEngine.loadData(CREDENTIAL_PREFIX + mName);
        if (data == null) {
            return false;
        }

        ByteArrayInputStream bais = new ByteArrayInputStream(data);
        List<DataItem> dataItems;
        try {
            dataItems = new CborDecoder(bais).decode();
        } catch (CborException e) {
            throw new IllegalStateException("Error decoded CBOR", e);
        }
        if (dataItems.size() != 1) {
            throw new IllegalStateException("Expected 1 item, found " + dataItems.size());
        }
        if (!(dataItems.get(0) instanceof co.nstant.in.cbor.model.Map)) {
            throw new IllegalStateException("Item is not a map");
        }
        co.nstant.in.cbor.model.Map map = (co.nstant.in.cbor.model.Map) dataItems.get(0);
        mDocType = Util.cborMapExtractString(map, "docType");

        String keystoreImplementationClassName =
                Util.cborMapExtractString(map, "keystoreImplementationClassName");
        mKeystoreEngine = keystoreEngineRepository.getImplementation(keystoreImplementationClassName);

        mCredentialKeyAlias = Util.cborMapExtractString(map, "credentialKeyAlias");

        DataItem credentialKeyCertChain = map.get(new UnicodeString("credentialKeyCertChain"));
        if (!(credentialKeyCertChain instanceof Array)) {
            throw new IllegalStateException("credentialKeyCertChain not found or not array");
        }
        mCredentialKeyCertificateChain = new ArrayList<>();
        for (DataItem item : ((Array) credentialKeyCertChain).getDataItems()) {
            byte[] encodedCert = ((ByteString) item).getBytes();
            try {
                CertificateFactory cf = CertificateFactory.getInstance("X.509");
                ByteArrayInputStream certBais = new ByteArrayInputStream(encodedCert);
                mCredentialKeyCertificateChain.add((X509Certificate) cf.generateCertificate(certBais));
            } catch (CertificateException e) {
                throw new IllegalStateException("Error decoding certificate blob", e);
            }
        }

        DataItem nameSpacedDataItem = map.get(new UnicodeString("nameSpacedData"));
        if (nameSpacedDataItem == null) {
            throw new IllegalStateException("nameSpacedData not found");
        }
        mNameSpacedData = NameSpacedData.fromCbor(nameSpacedDataItem);

        mPendingAuthenticationKeys = new ArrayList<>();
        DataItem pendingAuthenticationKeysDataItem = map.get(new UnicodeString("pendingAuthenticationKeys"));
        if (!(pendingAuthenticationKeysDataItem instanceof Array)) {
            throw new IllegalStateException("pendingAuthenticationKeys not found or not array");
        }
        for (DataItem item : ((Array) pendingAuthenticationKeysDataItem).getDataItems()) {
            mPendingAuthenticationKeys.add(PendingAuthenticationKey.fromCbor(item, this));
        }

        mAuthenticationKeys = new ArrayList<>();
        DataItem authenticationKeysDataItem = map.get(new UnicodeString("authenticationKeys"));
        if (!(authenticationKeysDataItem instanceof Array)) {
            throw new IllegalStateException("authenticationKeys not found or not array");
        }
        for (DataItem item : ((Array) authenticationKeysDataItem).getDataItems()) {
            mAuthenticationKeys.add(AuthenticationKey.fromCbor(item, this));
        }

        mAuthenticationKeyCounter = Util.cborMapExtractNumber(map, "authenticationKeyCounter");

        return true;
    }

    void deleteCredential() {
        // Need to use shallow copies because delete() modifies the list.
        for (PendingAuthenticationKey key : new ArrayList<>(mPendingAuthenticationKeys)) {
            key.delete();
        }
        for (AuthenticationKey key : new ArrayList<>(mAuthenticationKeys)) {
            key.delete();
        }
        mKeystoreEngine.ecKeyDelete(mCredentialKeyAlias);
        mStorageEngine.deleteData(CREDENTIAL_PREFIX + mName);
    }

    public @NonNull String getName() {
        return mName;
    }

    public @NonNull String getDocType() {
        return mDocType;
    }

    public @NonNull List<X509Certificate> getCredentialKeyCertificateChain() {
        return Collections.unmodifiableList(mCredentialKeyCertificateChain);
    }

    public @NonNull NameSpacedData getNameSpacedData() {
        return mNameSpacedData;
    }

    public void setNameSpacedData(@NonNull NameSpacedData nameSpacedData) {
        mNameSpacedData = nameSpacedData;
        saveCredential();
    }


    /**
     * Finds a suitable authentication key to use.
     *
     * @param now Pass current time to ensure that the selected slot's validity period or
     *   {@code null} to not consider validity times.
     * @return An authentication key which can be used for signing or {@code null} if none was found.
     */
    public @Nullable AuthenticationKey findAuthenticationKey(@Nullable Timestamp now) {

        AuthenticationKey candidate = null;
        for (AuthenticationKey authenticationKey : mAuthenticationKeys) {
            // If current time is passed...
            if (now != null) {
                // ... ignore slots that aren't yet valid
                if (now.toEpochMilli() < authenticationKey.getValidFrom().toEpochMilli()) {
                    continue;
                }
                // .. ignore slots that aren't valid anymore
                if (now.toEpochMilli() > authenticationKey.getValidUntil().toEpochMilli()) {
                    continue;
                }
            }
            // If we already have a candidate, prefer this one if its usage count is lower
            if (candidate != null) {
                if (authenticationKey.getUsageCount() < candidate.getUsageCount()) {
                    candidate = authenticationKey;
                }
            } else {
                candidate = authenticationKey;
            }
        }
        return candidate;
    }


    // TODO: add method to sign with CredentialKey

    public static class AuthenticationKey {
        List<X509Certificate> mCertificateChain;

        String mAlias;
        int mUsageCount;
        byte[] mData;
        Timestamp mValidFrom;
        Timestamp mValidUntil;
        private Credential mCredential;
        private String mKeystoreEngineName;

        static AuthenticationKey create(
                @NonNull PendingAuthenticationKey pendingAuthenticationKey,
                @NonNull byte[] issuerProvidedAuthenticationData,
                @NonNull Timestamp validFrom,
                @NonNull Timestamp validUntil,
                @NonNull Credential credential) {
            AuthenticationKey ret = new AuthenticationKey();
            ret.mAlias = pendingAuthenticationKey.mAlias;
            ret.mData = issuerProvidedAuthenticationData;
            ret.mValidFrom = validFrom;
            ret.mValidUntil = validUntil;
            ret.mCredential = credential;
            ret.mKeystoreEngineName = pendingAuthenticationKey.mKeystoreEngineName;
            ret.mCertificateChain = pendingAuthenticationKey.mCertificateChain;
            return ret;
        }

        /**
         * Gets the X.509 certificate chain for the authentication key.
         *
         * @return An X.509 certificate chain for the key.
         */
        public @Nullable List<X509Certificate> getCertificateChain() {
            return mCertificateChain;
        }

        /**
         * Returns how many time the key in the slot has been used.
         *
         * @return The number of times the key in slot has been used.
         */
        public int getUsageCount() {
            return mUsageCount;
        }

        /**
         * Gets the issuer-provided data associated with the key.
         *
         * @return The issuer-provided data.
         */
        public @NonNull byte[] getIssuerProvidedData() {
            return mData;
        }

        /**
         * Gets the point in time the issuer-provided data is valid from.
         *
         * @return The valid-from time.
         */
        public @NonNull Timestamp getValidFrom() {
            return mValidFrom;
        }

        /**
         * Gets the point in time the issuer-provided data is valid until.
         *
         * @return The valid-until time.
         */
        public @NonNull Timestamp getValidUntil() {
            return mValidUntil;
        }

        public void delete() {
            KeystoreEngine keystoreEngine = mCredential.mKeystoreEngineRepository
                    .getImplementation(mKeystoreEngineName);
            if (keystoreEngine == null) {
                throw new IllegalArgumentException("Unknown engine " + mKeystoreEngineName);
            }
            keystoreEngine.ecKeyDelete(mAlias);
            mCredential.removeAuthenticationKey(this);
        }

        public void increaseUsageCount() {
            mUsageCount += 1;
            mCredential.saveCredential();
        }

        DataItem toCbor() {
            CborBuilder builder = new CborBuilder();
            MapBuilder<CborBuilder> mapBuilder = builder.addMap();
            mapBuilder.put("alias", mAlias)
                    .put("keystoreEngineName", mKeystoreEngineName)
                    .put("usageCount", mUsageCount)
                    .put("data", mData)
                    .put("validFrom", mValidFrom.toEpochMilli())
                    .put("validUntil", mValidUntil.toEpochMilli());
            try {
                ArrayBuilder<MapBuilder<CborBuilder>> arrayBuilder =
                        mapBuilder.putArray("certificateChain");
                for (X509Certificate certificate : mCertificateChain) {
                    arrayBuilder.add(certificate.getEncoded());
                }
            } catch (CertificateEncodingException e) {
                throw new IllegalStateException("Error encoding pending certificate", e);
            }
            return builder.build().get(0);
        }

        static AuthenticationKey fromCbor(@NonNull DataItem dataItem,
                                          @NonNull Credential credential) {
            AuthenticationKey ret = new AuthenticationKey();
            ret.mAlias = Util.cborMapExtractString(dataItem, "alias");
            ret.mKeystoreEngineName = Util.cborMapExtractString(dataItem, "keystoreEngineName");
            ret.mUsageCount = (int) Util.cborMapExtractNumber(dataItem, "usageCount");
            ret.mData = Util.cborMapExtractByteString(dataItem, "data");
            ret.mValidFrom = Timestamp.ofEpochMilli(Util.cborMapExtractNumber(dataItem, "validFrom"));
            ret.mValidUntil = Timestamp.ofEpochMilli(Util.cborMapExtractNumber(dataItem, "validUntil"));
            ret.mCredential = credential;
            ret.mCertificateChain = new ArrayList<>();
            List<DataItem> certArrayDataItems = Util.cborMapExtractArray(dataItem, "certificateChain");
            for (DataItem certDataItem : certArrayDataItems) {
                byte[] encodedCert = ((ByteString) certDataItem).getBytes();
                try {
                    CertificateFactory cf = CertificateFactory.getInstance("X.509");
                    ByteArrayInputStream certBais = new ByteArrayInputStream(encodedCert);
                    ret.mCertificateChain.add((X509Certificate) cf.generateCertificate(certBais));
                } catch (CertificateException e) {
                    throw new IllegalStateException("Error decoding certificate blob", e);
                }
            }
            return ret;
        }
    }

    public static class PendingAuthenticationKey {
        String mKeystoreEngineName;
        List<X509Certificate> mCertificateChain;

        String mAlias;
        Credential mCredential;

        static @NonNull PendingAuthenticationKey create(
                @NonNull String alias,
                @NonNull KeystoreEngine.CreateKeySettings createKeySettings,
                @NonNull Credential credential) {
            PendingAuthenticationKey ret = new PendingAuthenticationKey();
            ret.mAlias = alias;
            ret.mKeystoreEngineName = createKeySettings.getKeystoreEngineClass().getName();
            KeystoreEngine keystoreEngine = credential.mKeystoreEngineRepository
                    .getImplementation(ret.mKeystoreEngineName);
            if (keystoreEngine == null) {
                throw new IllegalArgumentException("Unknown engine " + ret.mKeystoreEngineName);
            }
            ret.mCertificateChain = keystoreEngine.ecKeyCreate(alias, createKeySettings);
            ret.mCredential = credential;
            return ret;
        }

        /**
         * Gets the X.509 certificate chain for the authentication key pending certification.
         *
         * <p>The application should send this key to the issuer which should create issuer-provided
         * data (e.g. an MSO if using ISO/IEC 18013-5:2021) using the key as the {@code DeviceKey}.
         *
         * @return An X.509 certificate chain for the pending key or {@code null} if the slot isn't pending.
         */
        public @Nullable List<X509Certificate> getCertificateChain() {
            return mCertificateChain;
        }

        public void delete() {
            KeystoreEngine keystoreEngine = mCredential.mKeystoreEngineRepository
                    .getImplementation(mKeystoreEngineName);
            if (keystoreEngine == null) {
                throw new IllegalArgumentException("Unknown engine " + mKeystoreEngineName);
            }
            keystoreEngine.ecKeyDelete(mAlias);
            mCredential.removePendingAuthenticationKey(this);
        }

        public @NonNull AuthenticationKey certify(@NonNull byte[] issuerProvidedAuthenticationData,
                                                  @NonNull Timestamp validFrom,
                                                  @NonNull Timestamp validUntil) {
            return mCredential.certifyPendingAuthenticationKey(this,
                    issuerProvidedAuthenticationData,
                    validFrom,
                    validUntil);
        }

        @NonNull DataItem toCbor() {
            CborBuilder builder = new CborBuilder();
            MapBuilder<CborBuilder> mapBuilder = builder.addMap();
            mapBuilder.put("alias", mAlias)
                    .put("keystoreEngineName", mKeystoreEngineName);
            try {
                ArrayBuilder<MapBuilder<CborBuilder>> arrayBuilder =
                        mapBuilder.putArray("certificateChain");
                for (X509Certificate certificate : mCertificateChain) {
                    arrayBuilder.add(certificate.getEncoded());
                }
            } catch (CertificateEncodingException e) {
                throw new IllegalStateException("Error encoding pending certificate", e);
            }
            return builder.build().get(0);
        }

        static PendingAuthenticationKey fromCbor(@NonNull DataItem dataItem,
                                                 @NonNull Credential credential) {
            PendingAuthenticationKey ret = new PendingAuthenticationKey();
            ret.mAlias = Util.cborMapExtractString(dataItem, "alias");
            ret.mKeystoreEngineName = Util.cborMapExtractString(dataItem, "keystoreEngineName");
            ret.mCredential = credential;
            ret.mCertificateChain = new ArrayList<>();
            List<DataItem> certArrayDataItems = Util.cborMapExtractArray(dataItem, "certificateChain");
            for (DataItem certDataItem : certArrayDataItems) {
                byte[] encodedCert = ((ByteString) certDataItem).getBytes();
                try {
                    CertificateFactory cf = CertificateFactory.getInstance("X.509");
                    ByteArrayInputStream certBais = new ByteArrayInputStream(encodedCert);
                    ret.mCertificateChain.add((X509Certificate) cf.generateCertificate(certBais));
                } catch (CertificateException e) {
                    throw new IllegalStateException("Error decoding certificate blob", e);
                }
            }
            return ret;
        }
    }

    public @NonNull PendingAuthenticationKey createAuthenticationKey(
            @NonNull KeystoreEngine.CreateKeySettings createKeySettings) {
        String alias = AUTHENTICATION_KEY_ALIAS_PREFIX + mName + "_authKey_" + mAuthenticationKeyCounter++;
        PendingAuthenticationKey pendingAuthenticationKey =
                PendingAuthenticationKey.create(
                        alias,
                        createKeySettings,
                        this);
        mPendingAuthenticationKeys.add(pendingAuthenticationKey);
        saveCredential();
        return pendingAuthenticationKey;
    }

    void removePendingAuthenticationKey(@NonNull PendingAuthenticationKey pendingAuthenticationKey) {
        if (!mPendingAuthenticationKeys.remove(pendingAuthenticationKey)) {
            throw new IllegalStateException("Error removing pending authentication key");
        }
        saveCredential();
    }

    void removeAuthenticationKey(@NonNull AuthenticationKey authenticationKey) {
        if (!mAuthenticationKeys.remove(authenticationKey)) {
            throw new IllegalStateException("Error removing authentication key");
        }
        saveCredential();
    }

    @NonNull AuthenticationKey certifyPendingAuthenticationKey(
            @NonNull PendingAuthenticationKey pendingAuthenticationKey,
            @NonNull byte[] issuerProvidedAuthenticationData,
            @NonNull Timestamp validFrom,
            @NonNull Timestamp validUntil) {
        if (!mPendingAuthenticationKeys.remove(pendingAuthenticationKey)) {
            throw new IllegalStateException("Error removing pending authentication key");
        }
        AuthenticationKey authenticationKey =
                AuthenticationKey.create(pendingAuthenticationKey,
                        issuerProvidedAuthenticationData,
                        validFrom,
                        validUntil,
                        this);
        mAuthenticationKeys.add(authenticationKey);
        saveCredential();
        return authenticationKey;
    }

    public @NonNull List<PendingAuthenticationKey> getPendingAuthenticationKeys() {
        // Return a shallow copy b/c caller might call PendingAuthenticationKey.certify()
        // or PendingAuthenticationKey.delete() while iterating.
        return new ArrayList<>(mPendingAuthenticationKeys);
    }

    public @NonNull List<AuthenticationKey> getAuthenticationKeys() {
        // Return a shallow copy b/c caller might call AuthenticationKey.delete()
        // while iterating.
        return new ArrayList<>(mAuthenticationKeys);
    }
}
