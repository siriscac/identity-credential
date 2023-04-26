package com.android.identity;

import android.content.Context;
import android.os.Build;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.UnrecoverableEntryException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

/**
 * An implementation of {@link KeystoreEngine} using Android Keystore.
 */
public class AndroidKeystore implements KeystoreEngine {
    private static final String TAG = "AndroidKeystore";
    private final Context mContext;

    /**
     * Constructs a new {@link AndroidKeystore}.
     *
     * @param context the application context.
     */
    public AndroidKeystore(@NonNull Context context) {
        mContext = context;
    }

    @Override
    public @NonNull List<X509Certificate> ecKeyCreate(
            @NonNull String alias,
            @NonNull KeystoreEngine.CreateKeySettings createKeySettings) {
        CreateKeySettings aSettings = (CreateKeySettings) createKeySettings;
        KeyPairGenerator kpg = null;
        try {
            kpg = KeyPairGenerator.getInstance(
                    KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore");

            KeyGenParameterSpec.Builder builder = new KeyGenParameterSpec.Builder(
                    alias,
                    KeyProperties.PURPOSE_SIGN | KeyProperties.PURPOSE_VERIFY)
                    .setDigests(KeyProperties.DIGEST_SHA256, KeyProperties.DIGEST_SHA512);
            if (aSettings.getUserAuthenticationRequired()) {
                builder.setUserAuthenticationRequired(true);
                long timeoutMillis = aSettings.getUserAuthenticationTimeoutMillis();
                if (timeoutMillis == 0) {
                    builder.setUserAuthenticationValidityDurationSeconds(-1);
                } else {
                    int timeoutSeconds = (int) Math.max(1, timeoutMillis/1000);
                    builder.setUserAuthenticationValidityDurationSeconds(timeoutSeconds);
                }
                builder.setInvalidatedByBiometricEnrollment(false);
            }
            if (aSettings.getUseStrongBox()) {
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                    builder.setIsStrongBoxBacked(true);
                }
            }
            if (aSettings.getAttestKeyAlias() != null) {
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
                    builder.setAttestKeyAlias(aSettings.getAttestKeyAlias());
                }
            }
            builder.setAttestationChallenge(aSettings.getAttestationChallenge());
            try {
                kpg.initialize(builder.build());
            } catch (InvalidAlgorithmParameterException e) {
                throw new IllegalStateException("Unexpected exception", e);
            }
            kpg.generateKeyPair();
        } catch (NoSuchAlgorithmException
                 | NoSuchProviderException e) {
            throw new IllegalStateException("Error creating key", e);
        }

        List<X509Certificate> ret = new ArrayList<>();
        try {
            KeyStore ks = KeyStore.getInstance("AndroidKeyStore");
            ks.load(null);
            Certificate[] certificates = ks.getCertificateChain(alias);
            for (Certificate certificate : certificates) {
                ret.add((X509Certificate) certificate);
            }
        } catch (CertificateException
                | KeyStoreException
                | IOException
                | NoSuchAlgorithmException e) {
            throw new IllegalStateException("Error generate certificate chain", e);
        }
        Logger.d(TAG, "EC key with alias '" + alias + "' created");
        return ret;
    }

    @Override
    public void ecKeyDelete(@NonNull String alias) {
        KeyStore ks;
        KeyStore.Entry entry;
        try {
            ks = KeyStore.getInstance("AndroidKeyStore");
            ks.load(null);
            if (!ks.containsAlias(alias)) {
                Logger.w(TAG, "Key with alias '" + alias + "' doesn't exist");
                return;
            }
            ks.deleteEntry(alias);
        } catch (CertificateException
                 | IOException
                 | NoSuchAlgorithmException
                 | KeyStoreException e) {
            throw new IllegalStateException("Error loading keystore", e);
        }
        Logger.d(TAG, "EC key with alias '" + alias + "' deleted");
    }

    @Override
    public @NonNull byte[] ecKeySign(@NonNull String alias,
                                     @Algorithm int signatureAlgorithm,
                                     @NonNull byte[] dataToSign) {
        String signatureAlgorithmName;
        switch (signatureAlgorithm) {
            case ALGORITHM_ES256:
                signatureAlgorithmName = "SHA256withECDSA";
                break;
            case ALGORITHM_ES384:
                signatureAlgorithmName = "SHA384withECDSA";
                break;
            case ALGORITHM_ES512:
                signatureAlgorithmName = "SHA512withECDSA";
                break;
            default:
                throw new IllegalArgumentException(
                        "Unsupported signing algorithm  with id " + signatureAlgorithm);
        }
        KeyStore ks = null;
        try {
            ks = KeyStore.getInstance("AndroidKeyStore");
            ks.load(null);
            KeyStore.Entry entry = ks.getEntry(alias, null);
            if (entry == null) {
                throw new IllegalArgumentException("No entry for alias");
            }
            PrivateKey privateKey = ((KeyStore.PrivateKeyEntry) entry).getPrivateKey();
            Signature s = Signature.getInstance(signatureAlgorithmName);
            s.initSign(privateKey);
            return s.sign();
        } catch (UnrecoverableEntryException
                 | CertificateException
                 | KeyStoreException
                 | IOException
                 | NoSuchAlgorithmException
                 | SignatureException
                 | InvalidKeyException e) {
            throw new IllegalStateException("Unexpected exception while signing", e);
        }
    }

    /**
     * Class for holding Android Keystore-specific settings.
     */
    public static class CreateKeySettings extends KeystoreEngine.CreateKeySettings {
        private final byte[] mAttestationChallenge;
        private final boolean mUserAuthenticationRequired;
        private final long mUserAuthenticationTimeoutMillis;
        private final boolean mUseStrongBox;
        private final String mAttestKeyAlias;

        private CreateKeySettings(@NonNull byte[] attestationChallenge,
                                  boolean userAuthenticationRequired,
                                  long userAuthenticationTimeoutMillis,
                                  boolean useStrongBox,
                                  @Nullable String attestKeyAlias) {
            super(AndroidKeystore.class);
            mAttestationChallenge = attestationChallenge;
            mUserAuthenticationRequired = userAuthenticationRequired;
            mUserAuthenticationTimeoutMillis = userAuthenticationTimeoutMillis;
            mUseStrongBox = useStrongBox;
            mAttestKeyAlias = attestKeyAlias;
        }

        public @NonNull byte[] getAttestationChallenge() {
            return mAttestationChallenge;
        }

        public boolean getUserAuthenticationRequired() {
            return mUserAuthenticationRequired;
        }

        public long getUserAuthenticationTimeoutMillis() {
            return mUserAuthenticationTimeoutMillis;
        }

        public boolean getUseStrongBox() {
            return mUseStrongBox;
        }

        public @Nullable String getAttestKeyAlias() {
            return mAttestKeyAlias;
        }

        /**
         * A builder for {@link CreateKeySettings}.
         */
        public static class Builder {
            private final byte[] mAttestationChallenge;
            private boolean mUserAuthenticationRequired;
            private long mUserAuthenticationTimeoutMillis;
            private boolean mUseStrongBox;
            private String mAttestKeyAlias;

            /**
             * Constructor.
             *
             * @param attestationChallenge challenge to include in attestation for the key.
             */
            public Builder(@NonNull byte[] attestationChallenge) {
                mAttestationChallenge = attestationChallenge;
            }

            /**
             * Method to specify if user authentication is required to present the credential.
             *
             * <p>By default, no user authentication is required.
             *
             * @param required True if user authentication is required, false otherwise.
             * @param timeoutMillis If 0, user authentication is required for every presentation of
             *                      the credential, otherwise it's required within the given amount
             *                      of milliseconds.
             * @return the builder.
             */
            public @NonNull Builder setUserAuthenticationRequired(boolean required, long timeoutMillis) {
                mUserAuthenticationRequired = required;
                mUserAuthenticationTimeoutMillis = timeoutMillis;
                return this;
            }

            /**
             * Method to specify if StrongBox Android Keystore should be used, if available.
             *
             * By default StrongBox isn't used.
             *
             * @param useStrongBox Whether to use StrongBox.
             * @return the builder.
             */
            public @NonNull Builder setUseStrongBox(boolean useStrongBox) {
                mUseStrongBox = useStrongBox;
                return this;
            }

            /**
             * Method to specify if an attest key should be used.
             *
             * See <a href="https://developer.android.com/reference/android/security/keystore/KeyGenParameterSpec.Builder#setAttestKeyAlias(java.lang.String)">setAttestKeyAlias() method</a>
             * for more information about attest keys.
             *
             * @param attestKeyAlias the Android Keystore alias of the attest key or {@code null} to not use an attest key.
             * @return the builder.
             */
            public @NonNull Builder setAttestKeyAlias(@Nullable String attestKeyAlias) {
                mAttestKeyAlias = attestKeyAlias;
                return this;
            }

            /**
             * Builds the {@link CreateKeySettings}.
             *
             * @return a new {@link CreateKeySettings}.
             */
            public @NonNull CreateKeySettings build() {
                return new CreateKeySettings(
                        mAttestationChallenge,
                        mUserAuthenticationRequired,
                        mUserAuthenticationTimeoutMillis,
                        mUseStrongBox,
                        mAttestKeyAlias);
            }
        }

    }
}
