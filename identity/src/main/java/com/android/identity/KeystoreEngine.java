package com.android.identity;

import androidx.annotation.IntDef;
import androidx.annotation.NonNull;

import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.security.cert.X509Certificate;
import java.util.List;

/**
 * An interface to a Secure Keystore.
 *
 * <p>This interface exists to abstract the underlying hardware-backed keystore
 * used for creation of key material. For an implementation using Android Keystore,
 * see {@link AndroidKeystore}.
 */
public interface KeystoreEngine {

    /** The curve identifier for P-256 */
    int EC_CURVE_P256 = 1;
    /** The curve identifier for P-384 */
    int EC_CURVE_P384 = 2;
    /** The curve identifier for P-521 */
    int EC_CURVE_P521 = 3;
    /** The curve identifier for brainpoolP256r1 */
    int EC_CURVE_BRAINPOOLP256R1 = -65537;
    /** The curve identifier for brainpoolP320r1 */
    int EC_CURVE_BRAINPOOLP320R1 = -65538;
    /** The curve identifier for brainpoolP384r1 */
    int EC_CURVE_BRAINPOOLP384R1 = -65539;
    /** The curve identifier for brainpoolP512r1 */
    int EC_CURVE_BRAINPOOLP512R1 = -65540;
    /** The curve identifier for Ed25519 */
    int EC_CURVE_ED25519 = 6;
    /** The curve identifier for Ed448 */
    int EC_CURVE_ED448 = 7;

    /**
     * An annotation used to specify allowed curve identifiers.
     *
     * <p>All curve identifiers are from the <a href="https://www.iana.org/assignments/cose/cose.xhtml">IANA COSE registry</a>.
     */
    @Retention(RetentionPolicy.SOURCE)
    @IntDef(value = {
            EC_CURVE_P256,
            EC_CURVE_P384,
            EC_CURVE_P521,
            EC_CURVE_BRAINPOOLP256R1,
            EC_CURVE_BRAINPOOLP320R1,
            EC_CURVE_BRAINPOOLP384R1,
            EC_CURVE_BRAINPOOLP512R1,
            EC_CURVE_ED25519,
            EC_CURVE_ED448
    })
    @interface EcCurve {}

    /** The algorithm identifier for signatures using ECDSA with SHA-256 */
    int ALGORITHM_ES256 = -7;
    /** The algorithm identifier for signatures using ECDSA with SHA-384 */
    int ALGORITHM_ES384 = -35;
    /** The algorithm identifier for signatures using ECDSA with SHA-512 */
    int ALGORITHM_ES512 = -36;
    /** The algorithm identifier for signatures using EdDSA */
    int ALGORITHM_EDDSA = -8;

    /**
     * An annotation used to specify algorithms.
     *
     * <p>All algorithm identifiers are from the <a href="https://www.iana.org/assignments/cose/cose.xhtml">IANA COSE registry</a>.
     */
    @Retention(RetentionPolicy.SOURCE)
    @IntDef(value = {
            ALGORITHM_ES256,
            ALGORITHM_ES384,
            ALGORITHM_ES512,
            ALGORITHM_EDDSA
    })
    @interface Algorithm {}

    /**
     * Creates an EC key.
     *
     * <p>This creates an EC key-pair where the private part of the key never is exposed
     * to the user of this interface.
     *
     * <p>The returned certificate-chain depends on the specific Keystore Implementation used
     * and the only guarantee is that the leaf certificate contains the public key of the created
     * key. Usually a list of certificates chaining up to a well-known root is returned along
     * with platform specific information in the leaf certificate.
     *
     * <p>If an existing key with the given alias already exists it will be replaced by the
     * new key.
     *
     * @param alias             A unique string to identify the newly created key.
     * @param createKeySettings A {@link CreateKeySettings} object.
     * @return the certificate chain for the newly created key.
     */
    @NonNull List<X509Certificate> ecKeyCreate(@NonNull String alias,
                                               @NonNull CreateKeySettings createKeySettings);

    /**
     * Deletes a previously created EC key.
     *
     * <p>If the key to delete doesn't exist, this is a no-op.
     *
     * @param alias The alias of the EC key to delete.
     */
    void ecKeyDelete(@NonNull String alias);

    /**
     * Signs some data with an EC key.
     *
     * @param alias The alias of the EC key to sign with.
     * @param signatureAlgorithm the signature algorithm to use.
     * @param dataToSign the data to sign.
     * @return a DER encoded string with the signature.
     * @throws IllegalArgumentException if there is no key with the given alias.
     * @throws IllegalArgumentException if the signature algorithm isn’t compatible
     *                                  with the key.
     */
    @NonNull byte[] ecKeySign(@NonNull String alias,
                              @Algorithm int signatureAlgorithm,
                              @NonNull byte[] dataToSign);

    /**
     *  Abstract type used to indicate key creation settings (authentication required,
     *  nonce/challenge for remote attestation, etc.) and which {@link KeystoreEngine}
     *  to use.
     *
     *  <p>See {@link AndroidKeystore.CreateKeySettings} for the Android Keystore implementation.
     */
    abstract class CreateKeySettings {

        private final Class<?> mKeystoreEngineClass;

        protected CreateKeySettings(@NonNull Class<?> keystoreEngineClass) {
            mKeystoreEngineClass = keystoreEngineClass;
        }

        /**
         * Returns the class of the {@link KeystoreEngine} these settings are for.
         *
         * @return A {@link KeystoreEngine}-derived type.
         */
        public @NonNull
        Class<?> getKeystoreEngineClass() {
            return mKeystoreEngineClass;
        }
    }
}
