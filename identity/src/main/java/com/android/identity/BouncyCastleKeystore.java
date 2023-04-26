package com.android.identity;

import static java.util.concurrent.TimeUnit.DAYS;
import static java.util.concurrent.TimeUnit.MILLISECONDS;

import androidx.annotation.NonNull;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import co.nstant.in.cbor.CborBuilder;
import co.nstant.in.cbor.CborDecoder;
import co.nstant.in.cbor.CborException;
import co.nstant.in.cbor.builder.MapBuilder;
import co.nstant.in.cbor.model.DataItem;

public class BouncyCastleKeystore implements KeystoreEngine {
    private static final String TAG = "BouncyCastleKeystore";
    private static final String PREFIX = "com.android.identity.BouncyCastleKeystoreImplementation_";
    private final StorageEngine mStorageEngine;

    public BouncyCastleKeystore(@NonNull StorageEngine storageEngine) {
        mStorageEngine = storageEngine;
    }

    @NonNull
    @Override
    public List<X509Certificate> ecKeyCreate(@NonNull String alias,
                                             @NonNull KeystoreEngine.CreateKeySettings createKeySettings) {
        CreateKeySettings settings = (CreateKeySettings) createKeySettings;
        ArrayList<X509Certificate> certificateChain = new ArrayList<>();

        KeyPairGenerator kpg;
        String certSigningSignatureAlgorithm;
        try {
            kpg = KeyPairGenerator.getInstance("EC", new BouncyCastleProvider());
            switch (settings.getEcCurve()) {
                case EC_CURVE_P256:
                    kpg.initialize(new ECGenParameterSpec("secp256r1"));
                    certSigningSignatureAlgorithm = "SHA256withECDSA";
                    break;
                case EC_CURVE_P384:
                    kpg.initialize(new ECGenParameterSpec("secp384r1"));
                    certSigningSignatureAlgorithm = "SHA384withECDSA";
                    break;
                case EC_CURVE_P521:
                    kpg.initialize(new ECGenParameterSpec("secp521r1"));
                    certSigningSignatureAlgorithm = "SHA512withECDSA";
                    break;
                case EC_CURVE_BRAINPOOLP256R1:
                    kpg.initialize(new ECGenParameterSpec("brainpoolP256r1"));
                    certSigningSignatureAlgorithm = "SHA256withECDSA";
                    break;
                case EC_CURVE_BRAINPOOLP320R1:
                    kpg.initialize(new ECGenParameterSpec("brainpoolP320r1"));
                    certSigningSignatureAlgorithm = "SHA256withECDSA";
                    break;
                case EC_CURVE_BRAINPOOLP384R1:
                    kpg.initialize(new ECGenParameterSpec("brainpoolP384r1"));
                    certSigningSignatureAlgorithm = "SHA384withECDSA";
                    break;
                case EC_CURVE_BRAINPOOLP512R1:
                    kpg.initialize(new ECGenParameterSpec("brainpoolP512r1"));
                    certSigningSignatureAlgorithm = "SHA512withECDSA";
                    break;
                case EC_CURVE_ED25519:
                    kpg = KeyPairGenerator.getInstance("Ed25519", new BouncyCastleProvider());
                    certSigningSignatureAlgorithm = "Ed25519";
                    break;
                case EC_CURVE_ED448:
                    kpg = KeyPairGenerator.getInstance("Ed448", new BouncyCastleProvider());
                    certSigningSignatureAlgorithm = "Ed448";
                    break;
                default:
                    throw new IllegalArgumentException(
                            "Unknown curve with id " + settings.getEcCurve());
            }

            KeyPair keyPair = kpg.generateKeyPair();
            CborBuilder builder = new CborBuilder();
            MapBuilder<CborBuilder> map = builder.addMap();
            map.put("privateKey", keyPair.getPrivate().getEncoded());
            map.put("curve", settings.getEcCurve());
            mStorageEngine.saveData(PREFIX + alias, Util.cborEncode(builder.build().get(0)));

            X500Name issuer = new X500Name("CN=Android Identity Credential BC KS Impl");
            X500Name subject = new X500Name("CN=Android Identity Credential BC KS Impl");

            Date now = new Date();
            Date expirationDate = new Date(now.getTime() + MILLISECONDS.convert(365, DAYS));
            BigInteger serial = BigInteger.ONE;
            JcaX509v3CertificateBuilder certBuilder =
                    new JcaX509v3CertificateBuilder(issuer,
                            serial,
                            now,
                            expirationDate,
                            subject,
                            keyPair.getPublic());
            ContentSigner signer = new JcaContentSignerBuilder(certSigningSignatureAlgorithm)
                    .build(keyPair.getPrivate());
            byte[] encodedCert = certBuilder.build(signer).getEncoded();

            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            ByteArrayInputStream bais = new ByteArrayInputStream(encodedCert);
            certificateChain.add((X509Certificate) cf.generateCertificate(bais));

        } catch (NoSuchAlgorithmException
                 | CertificateException
                 | InvalidAlgorithmParameterException
                 | OperatorCreationException
                 | IOException e) {
            throw new IllegalStateException("Unexpected exception", e);
        }

        return certificateChain;
    }

    @Override
    public void ecKeyDelete(@NonNull String alias) {
        mStorageEngine.deleteData(PREFIX + alias);
    }

    @NonNull
    @Override
    public byte[] ecKeySign(@NonNull String alias,
                            @Algorithm int signatureAlgorithm,
                            @NonNull byte[] dataToSign) {
        byte[] data = mStorageEngine.loadData(PREFIX + alias);
        if (data == null) {
            throw new IllegalArgumentException("No key with given alias");
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
        byte[] encodedPrivateKey = Util.cborMapExtractByteString(map, "privateKey");
        @EcCurve int curve = (int) Util.cborMapExtractNumber(map, "curve");

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
            case ALGORITHM_EDDSA:
                if (curve == EC_CURVE_ED25519) {
                    signatureAlgorithmName = "Ed25519";
                } else if (curve == EC_CURVE_ED448) {
                    signatureAlgorithmName = "Ed448";
                } else {
                    throw new IllegalArgumentException("ALGORITHM_EDDSA can only be used with "
                            + "EC_CURVE_ED_25519 and EC_CURVE_ED_448");
                }
                break;
            default:
                throw new IllegalArgumentException(
                        "Unsupported signing algorithm  with id " + signatureAlgorithm);
        }

        Logger.d(TAG, "Signing with algorithm " + signatureAlgorithmName + " for curve " + curve);

        try {
            PKCS8EncodedKeySpec encodedKeySpec = new PKCS8EncodedKeySpec(encodedPrivateKey);
            KeyFactory ecKeyFac = KeyFactory.getInstance("EC", new BouncyCastleProvider());
            PrivateKey privateKey = ecKeyFac.generatePrivate(encodedKeySpec);
            Signature s = Signature.getInstance(signatureAlgorithmName);
            s.initSign(privateKey);
            return s.sign();
        } catch (NoSuchAlgorithmException
                 | SignatureException
                 | InvalidKeyException
                 | InvalidKeySpecException e) {
            throw new IllegalStateException("Unexpected Exception", e);
        }
    }

    public static class CreateKeySettings extends KeystoreEngine.CreateKeySettings {
        private final @EcCurve int mEcCurve;

        private CreateKeySettings(@EcCurve int ecCurve) {
            super(BouncyCastleKeystore.class);
            mEcCurve = ecCurve;
        }

        public @EcCurve int getEcCurve() {
            return mEcCurve;
        }

        /**
         * A builder for {@link CreateKeySettings}.
         */
        public static class Builder {
            private @EcCurve int mEcCurve = EC_CURVE_P256;

            /**
             * Sets the curve to use for EC keys.
             *
             * <p>By default {@link AndroidKeystore#EC_CURVE_P256} is used.
             *
             * @param curve the curve to use.
             * @return the builder.
             */
            public @NonNull Builder setEcCurve(@EcCurve int curve) {
                mEcCurve = curve;
                return this;
            }

            /**
             * Builds the {@link CreateKeySettings}.
             *
             * @return a new {@link CreateKeySettings}.
             */
            public @NonNull CreateKeySettings build() {
                return new CreateKeySettings(mEcCurve);
            }
        }
    }
}
