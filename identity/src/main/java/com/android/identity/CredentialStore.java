package com.android.identity;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

import java.util.ArrayList;
import java.util.List;

public class CredentialStore {
    private final StorageEngine mStorageEngine;
    private final KeystoreEngineRepository mKeystoreEngineRepository;

    public CredentialStore(@NonNull StorageEngine storageEngine,
                           @NonNull KeystoreEngineRepository keystoreEngineRepository) {
        mStorageEngine = storageEngine;
        mKeystoreEngineRepository = keystoreEngineRepository;
    }

    public @NonNull Credential createCredential(@NonNull String name,
                                                @NonNull String docType,
                                                @NonNull KeystoreEngine.CreateKeySettings credentialKeySettings) {
        return Credential.create(mStorageEngine,
                mKeystoreEngineRepository,
                name,
                docType,
                credentialKeySettings);
    }

    public @Nullable Credential lookupCredential(@NonNull String name) {
        return Credential.lookup(mStorageEngine, mKeystoreEngineRepository, name);
    }

    public @NonNull List<String> listCredentials() {
        ArrayList<String> ret = new ArrayList<>();
        for (String name : mStorageEngine.enumerateData()) {
            if (name.startsWith(Credential.CREDENTIAL_PREFIX)) {
                ret.add(name.substring(Credential.CREDENTIAL_PREFIX.length()));
            }
        }
        return ret;
    }

    public void deleteCredential(@NonNull String name) {
        Credential credential = lookupCredential(name);
        if (credential == null) {
            return;
        }
        credential.deleteCredential();
    }
}
