package com.android.identity;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

public class KeystoreEngineRepository {

    List<KeystoreEngine> mImplementations = new ArrayList<>();

    public KeystoreEngineRepository() {
    }

    public @NonNull List<KeystoreEngine> getImplementations() {
        return Collections.unmodifiableList(mImplementations);
    }

    public @Nullable KeystoreEngine getImplementation(String className) {
        for (KeystoreEngine implementation : mImplementations) {
            if (implementation.getClass().getName().equals(className)) {
                return implementation;
            }
        }
        return null;
    }

    public void addImplementation(KeystoreEngine keystoreEngine) {
        mImplementations.add(keystoreEngine);
    }
}
